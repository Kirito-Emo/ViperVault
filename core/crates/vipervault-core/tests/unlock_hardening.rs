// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::core::{UnlockError, unlock_vault_to_plaintext_json};
use vipervault_core::crypto::aead::{encrypt_xchacha20poly1305, generate_xchacha20_nonce};
use vipervault_core::crypto::kdf::{
    default_argon2id_params, derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::codec::{decode_vault_file, encode_vault_storage};
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, VaultHeader, VaultPayload, VaultStorage,
};

fn make_vault(password: &MasterPassword) -> Vec<u8> {
    let (mem_kib, time_cost, lanes) = default_argon2id_params();

    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib,
                time_cost,
                lanes,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
    };

    let payload = VaultPayload {
        entries: b"secret".to_vec(),
    };
    let payload_json = serde_json::to_vec(&payload).unwrap();

    let key =
        derive_master_key_from_password(password, &salt, mem_kib, time_cost, lanes).expect("kdf");
    let header_bytes = serde_json::to_vec(&header).unwrap();

    let ciphertext =
        encrypt_xchacha20poly1305(&key, &nonce, &payload_json, &header_bytes).expect("encrypt");
    encode_vault_storage(&header, &VaultStorage::Encrypted { ciphertext }, 1).expect("encode")
}

/// Changing KDF params in header (valid JSON) must break authentication via AAD mismatch
#[test]
fn rejects_kdf_param_tampering() {
    let password = MasterPassword::from_string("pw".to_string());
    let bytes = make_vault(&password);

    let parsed =
        decode_vault_file(Cursor::new(bytes.clone()), Some(1), 1024 * 1024, false).expect("decode");

    // Change KDF params but keep JSON valid
    let mut header = parsed.header.clone();
    header.crypto.kdf = KdfParams::Argon2id {
        mem_kib: 128 * 1024,
        time_cost: 4,
        lanes: 1,
    };

    let new_header_bytes = serde_json::to_vec(&header).expect("serialize header");

    // Rebuild container with same ciphertext
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&vipervault_core::vault::MAGIC);
    rebuilt.extend_from_slice(&parsed.format_version.to_le_bytes());
    rebuilt.push(parsed.mode as u8);
    rebuilt.extend_from_slice(&(new_header_bytes.len() as u32).to_le_bytes());
    rebuilt.extend_from_slice(&new_header_bytes);
    rebuilt.extend_from_slice(&(parsed.payload.len() as u64).to_le_bytes());
    rebuilt.extend_from_slice(&parsed.payload);

    let parsed2 =
        decode_vault_file(Cursor::new(rebuilt), Some(1), 1024 * 1024, false).expect("decode 2");

    let err = unlock_vault_to_plaintext_json(&parsed2, &password).expect_err("must fail");
    assert!(matches!(err, UnlockError::AuthFailed));
}
