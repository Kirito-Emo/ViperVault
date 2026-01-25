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

fn make_encrypted_vault(password: &MasterPassword) -> Vec<u8> {
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
        entries: b"secret-data".to_vec(),
    };
    let payload_json = serde_json::to_vec(&payload).unwrap();

    let key =
        derive_master_key_from_password(password, &salt, mem_kib, time_cost, lanes).expect("kdf");

    let header_bytes = serde_json::to_vec(&header).unwrap();

    let ciphertext =
        encrypt_xchacha20poly1305(&key, &nonce, &payload_json, &header_bytes).expect("encrypt");

    let storage = VaultStorage::Encrypted { ciphertext };

    encode_vault_storage(&header, &storage, 1).expect("encode")
}

/// Correct password unlocks successfully
#[test]
fn unlock_succeeds_with_correct_password() {
    let password = MasterPassword::from_string("correct-password".to_string());
    let bytes = make_encrypted_vault(&password);

    let parsed =
        decode_vault_file(Cursor::new(bytes), Some(1), 1024 * 1024, false).expect("decode");

    let plaintext =
        unlock_vault_to_plaintext_json(&parsed, &password).expect("unlock must succeed");

    let payload: VaultPayload = serde_json::from_slice(&plaintext).expect("decode payload");

    assert_eq!(payload.entries, b"secret-data");
}

/// Wrong password must fail with AuthFailed
#[test]
fn unlock_fails_with_wrong_password() {
    let correct = MasterPassword::from_string("correct-password".to_string());
    let wrong = MasterPassword::from_string("wrong-password".to_string());

    let bytes = make_encrypted_vault(&correct);

    let parsed =
        decode_vault_file(Cursor::new(bytes), Some(1), 1024 * 1024, false).expect("decode");

    let err = unlock_vault_to_plaintext_json(&parsed, &wrong).expect_err("unlock must fail");

    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Tampering with the header (AAD) must fail authentication
#[test]
fn unlock_fails_if_header_is_tampered() {
    let password = MasterPassword::from_string("password".to_string());
    let bytes = make_encrypted_vault(&password);

    // Decode once to extract structured components
    let parsed = decode_vault_file(Cursor::new(bytes.clone()), Some(1), 1024 * 1024, false)
        .expect("initial decode");

    // Deserialize header JSON
    let mut header = parsed.header.clone();

    // Semantic but valid modification
    header.schema_version += 1;

    let new_header_bytes = serde_json::to_vec(&header).expect("serialize header");

    // Rebuild the file manually
    let mut tampered = Vec::new();

    tampered.extend_from_slice(&vipervault_core::vault::MAGIC); // MAGIC
    tampered.extend_from_slice(&parsed.format_version.to_le_bytes()); // format version
    tampered.push(parsed.mode as u8); // storage mode
    tampered.extend_from_slice(&(new_header_bytes.len() as u32).to_le_bytes()); // header length
    tampered.extend_from_slice(&new_header_bytes); // header bytes
    tampered.extend_from_slice(&(parsed.payload.len() as u64).to_le_bytes()); // payload length
    tampered.extend_from_slice(&parsed.payload); // payload bytes (ciphertext unchanged)

    // Parsing must still succeed
    let parsed_tampered = decode_vault_file(Cursor::new(tampered), Some(1), 1024 * 1024, false)
        .expect("decode must succeed");

    // Unlock must fail due to AAD mismatch
    let err =
        unlock_vault_to_plaintext_json(&parsed_tampered, &password).expect_err("unlock must fail");

    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Tampering with ciphertext must fail authentication
#[test]
fn unlock_fails_if_ciphertext_is_tampered() {
    let password = MasterPassword::from_string("password".to_string());
    let mut bytes = make_encrypted_vault(&password);

    // Flip a bit near the end (ciphertext area)
    let last = bytes.len() - 1;
    bytes[last] ^= 0xAA;

    let parsed =
        decode_vault_file(Cursor::new(bytes), Some(1), 1024 * 1024, false).expect("decode");

    let err = unlock_vault_to_plaintext_json(&parsed, &password).expect_err("unlock must fail");

    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Plaintext vaults must not be unlockable
#[test]
fn unlock_rejects_plaintext_mode() {
    let password = MasterPassword::from_string("password".to_string());

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: 64 * 1024,
                time_cost: 3,
                lanes: 1,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: [0u8; 32],
            nonce: [0u8; 24],
        },
    };

    let storage = VaultStorage::PlaintextJson {
        json: br#"{"entries":"nope"}"#.to_vec(),
    };

    let bytes = encode_vault_storage(&header, &storage, 1).expect("encode");
    let parsed = decode_vault_file(Cursor::new(bytes), Some(1), 1024 * 1024, true).expect("decode");
    let err = unlock_vault_to_plaintext_json(&parsed, &password).expect_err("unlock must fail");

    assert!(matches!(err, UnlockError::AuthFailed));
}
