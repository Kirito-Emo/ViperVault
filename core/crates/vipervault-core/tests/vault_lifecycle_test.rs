// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Integration test: full vault lifecycle
//!
//! This test verifies that:
//! - a vault payload can be encrypted, encoded, written, read, decoded
//! - the vault can be unlocked with the correct password
//! - decrypted payload matches the original content
//!
//! This is an end-to-end test across crypto, codec, storage and core layers

use std::io::Cursor;
use std::time::Duration;
use uuid::Uuid;
use vipervault_core::core::VaultLockManager;
use vipervault_core::crypto::aead::generate_xchacha20_nonce;
use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, StorageMode, VaultHeader, VaultPayload, VaultStorage,
    decode_vault_file, encode_vault_storage,
};

/// Build a minimal encrypted vault storage from a payload
fn build_encrypted_vault(payload: &VaultPayload, password: &MasterPassword) -> Vec<u8> {
    // Crypto params
    let salt = generate_vault_salt().expect("salt generation");
    let nonce = generate_xchacha20_nonce().expect("nonce generation");

    let master_key = derive_master_key_from_password(
        password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
    };

    let plaintext = serde_json::to_vec(payload).expect("payload serialize");

    let ciphertext = vipervault_core::crypto::aead::encrypt_xchacha20poly1305(
        &master_key,
        &nonce,
        &plaintext,
        &serde_json::to_vec(&header).unwrap(),
    )
    .expect("encrypt");

    let storage = VaultStorage::Encrypted { ciphertext };

    encode_vault_storage(&header, &storage, 1).expect("encode vault")
}

#[tokio::test]
async fn full_vault_lifecycle_encrypt_decode_unlock() {
    // Initial payload
    let entry = VaultEntry::new_password(
        "Test entry".to_string(),
        Some("user".to_string()),
        "super-secret".to_string(),
        Some("note".to_string()),
    )
    .expect("entry");

    let payload = VaultPayload {
        entries: vec![entry],
    };

    let password = MasterPassword::new("correct horse battery staple".to_string());

    // Encrypt + encode
    let encoded = build_encrypted_vault(&payload, &password);

    // Decode
    let parsed = decode_vault_file(Cursor::new(&encoded), Some(1), 10 * 1024 * 1024, false)
        .expect("decode vault");

    assert_eq!(parsed.mode, StorageMode::Encrypted);

    // Unlock via lock manager
    let manager = VaultLockManager::new();
    let plaintext =
        vipervault_core::core::unlock_vault_to_plaintext_json(&parsed, &password).expect("unlock");

    manager
        .unlock_with_plaintext_json(plaintext.to_vec(), Duration::from_secs(60))
        .await;

    // Verify payload integrity
    let unlocked_payload = manager.get_payload().await.expect("payload");
    assert_eq!(unlocked_payload.entries.len(), 1);

    let view = manager
        .get_entry(unlocked_payload.entries[0].meta.id)
        .await
        .expect("entry view");

    assert_eq!(view.expose_title(), "Test entry");
    assert_eq!(view.expose_secret(), "super-secret");
}
