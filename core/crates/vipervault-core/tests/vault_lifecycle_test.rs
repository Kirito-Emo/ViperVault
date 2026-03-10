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
use vipervault_core::core::VaultLockManager;
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_encrypted_vault};
use vipervault_core::vault::{
    MAX_VAULT_CONTAINER_PAYLOAD_LEN, StorageMode, VaultPayload, decode_vault_file,
    encode_vault_storage,
};

/// Build a minimal encrypted vault storage from a payload
fn build_encrypted_vault(payload: &VaultPayload, password: &MasterPassword) -> Vec<u8> {
    let kdf = VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    };

    let vault = create_encrypted_vault(password, payload, 1, kdf).expect("create encrypted vault");
    encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault")
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

    let entry_id = entry.meta.id;

    let payload = VaultPayload {
        entries: vec![entry],
    };

    let password = MasterPassword::new("correct horse battery staple".to_string());

    // Encrypt + encode
    let encoded = build_encrypted_vault(&payload, &password);

    // Decode
    let parsed = decode_vault_file(
        Cursor::new(&encoded),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
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
    assert_eq!(unlocked_payload.entries[0].meta.id, entry_id);

    let view = manager.get_entry(entry_id).await.expect("entry view");

    assert_eq!(view.expose_title(), "Test entry");
    assert_eq!(view.expose_secret(), "super-secret");
}
