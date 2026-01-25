// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Integration test: metadata minimization (no secret metadata in cleartext)
//!
//! # Scope
//! This test verifies that user-controlled entry fields (title/username/note/secret)
//! do not appear in the cleartext bytes of the stored vault file
//!
//! # Security
//! Protects against offline metadata scraping from stolen vault files
//! Only the minimal unlock metadata (format/version/crypto params/vault_id) should be visible

use uuid::Uuid;
use vipervault_core::crypto::aead::encrypt_xchacha20poly1305;
use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, StorageMode, VaultHeader, VaultPayload,
};

/// Build an encrypted vault file bytes where header bytes are authenticated AAD
/// Keep header minimal and store all user data inside encrypted payload
fn build_encrypted_file_bytes(payload: &VaultPayload, password: &MasterPassword) -> Vec<u8> {
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
            salt: generate_vault_salt().unwrap(),
            nonce: [3u8; 24],
        },
    };

    // Use pretty JSON to create stable header bytes for AAD, but header still contains only unlock metadata
    let header_bytes = serde_json::to_string_pretty(&header).unwrap().into_bytes();

    let plaintext = serde_json::to_vec(payload).unwrap();

    let (mem_kib, time_cost, lanes) = match header.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
        _ => panic!("unsupported kdf algorithm"),
    };

    let key =
        derive_master_key_from_password(password, &header.crypto.salt, mem_kib, time_cost, lanes)
            .unwrap();
    let ct =
        encrypt_xchacha20poly1305(&key, &header.crypto.nonce, &plaintext, &header_bytes).unwrap();

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(StorageMode::Encrypted as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

#[test]
fn stored_file_does_not_leak_entry_metadata_or_secrets_in_cleartext() {
    let password = MasterPassword::new("pw".to_string());

    // Distinctive strings which must not be found in the raw file bytes
    let title = "VERY_UNLIKELY_TITLE_9f7a3c";
    let username = "VERY_UNLIKELY_USER_0b12d9";
    let note = "VERY_UNLIKELY_NOTE_52c7e1";
    let secret = "VERY_UNLIKELY_SECRET_aa77cc";

    let entry = VaultEntry::new_password(
        title.to_string(),
        Some(username.to_string()),
        secret.to_string(),
        Some(note.to_string()),
    )
    .unwrap();

    let payload = VaultPayload {
        entries: vec![entry],
    };

    let file_bytes = build_encrypted_file_bytes(&payload, &password);

    let haystack = String::from_utf8_lossy(&file_bytes);

    assert!(!haystack.contains(title), "title leaked in cleartext");
    assert!(!haystack.contains(username), "username leaked in cleartext");
    assert!(!haystack.contains(note), "note leaked in cleartext");
    assert!(!haystack.contains(secret), "secret leaked in cleartext");
}
