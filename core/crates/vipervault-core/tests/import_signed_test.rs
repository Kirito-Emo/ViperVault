// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Signed import tests
//!
//! # Scope
//! These tests validate the signed import primitive:
//! - valid signed backup import
//! - decoy policy denial
//! - wrong password and tamper coarse-grained behavior
//! - plaintext vault container rejection
//! - oversized inner vault payload rejection
//!
//! # Security
//! The signed import path is a high-value boundary because it accepts external
//! backup bytes. These tests ensure that:
//! - decoy mode denies import
//! - wrong password and tampering remain indistinguishable
//! - plaintext containers are rejected
//! - anti-DoS payload caps are enforced on the inner vault container

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::backup::{BackupKdfPolicy, encode_signed_backup};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::import::{ImportError, import_vipervault_from_signed_backup};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_encrypted_vault};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, MAX_VAULT_CONTAINER_PAYLOAD_LEN, SALT_LEN,
    StorageMode, VaultHeader, VaultPayload, XCHACHA20_NONCE_LEN, decode_vault_file,
    encode_vault_storage,
};

fn backup_kdf() -> BackupKdfPolicy {
    BackupKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

fn vault_kdf() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

fn sample_payload() -> VaultPayload {
    let entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "super-secret".to_string(),
        Some("note".to_string()),
    )
    .expect("entry");

    VaultPayload {
        entries: vec![entry],
    }
}

fn minimal_header() -> VaultHeader {
    VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: 64 * 1024,
                time_cost: 3,
                lanes: 1,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: [0u8; SALT_LEN],
            nonce: [0u8; XCHACHA20_NONCE_LEN],
        },
        duress: None,
    }
}

/// Build a plaintext vault container manually
///
/// # Security
/// This helper avoids depending on plaintext-export soft policy during test setup
fn build_plaintext_container_bytes(json_payload: &[u8]) -> Vec<u8> {
    let header = minimal_header();
    let header_bytes = serde_json::to_vec(&header).expect("serialize header");

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(StorageMode::PlaintextJson as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(json_payload.len() as u64).to_le_bytes());
    out.extend_from_slice(json_payload);
    out
}

/// Build an encrypted vault container whose payload length exceeds the accepted cap
///
/// # Security
/// This helper creates a tiny container that declares an oversized payload
/// without actually allocating it, so the parser can reject it before reading
fn build_oversized_inner_vault_bytes() -> Vec<u8> {
    let header = minimal_header();
    let header_bytes = serde_json::to_vec(&header).expect("serialize header");

    let oversized_len = MAX_VAULT_CONTAINER_PAYLOAD_LEN + 1;

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(StorageMode::Encrypted as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&oversized_len.to_le_bytes());
    out
}

/// Valid signed backup import must return a parsed encrypted vault container
#[test]
fn import_signed_backup_success() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let payload = sample_payload();

    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let parsed = import_vipervault_from_signed_backup(policy, &password, &signed).expect("import");

    assert_eq!(parsed.mode, StorageMode::Encrypted);
    assert_eq!(parsed.format_version, 1);

    // The parsed container must still be a valid vault container
    let reparsed = decode_vault_file(
        Cursor::new(vault_bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("redecode");

    assert_eq!(parsed.header.vault_id, reparsed.header.vault_id);
}

/// Decoy policy must deny signed import
#[test]
fn import_signed_backup_denied_in_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);
    let password = MasterPassword::new("pw".to_string());

    let err = import_vipervault_from_signed_backup(policy, &password, b"anything").unwrap_err();
    assert!(matches!(err, ImportError::PolicyDenied));
}

/// Wrong password must fail with coarse-grained `AuthFailed`
#[test]
fn import_signed_backup_wrong_password_is_auth_failed() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let wrong = MasterPassword::new("wrong".to_string());

    let payload = sample_payload();
    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let err = import_vipervault_from_signed_backup(policy, &wrong, &signed).unwrap_err();
    assert!(matches!(err, ImportError::AuthFailed));
}

/// Tampered signed backup must fail with the same coarse-grained `AuthFailed`
#[test]
fn import_signed_backup_tamper_is_auth_failed() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    let payload = sample_payload();
    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let mut signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let last = signed.len() - 1;
    signed[last] ^= 0x01;

    let err = import_vipervault_from_signed_backup(policy, &password, &signed).unwrap_err();
    assert!(matches!(err, ImportError::AuthFailed));
}

/// Plaintext vault containers must be rejected even if they are valid signed backups
#[test]
fn import_signed_backup_rejects_plaintext_container() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    let plaintext_vault_bytes = build_plaintext_container_bytes(br#"{"entries":[]}"#);

    let signed = encode_signed_backup(policy, &password, &plaintext_vault_bytes, backup_kdf())
        .expect("encode backup");

    let err = import_vipervault_from_signed_backup(policy, &password, &signed).unwrap_err();
    assert!(matches!(err, ImportError::InvalidFormat));
}

/// Oversized inner vault payload declarations must be rejected before allocation
#[test]
fn import_signed_backup_rejects_oversized_inner_vault_payload() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    let oversized_inner = build_oversized_inner_vault_bytes();

    let signed =
        encode_signed_backup(policy, &password, &oversized_inner, backup_kdf()).expect("encode");

    let err = import_vipervault_from_signed_backup(policy, &password, &signed).unwrap_err();
    assert!(matches!(err, ImportError::PayloadTooLarge));
}
