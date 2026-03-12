// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Signed backup codec tests
//!
//! # Scope
//! These tests validate the signed backup container codec:
//! - successful encode/decode roundtrip
//! - policy denial in decoy mode
//! - wrong password and tampering coarse-grained behavior
//! - unsupported version rejection
//! - payload size cap enforcement
//! - malformed container rejection
//!
//! # Security
//! The backup codec protects exported vault containers against tampering \
//! These tests ensure that:
//! - signing and verification remain consistent
//! - wrong password and tampered backup stay indistinguishable
//! - oversized payloads are rejected before unsafe processing
//! - malformed containers are rejected without panics

use vipervault_core::backup::types::{BACKUP_MAGIC, MAX_BACKUP_PAYLOAD_LEN};
use vipervault_core::backup::{
    BackupError, BackupKdfPolicy, decode_signed_backup, encode_signed_backup,
};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::duress::UnlockOutcome;

fn backup_kdf() -> BackupKdfPolicy {
    BackupKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// A valid signed backup must roundtrip successfully
#[test]
fn signed_backup_roundtrip_success() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let vault_bytes = b"test-vault-container".to_vec();

    let encoded =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let decoded = decode_signed_backup(policy, &password, &encoded).expect("decode backup");

    assert_eq!(decoded, vault_bytes);
}

/// Decoy policy must deny backup encoding
#[test]
fn signed_backup_encode_denied_in_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);
    let password = MasterPassword::new("pw".to_string());

    let err = encode_signed_backup(policy, &password, b"vault", backup_kdf()).unwrap_err();
    assert!(matches!(err, BackupError::PolicyDenied));
}

/// Decoy policy must deny backup decoding
#[test]
fn signed_backup_decode_denied_in_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);
    let password = MasterPassword::new("pw".to_string());

    let err = decode_signed_backup(policy, &password, b"anything").unwrap_err();
    assert!(matches!(err, BackupError::PolicyDenied));
}

/// Wrong password must fail with coarse-grained `AuthFailed`
#[test]
fn signed_backup_wrong_password_is_auth_failed() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let wrong = MasterPassword::new("wrong".to_string());
    let vault_bytes = b"test-vault-container".to_vec();

    let encoded =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let err = decode_signed_backup(policy, &wrong, &encoded).unwrap_err();
    assert!(matches!(err, BackupError::AuthFailed));
}

/// Tampering must fail with the same coarse-grained `AuthFailed`
#[test]
fn signed_backup_tamper_is_auth_failed() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let vault_bytes = b"test-vault-container".to_vec();

    let mut encoded =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;

    let err = decode_signed_backup(policy, &password, &encoded).unwrap_err();
    assert!(matches!(err, BackupError::AuthFailed));
}

/// Payloads above the backup cap must be rejected on encode
#[test]
fn signed_backup_encode_rejects_oversized_payload() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let oversized = vec![0u8; (MAX_BACKUP_PAYLOAD_LEN as usize) + 1];

    let err = encode_signed_backup(policy, &password, &oversized, backup_kdf()).unwrap_err();
    assert!(matches!(err, BackupError::PayloadTooLarge));
}

/// Invalid magic must be rejected
#[test]
fn signed_backup_invalid_magic_is_rejected() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    let mut bad = vec![0u8; BACKUP_MAGIC.len()];
    bad.copy_from_slice(b"NOTMAGIC");

    let err = decode_signed_backup(policy, &password, &bad).unwrap_err();
    assert!(matches!(err, BackupError::InvalidFormat));
}

/// Unsupported version must be rejected
#[test]
fn signed_backup_unsupported_version_is_rejected() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&BACKUP_MAGIC);
    bytes.extend_from_slice(&999u16.to_le_bytes());

    let err = decode_signed_backup(policy, &password, &bytes).unwrap_err();
    assert!(matches!(err, BackupError::UnsupportedVersion));
}

/// Truncated containers must be rejected safely
#[test]
fn signed_backup_truncated_container_is_rejected() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    let mut encoded =
        encode_signed_backup(policy, &password, b"vault", backup_kdf()).expect("encode backup");
    encoded.truncate(encoded.len() - 3);

    let err = decode_signed_backup(policy, &password, &encoded).unwrap_err();
    assert!(matches!(err, BackupError::InvalidFormat));
}

/// Trailing garbage must be rejected safely
#[test]
fn signed_backup_trailing_bytes_are_rejected() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    let mut encoded =
        encode_signed_backup(policy, &password, b"vault", backup_kdf()).expect("encode backup");
    encoded.extend_from_slice(b"garbage");

    let err = decode_signed_backup(policy, &password, &encoded).unwrap_err();
    assert!(matches!(err, BackupError::InvalidFormat));
}
