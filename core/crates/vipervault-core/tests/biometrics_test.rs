// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometrics contract and runtime unlock tests
//!
//! # Scope
//! These tests validate both:
//! - the abstract biometric backend contract
//! - the high-level runtime biometric unlock flow through `VaultLockManager`
//!
//! # Security
//! Biometrics are used only as a gate to release a previously stored
//! 32-byte master key
//!
//! These tests ensure:
//! - availability and backend errors remain correctly classified
//! - runtime unlock succeeds only for encrypted non-duress vaults
//! - policy denial remains distinct
//! - unsupported or restrictive runtime states fail closed

use std::io::Cursor;
use std::time::Duration;
use vipervault_core::biometrics::{BiometricBackend, BiometricError};
use vipervault_core::core::{PolicyContext, RuntimeInspectionState, VaultLockManager};
use vipervault_core::memory::{KeyMaterial, MasterPassword};
use vipervault_core::vault::create::{create_duress_vault, create_encrypted_vault, VaultKdfPolicy};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{
    decode_vault_file, encode_vault_storage, ParsedVaultFile, StorageMode, VaultPayload,
};

/// Simple test backend used to exercise the trait contract and runtime unlocks
#[derive(Debug)]
struct StubBackend {
    available: bool,
    result: Result<[u8; 32], BiometricError>,
}

impl BiometricBackend for StubBackend {
    fn is_available(&self) -> bool {
        self.available
    }

    fn unseal_master_key(&self, vault_id: &[u8]) -> Result<KeyMaterial, BiometricError> {
        if vault_id.is_empty() {
            return Err(BiometricError::InvalidResponse);
        }

        match &self.result {
            Ok(bytes) => Ok(KeyMaterial::new(*bytes)),
            Err(BiometricError::PolicyDenied) => Err(BiometricError::PolicyDenied),
            Err(BiometricError::Unavailable) => Err(BiometricError::Unavailable),
            Err(BiometricError::AuthFailed) => Err(BiometricError::AuthFailed),
            Err(BiometricError::InvalidResponse) => Err(BiometricError::InvalidResponse),
            Err(BiometricError::NotSupported) => Err(BiometricError::NotSupported),
        }
    }
}

/// Build the KDF policy used across vault-creation tests
fn vault_kdf() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build a small decrypted payload for runtime biometric tests
fn sample_payload() -> VaultPayload {
    VaultPayload { entries: vec![] }
}

/// Build a parsed encrypted vault using the provided password
fn parsed_encrypted_vault(password: &MasterPassword) -> ParsedVaultFile {
    let payload = sample_payload();
    let vault = create_encrypted_vault(password, &payload, 1, vault_kdf()).expect("create vault");
    let encoded = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    decode_vault_file(Cursor::new(encoded), Some(1), 1024 * 1024, false).expect("decode vault")
}

/// Build a parsed duress-enabled encrypted vault
fn parsed_duress_vault(
    primary_password: &MasterPassword,
    decoy_password: &MasterPassword,
) -> ParsedVaultFile {
    let primary_payload = sample_payload();
    let decoy_payload = sample_payload();

    let vault = create_duress_vault(
        primary_password,
        decoy_password,
        &primary_payload,
        &decoy_payload,
        1,
        vault_kdf(),
    )
        .expect("create duress vault");

    let encoded = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    decode_vault_file(Cursor::new(encoded), Some(1), 1024 * 1024, false)
        .expect("decode duress vault")
}

/// Build a plaintext-mode parsed vault by mutating a valid encrypted parsed vault
///
/// # Design
/// This preserves a structurally valid parsed object while forcing the runtime
/// biometric path to reject non-encrypted storage
fn parsed_plaintext_mode_vault(password: &MasterPassword) -> ParsedVaultFile {
    let mut parsed = parsed_encrypted_vault(password);
    parsed.mode = StorageMode::PlaintextJson;
    parsed.payload = br#"{"entries":[]}"#.to_vec();
    parsed
}

/// Availability must be reported faithfully by the backend
#[test]
fn backend_reports_availability() {
    let available = StubBackend {
        available: true,
        result: Ok([7u8; 32]),
    };
    let unavailable = StubBackend {
        available: false,
        result: Err(BiometricError::Unavailable),
    };

    assert!(available.is_available());
    assert!(!unavailable.is_available());
}

/// Successful unseal must return exactly 32 bytes of key material
#[test]
fn unseal_success_returns_key_material() {
    let backend = StubBackend {
        available: true,
        result: Ok([0xAB; 32]),
    };

    let key = backend
        .unseal_master_key(b"vault-id")
        .expect("unseal master key");

    assert_eq!(key.as_bytes().len(), 32);
    assert_eq!(key.as_bytes().as_slice(), &[0xAB; 32]);
}

/// Empty vault identifiers must be rejected by the backend contract
#[test]
fn empty_vault_id_is_invalid_response() {
    let backend = StubBackend {
        available: true,
        result: Ok([1u8; 32]),
    };

    let err = backend.unseal_master_key(b"").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
}

/// Unavailable backends must return `Unavailable`
#[test]
fn unavailable_is_preserved() {
    let backend = StubBackend {
        available: false,
        result: Err(BiometricError::Unavailable),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::Unavailable));
}

/// Authentication failures must remain coarse-grained
#[test]
fn auth_failed_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::AuthFailed),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::AuthFailed));
}

/// Policy denial must remain distinct from generic auth failure
#[test]
fn policy_denied_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::PolicyDenied),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::PolicyDenied));
}

/// Unsupported vault modes must return `NotSupported`
#[test]
fn not_supported_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::NotSupported),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::NotSupported));
}

/// Invalid backend responses must remain coarse-grained
#[test]
fn invalid_response_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::InvalidResponse),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
}

/// Unlocking with a correct master key through the biometric path must unlock the manager
#[tokio::test]
async fn unlock_with_master_key_unlocks_manager() {
    let policy =
        PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let password = MasterPassword::new("pw".to_string());
    let parsed = parsed_encrypted_vault(&password);
    let manager = VaultLockManager::new();

    let key_bytes = vipervault_core::crypto::kdf::derive_master_key_from_password(
        &password,
        &parsed.header.crypto.salt,
        64 * 1024,
        3,
        1,
    )
        .expect("derive master key");

    manager
        .unlock_with_master_key(policy, &parsed, &key_bytes, Duration::from_secs(60))
        .await
        .expect("unlock with master key");

    let payload = manager.get_payload().await.expect("payload");
    assert!(payload.entries.is_empty());
}

/// High-level biometric unlock must unlock the manager when the backend returns
/// the correct master key
#[tokio::test]
async fn unlock_with_biometrics_unlocks_manager() {
    let policy =
        PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let password = MasterPassword::new("pw".to_string());
    let parsed = parsed_encrypted_vault(&password);
    let manager = VaultLockManager::new();

    let key_bytes = vipervault_core::crypto::kdf::derive_master_key_from_password(
        &password,
        &parsed.header.crypto.salt,
        64 * 1024,
        3,
        1,
    )
        .expect("derive master key");

    let mut raw = [0u8; 32];
    raw.copy_from_slice(key_bytes.as_bytes());

    let backend = StubBackend {
        available: true,
        result: Ok(raw),
    };

    manager
        .unlock_with_biometrics(
            policy,
            &parsed,
            &backend,
            parsed.header.vault_id.as_bytes(),
            Duration::from_secs(60),
        )
        .await
        .expect("unlock with biometrics");

    let payload = manager.get_payload().await.expect("payload");
    assert!(payload.entries.is_empty());
}

/// Biometric unlock must be denied when policy forbids it
#[tokio::test]
async fn unlock_with_biometrics_respects_policy_denied() {
    let policy =
        PolicyContext::from_parts(UnlockOutcome::Decoy, RuntimeInspectionState::NotDebugged);
    let password = MasterPassword::new("pw".to_string());
    let parsed = parsed_encrypted_vault(&password);
    let manager = VaultLockManager::new();

    let backend = StubBackend {
        available: true,
        result: Ok([1u8; 32]),
    };

    let err = manager
        .unlock_with_biometrics(
            policy,
            &parsed,
            &backend,
            parsed.header.vault_id.as_bytes(),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, BiometricError::PolicyDenied));
    assert!(manager.get_payload().await.is_none());
}

/// Unknown runtime state must deny biometric unlock
#[tokio::test]
async fn unlock_with_biometrics_denied_under_unknown_runtime() {
    let policy = PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::Unknown);
    let password = MasterPassword::new("pw".to_string());
    let parsed = parsed_encrypted_vault(&password);
    let manager = VaultLockManager::new();

    let backend = StubBackend {
        available: true,
        result: Ok([1u8; 32]),
    };

    let err = manager
        .unlock_with_biometrics(
            policy,
            &parsed,
            &backend,
            parsed.header.vault_id.as_bytes(),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, BiometricError::PolicyDenied));
    assert!(manager.get_payload().await.is_none());
}

/// Biometric unlock must fail with `Unavailable` when the backend is not available
#[tokio::test]
async fn unlock_with_biometrics_unavailable_backend_is_rejected() {
    let policy =
        PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let password = MasterPassword::new("pw".to_string());
    let parsed = parsed_encrypted_vault(&password);
    let manager = VaultLockManager::new();

    let backend = StubBackend {
        available: false,
        result: Err(BiometricError::Unavailable),
    };

    let err = manager
        .unlock_with_biometrics(
            policy,
            &parsed,
            &backend,
            parsed.header.vault_id.as_bytes(),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, BiometricError::Unavailable));
    assert!(manager.get_payload().await.is_none());
}

/// Duress-enabled vaults must not support biometric unlock
#[tokio::test]
async fn unlock_with_master_key_rejects_duress_vaults() {
    let policy =
        PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let primary = MasterPassword::new("pw".to_string());
    let decoy = MasterPassword::new("decoy".to_string());
    let parsed = parsed_duress_vault(&primary, &decoy);
    let manager = VaultLockManager::new();

    let key_bytes = vipervault_core::crypto::kdf::derive_master_key_from_password(
        &primary,
        &parsed.header.crypto.salt,
        64 * 1024,
        3,
        1,
    )
        .expect("derive master key");

    let err = manager
        .unlock_with_master_key(policy, &parsed, &key_bytes, Duration::from_secs(60))
        .await
        .unwrap_err();

    assert!(matches!(err, BiometricError::NotSupported));
    assert!(manager.get_payload().await.is_none());
}

/// Plaintext-mode parsed vaults must be rejected by the biometric path
#[tokio::test]
async fn unlock_with_master_key_rejects_plaintext_mode() {
    let policy =
        PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let password = MasterPassword::new("pw".to_string());
    let parsed = parsed_plaintext_mode_vault(&password);
    let manager = VaultLockManager::new();

    let key_bytes = vipervault_core::crypto::kdf::derive_master_key_from_password(
        &password,
        &parsed.header.crypto.salt,
        64 * 1024,
        3,
        1,
    )
        .expect("derive master key");

    let err = manager
        .unlock_with_master_key(policy, &parsed, &key_bytes, Duration::from_secs(60))
        .await
        .unwrap_err();

    assert!(matches!(err, BiometricError::AuthFailed));
    assert!(manager.get_payload().await.is_none());
}

/// Incorrect master keys must fail with coarse-grained `AuthFailed`
#[tokio::test]
async fn unlock_with_master_key_wrong_key_is_auth_failed() {
    let policy =
        PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let password = MasterPassword::new("pw".to_string());
    let parsed = parsed_encrypted_vault(&password);
    let manager = VaultLockManager::new();

    let wrong_key = KeyMaterial::new([0x55; 32]);

    let err = manager
        .unlock_with_master_key(policy, &parsed, &wrong_key, Duration::from_secs(60))
        .await
        .unwrap_err();

    assert!(matches!(err, BiometricError::AuthFailed));
    assert!(manager.get_payload().await.is_none());
}
