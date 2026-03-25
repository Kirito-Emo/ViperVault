// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Signed import E2E tests
//!
//! # Scope
//! These tests validate the high-level signed import and unlock flow:
//! - successful import and manager unlock
//! - policy denial in decoy mode
//! - wrong password coarse-grained rejection
//! - tamper coarse-grained rejection
//! - resulting manager usability after successful import
//! - decrypted payload availability only after successful unlock
//!
//! # Security
//! This path is the async UI-facing import boundary. These tests ensure that:
//! - policy gates are enforced
//! - the gated unlock path is exercised
//! - wrong password and tampering remain indistinguishable
//! - imported content becomes available only through the unlocked manager

use secrecy::ExposeSecret;
use std::time::Duration;
use vipervault_core::backup::{encode_signed_backup, BackupKdfPolicy};
use vipervault_core::core::auth_gate::AuthGate;
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::core::rate_limit::UnlockThrottlePolicy;
use vipervault_core::core::VaultLockManager;
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::import::{import_signed_vault_and_unlock, ImportError};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{create_encrypted_vault, VaultKdfPolicy};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{encode_vault_storage, VaultPayload};

/// Build the backup KDF policy used across tests
fn backup_kdf() -> BackupKdfPolicy {
    BackupKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build the vault KDF policy used across tests
fn vault_kdf() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build a tiny throttle policy for tests
fn tiny_test_policy() -> UnlockThrottlePolicy {
    UnlockThrottlePolicy {
        quiet_period: Duration::from_secs(60),
        max_delay: Duration::from_millis(1),
        jitter_max: Duration::ZERO,
    }
}

/// Build a representative payload used across E2E import tests
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

/// Successful signed import must unlock the manager with the imported content
#[tokio::test]
async fn import_signed_e2e_success_unlocks_manager() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let gate = AuthGate::new(tiny_test_policy());
    let manager = VaultLockManager::new();
    let password = MasterPassword::new("pw".to_string());

    let payload = sample_payload();
    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    import_signed_vault_and_unlock(
        policy,
        &gate,
        &manager,
        password,
        &signed,
        Duration::from_secs(60),
    )
    .await
    .expect("e2e import");

    let entries = manager.list_entries().await.expect("list entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].expose_title(), "GitHub");

    let view = manager
        .get_entry(entries[0].id)
        .await
        .expect("get imported entry");
    assert_eq!(view.expose_title(), "GitHub");
    assert_eq!(view.expose_secret(), "super-secret");
}

/// Successful E2E import must make the decrypted payload available through the
/// runtime lock manager
#[tokio::test]
async fn import_signed_e2e_exposes_expected_payload_after_unlock() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let gate = AuthGate::new(tiny_test_policy());
    let manager = VaultLockManager::new();
    let password = MasterPassword::new("pw".to_string());

    let payload = sample_payload();
    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    import_signed_vault_and_unlock(
        policy,
        &gate,
        &manager,
        password,
        &signed,
        Duration::from_secs(60),
    )
        .await
        .expect("e2e import");

    let unlocked_payload = manager.get_payload().await.expect("payload");
    assert_eq!(unlocked_payload.entries.len(), 1);

    let entry = &unlocked_payload.entries[0];
    assert_eq!(entry.secret.title.expose_secret(), "GitHub");
    assert_eq!(entry.secret.secret.expose_secret(), "super-secret");
}

/// Decoy policy must deny the E2E signed import path
#[tokio::test]
async fn import_signed_e2e_denied_in_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);
    let gate = AuthGate::new(tiny_test_policy());
    let manager = VaultLockManager::new();
    let password = MasterPassword::new("pw".to_string());

    let err = import_signed_vault_and_unlock(
        policy,
        &gate,
        &manager,
        password,
        b"anything",
        Duration::from_secs(60),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, ImportError::PolicyDenied));
    assert!(manager.get_payload().await.is_none());
}

/// Wrong password must remain coarse-grained at the E2E layer
#[tokio::test]
async fn import_signed_e2e_wrong_password_is_auth_failed() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let gate = AuthGate::new(tiny_test_policy());
    let manager = VaultLockManager::new();
    let password = MasterPassword::new("pw".to_string());
    let wrong = MasterPassword::new("wrong".to_string());

    let payload = sample_payload();
    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let err = import_signed_vault_and_unlock(
        policy,
        &gate,
        &manager,
        wrong,
        &signed,
        Duration::from_secs(60),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, ImportError::AuthFailed));
    assert!(manager.list_entries().await.is_none());
    assert!(manager.get_payload().await.is_none());
}

/// Tampering must remain coarse-grained at the E2E layer
#[tokio::test]
async fn import_signed_e2e_tamper_is_auth_failed() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let gate = AuthGate::new(tiny_test_policy());
    let manager = VaultLockManager::new();
    let password = MasterPassword::new("pw".to_string());

    let payload = sample_payload();
    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let mut signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    let last = signed.len() - 1;
    signed[last] ^= 0x01;

    let err = import_signed_vault_and_unlock(
        policy,
        &gate,
        &manager,
        password,
        &signed,
        Duration::from_secs(60),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, ImportError::AuthFailed));
    assert!(manager.list_entries().await.is_none());
    assert!(manager.get_payload().await.is_none());
}

/// Successful import must leave the manager usable for follow-up reads
#[tokio::test]
async fn import_signed_e2e_manager_is_usable_after_success() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let gate = AuthGate::new(tiny_test_policy());
    let manager = VaultLockManager::new();
    let password = MasterPassword::new("pw".to_string());

    let payload = sample_payload();
    let vault = create_encrypted_vault(&password, &payload, 1, vault_kdf()).expect("create vault");
    let vault_bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    let signed =
        encode_signed_backup(policy, &password, &vault_bytes, backup_kdf()).expect("encode backup");

    import_signed_vault_and_unlock(
        policy,
        &gate,
        &manager,
        password,
        &signed,
        Duration::from_secs(60),
    )
    .await
    .expect("e2e import");

    let summaries = manager.list_entries().await.expect("list");
    let id = summaries[0].id;

    let first = manager.get_entry(id).await.expect("first read");
    let second = manager.get_entry(id).await.expect("second read");

    assert_eq!(first.expose_title(), second.expose_title());
    assert_eq!(first.expose_secret(), second.expose_secret());
}
