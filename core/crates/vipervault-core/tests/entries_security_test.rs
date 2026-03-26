// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entry security boundary tests
//!
//! # Scope
//! These tests validate manager-aware sensitive entry boundaries:
//! - re-authenticated entry access
//! - secret reveal
//! - secret copy
//! - TOTP copy
//!
//! # Security
//! Sensitive entry operations must distinguish among:
//! - locked vault
//! - unlocked but re-auth-required session
//! - unlocked and sufficiently strong session
//! - wrong entry type
//! - invalid/corrupted entry data

use secrecy::ExposeSecret;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vipervault_core::clipboard::guard::{ClipboardBackend, ClipboardGuard};
use vipervault_core::core::{
    AuthenticationStrength, RuntimeSecurityEvent, SensitiveOperation, VaultLockManager,
};
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret};
use vipervault_core::entries::{EntryError, VaultEntry};
use vipervault_core::vault::VaultPayload;

#[derive(Debug, Clone, Default)]
struct TestClipboardBackend {
    value: Arc<Mutex<Option<String>>>,
}

impl ClipboardBackend for TestClipboardBackend {
    fn set(&self, value: &str) {
        *self.value.lock().expect("clipboard lock") = Some(value.to_string());
    }

    fn get(&self) -> Option<String> {
        self.value.lock().expect("clipboard lock").clone()
    }

    fn clear(&self) {
        *self.value.lock().expect("clipboard lock") = None;
    }
}

/// Build a payload containing a single password entry and return its ID
fn payload_with_password_entry() -> (VaultPayload, uuid::Uuid) {
    let entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "super-secret".to_string(),
        Some("note".to_string()),
    )
        .expect("entry");

    let id = entry.meta.id;
    (
        VaultPayload {
            entries: vec![entry],
        },
        id,
    )
}

fn payload_with_totp_entry() -> (VaultPayload, uuid::Uuid) {
    let totp = TotpSecret {
        issuer: Some(secrecy::SecretString::new("GitHub".to_string().into())),
        account_name: Some(secrecy::SecretString::new("octocat".to_string().into())),
        secret_b32: secrecy::SecretString::new(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string().into(),
        ),
        digits: 6,
        period_secs: 30,
        algorithm: TotpAlgorithm::Sha1,
    };

    let entry = VaultEntry::new_totp("GitHub TOTP".to_string(), totp, None).expect("entry");
    let id = entry.meta.id;

    (
        VaultPayload {
            entries: vec![entry],
        },
        id,
    )
}

fn payload_with_non_totp_entry() -> (VaultPayload, uuid::Uuid) {
    let entry =
        VaultEntry::new_secure_note("note".to_string(), "secret".to_string()).expect("entry");
    let id = entry.meta.id;

    (
        VaultPayload {
            entries: vec![entry],
        },
        id,
    )
}

/// Strong sessions must allow sensitive reveal operations
#[tokio::test]
async fn strong_session_allows_reveal_secret_operation() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let entry = manager
        .get_entry_for_operation(entry_id, SensitiveOperation::RevealSecret)
        .await
        .expect("entry should be accessible after strong auth");

    assert_eq!(entry.expose_title(), "GitHub");
    assert_eq!(entry.expose_secret(), "super-secret");
}

/// Biometric sessions must require strong re-authentication for secret reveal
#[tokio::test]
async fn biometric_session_requires_reauth_for_reveal_secret() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json_with_strength(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Biometric,
        )
        .await;

    let err = manager
        .get_entry_for_operation(entry_id, SensitiveOperation::RevealSecret)
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Quick-unlock sessions must require strong re-authentication for secret copy
#[tokio::test]
async fn quick_unlock_session_requires_reauth_for_copy_secret() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json_with_strength(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::QuickUnlock,
        )
        .await;

    let err = manager
        .get_entry_for_operation(entry_id, SensitiveOperation::CopySecret)
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Sticky re-auth requirements must block sensitive operations even in a strong session
#[tokio::test]
async fn sticky_reauth_requirement_blocks_sensitive_operations() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    assert_eq!(manager.strong_reauth_required().await, Some(false));

    manager
        .handle_runtime_security_event(RuntimeSecurityEvent::AppBackgrounded)
        .await;

    assert_eq!(manager.strong_reauth_required().await, Some(true));

    let err = manager
        .get_entry_for_operation(entry_id, SensitiveOperation::RevealSecret)
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Clearing sticky re-auth requirements after a strong step must restore access
#[tokio::test]
async fn clearing_reauth_requirement_restores_sensitive_access() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    manager
        .handle_runtime_security_event(RuntimeSecurityEvent::AppBackgrounded)
        .await;

    let first_err = manager
        .get_entry_for_operation(entry_id, SensitiveOperation::RevealSecret)
        .await
        .unwrap_err();
    assert!(matches!(first_err, EntryError::ReauthRequired));

    assert!(manager.clear_strong_reauth_requirement().await);

    let entry = manager
        .get_entry_for_operation(entry_id, SensitiveOperation::RevealSecret)
        .await
        .expect("entry should be accessible again after clearing reauth");

    assert_eq!(entry.expose_secret(), "super-secret");
}

/// Locked managers must still fail with `VaultLocked` rather than `ReauthRequired`
#[tokio::test]
async fn locked_manager_returns_vault_locked_for_sensitive_access() {
    let manager = VaultLockManager::new();
    let (_, entry_id) = payload_with_password_entry();

    let err = manager
        .get_entry_for_operation(entry_id, SensitiveOperation::RevealSecret)
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::VaultLocked));
}

/// Missing entries must still return `EntryNotFound` once re-auth is satisfied
#[tokio::test]
async fn missing_entry_returns_entry_not_found_after_strong_auth() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let err = manager
        .get_entry_for_operation(uuid::Uuid::new_v4(), SensitiveOperation::RevealSecret)
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::EntryNotFound));
}

/// Strong sessions must allow secret reveal
#[tokio::test]
async fn strong_session_can_reveal_secret() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let secret = manager
        .reveal_entry_secret(entry_id)
        .await
        .expect("secret should be revealable in strong session");

    assert_eq!(secret.expose_secret(), "super-secret");
}

/// Biometric sessions must require re-authentication for secret reveal
#[tokio::test]
async fn biometric_session_requires_reauth_for_reveal() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json_with_strength(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Biometric,
        )
        .await;

    let err = manager.reveal_entry_secret(entry_id).await.unwrap_err();
    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Sticky re-auth requirement must also block secret reveal
#[tokio::test]
async fn sticky_reauth_requirement_blocks_reveal() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    manager
        .handle_runtime_security_event(RuntimeSecurityEvent::AppBackgrounded)
        .await;

    let err = manager.reveal_entry_secret(entry_id).await.unwrap_err();
    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Locked managers must still report `VaultLocked` on reveal
#[tokio::test]
async fn locked_manager_returns_vault_locked_for_reveal() {
    let manager = VaultLockManager::new();
    let (_, entry_id) = payload_with_password_entry();

    let err = manager.reveal_entry_secret(entry_id).await.unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));
}

/// Strong sessions must allow secret copy
#[tokio::test]
async fn strong_session_can_copy_secret() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend.clone());
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    manager
        .copy_entry_secret(entry_id, &mut clipboard, Duration::from_secs(30))
        .await
        .expect("copy should succeed in strong session");

    assert_eq!(
        backend.get().as_deref(),
        Some("super-secret"),
        "clipboard should contain the copied secret"
    );
}

/// Biometric sessions must require re-authentication for secret copy
#[tokio::test]
async fn biometric_session_requires_reauth_for_copy() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend);
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json_with_strength(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Biometric,
        )
        .await;

    let err = manager
        .copy_entry_secret(entry_id, &mut clipboard, Duration::from_secs(30))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Sticky re-auth requirement must also block secret copy
#[tokio::test]
async fn sticky_reauth_requirement_blocks_copy() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend);
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    manager
        .handle_runtime_security_event(RuntimeSecurityEvent::AppBackgrounded)
        .await;

    let err = manager
        .copy_entry_secret(entry_id, &mut clipboard, Duration::from_secs(30))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Locked managers must still report `VaultLocked` on secret copy
#[tokio::test]
async fn locked_manager_returns_vault_locked_for_secret_copy() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend);
    let manager = VaultLockManager::new();
    let (_, entry_id) = payload_with_password_entry();

    let err = manager
        .copy_entry_secret(entry_id, &mut clipboard, Duration::from_secs(30))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::VaultLocked));
}

/// Strong sessions must allow TOTP copy
#[tokio::test]
async fn strong_session_can_copy_totp() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend.clone());
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_totp_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    manager
        .copy_entry_totp(
            entry_id,
            1_700_000_000,
            &mut clipboard,
            Some(Duration::from_secs(30)),
        )
        .await
        .expect("totp copy should succeed in strong session");

    let copied = backend.get().expect("clipboard value");
    assert_eq!(copied.len(), 6, "clipboard should contain a 6-digit TOTP");
    assert!(copied.chars().all(|c| c.is_ascii_digit()));
}

/// Biometric sessions must require re-authentication for TOTP copy
#[tokio::test]
async fn biometric_session_requires_reauth_for_totp_copy() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend);
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_totp_entry();

    manager
        .unlock_with_plaintext_json_with_strength(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Biometric,
        )
        .await;

    let err = manager
        .copy_entry_totp(
            entry_id,
            1_700_000_000,
            &mut clipboard,
            Some(Duration::from_secs(30)),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Sticky re-auth requirement must also block TOTP copy
#[tokio::test]
async fn sticky_reauth_requirement_blocks_totp_copy() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend);
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_totp_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    manager
        .handle_runtime_security_event(RuntimeSecurityEvent::AppBackgrounded)
        .await;

    let err = manager
        .copy_entry_totp(
            entry_id,
            1_700_000_000,
            &mut clipboard,
            Some(Duration::from_secs(30)),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::ReauthRequired));
}

/// Locked managers must still report `VaultLocked` on TOTP copy
#[tokio::test]
async fn locked_manager_returns_vault_locked_for_totp_copy() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend);
    let manager = VaultLockManager::new();
    let (_, entry_id) = payload_with_totp_entry();

    let err = manager
        .copy_entry_totp(
            entry_id,
            1_700_000_000,
            &mut clipboard,
            Some(Duration::from_secs(30)),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::VaultLocked));
}

/// Non-TOTP entries must report `InvalidType`
#[tokio::test]
async fn non_totp_entry_returns_invalid_type() {
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend);
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_non_totp_entry();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let err = manager
        .copy_entry_totp(
            entry_id,
            1_700_000_000,
            &mut clipboard,
            Some(Duration::from_secs(30)),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::InvalidType));
}
