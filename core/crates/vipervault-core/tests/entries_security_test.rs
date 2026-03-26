// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entry security boundary tests
//!
//! # Scope
//! These tests validate manager-aware sensitive entry boundaries:
//! - re-authenticated entry access
//! - runtime-policy-gated entry access
//! - secret reveal
//! - secret copy
//! - TOTP copy
//!
//! # Security
//! Sensitive entry operations must distinguish among:
//! - locked vault
//! - unlocked but policy-denied session
//! - unlocked but re-auth-required session
//! - unlocked and sufficiently strong session
//! - wrong entry type
//! - invalid/corrupted entry data

use secrecy::ExposeSecret;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vipervault_core::clipboard::guard::{ClipboardBackend, ClipboardGuard};
use vipervault_core::core::{
    AuthenticationStrength, RuntimeInspectionState, RuntimeSecurityEvent, SensitiveOperation,
    VaultLockManager,
};
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret};
use vipervault_core::entries::{EntryError, VaultEntry};
use vipervault_core::vault::VaultPayload;
use vipervault_core::vault::duress::UnlockOutcome;

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
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
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
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Biometric,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
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
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::QuickUnlock,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
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
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
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
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
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

/// Decoy sessions must deny sensitive reveal operations even when the runtime is clean
#[tokio::test]
async fn decoy_session_denies_sensitive_reveal() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Decoy,
            RuntimeInspectionState::NotDebugged,
        )
        .await;

    let err = manager.reveal_entry_secret(entry_id).await.unwrap_err();
    assert!(matches!(err, EntryError::PolicyDenied));
}

/// Restrictive runtime states must deny secret copy before clipboard exposure happens
#[tokio::test]
async fn restrictive_runtime_denies_secret_copy() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend.clone());

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::Debugged,
        )
        .await;

    let err = manager
        .copy_entry_secret(entry_id, &mut clipboard, Duration::from_secs(30))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::PolicyDenied));
    assert_eq!(backend.get(), None);
}

/// Restrictive runtime states must deny TOTP copy before generation/copy occurs
#[tokio::test]
async fn restrictive_runtime_denies_totp_copy() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_totp_entry();
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend.clone());

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::TamperSuspected,
        )
        .await;

    let err = manager
        .copy_entry_totp(entry_id, 59, &mut clipboard, Some(Duration::from_secs(30)))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::PolicyDenied));
    assert_eq!(backend.get(), None);
}

/// Locked managers must still fail with `VaultLocked`
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

/// Missing entries must still return `EntryNotFound` once authorization succeeds
#[tokio::test]
async fn missing_entry_returns_entry_not_found_after_authorization() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
        )
        .await;

    let err = manager
        .get_entry_for_operation(uuid::Uuid::new_v4(), SensitiveOperation::RevealSecret)
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::EntryNotFound));
}

/// TOTP entries currently expose the mirrored seed secret through the generic reveal path
///
/// # Design
/// The current entry model mirrors the TOTP seed into the primary `secret` field
/// for compatibility with existing secret-centric flows
#[tokio::test]
async fn reveal_secret_for_totp_returns_mirrored_seed_secret() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_totp_entry();

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
        )
        .await;

    let secret = manager
        .reveal_entry_secret(entry_id)
        .await
        .expect("totp entries currently reveal their mirrored seed secret");

    assert_eq!(secret.expose_secret(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
}

/// TOTP copy must fail for non-TOTP entries
#[tokio::test]
async fn totp_copy_rejects_invalid_entry_type() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_non_totp_entry();
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend.clone());

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
        )
        .await;

    let err = manager
        .copy_entry_totp(entry_id, 59, &mut clipboard, Some(Duration::from_secs(30)))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::InvalidType));
    assert_eq!(backend.get(), None);
}

/// Secret copy must place the secret into the clipboard on success
#[tokio::test]
async fn copy_secret_writes_clipboard_on_success() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_password_entry();
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend.clone());

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
        )
        .await;

    manager
        .copy_entry_secret(entry_id, &mut clipboard, Duration::from_secs(30))
        .await
        .expect("copy must succeed");

    assert_eq!(backend.get().as_deref(), Some("super-secret"));
}

/// TOTP copy must write a code to the clipboard on success
#[tokio::test]
async fn copy_totp_writes_clipboard_on_success() {
    let manager = VaultLockManager::new();
    let (payload, entry_id) = payload_with_totp_entry();
    let backend = TestClipboardBackend::default();
    let mut clipboard = ClipboardGuard::new(backend.clone());

    manager
        .unlock_with_plaintext_json_with_context(
            serde_json::to_vec(&payload).expect("serialize payload"),
            Duration::from_secs(60),
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            RuntimeInspectionState::NotDebugged,
        )
        .await;

    manager
        .copy_entry_totp(entry_id, 59, &mut clipboard, Some(Duration::from_secs(30)))
        .await
        .expect("totp copy must succeed");

    let copied = backend.get().expect("clipboard must contain a TOTP code");
    assert_eq!(copied.len(), 6);
    assert!(copied.chars().all(|c| c.is_ascii_digit()));
}
