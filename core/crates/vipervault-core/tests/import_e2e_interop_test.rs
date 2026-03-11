// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Interop import E2E tests
//!
//! # Scope
//! These tests validate the high-level quarantine + commit flow on an unlocked vault:
//! - quarantine-only parsing
//! - successful commit into an unlocked manager
//! - report generation
//! - decoy policy denial
//! - locked-manager fail-closed behavior
//!
//! # Security
//! This is the UI-facing plaintext import path. These tests ensure that:
//! - import remains denied in decoy sessions
//! - quarantine does not mutate vault state
//! - commit requires an unlocked vault
//! - success reports expose only minimal counts

use std::time::Duration;
use vipervault_core::core::VaultLockManager;
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::VaultEntry;
use vipervault_core::import::{
    ImportError, ImportIntent, InteropFormat, interop_import_and_commit_into_unlocked_vault,
    interop_import_commit_report, interop_import_to_quarantine,
};
use vipervault_core::vault::VaultPayload;
use vipervault_core::vault::duress::UnlockOutcome;

fn primary_policy() -> PolicyContext {
    PolicyContext::new(UnlockOutcome::Primary)
}

fn decoy_policy() -> PolicyContext {
    PolicyContext::new(UnlockOutcome::Decoy)
}

/// Return a known-good OTPAuth URI list accepted by the hardened parser
fn interop_bytes() -> &'static [u8] {
    br#"otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30
"#
}

/// Quarantine-only import must not mutate vault state
#[tokio::test]
async fn interop_quarantine_only_does_not_mutate_manager() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload {
                entries: vec![
                    VaultEntry::new_secure_note("note".to_string(), "secret".to_string())
                        .expect("entry"),
                ],
            })
            .expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let bytes = interop_bytes();

    let q = interop_import_to_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        bytes,
    )
    .expect("quarantine");

    assert_eq!(q.payload().entries.len(), 1);

    let entries = manager.list_entries().await.expect("list entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].expose_title(), "note");
}

/// Successful interop import must commit into the unlocked manager
#[tokio::test]
async fn interop_commit_into_unlocked_manager_success() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let bytes = interop_bytes();

    interop_import_and_commit_into_unlocked_vault(
        primary_policy(),
        &manager,
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        bytes,
    )
    .await
    .expect("interop import commit");

    let entries = manager.list_entries().await.expect("list entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].entry_type,
        vipervault_core::entries::EntryType::Totp
    );
}

/// Decoy policy must deny the E2E interop path
#[tokio::test]
async fn interop_commit_denied_in_decoy() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let bytes = interop_bytes();

    let err = interop_import_and_commit_into_unlocked_vault(
        decoy_policy(),
        &manager,
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        bytes,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, ImportError::PolicyDenied));
}

/// Committing into a locked manager must fail closed
///
/// # Security
/// The E2E path must not reveal lock-state details beyond a generic policy denial
#[tokio::test]
async fn interop_commit_into_locked_manager_fails_closed() {
    let manager = VaultLockManager::new();
    let bytes = interop_bytes();

    let err = interop_import_and_commit_into_unlocked_vault(
        primary_policy(),
        &manager,
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        bytes,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, ImportError::PolicyDenied));
}

/// Report generation must return only minimal counters after successful commit
#[tokio::test]
async fn interop_commit_report_returns_minimal_counts() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize payload"),
            Duration::from_secs(60),
        )
        .await;

    let bytes = interop_bytes();

    let report = interop_import_commit_report(
        primary_policy(),
        &manager,
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        bytes,
    )
    .await
    .expect("commit report");

    assert!(matches!(report.format, InteropFormat::OtpAuthTotpUriList));
    assert_eq!(report.imported_entries, 1);
    assert_eq!(report.total_entries_after_commit, 1);
}
