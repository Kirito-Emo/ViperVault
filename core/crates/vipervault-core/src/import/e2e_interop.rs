// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Interop import E2E flow (quarantine -> commit into unlocked vault)
//!
//! # Purpose
//! Provide a safe flow so the UI/FFI layer does not accidentally bypass policy gates,
//! lock-state checks or invariant validation
//!
//! # Security
//! - Denied in decoy mode
//! - Denied under anti-debug soft policy
//! - Requires explicit user intent
//! - Requires an unlocked vault (commit is performed via [`VaultLockManager`])
//! - Exposes only non-sensitive import metadata (counts), never the imported secrets

use super::ImportError;
use super::interop::{ImportIntent, InteropFormat, QuarantinedImport, import_interop_quarantine};
use crate::core::VaultLockManager;
use crate::core::policy::PolicyContext;

/// Minimal, non-sensitive report for an interop import
#[derive(Debug, Clone, Copy)]
pub struct InteropImportReport {
    /// Interop format used
    pub format: InteropFormat,
    /// Number of entries parsed from the plaintext export
    pub imported_entries: usize,
    /// Total number of entries after commit
    pub total_entries_after_commit: usize,
}

/// Import interop bytes into quarantine
///
/// # Security
/// This is a pure parsing step (vault state is not mutated)
pub fn interop_import_to_quarantine(
    policy: PolicyContext,
    intent: ImportIntent,
    format: InteropFormat,
    bytes: &[u8],
) -> Result<QuarantinedImport, ImportError> {
    import_interop_quarantine(policy, intent, format, bytes)
}

/// Import interop bytes and commit them into the currently unlocked vault
///
/// # Security
/// - Denied in decoy mode
/// - Denied under anti-debug soft policy
/// - Requires unlocked manager
pub async fn interop_import_and_commit_into_unlocked_vault(
    policy: PolicyContext,
    manager: &VaultLockManager,
    intent: ImportIntent,
    format: InteropFormat,
    bytes: &[u8],
) -> Result<(), ImportError> {
    let quarantined = import_interop_quarantine(policy, intent, format, bytes)?;

    // Commit via manager
    manager.commit_quarantine_import(policy, quarantined).await
}

/// Import interop bytes, commit into the unlocked vault and return a minimal report
///
/// # Security
/// The report intentionally contains only counts
pub async fn interop_import_commit_report(
    policy: PolicyContext,
    manager: &VaultLockManager,
    intent: ImportIntent,
    format: InteropFormat,
    bytes: &[u8],
) -> Result<InteropImportReport, ImportError> {
    let quarantined = import_interop_quarantine(policy, intent, format, bytes)?;

    // Compute imported count before consuming the quarantine object
    let imported_entries = quarantined.payload().entries.len();

    manager
        .commit_quarantine_import(policy, quarantined)
        .await?;

    // If the vault is no longer unlocked, return PolicyDenied
    let total = manager
        .with_unlocked_payload(|p| p.entries.len())
        .await
        .ok_or(ImportError::PolicyDenied)?;

    Ok(InteropImportReport {
        format,
        imported_entries,
        total_entries_after_commit: total,
    })
}
