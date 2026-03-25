// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Quarantine import integration for the vault lock manager
//!
//! # Security
//! - The vault must be unlocked
//! - Denied in decoy mode (policy)
//! - Denied under restrictive runtime policy
//! - Mutations happen in-memory only and are re-serialized immediately
//!
//! # Design
//! This module provides a single high-level entry point so the UI layer never
//! directly manipulates [`crate::vault::VaultPayload`]

use crate::core::policy::PolicyContext;
use crate::core::VaultLockManager;
use crate::import::interop::{commit_quarantined_import_into_payload, QuarantinedImport};
use crate::import::ImportError;

impl VaultLockManager {
    /// Commit a quarantined import into the currently unlocked vault payload
    ///
    /// # Security
    /// - Requires unlocked state, otherwise returns `ImportError::PolicyDenied`
    ///   (fail-closed, avoids leaking lock state details across boundaries)
    /// - Applies policy gates before mutating payload state
    pub async fn commit_quarantine_import(
        &self,
        policy: PolicyContext,
        quarantined: QuarantinedImport,
    ) -> Result<(), ImportError> {
        self.with_unlocked_payload_mut(|payload| {
            commit_quarantined_import_into_payload(policy, payload, quarantined)
        })
        .await
        .unwrap_or(Err(ImportError::PolicyDenied))
    }
}
