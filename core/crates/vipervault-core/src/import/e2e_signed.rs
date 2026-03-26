// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Import E2E flows for signed backups
//!
//! # Purpose
//! Provide a safe high-level flow so the UI or FFI layer does not skip critical
//! steps such as policy gates, decrypt verification and unlock
//!
//! # Security
//! - Denied in decoy mode
//! - Denied under restrictive runtime policy
//! - Does not distinguish wrong password from tampering (`AuthFailed`)
//! - The unlock path now reuses the protected plaintext JSON returned by the gated
//!   unlock primitive instead of re-serializing a materialized payload

use super::ImportError;
use super::signed::import_vipervault_from_signed_backup;
use crate::core::VaultLockManager;
use crate::core::auth_gate::AuthGate;
use crate::core::policy::PolicyContext;
use crate::core::unlock::unlock_plaintext_json_gated;
use crate::memory::MasterPassword;
use std::time::Duration;

/// Import a signed backup blob and unlock the manager
///
/// # Design
/// - Reuses the signed import primitive
/// - Performs an actual decrypt attempt before unlocking as an integrity/authentication check
///
/// # Security
/// - Does not leak wrong password vs tampering
/// - Runs password-based unlock under [`AuthGate`]
/// - Denied by the centralized runtime policy
/// - Reuses the protected plaintext JSON returned by the unlock primitive to
///   avoid an additional plaintext serialization step
pub async fn import_signed_vault_and_unlock(
    policy: PolicyContext,
    gate: &AuthGate,
    manager: &VaultLockManager,
    password: MasterPassword,
    signed_backup_bytes: &[u8],
    timeout: Duration,
) -> Result<(), ImportError> {
    if !policy.allow_signed_backup_transfer() {
        return Err(ImportError::PolicyDenied);
    }

    let parsed = import_vipervault_from_signed_backup(policy, &password, signed_backup_bytes)?;

    let (_outcome, plaintext_json) = unlock_plaintext_json_gated(gate, parsed, password)
        .await
        .map_err(|_| ImportError::AuthFailed)?;

    manager
        .unlock_with_plaintext_json(plaintext_json, timeout)
        .await;

    Ok(())
}
