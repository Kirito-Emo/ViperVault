// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Import E2E flows
//!
//! # Purpose
//! Provide a safe high-level flow so the UI/FFI layer does not skip critical steps (policy gates, decrypt verification, unlock)
//!
//! # Security
//! - Denied in decoy mode
//! - Denied under anti-debug soft policy
//! - Does not distinguish wrong password vs tampering (AuthFailed)

use super::ImportError;
use super::signed::import_vipervault_from_signed_backup;
use crate::core::auth_gate::AuthGate;
use crate::core::policy::PolicyContext;
use crate::core::unlock::unlock_session_gated;
use crate::core::{VaultLockManager, allow_clipboard_under_soft_policy};
use crate::memory::MasterPassword;
use std::time::Duration;

/// Import a signed backup blob and unlock the manager
///
/// # Design
/// - Reuses the signed import primitive
/// - Performs an actual decrypt attempt before unlocking (integrity/auth check)
///
/// # Security
/// - Does not leak wrong password vs tampering
/// - Runs password-based unlock under [`AuthGate`] (throttling + spawn_blocking)
pub async fn import_signed_vault_and_unlock(
    policy: PolicyContext,
    gate: &AuthGate,
    manager: &VaultLockManager,
    password: MasterPassword,
    signed_backup_bytes: &[u8],
    timeout: Duration,
) -> Result<(), ImportError> {
    if policy.is_decoy() {
        return Err(ImportError::PolicyDenied);
    }

    if !allow_clipboard_under_soft_policy() {
        return Err(ImportError::PolicyDenied);
    }

    let parsed = import_vipervault_from_signed_backup(policy, &password, signed_backup_bytes)?;

    let session = unlock_session_gated(gate, parsed, password)
        .await
        .map_err(|_| ImportError::AuthFailed)?;

    let plaintext_json =
        serde_json::to_vec(session.payload()).map_err(|_| ImportError::InvalidFormat)?;

    manager
        .unlock_with_plaintext_json(plaintext_json, timeout)
        .await;

    Ok(())
}
