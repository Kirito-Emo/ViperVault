// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Signed import of ViperVault containers
//!
//! # Security
//! - External `.vlt` imports must be authenticated first (Ed25519 signed backup container)
//! - Plaintext containers are rejected
//! - Does not leak wrong password vs tampering (AuthFailed)

use super::ImportError;
use crate::backup::decode_signed_backup;
use crate::core::policy::PolicyContext;
use crate::memory::MasterPassword;
use crate::vault::{
    MAX_VAULT_CONTAINER_PAYLOAD_LEN, ParsedVaultFile, StorageMode, VaultParseError,
    decode_vault_file,
};
use std::io::Cursor;

/// Import a ViperVault container from a signed backup blob
///
/// # Security
/// - Denied in decoy
/// - Rejects plaintext vault containers
/// - Maps errors to coarse-grained `ImportError`
pub fn import_vipervault_from_signed_backup(
    policy: PolicyContext,
    password: &MasterPassword,
    signed_backup_bytes: &[u8],
) -> Result<ParsedVaultFile, ImportError> {
    if policy.is_decoy() {
        return Err(ImportError::PolicyDenied);
    }

    let vault_bytes = decode_signed_backup(policy, password, signed_backup_bytes)
        .map_err(|_| ImportError::AuthFailed)?;

    // Decode a vault container (plaintext mode not allowed)
    let parsed = decode_vault_file(
        Cursor::new(vault_bytes),
        None,
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .map_err(map_vault_parse)?;

    // Even if decode_vault_file was misconfigured, reject plaintext containers
    if parsed.mode == StorageMode::PlaintextJson {
        return Err(ImportError::InvalidFormat);
    }

    Ok(parsed)
}

fn map_vault_parse(err: VaultParseError) -> ImportError {
    match err {
        VaultParseError::AuthFailed => ImportError::AuthFailed,
        VaultParseError::PayloadTooLarge => ImportError::PayloadTooLarge,
        VaultParseError::UnsupportedVersion => ImportError::InvalidFormat,
        _ => ImportError::InvalidFormat,
    }
}
