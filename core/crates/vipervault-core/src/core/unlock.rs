// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use crate::crypto::aead::{AeadError, decrypt_xchacha20poly1305};
use crate::crypto::kdf::{KdfError, derive_master_key_from_password};
use crate::memory::MasterPassword;
use crate::vault::{KdfParams, ParsedVaultFile, StorageMode, VaultParseError, VaultPayload};
use zeroize::Zeroizing;

/// Errors returned by the unlock flow
///
/// # Security
/// This error type is designed to avoid leaking whether a failure was caused by a wrong password or tampering
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// Parsing/IO errors while reading the vault container
    #[error("vault parse error")]
    Parse(#[from] VaultParseError),

    /// KDF failure (invalid params, internal errors)
    #[error("kdf error")]
    Kdf(#[from] KdfError),

    /// Authentication failure: wrong password OR tampered vault
    #[error("authentication failed")]
    AuthFailed,

    /// Payload decode failed (e.g., invalid JSON structure)
    #[error("payload decode error")]
    PayloadDecode,
}

/// Unlocks an encrypted vault payload from a previously parsed container using the provided password
///
/// # Parameters
/// - `parsed`: parsed vault container including raw header bytes (AAD)
/// - `password`: master password wrapper (wiped on drop)
///
/// # Returns
/// Decrypted payload as [`VaultPayload`]
///
/// # Security
/// - Uses raw `header_bytes` as AEAD AAD to prevent header tampering
/// - Maps AEAD decryption errors to `AuthFailed` to avoid oracle behavior
/// - Derived key and plaintext are wiped automatically (Zeroizing)
///
/// # Errors
/// Returns [`UnlockError`]
pub fn unlock_vault(
    parsed: &ParsedVaultFile,
    password: &MasterPassword,
) -> Result<VaultPayload, UnlockError> {
    let plaintext = unlock_vault_to_plaintext_json(parsed, password)?;

    serde_json::from_slice(&plaintext).map_err(|_| UnlockError::PayloadDecode)
}

/// Unlocks vault and returns plaintext JSON (for auto-lock manager)
pub fn unlock_vault_to_plaintext_json(
    parsed: &ParsedVaultFile,
    password: &MasterPassword,
) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
    if parsed.mode != StorageMode::Encrypted {
        return Err(UnlockError::AuthFailed);
    }

    let (mem_kib, time_cost, lanes) = match &parsed.header.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (*mem_kib, *time_cost, *lanes),
    };

    let master_key = derive_master_key_from_password(
        password,
        &parsed.header.crypto.salt,
        mem_kib,
        time_cost,
        lanes,
    )?;

    decrypt_xchacha20poly1305(
        &master_key,
        &parsed.header.crypto.nonce,
        &parsed.payload,
        &parsed.header_bytes,
    )
    .map_err(map_aead_error)
}

/// Map AEAD errors to auth failure without leaking details (no oracle)
///
/// # Security
/// Keep it intentionally coarse-grained
fn map_aead_error(_err: AeadError) -> UnlockError {
    UnlockError::AuthFailed
}
