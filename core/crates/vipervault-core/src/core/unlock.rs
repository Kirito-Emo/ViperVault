// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault unlock flows
//!
//! # Security
//! - Authentication failures are coarse-grained to avoid creating wrong-password vs tampering oracles
//! - Plaintext vault JSON is returned in a protected buffer when needed for the runtime lock manager

use super::auth_gate::AuthGate;
use super::session::UnlockedVaultSession;
use crate::crypto::aead::{decrypt_xchacha20poly1305, AeadError};
use crate::crypto::kdf::{derive_master_key_from_password, KdfError};
use crate::memory::{MasterPassword, SecretBytes};
use crate::vault::duress::{unlock_duress_envelope, UnlockOutcome};
use crate::vault::{
    DualCiphertextEnvelope, KdfParams, ParsedVaultFile, StorageMode, VaultParseError, VaultPayload,
};
use zeroize::Zeroizing;

/// Errors returned by the unlock flow
///
/// # Security
/// This error type is designed to avoid leaking whether a failure was caused
/// by a wrong password or by vault tampering
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// Parsing or I/O errors while reading the vault container
    #[error("vault parse error")]
    Parse(#[from] VaultParseError),

    /// KDF failure (invalid params, internal errors)
    #[error("kdf error")]
    Kdf(#[from] KdfError),

    /// Authentication failure: wrong password or tampered vault
    #[error("authentication failed")]
    AuthFailed,

    /// Payload decode failed (e.g., invalid JSON structure)
    #[error("payload decode error")]
    PayloadDecode,

    /// Internal execution failure (e.g. panics or join failures)
    #[error("internal error")]
    Internal,
}

/// Unlock the vault into a session object under [`AuthGate`]
///
/// # Security
/// - Applies delay only on `AuthFailed` (wrong password or tampering)
/// - Does not delay on parse/KDF/payload errors to avoid DoS via malformed files
/// - In duress mode, a successful decoy unlock does not reset the throttle state
pub async fn unlock_session_gated(
    gate: &AuthGate,
    parsed: ParsedVaultFile,
    password: MasterPassword,
) -> Result<UnlockedVaultSession, UnlockError> {
    let (outcome, payload) = gate
        .run(
            || async move { unlock_vault_with_outcome(&parsed, &password) },
            |e: &UnlockError| matches!(e, UnlockError::AuthFailed),
            |_| false,
        )
        .await?;

    if outcome == UnlockOutcome::Primary {
        gate.reset().await;
    }

    Ok(UnlockedVaultSession::new(outcome, payload))
}

/// Unlock an encrypted vault payload from a previously parsed container using the provided password
///
/// If duress mode is enabled, this returns whichever payload the password unlocks
pub fn unlock_vault(
    parsed: &ParsedVaultFile,
    password: &MasterPassword,
) -> Result<VaultPayload, UnlockError> {
    let plaintext = unlock_vault_to_plaintext_json(parsed, password)?;
    serde_json::from_slice(&plaintext).map_err(|_| UnlockError::PayloadDecode)
}

/// Unlock the vault and return plaintext JSON for the runtime lock manager
///
/// # Security
/// - Uses raw `header_bytes` as AEAD AAD to prevent header tampering
/// - Maps AEAD decryption errors to `AuthFailed` to avoid oracle behaviour
/// - Returns the plaintext in a protected buffer
pub fn unlock_vault_to_plaintext_json(
    parsed: &ParsedVaultFile,
    password: &MasterPassword,
) -> Result<SecretBytes, UnlockError> {
    if parsed.mode != StorageMode::Encrypted {
        return Err(UnlockError::AuthFailed);
    }

    // Duress mode: payload is a JSON envelope, decrypt either primary or decoy
    if let Some(ref duress_header) = parsed.header.duress {
        let envelope: DualCiphertextEnvelope = serde_json::from_slice(parsed.payload.as_slice())
            .map_err(|_| UnlockError::PayloadDecode)?;

        let (_outcome, payload) = unlock_duress_envelope(
            parsed.header_bytes.as_slice(),
            duress_header,
            &envelope,
            password,
        )
        .map_err(|_| UnlockError::AuthFailed)?;

        let json =
            Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| UnlockError::PayloadDecode)?);
        return Ok(json);
    }

    // Legacy mode: payload is a raw ciphertext
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

/// Unlock the vault and report whether the primary or decoy payload was unlocked
pub fn unlock_vault_with_outcome(
    parsed: &ParsedVaultFile,
    password: &MasterPassword,
) -> Result<(UnlockOutcome, VaultPayload), UnlockError> {
    if parsed.mode != StorageMode::Encrypted {
        return Err(UnlockError::AuthFailed);
    }

    if let Some(ref duress_header) = parsed.header.duress {
        let envelope: DualCiphertextEnvelope = serde_json::from_slice(parsed.payload.as_slice())
            .map_err(|_| UnlockError::PayloadDecode)?;

        let (outcome, payload) = unlock_duress_envelope(
            parsed.header_bytes.as_slice(),
            duress_header,
            &envelope,
            password,
        )
        .map_err(|_| UnlockError::AuthFailed)?;

        return Ok((outcome, payload));
    }

    // Legacy mode always unlocks the primary payload
    let payload = unlock_vault(parsed, password)?;
    Ok((UnlockOutcome::Primary, payload))
}

/// Map AEAD errors to authentication failure without leaking details
///
/// # Security
/// This mapping is intentionally coarse-grained
fn map_aead_error(_err: AeadError) -> UnlockError {
    UnlockError::AuthFailed
}
