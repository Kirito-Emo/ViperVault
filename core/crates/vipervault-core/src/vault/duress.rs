// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Duress / decoy vault support
//!
//! # Design
//! If `VaultHeader.duress` is present, the vault payload bytes contain a JSON envelope:
//! - `primary_ct` ciphertext for the primary vault
//! - `decoy_ct` ciphertext for the decoy vault
//!
//! Both ciphertexts are authenticated using the raw header bytes as AEAD AAD
//!
//! # Security
//! - Decryption failures are mapped to `VaultParseError::AuthFailed` to avoid oracle behaviour
//! - The canonical low-level unlock path returns validated protected plaintext JSON bytes

use super::error::VaultParseError;
use super::types::{
    CryptoHeader, DualCiphertextEnvelope, DualVaultHeader, KdfParams, VaultPayload,
};
use crate::crypto::aead::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305};
use crate::crypto::kdf::derive_master_key_from_password;
use crate::memory::{MasterPassword, SecretBytes};
use zeroize::Zeroizing;

/// Which payload was unlocked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockOutcome {
    Primary, // The primary (real) vault was unlocked
    Decoy,   // The decoy vault was unlocked
}

/// Unlock a duress-enabled vault envelope into validated protected plaintext JSON bytes
///
/// Tries primary first, then decoy, if both fail, returns `AuthFailed`
///
/// # Security
/// Validation is performed before returning the plaintext buffer so callers can
/// keep using the protected bytes without introducing an extra serialization step
pub fn unlock_duress_envelope_to_plaintext_json(
    header_bytes: &[u8],
    duress_header: &DualVaultHeader,
    envelope: &DualCiphertextEnvelope,
    password: &MasterPassword,
) -> Result<(UnlockOutcome, SecretBytes), VaultParseError> {
    if let Ok(pt) = decrypt_with_crypto_header(
        header_bytes,
        &duress_header.primary,
        envelope.primary_ct.as_slice(),
        password,
    ) {
        validate_payload_json(pt.as_slice())?;
        return Ok((UnlockOutcome::Primary, pt));
    }

    if let Ok(pt) = decrypt_with_crypto_header(
        header_bytes,
        &duress_header.decoy,
        envelope.decoy_ct.as_slice(),
        password,
    ) {
        validate_payload_json(pt.as_slice())?;
        return Ok((UnlockOutcome::Decoy, pt));
    }

    Err(VaultParseError::AuthFailed)
}

/// Unlock a duress-enabled vault envelope
///
/// Tries primary first, then decoy, if both fail, returns `AuthFailed`
pub fn unlock_duress_envelope(
    header_bytes: &[u8],
    duress_header: &DualVaultHeader,
    envelope: &DualCiphertextEnvelope,
    password: &MasterPassword,
) -> Result<(UnlockOutcome, VaultPayload), VaultParseError> {
    let (outcome, plaintext_json) =
        unlock_duress_envelope_to_plaintext_json(header_bytes, duress_header, envelope, password)?;

    let payload: VaultPayload = serde_json::from_slice(plaintext_json.as_slice())
        .map_err(|_| VaultParseError::InvalidPayload)?;

    Ok((outcome, payload))
}

/// Encrypt a primary + decoy payload into an envelope
pub fn encrypt_duress_envelope(
    header_bytes: &[u8],
    duress_header: &DualVaultHeader,
    primary_password: &MasterPassword,
    decoy_password: &MasterPassword,
    primary_payload: &VaultPayload,
    decoy_payload: &VaultPayload,
) -> Result<DualCiphertextEnvelope, VaultParseError> {
    let primary_pt = Zeroizing::new(
        serde_json::to_vec(primary_payload).map_err(|_| VaultParseError::Serialize)?,
    );
    let decoy_pt =
        Zeroizing::new(serde_json::to_vec(decoy_payload).map_err(|_| VaultParseError::Serialize)?);

    encrypt_duress_envelope_from_plaintext_json(
        header_bytes,
        duress_header,
        primary_password,
        decoy_password,
        primary_pt.as_slice(),
        decoy_pt.as_slice(),
    )
}

/// Encrypt primary + decoy plaintext JSON bytes into an envelope
///
/// # Security
/// In case of already validated plaintext JSON, prefer this helper
/// to avoid materializing an additional [`VaultPayload`] only for re-serialization
pub fn encrypt_duress_envelope_from_plaintext_json(
    header_bytes: &[u8],
    duress_header: &DualVaultHeader,
    primary_password: &MasterPassword,
    decoy_password: &MasterPassword,
    primary_plaintext_json: &[u8],
    decoy_plaintext_json: &[u8],
) -> Result<DualCiphertextEnvelope, VaultParseError> {
    validate_payload_json(primary_plaintext_json)?;
    validate_payload_json(decoy_plaintext_json)?;

    let primary_ct = encrypt_with_crypto_header(
        header_bytes,
        &duress_header.primary,
        primary_plaintext_json,
        primary_password,
    )?;
    let decoy_ct = encrypt_with_crypto_header(
        header_bytes,
        &duress_header.decoy,
        decoy_plaintext_json,
        decoy_password,
    )?;

    Ok(DualCiphertextEnvelope {
        primary_ct,
        decoy_ct,
    })
}

fn decrypt_with_crypto_header(
    header_bytes: &[u8],
    ch: &CryptoHeader,
    ciphertext: &[u8],
    password: &MasterPassword,
) -> Result<Zeroizing<Vec<u8>>, VaultParseError> {
    // Currently only Argon2id is supported in this project
    let (mem_kib, time_cost, lanes) = match ch.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
    };

    let key = derive_master_key_from_password(password, &ch.salt, mem_kib, time_cost, lanes)
        .map_err(|_| VaultParseError::AuthFailed)?;

    decrypt_xchacha20poly1305(&key, &ch.nonce, ciphertext, header_bytes)
        .map_err(|_| VaultParseError::AuthFailed)
}

fn encrypt_with_crypto_header(
    header_bytes: &[u8],
    ch: &CryptoHeader,
    plaintext: &[u8],
    password: &MasterPassword,
) -> Result<Vec<u8>, VaultParseError> {
    let (mem_kib, time_cost, lanes) = match ch.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
    };

    let key = derive_master_key_from_password(password, &ch.salt, mem_kib, time_cost, lanes)
        .map_err(|_| VaultParseError::AuthFailed)?;

    encrypt_xchacha20poly1305(&key, &ch.nonce, plaintext, header_bytes)
        .map_err(|_| VaultParseError::AuthFailed)
}

/// Validate that a plaintext JSON buffer decodes into a vault payload
///
/// # Security
/// This helper is intentionally strict so callers can reject malformed JSON
/// before persisting or returning it across a trust boundary
fn validate_payload_json(plaintext_json: &[u8]) -> Result<(), VaultParseError> {
    let _payload: VaultPayload =
        serde_json::from_slice(plaintext_json).map_err(|_| VaultParseError::InvalidPayload)?;
    Ok(())
}
