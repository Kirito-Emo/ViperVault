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
//! - Decryption failures are mapped to `VaultParseError::AuthFailed` to avoid oracle behavior

use super::error::VaultParseError;
use super::types::{
    CryptoHeader, DualCiphertextEnvelope, DualVaultHeader, KdfParams, VaultPayload,
};
use crate::crypto::aead::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305};
use crate::crypto::kdf::derive_master_key_from_password;
use crate::memory::MasterPassword;
use zeroize::Zeroizing;

/// Which payload was unlocked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockOutcome {
    Primary, // The primary (real) vault was unlocked
    Decoy,   // The decoy vault was unlocked
}

/// Unlock a duress-enabled vault envelope
///
/// Tries primary first, then decoy
/// If both fail, returns `AuthFailed`
pub fn unlock_duress_envelope(
    header_bytes: &[u8],
    duress_header: &DualVaultHeader,
    envelope: &DualCiphertextEnvelope,
    password: &MasterPassword,
) -> Result<(UnlockOutcome, VaultPayload), VaultParseError> {
    if let Ok(pt) = decrypt_with_crypto_header(
        header_bytes,
        &duress_header.primary,
        envelope.primary_ct.as_slice(),
        password,
    ) {
        let payload: VaultPayload =
            serde_json::from_slice(pt.as_slice()).map_err(|_| VaultParseError::InvalidPayload)?;
        return Ok((UnlockOutcome::Primary, payload));
    }

    if let Ok(pt) = decrypt_with_crypto_header(
        header_bytes,
        &duress_header.decoy,
        envelope.decoy_ct.as_slice(),
        password,
    ) {
        let payload: VaultPayload =
            serde_json::from_slice(pt.as_slice()).map_err(|_| VaultParseError::InvalidPayload)?;
        return Ok((UnlockOutcome::Decoy, payload));
    }

    Err(VaultParseError::AuthFailed)
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
    let primary_pt = serde_json::to_vec(primary_payload).map_err(|_| VaultParseError::Serialize)?;
    let decoy_pt = serde_json::to_vec(decoy_payload).map_err(|_| VaultParseError::Serialize)?;

    let primary_ct = encrypt_with_crypto_header(
        header_bytes,
        &duress_header.primary,
        primary_pt.as_slice(),
        primary_password,
    )?;
    let decoy_ct = encrypt_with_crypto_header(
        header_bytes,
        &duress_header.decoy,
        decoy_pt.as_slice(),
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
    // Currently only Argon2id is supported in this project.
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
        .map_err(|_| VaultParseError::InvalidHeader)?;

    encrypt_xchacha20poly1305(&key, &ch.nonce, plaintext, header_bytes)
        .map_err(|_| VaultParseError::Serialize)
}
