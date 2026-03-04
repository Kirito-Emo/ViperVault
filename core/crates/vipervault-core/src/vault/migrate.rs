// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault migration utilities
//!
//! Enables converting an existing encrypted vault into a duress-enabled vault
//!
//! # Security notes
//! - Requires the primary password (vault must be unlocked)
//! - Re-encrypts payload into dual ciphertext envelope
//! - Preserves vault_id and schema_version
//! - Uses fresh salts and nonces for both primary and decoy branches
//! - Avoids panics: returns coarse-grained errors (no oracles)

use super::create::VaultKdfPolicy;
use super::duress::encrypt_duress_envelope;
use super::error::VaultParseError;
use super::types::{
    AeadSuite, CryptoHeader, DualCiphertextEnvelope, DualVaultHeader, KdfParams, SALT_LEN,
    VaultFile, VaultHeader, VaultPayload, VaultStorage, XCHACHA20_NONCE_LEN,
};
use crate::memory::MasterPassword;
use rand::RngCore;

/// Convert an encrypted vault into a duress-enabled vault
///
/// # Parameters
/// - `vault`: existing encrypted vault (must not already be duress-enabled)
/// - `primary_password`: correct current vault password
/// - `decoy_password`: new coercion password
/// - `decoy_payload`: payload to expose under coercion
/// - `kdf`: KDF policy to use for both primary and decoy branches
///
/// # Errors
/// - `InvalidHeader` if vault already has duress enabled or is not encrypted
/// - `AuthFailed` if primary decryption fails (wrong password OR tampering)
pub fn enable_duress_on_vault(
    vault: &VaultFile,
    primary_password: &MasterPassword,
    decoy_password: &MasterPassword,
    decoy_payload: &VaultPayload,
    kdf: VaultKdfPolicy,
) -> Result<VaultFile, VaultParseError> {
    // Ensure vault is encrypted and not already duress-enabled
    let legacy_ciphertext = match &vault.storage {
        VaultStorage::Encrypted { ciphertext } => ciphertext,
        VaultStorage::PlaintextJson { .. } => return Err(VaultParseError::InvalidHeader),
    };

    if vault.header.duress.is_some() {
        return Err(VaultParseError::InvalidHeader);
    }

    // Derive key from legacy crypto header
    let (mem_kib, time_cost, lanes) = match vault.header.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
    };

    let primary_key = crate::crypto::kdf::derive_master_key_from_password(
        primary_password,
        &vault.header.crypto.salt,
        mem_kib,
        time_cost,
        lanes,
    )
    .map_err(|_| VaultParseError::AuthFailed)?;

    // Decrypt legacy payload
    //
    // # Security
    // The header bytes are used as AEAD AAD to prevent header tampering
    let legacy_header_bytes =
        serde_json::to_vec(&vault.header).map_err(|_| VaultParseError::Serialize)?;

    let plaintext = crate::crypto::aead::decrypt_xchacha20poly1305(
        &primary_key,
        &vault.header.crypto.nonce,
        legacy_ciphertext,
        &legacy_header_bytes,
    )
    .map_err(|_| VaultParseError::AuthFailed)?;

    let primary_payload: VaultPayload =
        serde_json::from_slice(&plaintext).map_err(|_| VaultParseError::InvalidPayload)?;

    // Generate fresh salts and nonces for duress mode
    let mut salt1 = [0u8; SALT_LEN];
    let mut nonce1 = [0u8; XCHACHA20_NONCE_LEN];
    let mut salt2 = [0u8; SALT_LEN];
    let mut nonce2 = [0u8; XCHACHA20_NONCE_LEN];

    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt1);
    rng.fill_bytes(&mut nonce1);
    rng.fill_bytes(&mut salt2);
    rng.fill_bytes(&mut nonce2);

    let primary_crypto = CryptoHeader {
        kdf: kdf.as_kdf_params(),
        aead: AeadSuite::XChaCha20Poly1305,
        salt: salt1,
        nonce: nonce1,
    };

    let decoy_crypto = CryptoHeader {
        kdf: kdf.as_kdf_params(),
        aead: AeadSuite::XChaCha20Poly1305,
        salt: salt2,
        nonce: nonce2,
    };

    let new_header = VaultHeader {
        schema_version: vault.header.schema_version,
        vault_id: vault.header.vault_id,
        crypto: primary_crypto.clone(),
        duress: Some(DualVaultHeader {
            primary: primary_crypto.clone(),
            decoy: decoy_crypto.clone(),
        }),
    };

    let header_bytes = serde_json::to_vec(&new_header).map_err(|_| VaultParseError::Serialize)?;

    let duress_ref = new_header
        .duress
        .as_ref()
        .ok_or(VaultParseError::InvalidHeader)?;

    let envelope: DualCiphertextEnvelope = encrypt_duress_envelope(
        &header_bytes,
        duress_ref,
        primary_password,
        decoy_password,
        &primary_payload,
        decoy_payload,
    )?;

    let ciphertext = serde_json::to_vec(&envelope).map_err(|_| VaultParseError::Serialize)?;

    Ok(VaultFile {
        header: new_header,
        storage: VaultStorage::Encrypted { ciphertext },
    })
}
