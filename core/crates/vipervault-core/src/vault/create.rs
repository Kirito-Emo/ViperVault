// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault creation utilities
//!
//! Adds support for creating duress-enabled vaults
//!
//! # Security notes
//! - All payloads are encrypted with AEAD
//! - Header bytes are used as AAD
//! - Duress vaults store a JSON envelope with dual ciphertext
//! - Plaintext export is not handled here; it remains gated by policy in the codec layer

use super::duress::encrypt_duress_envelope;
use super::error::VaultParseError;
use super::types::{
    AeadSuite, CryptoHeader, DualVaultHeader, KdfParams, SALT_LEN, VaultFile, VaultHeader,
    VaultPayload, VaultStorage, XCHACHA20_NONCE_LEN,
};
use crate::crypto::aead::encrypt_xchacha20poly1305;
use crate::crypto::kdf::derive_master_key_from_password;
use crate::memory::MasterPassword;
use rand::RngCore;
use uuid::Uuid;

/// KDF policy used when creating new vaults
#[derive(Debug, Clone, Copy)]
pub struct VaultKdfPolicy {
    pub mem_kib: u32,   // Argon2id memory cost in KiB
    pub time_cost: u32, // Argon2id time cost (iterations)
    pub lanes: u32,     // Argon2id lanes (parallelism)
}

impl VaultKdfPolicy {
    /// Build KDF params for headers
    pub(crate) fn as_kdf_params(self) -> KdfParams {
        KdfParams::Argon2id {
            mem_kib: self.mem_kib,
            time_cost: self.time_cost,
            lanes: self.lanes,
        }
    }
}

/// Create an encrypted vault
///
/// # Notes
/// This produces a vault with `VaultHeader.duress = None` and a single ciphertext payload
pub fn create_encrypted_vault(
    password: &MasterPassword,
    payload: &VaultPayload,
    schema_version: u16,
    kdf: VaultKdfPolicy,
) -> Result<VaultFile, VaultParseError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];

    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let crypto = CryptoHeader {
        kdf: kdf.as_kdf_params(),
        aead: AeadSuite::XChaCha20Poly1305,
        salt,
        nonce,
    };

    let header = VaultHeader {
        schema_version,
        vault_id: Uuid::new_v4(),
        crypto: crypto.clone(),
        duress: None,
    };

    let header_bytes = serde_json::to_vec(&header).map_err(|_| VaultParseError::Serialize)?;

    let master_key =
        derive_master_key_from_password(password, &salt, kdf.mem_kib, kdf.time_cost, kdf.lanes)
            .map_err(|_| VaultParseError::InvalidHeader)?;

    let plaintext = serde_json::to_vec(payload).map_err(|_| VaultParseError::Serialize)?;

    let ciphertext = encrypt_xchacha20poly1305(&master_key, &nonce, &plaintext, &header_bytes)
        .map_err(|_| VaultParseError::Serialize)?;

    Ok(VaultFile {
        header,
        storage: VaultStorage::Encrypted { ciphertext },
    })
}

/// Create a duress-enabled encrypted vault
///
/// # Parameters
/// - `primary_password`: real vault password
/// - `decoy_password`: coercion password
///
/// # Notes
/// The resulting payload bytes store a JSON-serialized `DualCiphertextEnvelope`
pub fn create_duress_vault(
    primary_password: &MasterPassword,
    decoy_password: &MasterPassword,
    primary_payload: &VaultPayload,
    decoy_payload: &VaultPayload,
    schema_version: u16,
    kdf: VaultKdfPolicy,
) -> Result<VaultFile, VaultParseError> {
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

    let header = VaultHeader {
        schema_version,
        vault_id: Uuid::new_v4(),
        crypto: primary_crypto.clone(),
        duress: Some(DualVaultHeader {
            primary: primary_crypto.clone(),
            decoy: decoy_crypto.clone(),
        }),
    };

    let header_bytes = serde_json::to_vec(&header).map_err(|_| VaultParseError::Serialize)?;
    let duress_header = header
        .duress
        .as_ref()
        .ok_or(VaultParseError::InvalidHeader)?;

    let envelope = encrypt_duress_envelope(
        &header_bytes,
        duress_header,
        primary_password,
        decoy_password,
        primary_payload,
        decoy_payload,
    )?;

    // Store envelope bytes as the "ciphertext" for the container
    let ciphertext = serde_json::to_vec(&envelope).map_err(|_| VaultParseError::Serialize)?;

    Ok(VaultFile {
        header,
        storage: VaultStorage::Encrypted { ciphertext },
    })
}
