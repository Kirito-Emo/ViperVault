// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Key derivation functions (KDF)

use crate::memory::{KeyMaterial, MasterPassword};
use crate::vault::SALT_LEN;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// Default Argon2id parameters (OWASP-compliant)
pub const DEFAULT_ARGON2ID_MEM_KIB: u32 = 64 * 1024;
pub const DEFAULT_ARGON2ID_TIME_COST: u32 = 3;
pub const DEFAULT_ARGON2ID_LANES: u32 = 1;

/// Hard upper bounds (DoS protection)
pub const MAX_ARGON2ID_MEM_KIB: u32 = 512 * 1024;
pub const MAX_ARGON2ID_TIME_COST: u32 = 5;
pub const MAX_ARGON2ID_LANES: u32 = 1;

/// Errors returned by the KDF layer
///
/// # Security
/// Errors are intentionally coarse-grained (avoid leaking details)
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    /// Invalid or unsupported KDF parameters
    #[error("invalid kdf parameters")]
    InvalidParams,

    /// Argon2 core operation failed
    #[error("argon2 failure")]
    Argon2Failure,

    /// OS randomness source failed (extremely rare)
    #[error("os rng failure")]
    OsRng,
}

/// Generates a fresh random salt for a vault
///
/// # Security
/// - Salt MUST be unique per vault
/// - Salt is NOT secret, but must be unpredictable and stored in the vault header
///
/// # Errors
/// Returns [`KdfError::OsRng`] if the OS RNG fails
pub fn generate_vault_salt() -> Result<[u8; SALT_LEN], KdfError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| KdfError::OsRng)?;
    Ok(salt)
}

/// Validates Argon2id parameters against minimums and maximums
///
/// # Security
/// Enforces policy:
/// - memory ≥ 64 MiB
/// - iterations ≥ 3
/// - parallelism = 1
///
/// # Errors
/// Returns [`KdfError::InvalidParams`] if validation fails
pub fn validate_argon2id_params(mem_kib: u32, time_cost: u32, lanes: u32) -> Result<(), KdfError> {
    if !(DEFAULT_ARGON2ID_MEM_KIB..=MAX_ARGON2ID_MEM_KIB).contains(&mem_kib)
        || !(DEFAULT_ARGON2ID_TIME_COST..=MAX_ARGON2ID_TIME_COST).contains(&time_cost)
        || lanes != DEFAULT_ARGON2ID_LANES
    {
        return Err(KdfError::InvalidParams);
    }

    Ok(())
}

/// Derives the master key from a [`MasterPassword`] using Argon2id
///
/// # Security
/// - Output wrapped in `KeyMaterial`
/// - Zeroized automatically on drop
pub fn derive_master_key_from_password(
    password: &MasterPassword,
    salt: &[u8; SALT_LEN],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<KeyMaterial, KdfError> {
    validate_argon2id_params(mem_kib, time_cost, lanes)?;

    let params =
        Params::new(mem_kib, time_cost, lanes, Some(32)).map_err(|_| KdfError::InvalidParams)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(password.expose().as_bytes(), salt, &mut out[..])
        .map_err(|_| KdfError::Argon2Failure)?;

    Ok(KeyMaterial(out))
}
