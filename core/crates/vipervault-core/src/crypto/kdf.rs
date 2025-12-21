// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use crate::memory::MasterPassword;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::SALT_LEN;

/// Default Argon2id parameters
///
/// # Notes
/// - Memory cost is expressed in KiB for the `argon2` crate `Params`
/// - These defaults are above OWASP minimum recommendations
pub const DEFAULT_ARGON2ID_MEM_KIB: u32 = 64 * 1024;
pub const DEFAULT_ARGON2ID_TIME_COST: u32 = 3;
pub const DEFAULT_ARGON2ID_LANES: u32 = 1;

/// Hard upper bounds to reduce accidental DoS due to extreme parameters
///
/// # Security
/// Attackers may craft a vault header with absurd KDF settings to force huge allocations
/// or very long execution times, so values are capped to keep operations within sane limits
pub const MAX_ARGON2ID_MEM_KIB: u32 = 512 * 1024;
pub const MAX_ARGON2ID_TIME_COST: u32 = 5;
pub const MAX_ARGON2ID_LANES: u32 = 1;

/// Output length for the derived master key
///
/// # Notes
/// 32 bytes = 256-bit key, suitable for XChaCha20-Poly1305
pub const MASTER_KEY_LEN: usize = 32;

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
    #[error("argon2 error")]
    Argon2,

    /// OS randomness source failed (extremely rare)
    #[error("os rng error")]
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
    // OsRng reads from the OS CSPRNG
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
/// - parallelism = 2
///
/// # Errors
/// Returns [`KdfError::InvalidParams`] if validation fails
pub fn validate_argon2id_params(mem_kib: u32, time_cost: u32, lanes: u32) -> Result<(), KdfError> {
    // Enforce minimums
    if mem_kib < DEFAULT_ARGON2ID_MEM_KIB {
        return Err(KdfError::InvalidParams);
    }
    if time_cost < DEFAULT_ARGON2ID_TIME_COST {
        return Err(KdfError::InvalidParams);
    }
    if lanes != DEFAULT_ARGON2ID_LANES {
        return Err(KdfError::InvalidParams);
    }
    // Enforce maximums to reduce DoS risks
    if mem_kib > MAX_ARGON2ID_MEM_KIB
        || time_cost > MAX_ARGON2ID_TIME_COST
        || lanes > MAX_ARGON2ID_LANES
    {
        return Err(KdfError::InvalidParams);
    }

    Ok(())
}

/// Derives the vault master key from the master password using Argon2id
///
/// # Parameters
/// - `password`: master password bytes
/// - `salt`: per-vault random salt stored in the vault header
/// - `mem_kib`, `time_cost`, `lanes`: Argon2id parameters
///
/// # Returns
/// A zeroizing 32-byte master key
///
/// # Security
/// - The returned key is wrapped in [`Zeroizing`], so it is wiped on drop
/// - This function never allocates unbounded memory; it relies on validated parameters
///
/// # Errors
/// Returns [`KdfError`] on invalid params or Argon2 failure
pub fn derive_master_key_argon2id(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KdfError> {
    validate_argon2id_params(mem_kib, time_cost, lanes)?;

    // Argon2 crate expects memory in KiB blocks
    let params = Params::new(mem_kib, time_cost, lanes, Some(MASTER_KEY_LEN))
        .map_err(|_| KdfError::InvalidParams)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Output key is sensitive -> always zeroize on drop
    let mut out = Zeroizing::new([0u8; MASTER_KEY_LEN]);

    // Derive raw bytes directly into `out`
    argon2
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| KdfError::Argon2)?;

    Ok(out)
}

/// Convenience helper: returns the recommended default KDF parameters
pub fn default_argon2id_params() -> (u32, u32, u32) {
    (
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
}

/// Derives the master key from a [`MasterPassword`]
///
/// # Security
/// This avoids passing raw password bytes around
pub fn derive_master_key_from_password(
    password: &MasterPassword,
    salt: &[u8; SALT_LEN],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, KdfError> {
    derive_master_key_argon2id(password.as_bytes(), salt, mem_kib, time_cost, lanes)
}

/// Best-effort wipe for a password buffer (if you own it)
///
/// # Security
/// This only wipes the provided buffer
pub fn wipe_password_bytes(buf: &mut [u8]) {
    buf.zeroize();
}
