// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Argon2id hardening tests
//!
//! # Scope
//! These tests validate that the KDF layer:
//! - enforces parameter policy (min/max bounds)
//! - rejects invalid configurations (DoS prevention)
//! - behaves safely without panics
//!
//! # Security
//! - Prevents attackers from embedding extreme Argon2 parameters in a vault header that would cause excessive CPU/RAM usage
//! - Ensures consistent error behavior (coarse-grained errors, no oracle)

use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST, KdfError,
    MAX_ARGON2ID_LANES, MAX_ARGON2ID_MEM_KIB, MAX_ARGON2ID_TIME_COST,
    derive_master_key_from_password, validate_argon2id_params,
};
use vipervault_core::memory::MasterPassword;

#[test]
fn validate_rejects_low_memory() {
    let res = validate_argon2id_params(
        DEFAULT_ARGON2ID_MEM_KIB - 1,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    );
    assert!(matches!(res, Err(KdfError::InvalidParams)));
}

#[test]
fn validate_rejects_high_memory() {
    let res = validate_argon2id_params(
        MAX_ARGON2ID_MEM_KIB + 1,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    );
    assert!(matches!(res, Err(KdfError::InvalidParams)));
}

#[test]
fn validate_rejects_low_time_cost() {
    let res = validate_argon2id_params(
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST - 1,
        DEFAULT_ARGON2ID_LANES,
    );
    assert!(matches!(res, Err(KdfError::InvalidParams)));
}

#[test]
fn validate_rejects_high_time_cost() {
    let res = validate_argon2id_params(
        DEFAULT_ARGON2ID_MEM_KIB,
        MAX_ARGON2ID_TIME_COST + 1,
        DEFAULT_ARGON2ID_LANES,
    );
    assert!(matches!(res, Err(KdfError::InvalidParams)));
}

#[test]
fn validate_rejects_wrong_lanes() {
    // Project policy enforces lanes == DEFAULT_ARGON2ID_LANES (currently 1)
    let res = validate_argon2id_params(
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES + 1,
    );
    assert!(matches!(res, Err(KdfError::InvalidParams)));

    let res2 = validate_argon2id_params(
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        MAX_ARGON2ID_LANES + 1,
    );
    assert!(matches!(res2, Err(KdfError::InvalidParams)));
}

/// Derivation must fail if parameters violate policy
///
/// # Security
/// This ensures untrusted vault headers cannot force unsafe resource usage
#[test]
fn derive_rejects_invalid_params() {
    let password = MasterPassword::new("pw".to_string());
    let salt = [0u8; 32];

    let res = derive_master_key_from_password(
        &password,
        &salt,
        1, // far below minimum
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    );

    assert!(matches!(res, Err(KdfError::InvalidParams)));
}

/// Derivation should succeed on maximum allowed parameters
///
/// # Security
/// Ensures that the configured maxima are actually usable for legitimate vaults
#[test]
fn derive_accepts_max_allowed_params() {
    let password = MasterPassword::new("pw".to_string());
    let salt = [1u8; 32];

    let res = derive_master_key_from_password(
        &password,
        &salt,
        MAX_ARGON2ID_MEM_KIB,
        MAX_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    );

    assert!(res.is_ok());
}
