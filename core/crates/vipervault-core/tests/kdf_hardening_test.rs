// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Argon2id hardening tests
//!
//! # Scope
//! These tests validate rejection behavior and boundary enforcement for the KDF layer:
//! - invalid policy parameters are rejected
//! - lower and upper bounds are enforced
//! - output size remains fixed
//!
//! # Security
//! The KDF must reject unsafe or abusive parameter choices to prevent:
//! - weak derivation settings
//! - excessive memory/time amplification
//! - accidental policy regressions

use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST, KdfError,
    MAX_ARGON2ID_LANES, MAX_ARGON2ID_MEM_KIB, MAX_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::memory::MasterPassword;

/// Default project parameters must remain accepted
#[test]
fn default_policy_params_are_valid() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let key = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf");

    assert_eq!(key.as_bytes().len(), 32);
}

/// Minimum accepted policy values must remain valid
#[test]
fn minimum_policy_params_are_valid() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let key = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf");

    assert_eq!(key.as_bytes().len(), 32);
}

/// Memory cost below the minimum must be rejected
#[test]
fn memory_cost_below_minimum_is_rejected() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let err = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB - 1,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap_err();

    assert!(matches!(err, KdfError::InvalidParams));
}

/// Time cost below the minimum must be rejected
#[test]
fn time_cost_below_minimum_is_rejected() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let err = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST - 1,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap_err();

    assert!(matches!(err, KdfError::InvalidParams));
}

/// Lanes below the minimum must be rejected
#[test]
fn lanes_below_minimum_is_rejected() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let err = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        0,
    )
    .unwrap_err();

    assert!(matches!(err, KdfError::InvalidParams));
}

/// Memory cost above the maximum must be rejected
///
/// # Security
/// Prevents abusive allocations and policy bypass via untrusted headers
#[test]
fn memory_cost_above_maximum_is_rejected() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let err = derive_master_key_from_password(
        &password,
        &salt,
        MAX_ARGON2ID_MEM_KIB + 1,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap_err();

    assert!(matches!(err, KdfError::InvalidParams));
}

/// Time cost above the maximum must be rejected
#[test]
fn time_cost_above_maximum_is_rejected() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let err = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        MAX_ARGON2ID_TIME_COST + 1,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap_err();

    assert!(matches!(err, KdfError::InvalidParams));
}

/// Lanes above the maximum must be rejected
#[test]
fn lanes_above_maximum_is_rejected() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let err = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        MAX_ARGON2ID_LANES + 1,
    )
    .unwrap_err();

    assert!(matches!(err, KdfError::InvalidParams));
}

/// Boundary: the documented maximum accepted policy values must still work
#[test]
fn maximum_policy_params_are_valid() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().expect("salt");

    let key = derive_master_key_from_password(
        &password,
        &salt,
        MAX_ARGON2ID_MEM_KIB,
        MAX_ARGON2ID_TIME_COST,
        MAX_ARGON2ID_LANES,
    )
    .expect("kdf");

    assert_eq!(key.as_bytes().len(), 32);
}

/// Different salts must remain accepted even across repeated invocations
///
/// # Security
/// Random per-vault salts do not trigger stateful failures
#[test]
fn multiple_random_salts_remain_valid() {
    let password = MasterPassword::new("pw".to_string());

    for _ in 0..8 {
        let salt = generate_vault_salt().expect("salt");
        let key = derive_master_key_from_password(
            &password,
            &salt,
            DEFAULT_ARGON2ID_MEM_KIB,
            DEFAULT_ARGON2ID_TIME_COST,
            DEFAULT_ARGON2ID_LANES,
        )
        .expect("kdf with random salt");

        assert_eq!(key.as_bytes().len(), 32);
    }
}
