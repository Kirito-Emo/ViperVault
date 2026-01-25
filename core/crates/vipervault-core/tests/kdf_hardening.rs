// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    MAX_ARGON2ID_LANES, MAX_ARGON2ID_MEM_KIB, MAX_ARGON2ID_TIME_COST,
    derive_master_key_from_password,
};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::SALT_LEN;

/// Minimum defaults should succeed (baseline config)
#[test]
fn accepts_default_params() {
    let password = MasterPassword::from_string("pw".to_string());
    let salt = [1u8; SALT_LEN];

    let key = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("must succeed");

    assert_eq!(key.len(), 32);
}

/// Max bounds should be accepted (inclusive)
#[test]
fn accepts_max_bounds_inclusive() {
    let password = MasterPassword::from_string("pw".to_string());
    let salt = [2u8; SALT_LEN];

    let key = derive_master_key_from_password(
        &password,
        &salt,
        MAX_ARGON2ID_MEM_KIB,
        MAX_ARGON2ID_TIME_COST,
        MAX_ARGON2ID_LANES,
    )
    .expect("must succeed");

    assert_eq!(key.len(), 32);
}

/// Zero memory should be rejected (invalid/DoS-prone)
#[test]
fn rejects_zero_memory() {
    let password = MasterPassword::from_string("pw".to_string());
    let salt = [3u8; SALT_LEN];

    let res = derive_master_key_from_password(
        &password,
        &salt,
        0,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    );

    assert!(res.is_err());
}

/// Zero iterations should be rejected (invalid)
#[test]
fn rejects_zero_time_cost() {
    let password = MasterPassword::from_string("pw".to_string());
    let salt = [4u8; SALT_LEN];

    let res = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        0,
        DEFAULT_ARGON2ID_LANES,
    );

    assert!(res.is_err());
}

/// Zero lanes should be rejected (invalid)
#[test]
fn rejects_zero_lanes() {
    let password = MasterPassword::from_string("pw".to_string());
    let salt = [5u8; SALT_LEN];

    let res = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        0,
    );

    assert!(res.is_err());
}
