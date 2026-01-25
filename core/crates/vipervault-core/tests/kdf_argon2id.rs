// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    MAX_ARGON2ID_MEM_KIB, MAX_ARGON2ID_TIME_COST, derive_master_key_from_password,
};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::SALT_LEN;

/// Same password + same salt + same params ⇒ same derived key
#[test]
fn kdf_deterministic() {
    let password = MasterPassword::from_string("test-password".to_string());
    let salt = [1u8; SALT_LEN];

    let key1 = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf must succeed");

    let key2 = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf must succeed");

    assert_eq!(key1.as_slice(), key2.as_slice());
}

/// Different salt ⇒ different derived key
#[test]
fn kdf_salt_changes_key() {
    let password = MasterPassword::from_string("test-password".to_string());

    let salt1 = [1u8; SALT_LEN];
    let salt2 = [2u8; SALT_LEN];

    let key1 = derive_master_key_from_password(
        &password,
        &salt1,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf must succeed");

    let key2 = derive_master_key_from_password(
        &password,
        &salt2,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf must succeed");

    assert_ne!(key1.as_slice(), key2.as_slice());
}

/// Derived key length must be correct
#[test]
fn kdf_key_length() {
    let password = MasterPassword::from_string("test-password".to_string());
    let salt = [0u8; SALT_LEN];

    let key = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .expect("kdf must succeed");

    // 32 bytes = 256-bit master key
    assert_eq!(key.len(), 32);
}

/// Memory cost above MAX must be rejected
#[test]
fn kdf_rejects_excessive_memory() {
    let password = MasterPassword::from_string("test-password".to_string());
    let salt = [0u8; SALT_LEN];

    let result = derive_master_key_from_password(
        &password,
        &salt,
        MAX_ARGON2ID_MEM_KIB + 1,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    );

    assert!(result.is_err());
}

/// Time cost above MAX must be rejected
#[test]
fn kdf_rejects_excessive_time_cost() {
    let password = MasterPassword::from_string("test-password".to_string());
    let salt = [0u8; SALT_LEN];

    let result = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        MAX_ARGON2ID_TIME_COST + 1,
        DEFAULT_ARGON2ID_LANES,
    );

    assert!(result.is_err());
}
