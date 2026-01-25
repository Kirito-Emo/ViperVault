// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Argon2id functional tests
//!
//! # Scope
//! These tests validate the correctness of Argon2id key derivation:
//! - deterministic output for same inputs
//! - output changes when password or salt changes
//! - correct output size
//!
//! # Security
//! The goal is to ensure:
//! - stable derivation behavior
//! - no accidental acceptance of invalid parameters (covered more in hardening tests)

use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::memory::MasterPassword;

/// Same password + same salt + same params => same derived key
///
/// # Security
/// Determinism is required for unlocking the same vault reliably
#[test]
fn kdf_is_deterministic_for_same_inputs() {
    let password = MasterPassword::new("correct horse battery staple".to_string());
    let salt = generate_vault_salt().unwrap();

    let k1 = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap();

    let k2 = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap();

    assert_eq!(k1.as_bytes().as_slice(), k2.as_bytes().as_slice());
    assert_eq!(k1.as_bytes().len(), 32);
}

/// Changing the password must change the derived key
///
/// # Security
/// Prevents key reuse across different passwords
#[test]
fn kdf_changes_with_password() {
    let salt = generate_vault_salt().unwrap();

    let p1 = MasterPassword::new("password-1".to_string());
    let p2 = MasterPassword::new("password-2".to_string());

    let k1 = derive_master_key_from_password(
        &p1,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap();

    let k2 = derive_master_key_from_password(
        &p2,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap();

    assert_ne!(k1.as_bytes().as_slice(), k2.as_bytes().as_slice());
}

/// Changing the salt must change the derived key
///
/// # Security
/// Ensures per-vault uniqueness and protects against rainbow tables
#[test]
fn kdf_changes_with_salt() {
    let password = MasterPassword::new("same-password".to_string());
    let salt1 = generate_vault_salt().unwrap();
    let salt2 = generate_vault_salt().unwrap();

    let k1 = derive_master_key_from_password(
        &password,
        &salt1,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap();

    let k2 = derive_master_key_from_password(
        &password,
        &salt2,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap();

    assert_ne!(k1.as_bytes().as_slice(), k2.as_bytes().as_slice());
}

/// KDF must accept the project's default parameters
///
/// # Security
/// Ensures that defaults remain valid and consistent across refactors
#[test]
fn kdf_accepts_default_params() {
    let password = MasterPassword::new("pw".to_string());
    let salt = generate_vault_salt().unwrap();

    let k = derive_master_key_from_password(
        &password,
        &salt,
        DEFAULT_ARGON2ID_MEM_KIB,
        DEFAULT_ARGON2ID_TIME_COST,
        DEFAULT_ARGON2ID_LANES,
    )
    .unwrap();

    assert_eq!(k.as_bytes().len(), 32);
}
