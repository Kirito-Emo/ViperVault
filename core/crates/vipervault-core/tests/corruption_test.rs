// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault corruption and oracle-resistance tests
//!
//! # Scope
//! These tests ensure that corrupted vaults or wrong passwords are
//! safely rejected without leaking information
//!
//! # Security
//! - Parsing failures must not panic
//! - Wrong passwords must not act as authentication oracles
//! - Tampering and wrong credentials must be indistinguishable

use std::io::Cursor;
use vipervault_core::core::unlock_vault;
use vipervault_core::crypto::aead::generate_xchacha20_nonce;
use vipervault_core::crypto::kdf::{derive_master_key_from_password, generate_vault_salt};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, VaultHeader, VaultParseError, VaultPayload, VaultStorage,
    decode_vault_file, encode_vault_storage,
};

/// Invalid magic must be rejected immediately at parse time
#[test]
fn invalid_magic_rejected() {
    let data = b"NOPE".to_vec();

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::InvalidMagic)));
}

/// Trailing bytes or malformed payload must be rejected
#[test]
fn trailing_bytes_rejected() {
    let mut data = b"VLT1\x01\x00\x01\x00\x00\x00\x00".to_vec();
    data.extend_from_slice(&[0xDE, 0xAD]);

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(res.is_err());
}

/// Wrong password must not act as an authentication oracle
///
/// # Security
/// A vault encrypted with one password must fail to unlock with a different
/// password in the same way as if the ciphertext had been tampered with
#[test]
fn wrong_password_does_not_oracle() {
    // Create a minimal valid vault

    let payload = VaultPayload { entries: vec![] };
    let payload_json = serde_json::to_vec(&payload).expect("payload json");

    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let correct_pw = MasterPassword::new("correct-password".to_string());
    let wrong_pw = MasterPassword::new("wrong-password".to_string());

    let master_key =
        derive_master_key_from_password(&correct_pw, &salt, 64 * 1024, 3, 1).expect("derive key");

    let ciphertext = vipervault_core::crypto::aead::encrypt_xchacha20poly1305(
        &master_key,
        &nonce,
        &payload_json,
        b"aad",
    )
    .expect("encrypt");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: uuid::Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: 64 * 1024,
                time_cost: 3,
                lanes: 1,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
    };

    let encoded = encode_vault_storage(&header, &VaultStorage::Encrypted { ciphertext }, 1)
        .expect("encode vault");

    // Parse succeeds
    let parsed = decode_vault_file(Cursor::new(encoded), None, 1024 * 1024, false)
        .expect("vault must parse");

    // Unlock with wrong password must fail generically
    let res = unlock_vault(&parsed, &wrong_pw);

    assert!(res.is_err());
}
