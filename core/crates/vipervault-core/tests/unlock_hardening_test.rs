// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Unlock hardening tests
//!
//! # Scope
//! These tests validate security-hardening properties of the unlock flow:
//! - wrong password and tampering must be indistinguishable (no oracle)
//! - invalid KDF parameters must be rejected early (DoS protection)
//! - error surface remains coarse-grained
//!
//! # Security
//! Unlock must not leak whether authentication failed due to:
//! - wrong password
//! - ciphertext tampering
//! - AAD/header tampering
//!
//! All such cases must map to `AuthFailed`

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::core::{UnlockError, unlock_vault, unlock_vault_to_plaintext_json};
use vipervault_core::crypto::aead::{encrypt_xchacha20poly1305, generate_xchacha20_nonce};
use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST, KdfError,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, ParsedVaultFile, StorageMode, VaultHeader,
    VaultPayload, decode_vault_file,
};

/// Construct an encrypted container with AAD exactly equal to stored `header_bytes`
fn build_encrypted_container_bytes(
    header: &VaultHeader,
    payload_plaintext: &[u8],
    password: &MasterPassword,
) -> Vec<u8> {
    let header_bytes = serde_json::to_vec(header).expect("header serialize");

    let (mem_kib, time_cost, lanes) = match header.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
        _ => panic!("unsupported kdf algorithm"),
    };

    let master_key =
        derive_master_key_from_password(password, &header.crypto.salt, mem_kib, time_cost, lanes)
            .expect("kdf");

    let ct = encrypt_xchacha20poly1305(
        &master_key,
        &header.crypto.nonce,
        payload_plaintext,
        &header_bytes,
    )
    .expect("encrypt");

    let format_version: u16 = 1;
    let mode: u8 = StorageMode::Encrypted as u8;

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&format_version.to_le_bytes());
    out.push(mode);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

fn parse_container(bytes: &[u8]) -> ParsedVaultFile {
    decode_vault_file(Cursor::new(bytes), Some(1), 16 * 1024 * 1024, false).expect("decode")
}

/// Ensure wrong password and ciphertext tampering map to the same public error (`AuthFailed`)
///
/// # Security
/// This test enforces the "no oracle" requirement
#[test]
fn wrong_password_and_tampering_are_indistinguishable() {
    let password_ok = MasterPassword::new("ok".to_string());
    let password_bad = MasterPassword::new("bad".to_string());

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().unwrap(),
            nonce: generate_xchacha20_nonce().unwrap(),
        },
    };

    let payload = VaultPayload { entries: vec![] };
    let plaintext = serde_json::to_vec(&payload).unwrap();

    // Case A: wrong password
    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password_ok);
    let parsed = parse_container(&bytes);
    let err_a = unlock_vault(&parsed, &password_bad).unwrap_err();
    assert!(matches!(err_a, UnlockError::AuthFailed));

    // Case B: tampered ciphertext
    let mut bytes_t = bytes.clone();
    if let Some(last) = bytes_t.last_mut() {
        *last ^= 0xFF;
    }
    let parsed_t = parse_container(&bytes_t);
    let err_b = unlock_vault(&parsed_t, &password_ok).unwrap_err();
    assert!(matches!(err_b, UnlockError::AuthFailed));
}

/// Invalid KDF params must be rejected early
///
/// # Security
/// This prevents an attacker-controlled header from forcing extreme resource usage
/// The failure must surface as `UnlockError::Kdf(_)`
#[test]
fn invalid_kdf_params_are_rejected() {
    let password = MasterPassword::new("pw".to_string());

    // Deliberately invalid: mem_kib below minimum
    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: 1,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: [0u8; 32],
            nonce: generate_xchacha20_nonce().unwrap(),
        },
    };

    // Payload is irrelevant: KDF validation must fail before decryption
    let bytes = {
        let header_bytes = serde_json::to_vec(&header).unwrap();

        let format_version: u16 = 1;
        let mode: u8 = StorageMode::Encrypted as u8;

        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&format_version.to_le_bytes());
        out.push(mode);
        out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&(0u64).to_le_bytes()); // empty payload
        out
    };

    let parsed = parse_container(&bytes);

    let err = unlock_vault_to_plaintext_json(&parsed, &password).unwrap_err();
    match err {
        UnlockError::Kdf(KdfError::InvalidParams) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Tampering with AAD must map to `AuthFailed`, not to a more specific error
///
/// # Security
/// Ensures the unlock flow does not create an authentication oracle
#[test]
fn aad_tampering_maps_to_auth_failed() {
    let password = MasterPassword::new("pw".to_string());

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().unwrap(),
            nonce: generate_xchacha20_nonce().unwrap(),
        },
    };

    let payload = VaultPayload { entries: vec![] };
    let plaintext = serde_json::to_vec(&payload).unwrap();

    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password);
    let mut parsed = parse_container(&bytes);

    parsed.header_bytes[0] ^= 0x01;

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}
