// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Unlock hardening tests
//!
//! # Scope
//! These tests validate security-hardening properties of the unlock flow:
//! - wrong password and tampering must be indistinguishable (no oracle)
//! - invalid KDF parameters must be rejected early (DoS protection)
//! - error surface remains coarse-grained
//! - duress vaults must preserve the same non-oracle behavior
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
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_duress_vault};
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, MAX_VAULT_CONTAINER_PAYLOAD_LEN, StorageMode,
    VaultHeader, VaultPayload, decode_vault_file,
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
        _ => unreachable!("unsupported KDF params in tests"),
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

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(StorageMode::Encrypted as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Construct an encrypted container without performing real encryption
///
/// # Purpose
/// This helper is used for tests that need decoding to succeed while unlock must fail before decryption
fn build_container_with_raw_payload(header: &VaultHeader, payload: &[u8]) -> Vec<u8> {
    let header_bytes = serde_json::to_vec(header).expect("header serialize");

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(StorageMode::Encrypted as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn sample_payload() -> VaultPayload {
    let entry = VaultEntry::new_secure_note("note".to_string(), "secret".to_string())
        .expect("entry create");

    VaultPayload {
        entries: vec![entry],
    }
}

#[test]
fn no_oracle_wrong_password_vs_ciphertext_tamper() {
    let password = MasterPassword::new("pw".to_string());
    let wrong = MasterPassword::new("wrong".to_string());

    let payload = sample_payload();
    let payload_json = serde_json::to_vec(&payload).expect("payload json");

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
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    let bytes_ok = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed_ok = decode_vault_file(
        Cursor::new(bytes_ok),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let err_wrong = unlock_vault(&parsed_ok, &wrong).unwrap_err();
    assert!(matches!(err_wrong, UnlockError::AuthFailed));

    let mut bytes_t = build_encrypted_container_bytes(&header, &payload_json, &password);
    let last = bytes_t.len() - 1;
    bytes_t[last] ^= 0x01;

    let parsed_t = decode_vault_file(
        Cursor::new(bytes_t),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let err_tamper = unlock_vault(&parsed_t, &password).unwrap_err();
    assert!(matches!(err_tamper, UnlockError::AuthFailed));
}

#[test]
fn no_oracle_aad_tamper_is_auth_failed() {
    let password = MasterPassword::new("pw".to_string());

    let payload = sample_payload();
    let payload_json = serde_json::to_vec(&payload).expect("payload json");

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
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let mut parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    parsed.header_bytes[0] ^= 0x01;

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

#[test]
fn invalid_kdf_params_are_rejected() {
    let password = MasterPassword::new("pw".to_string());

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: 1,   // far below minimum policy
                time_cost: 1, // too low
                lanes: 0,     // invalid
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    // Raw payload is enough because unlock must fail during KDF validation,
    // before attempting authenticated decryption
    let bytes = build_container_with_raw_payload(&header, b"not-important");
    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let err = unlock_vault_to_plaintext_json(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::Kdf(KdfError::InvalidParams)));
}

#[test]
fn duress_no_oracle_wrong_password_vs_tamper() {
    let primary_pw = MasterPassword::new("primary".to_string());
    let decoy_pw = MasterPassword::new("decoy".to_string());
    let wrong_pw = MasterPassword::new("wrong".to_string());

    let primary_payload = sample_payload();
    let decoy_payload = sample_payload();

    let kdf = VaultKdfPolicy {
        mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
        time_cost: DEFAULT_ARGON2ID_TIME_COST,
        lanes: DEFAULT_ARGON2ID_LANES,
    };

    let vf = create_duress_vault(
        &primary_pw,
        &decoy_pw,
        &primary_payload,
        &decoy_payload,
        1,
        kdf,
    )
    .expect("create duress vault");

    let bytes_ok = vipervault_core::vault::codec::encode_vault_storage(&vf.header, &vf.storage, 1)
        .expect("encode");
    let parsed_ok = decode_vault_file(
        Cursor::new(bytes_ok),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let err_wrong = unlock_vault(&parsed_ok, &wrong_pw).unwrap_err();
    assert!(matches!(err_wrong, UnlockError::AuthFailed));

    let bytes_t = vipervault_core::vault::codec::encode_vault_storage(&vf.header, &vf.storage, 1)
        .expect("encode");
    let mut parsed_t = decode_vault_file(
        Cursor::new(bytes_t),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    // Tamper with authenticated header bytes while keeping the duress envelope JSON valid
    parsed_t.header_bytes[0] ^= 0x01;

    let err_tamper = unlock_vault(&parsed_t, &primary_pw).unwrap_err();
    assert!(matches!(err_tamper, UnlockError::AuthFailed));
}
