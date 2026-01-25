// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Unlock functional tests
//!
//! # Scope
//! These tests validate the functional correctness of the unlock flow:
//! - correct password unlocks the vault
//! - wrong password fails with `AuthFailed`
//! - tampering is detected (ciphertext/AAD mismatch => `AuthFailed`)
//! - invalid plaintext JSON produces `PayloadDecode`
//! - non-encrypted mode is rejected
//!
//! # Security
//! The unlock API must not leak whether a failure was due to a wrong password
//! or to tampering; both must map to `AuthFailed`

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::core::{UnlockError, unlock_vault, unlock_vault_to_plaintext_json};
use vipervault_core::crypto::aead::{encrypt_xchacha20poly1305, generate_xchacha20_nonce};
use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, ParsedVaultFile, StorageMode, VaultHeader,
    VaultPayload, decode_vault_file,
};

/// Build an encrypted vault container where AEAD AAD is exactly the stored `header_bytes`
///
/// # Security
/// This function constructs the container manually to guarantee that:
/// - AAD used for encryption matches the exact header bytes stored in the file
/// - tests do not rely on JSON re-serialization equivalence
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

    // Container format:
    // MAGIC(4) | FORMAT_VERSION(u16 LE) | STORAGE_MODE(u8) | HEADER_LEN(u32 LE) | HEADER_JSON | PAYLOAD_LEN(u64 LE) | PAYLOAD
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

/// Create a minimal valid encrypted header with project-default KDF params
fn make_default_header() -> VaultHeader {
    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
    }
}

/// Decode helper for the constructed container bytes
fn parse_container(bytes: &[u8]) -> ParsedVaultFile {
    decode_vault_file(Cursor::new(bytes), Some(1), 16 * 1024 * 1024, false).expect("decode")
}

/// Correct password unlocks and returns the decrypted payload
#[test]
fn unlock_success_returns_payload() {
    let password = MasterPassword::new("correct horse battery staple".to_string());

    let entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "super-secret".to_string(),
        Some("note".to_string()),
    )
    .expect("entry");

    let payload = VaultPayload {
        entries: vec![entry],
    };
    let plaintext = serde_json::to_vec(&payload).expect("payload json");

    let header = make_default_header();
    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password);
    let parsed = parse_container(&bytes);

    let out = unlock_vault(&parsed, &password).expect("unlock ok");
    assert_eq!(out.entries.len(), 1);
    assert_eq!(out.entries[0].to_view().expose_title(), "GitHub");
}

/// Unlock-to-plaintext returns JSON bytes which decode to the same payload
#[test]
fn unlock_to_plaintext_json_roundtrip() {
    let password = MasterPassword::new("pw".to_string());
    let header = make_default_header();

    let payload = VaultPayload { entries: vec![] };
    let plaintext = serde_json::to_vec(&payload).expect("payload json");

    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password);
    let parsed = parse_container(&bytes);

    let pt = unlock_vault_to_plaintext_json(&parsed, &password).expect("unlock pt");
    let decoded: VaultPayload = serde_json::from_slice(&pt).expect("decode payload");
    assert_eq!(decoded.entries.len(), 0);
}

/// Wrong password must fail with `AuthFailed` (no oracle)
#[test]
fn wrong_password_returns_auth_failed() {
    let password_ok = MasterPassword::new("ok".to_string());
    let password_bad = MasterPassword::new("bad".to_string());
    let header = make_default_header();

    let payload = VaultPayload { entries: vec![] };
    let plaintext = serde_json::to_vec(&payload).expect("payload json");

    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password_ok);
    let parsed = parse_container(&bytes);

    let err = unlock_vault(&parsed, &password_bad).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Tampering with ciphertext must be detected and mapped to `AuthFailed`
#[test]
fn tampered_ciphertext_returns_auth_failed() {
    let password = MasterPassword::new("pw".to_string());
    let header = make_default_header();

    let payload = VaultPayload { entries: vec![] };
    let plaintext = serde_json::to_vec(&payload).expect("payload json");

    let mut bytes = build_encrypted_container_bytes(&header, &plaintext, &password);

    // Flip one byte near the end (in ciphertext region).
    if let Some(last) = bytes.last_mut() {
        *last ^= 0xFF;
    }

    let parsed = parse_container(&bytes);
    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Tampering with AAD (header_bytes) must be detected and mapped to `AuthFailed`
#[test]
fn tampered_aad_returns_auth_failed() {
    let password = MasterPassword::new("pw".to_string());
    let header = make_default_header();

    let payload = VaultPayload { entries: vec![] };
    let plaintext = serde_json::to_vec(&payload).expect("payload json");

    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password);
    let mut parsed = parse_container(&bytes);

    // Modify header_bytes without changing parsed.header fields.
    // This simulates an attacker altering the raw header bytes used as AAD.
    if !parsed.header_bytes.is_empty() {
        parsed.header_bytes[0] ^= 0x01;
    } else {
        // Extremely unlikely: JSON header bytes are never empty.
        parsed.header_bytes.push(0x01);
    }

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// If decrypted plaintext is not valid JSON for `VaultPayload`, unlock must return `PayloadDecode`
#[test]
fn invalid_json_payload_returns_payload_decode() {
    let password = MasterPassword::new("pw".to_string());
    let header = make_default_header();

    // Not valid JSON
    let plaintext = b"this is not json".to_vec();

    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password);
    let parsed = parse_container(&bytes);

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::PayloadDecode));
}

/// Unlock must reject non-encrypted mode
#[test]
fn non_encrypted_mode_is_rejected() {
    let password = MasterPassword::new("pw".to_string());
    let header = make_default_header();

    let payload = VaultPayload { entries: vec![] };
    let plaintext = serde_json::to_vec(&payload).expect("payload json");

    let bytes = build_encrypted_container_bytes(&header, &plaintext, &password);
    let mut parsed = parse_container(&bytes);

    parsed.mode = StorageMode::PlaintextJson;

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}
