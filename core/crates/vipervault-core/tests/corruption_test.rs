// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault corruption tests
//!
//! # Scope
//! These tests validate safe rejection of corrupted vault containers:
//! - corrupted magic / version / mode
//! - corrupted header JSON
//! - corrupted payload bytes
//! - ciphertext tampering after successful decoding
//! - truncated containers
//!
//! # Security
//! Corrupted inputs must be rejected safely without panics, partial success
//! or oracle-like error detail leakage in the unlock path

use std::io::Cursor;
use vipervault_core::core::{UnlockError, unlock_vault};
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_encrypted_vault};
use vipervault_core::vault::{
    MAX_VAULT_CONTAINER_PAYLOAD_LEN, StorageMode, VaultParseError, VaultPayload, decode_vault_file,
    encode_vault_storage,
};

fn build_valid_vault_bytes() -> (Vec<u8>, MasterPassword) {
    let entry =
        VaultEntry::new_secure_note("note".to_string(), "secret".to_string()).expect("entry");

    let payload = VaultPayload {
        entries: vec![entry],
    };

    let password = MasterPassword::new("pw".to_string());

    let kdf = VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    };

    let vault = create_encrypted_vault(&password, &payload, 1, kdf).expect("create vault");
    let bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault");

    (bytes, password)
}

/// Corrupting the magic must reject decoding
#[test]
fn corrupted_magic_is_rejected() {
    let (mut bytes, _) = build_valid_vault_bytes();
    bytes[0] ^= 0xFF;

    let err = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .unwrap_err();

    assert!(matches!(err, VaultParseError::InvalidMagic));
}

/// Corrupting the version must reject decoding
#[test]
fn corrupted_version_is_rejected() {
    let (mut bytes, _) = build_valid_vault_bytes();

    // Version is stored after 4-byte magic
    bytes[4] = 0;
    bytes[5] = 0;

    let err = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .unwrap_err();

    assert!(matches!(err, VaultParseError::UnsupportedVersion));
}

/// Corrupting the storage mode must reject decoding
#[test]
fn corrupted_storage_mode_is_rejected() {
    let (mut bytes, _) = build_valid_vault_bytes();

    // Storage mode byte follows magic(4) + version(2)
    bytes[6] = 0xFF;

    let err = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .unwrap_err();

    assert!(matches!(err, VaultParseError::UnsupportedStorageMode));
}

/// Truncating the container must reject decoding
#[test]
fn truncated_container_is_rejected() {
    let (mut bytes, _) = build_valid_vault_bytes();
    bytes.truncate(bytes.len() / 2);

    let err = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .unwrap_err();

    assert!(matches!(err, VaultParseError::Io(_)));
}

/// Corrupting a header byte inside the serialized header must reject decoding or unlocking
#[test]
fn corrupted_header_bytes_are_rejected() {
    let (mut bytes, _) = build_valid_vault_bytes();

    // Layout:
    // 0..4 magic
    // 4..6 version
    // 6 mode
    // 7..11 header_len (u32 LE)
    let header_len = u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]) as usize;
    let header_start = 11;

    assert!(header_len > 0);
    bytes[header_start] ^= 0x01;

    let res = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    );

    assert!(res.is_err());
}

/// Ciphertext tampering after successful decoding must be reported as `AuthFailed`
#[test]
fn ciphertext_tamper_maps_to_auth_failed() {
    let (mut bytes, password) = build_valid_vault_bytes();

    // Flip the last byte, which belongs to payload/ciphertext
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    assert_eq!(parsed.mode, StorageMode::Encrypted);

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Trailing bytes must be rejected
#[test]
fn trailing_bytes_are_rejected() {
    let (mut bytes, _) = build_valid_vault_bytes();
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let err = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .unwrap_err();

    assert!(matches!(err, VaultParseError::TrailingBytes));
}
