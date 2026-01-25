// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault codec hardening tests
//!
//! # Scope
//! These tests validate the robustness of the vault container decoder against
//! malformed, truncated, or adversarial input
//! The goal is rejection, not precise error classification
//!
//! # Security
//! - No malformed input must be accepted
//! - No panics or undefined behavior
//! - Length-prefixed parsing must not allow over-reads
//! - Trailing bytes must not be silently ignored

use std::io::Cursor;
use vipervault_core::vault::{MAX_HEADER_LEN, StorageMode, VaultParseError, decode_vault_file};

/// Helper: return `true` if the error represents a valid rejection
///
/// # Rationale
/// The codec is allowed to reject malformed input through multiple
/// semantically-correct error paths (I/O, bounds, format)
/// Hardening tests must accept *any* of these
fn is_valid_rejection(err: &VaultParseError) -> bool {
    matches!(
        err,
        VaultParseError::Io(_)
            | VaultParseError::InvalidMagic
            | VaultParseError::UnsupportedVersion
            | VaultParseError::UnsupportedStorageMode
            | VaultParseError::PlaintextNotAllowed
            | VaultParseError::HeaderTooLarge
            | VaultParseError::PayloadTooLarge
            | VaultParseError::TrailingBytes
            | VaultParseError::Serialize
            | VaultParseError::Deserialize
    )
}

/// Build a minimal valid-looking vault prefix with the given payload length
///
/// This is intentionally *not* a fully valid vault; it is used to construct
/// truncated and malformed inputs deterministically
fn minimal_prefix(payload_len: u64) -> Vec<u8> {
    let mut buf = Vec::new();

    // MAGIC
    buf.extend_from_slice(b"VLT1");

    // FORMAT_VERSION (1)
    buf.extend_from_slice(&1u16.to_le_bytes());

    // STORAGE_MODE: Encrypted
    buf.push(StorageMode::Encrypted as u8);

    // HEADER_LEN = 0
    buf.extend_from_slice(&0u32.to_le_bytes());

    // PAYLOAD_LEN
    buf.extend_from_slice(&payload_len.to_le_bytes());

    buf
}

/// Invalid magic must be rejected
#[test]
fn invalid_magic_is_rejected() {
    let data = b"NOPE".to_vec();

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::InvalidMagic)));
}

/// Unknown storage mode must be rejected
#[test]
fn unknown_storage_mode_is_rejected() {
    let mut data = minimal_prefix(0);

    // Corrupt storage mode byte
    data[6] = 0xFF;

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::UnsupportedStorageMode)));
}

/// Truncated magic must result in an I/O error
#[test]
fn truncated_magic_is_io_error() {
    let data = vec![0x56, 0x4C]; // "VL"

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::Io(_))));
}

/// Truncated version field must result in an I/O error
#[test]
fn truncated_version_is_io_error() {
    let data = b"VLT1\x01".to_vec();

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::Io(_))));
}

/// Truncated storage mode must result in an I/O error
#[test]
fn truncated_mode_is_io_error() {
    let data = b"VLT1\x01\x00".to_vec();

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::Io(_))));
}

/// Header length exceeding the maximum must be rejected
#[test]
fn oversized_header_is_rejected() {
    let mut data = Vec::new();

    data.extend_from_slice(b"VLT1");
    data.extend_from_slice(&1u16.to_le_bytes());
    data.push(StorageMode::Encrypted as u8);
    data.extend_from_slice(&(MAX_HEADER_LEN + 1).to_le_bytes());

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::HeaderTooLarge)));
}

/// Truncated header bytes must result in rejection
#[test]
fn truncated_header_bytes_is_rejected() {
    let mut data = Vec::new();

    data.extend_from_slice(b"VLT1");
    data.extend_from_slice(&1u16.to_le_bytes());
    data.push(StorageMode::Encrypted as u8);
    data.extend_from_slice(&4u32.to_le_bytes()); // header len = 4
    data.extend_from_slice(&[0xAA, 0xBB]); // truncated header

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(res.is_err());
    assert!(is_valid_rejection(res.as_ref().unwrap_err()));
}

/// Truncated payload length field must be rejected
#[test]
fn truncated_payload_len_is_rejected() {
    let mut data = minimal_prefix(0);

    // Remove last byte of payload_len
    data.pop();

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(res.is_err());
    assert!(is_valid_rejection(res.as_ref().unwrap_err()));
}

/// Truncated payload bytes must be rejected
#[test]
fn truncated_payload_bytes_is_rejected() {
    let mut data = minimal_prefix(10);

    // Provide fewer payload bytes than declared
    data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(res.is_err());
    assert!(is_valid_rejection(res.as_ref().unwrap_err()));
}

/// Trailing bytes after a well-formed payload must be rejected
///
/// # Note
/// Depending on where the parser detects the inconsistency, this may result
/// in `TrailingBytes` or another valid rejection error
#[test]
fn trailing_bytes_are_rejected() {
    let mut data = minimal_prefix(0);

    // Add trailing garbage
    data.push(0xDE);
    data.push(0xAD);

    let res = decode_vault_file(Cursor::new(data), None, 1024, false);

    assert!(res.is_err());
    assert!(is_valid_rejection(res.as_ref().unwrap_err()));
}

/// I/O errors from the reader must be propagated
#[test]
fn io_errors_are_propagated() {
    struct FailingReader;

    impl std::io::Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "boom"))
        }
    }

    let res = decode_vault_file(FailingReader, None, 1024, false);

    assert!(matches!(res, Err(VaultParseError::Io(_))));
}
