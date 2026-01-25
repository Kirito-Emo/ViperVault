// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::vault::codec::{decode_vault_file, encode_vault_storage};
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, MAX_HEADER_LEN, SALT_LEN, VaultHeader,
    VaultParseError, VaultStorage, XCHACHA20_NONCE_LEN,
};

fn sample_header() -> VaultHeader {
    VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: 64 * 1024,
                time_cost: 3,
                lanes: 1,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: [7u8; SALT_LEN],
            nonce: [9u8; XCHACHA20_NONCE_LEN],
        },
    }
}

/// Empty payload should be allowed (represents an empty encrypted vault container)
#[test]
fn allows_zero_length_payload() {
    let header = sample_header();
    let storage = VaultStorage::Encrypted {
        ciphertext: Vec::new(),
    };

    let bytes = encode_vault_storage(&header, &storage, 1).expect("encode");

    let parsed =
        decode_vault_file(Cursor::new(bytes), Some(1), 1024 * 1024, false).expect("decode");
    assert!(parsed.payload.is_empty());
}

/// Header length = 0 should fail (JSON header cannot be empty)
#[test]
fn rejects_zero_length_header() {
    // Build container manually with header_len = 0, payload_len = 0
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC); // magic
    bytes.extend_from_slice(&1u16.to_le_bytes()); // version
    bytes.push(1u8); // mode: encrypted
    bytes.extend_from_slice(&0u32.to_le_bytes()); // header_len
    bytes.extend_from_slice(&0u64.to_le_bytes()); // payload_len

    let err = decode_vault_file(Cursor::new(bytes), Some(1), 1024, false).expect_err("must fail");
    assert!(matches!(err, VaultParseError::Deserialize));
}

/// Truncated header bytes must be rejected safely (no panic, no huge alloc)
#[test]
fn rejects_truncated_header_bytes() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(1u8);

    // header_len is small and under MAX, but we won't provide enough bytes
    bytes.extend_from_slice(&10u32.to_le_bytes());
    bytes.extend_from_slice(&[0x7Bu8; 3]); // only 3/10 bytes of header

    let err = decode_vault_file(Cursor::new(bytes), Some(1), 1024, false).expect_err("must fail");
    assert!(matches!(err, VaultParseError::Io(_)));
}

/// Truncated payload bytes must be rejected safely (declared payload_len > available bytes)
#[test]
fn rejects_truncated_payload_bytes() {
    let header = sample_header();
    let storage = VaultStorage::Encrypted {
        ciphertext: vec![1, 2, 3, 4, 5],
    };
    let mut bytes = encode_vault_storage(&header, &storage, 1).expect("encode");

    // Remove last 2 bytes => payload is now truncated
    bytes.truncate(bytes.len().saturating_sub(2));

    let err =
        decode_vault_file(Cursor::new(bytes), Some(1), 1024 * 1024, false).expect_err("must fail");
    assert!(matches!(err, VaultParseError::Io(_)));
}

/// Header length above MAX must be rejected immediately (DoS guard)
#[test]
fn rejects_header_len_over_max() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(1u8);
    bytes.extend_from_slice(&(MAX_HEADER_LEN + 1).to_le_bytes());

    let err = decode_vault_file(Cursor::new(bytes), Some(1), 1024, false).expect_err("must fail");
    assert!(matches!(err, VaultParseError::HeaderTooLarge));
}
