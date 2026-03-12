// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault storage tests
//!
//! # Scope
//! These tests validate storage helpers and end-to-end byte persistence through
//! the vault codec layer
//!
//! Covered:
//! - encoded bytes survive write/read roundtrip
//! - decoded payload matches stored ciphertext/plaintext bytes
//! - trailing corruption is rejected after readback
//! - atomic write creates missing files
//! - atomic overwrite replaces previous bytes exactly
//! - public locked read observes exact persisted bytes
//!
//! # Security
//! Storage roundtrips must preserve bytes exactly. Silent corruption, truncation or
//! partial writes would undermine authenticated decryption and vault integrity

use std::io::Cursor;
use tempfile::tempdir;
use uuid::Uuid;
use vipervault_core::vault::codec::encode_vault_storage;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAX_VAULT_CONTAINER_PAYLOAD_LEN, StorageMode, VaultHeader,
    VaultParseError, VaultStorage, decode_vault_file, read_vault_locked, write_vault_atomic,
};

fn header_minimal() -> VaultHeader {
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
            salt: [0u8; 32],
            nonce: [0u8; 24],
        },
        duress: None,
    }
}

/// Encrypted storage bytes must survive file write/read roundtrip
#[test]
fn encrypted_storage_file_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("vault.bin");

    let header = header_minimal();
    let ciphertext = vec![1u8, 2, 3, 4, 5, 6];
    let storage = VaultStorage::Encrypted {
        ciphertext: ciphertext.clone(),
    };

    let encoded = encode_vault_storage(&header, &storage, 1).expect("encode");
    write_vault_atomic(&path, &encoded).expect("atomic write");

    let readback = read_vault_locked(&path).expect("locked read");
    assert_eq!(readback, encoded);

    let parsed = decode_vault_file(
        Cursor::new(readback),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    assert_eq!(parsed.mode, StorageMode::Encrypted);
    assert_eq!(parsed.payload, ciphertext);
}

/// Plaintext storage, when allowed by policy, must survive file write/read roundtrip
#[test]
fn plaintext_storage_file_roundtrip_when_allowed() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("vault-plaintext.bin");

    let header = header_minimal();
    let json = br#"{"test":true}"#.to_vec();
    let storage = VaultStorage::PlaintextJson { json: json.clone() };

    let encoded = encode_vault_storage(&header, &storage, 1);

    match encoded {
        Ok(bytes) => {
            write_vault_atomic(&path, &bytes).expect("atomic write");
            let readback = read_vault_locked(&path).expect("locked read");

            let parsed = decode_vault_file(
                Cursor::new(readback),
                Some(1),
                MAX_VAULT_CONTAINER_PAYLOAD_LEN,
                true,
            );

            assert!(parsed.is_ok() || matches!(parsed, Err(VaultParseError::PlaintextNotAllowed)));

            if let Ok(parsed) = parsed {
                assert_eq!(parsed.mode, StorageMode::PlaintextJson);
                assert_eq!(parsed.payload, json);
            }
        }
        Err(VaultParseError::PlaintextNotAllowed) => {
            // Valid under soft policy
        }
        Err(e) => panic!("unexpected encode error: {e:?}"),
    }
}

/// Trailing corruption after persisted bytes must be rejected after readback
#[test]
fn persisted_trailing_corruption_is_rejected() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("vault-corrupt.bin");

    let header = header_minimal();
    let storage = VaultStorage::Encrypted {
        ciphertext: vec![7u8, 8, 9],
    };

    let mut encoded = encode_vault_storage(&header, &storage, 1).expect("encode");
    encoded.extend_from_slice(&[0xAA, 0xBB]);

    write_vault_atomic(&path, &encoded).expect("atomic write");
    let readback = read_vault_locked(&path).expect("locked read");

    let err = decode_vault_file(
        Cursor::new(readback),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .unwrap_err();

    assert!(matches!(err, VaultParseError::TrailingBytes));
}

/// Atomic write must create the target file when it does not already exist
#[test]
fn atomic_write_creates_missing_target_file() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("new-vault.bin");

    assert!(!path.exists());

    write_vault_atomic(&path, b"new-bytes").expect("atomic write");

    assert!(path.exists());
    assert_eq!(read_vault_locked(&path).expect("locked read"), b"new-bytes");
}

/// Atomic overwrite must replace previous bytes exactly
#[test]
fn atomic_write_replaces_existing_bytes_exactly() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("vault.bin");

    write_vault_atomic(&path, b"first-version").expect("first write");
    write_vault_atomic(&path, b"second-version").expect("second write");

    let readback = read_vault_locked(&path).expect("locked read");
    assert_eq!(readback, b"second-version");
}

/// Public locked read must observe the exact bytes persisted by the atomic writer
#[test]
fn atomic_write_and_locked_read_roundtrip_exact_bytes() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("vault.bin");
    let bytes = b"vault-container-bytes";

    write_vault_atomic(&path, bytes).expect("atomic write");
    let readback = read_vault_locked(&path).expect("locked read");

    assert_eq!(readback, bytes);
}
