// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::vault::codec::{decode_vault_file, encode_vault_storage};
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, MAX_HEADER_LEN, SALT_LEN, StorageMode, VaultHeader,
    VaultParseError, VaultStorage, XCHACHA20_NONCE_LEN,
};

/// Encode -> decode should preserve header + mode + payload
#[test]
fn encode_decode_roundtrip_encrypted() {
    let salt = [7u8; SALT_LEN];
    let nonce = [9u8; XCHACHA20_NONCE_LEN];

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
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

    let ciphertext = vec![1, 2, 3, 4, 5];
    let storage = VaultStorage::Encrypted {
        ciphertext: ciphertext.clone(),
    };

    let format_version: u16 = 1;
    let bytes = encode_vault_storage(&header, &storage, format_version).expect("encode");

    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(format_version),
        1024 * 1024,
        false, // allow_plaintext
    )
    .expect("decode");

    assert_eq!(parsed.format_version, format_version);
    assert_eq!(parsed.mode, StorageMode::Encrypted);
    assert_eq!(parsed.header.vault_id, header.vault_id);
    assert_eq!(parsed.header.schema_version, header.schema_version);
    assert_eq!(parsed.header.crypto.salt, salt);
    assert_eq!(parsed.header.crypto.nonce, nonce);
    assert_eq!(parsed.payload, ciphertext);
}

/// Trailing bytes should be rejected
#[test]
fn rejects_trailing_bytes() {
    let salt = [0u8; SALT_LEN];
    let nonce = [0u8; XCHACHA20_NONCE_LEN];

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
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

    let storage = VaultStorage::Encrypted {
        ciphertext: vec![1, 2, 3],
    };
    let bytes = encode_vault_storage(&header, &storage, 1).expect("encode");

    let mut tampered = bytes.clone();
    tampered.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let err = decode_vault_file(Cursor::new(tampered), Some(1), 1024 * 1024, false)
        .expect_err("must fail");

    assert!(matches!(err, VaultParseError::TrailingBytes));
}

/// Plaintext mode must be rejected if `allow_plaintext = false`
#[test]
fn plaintext_not_allowed() {
    let salt = [1u8; SALT_LEN];
    let nonce = [2u8; XCHACHA20_NONCE_LEN];

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
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

    let storage = VaultStorage::PlaintextJson {
        json: br#"{"entries":[1,2,3]}"#.to_vec(),
    };
    let bytes = encode_vault_storage(&header, &storage, 1).expect("encode");

    let err =
        decode_vault_file(Cursor::new(bytes), Some(1), 1024 * 1024, false).expect_err("must fail");

    assert!(matches!(err, VaultParseError::PlaintextNotAllowed));
}

/// Invalid magic should be rejected
#[test]
fn invalid_magic() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"NOPE"); // wrong magic
    bytes.extend_from_slice(&1u16.to_le_bytes()); // version
    bytes.push(1u8); // mode encrypted
    bytes.extend_from_slice(&0u32.to_le_bytes()); // header_len
    bytes.extend_from_slice(&0u64.to_le_bytes()); // payload_len

    let err = decode_vault_file(Cursor::new(bytes), Some(1), 1024, false).expect_err("must fail");

    assert!(matches!(err, VaultParseError::InvalidMagic));
}

/// Header length over MAX_HEADER_LEN should be rejected (DoS guard)
#[test]
fn header_too_large() {
    // Construct a minimal valid prefix up to header_len
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&1u16.to_le_bytes()); // version
    bytes.push(1u8); // mode encrypted

    // header_len = MAX_HEADER_LEN + 1
    bytes.extend_from_slice(&(MAX_HEADER_LEN + 1).to_le_bytes());

    // No need to append header bytes: decoder will fail immediately on header_len check
    let err = decode_vault_file(Cursor::new(bytes), Some(1), 1024, false).expect_err("must fail");

    assert!(matches!(err, VaultParseError::HeaderTooLarge));
}
