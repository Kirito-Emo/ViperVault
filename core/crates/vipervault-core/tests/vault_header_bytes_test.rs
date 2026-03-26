// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault header byte-preservation tests
//!
//! # Purpose
//! These tests verify that the raw header bytes stored in the parsed vault file
//! are preserved exactly as encoded in the container, because they are later
//! used as AEAD associated data
//!
//! # Security
//! The parser must retain the exact serialized header bytes from the container \
//! Re-serializing the parsed header object for AAD would be incorrect because
//! even semantically equivalent JSON could differ at the byte level

use uuid::Uuid;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, ParsedVaultFile, StorageMode, VaultHeader, VaultStorage,
    decode_vault_file, encode_vault_storage,
};

/// Build a minimal encrypted vault header for testing
///
/// # Security
/// The header contents are non-secret, but they are integrity-critical because
/// they are authenticated as AEAD AAD
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
            salt: [7u8; 32],
            nonce: [9u8; 24],
        },
        duress: None,
    }
}

/// Decode a container and return the parsed representation
///
/// # Errors
/// Panics on test failures
fn decode(encoded: &[u8]) -> ParsedVaultFile {
    decode_vault_file(encoded, Some(1), 1024 * 1024, false).expect("decode vault file")
}

/// Encoded and decoded raw header bytes must match exactly
#[test]
fn parsed_header_bytes_match_encoded_header_bytes_exactly() {
    let header = sample_header();
    let storage = VaultStorage::Encrypted {
        ciphertext: vec![1, 2, 3, 4, 5],
    };

    let encoded = encode_vault_storage(&header, &storage, 1).expect("encode vault");
    let parsed = decode(&encoded);

    let expected_header_bytes = serde_json::to_vec(&header).expect("serialize header");

    assert_eq!(parsed.mode, StorageMode::Encrypted);
    assert_eq!(parsed.header_bytes, expected_header_bytes);
}

/// Parsed header bytes must equal the original raw byte slice stored in the container
///
/// # Security
/// This verifies that the parser preserves the exact on-disk bytes rather than
/// reconstructing them from the parsed header object
#[test]
fn parsed_header_bytes_are_the_original_container_slice() {
    let header = sample_header();
    let storage = VaultStorage::Encrypted {
        ciphertext: vec![8, 9, 10],
    };

    let encoded = encode_vault_storage(&header, &storage, 1).expect("encode vault");

    let header_len_offset = 4 + 2 + 1;
    let header_len = u32::from_le_bytes(
        encoded[header_len_offset..header_len_offset + 4]
            .try_into()
            .expect("header length bytes"),
    ) as usize;

    let header_start = header_len_offset + 4;
    let header_end = header_start + header_len;
    let raw_header_slice = &encoded[header_start..header_end];

    let parsed = decode(&encoded);

    assert_eq!(parsed.header_bytes.as_slice(), raw_header_slice);
}

/// The decoded header object must remain semantically equal to the original
/// header while `header_bytes` preserves the exact serialized representation
#[test]
fn parsed_header_object_matches_original_header() {
    let header = sample_header();
    let storage = VaultStorage::Encrypted {
        ciphertext: vec![42, 43, 44],
    };

    let encoded = encode_vault_storage(&header, &storage, 1).expect("encode vault");
    let parsed = decode(&encoded);

    assert_eq!(parsed.header.schema_version, header.schema_version);
    assert_eq!(parsed.header.vault_id, header.vault_id);
    assert!(matches!(
        parsed.header.crypto.aead,
        AeadSuite::XChaCha20Poly1305
    ));

    match (&parsed.header.crypto.kdf, &header.crypto.kdf) {
        (
            KdfParams::Argon2id {
                mem_kib: pm,
                time_cost: pt,
                lanes: pl,
            },
            KdfParams::Argon2id {
                mem_kib: hm,
                time_cost: ht,
                lanes: hl,
            },
        ) => {
            assert_eq!(pm, hm);
            assert_eq!(pt, ht);
            assert_eq!(pl, hl);
        }
        _ => panic!("unexpected KDF variant mismatch"),
    }

    assert_eq!(parsed.header.crypto.salt, header.crypto.salt);
    assert_eq!(parsed.header.crypto.nonce, header.crypto.nonce);
    assert!(parsed.header.duress.is_none());
}
