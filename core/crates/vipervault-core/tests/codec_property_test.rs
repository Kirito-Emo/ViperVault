// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Codec property-style tests
//!
//! # Scope
//! These tests validate broader invariants of the vault container codec and the
//! signed backup codec using deterministic input matrices rather than single examples
//!
//! Covered:
//! - encrypted vault encode/decode roundtrip over multiple payload sizes
//! - format-version preservation across a version matrix
//! - trailing-byte rejection across multiple payload sizes
//! - duress + plaintext denial across multiple versions
//! - signed backup roundtrip over multiple payload sizes
//! - signed backup tamper detection over representative mutation offsets
//!
//! # Security
//! These tests aim to protect codec invariants that should remain true across
//! broad classes of input, not only for one or two fixed examples

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::backup::types::MAX_BACKUP_PAYLOAD_LEN;
use vipervault_core::backup::{
    BackupError, BackupKdfPolicy, decode_signed_backup, encode_signed_backup,
};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::codec::{MAX_VAULT_CONTAINER_PAYLOAD_LEN, encode_vault_storage};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, DualVaultHeader, KdfParams, StorageMode, VaultHeader, VaultParseError,
    VaultStorage, decode_vault_file,
};

/// Build a deterministic minimal header suitable for codec tests
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
            salt: [0x11; 32],
            nonce: [0x22; 24],
        },
        duress: None,
    }
}

/// Build a deterministic duress-enabled header
fn header_with_duress() -> VaultHeader {
    let primary = CryptoHeader {
        kdf: KdfParams::Argon2id {
            mem_kib: 64 * 1024,
            time_cost: 3,
            lanes: 1,
        },
        aead: AeadSuite::XChaCha20Poly1305,
        salt: [0x33; 32],
        nonce: [0x44; 24],
    };

    let decoy = CryptoHeader {
        kdf: KdfParams::Argon2id {
            mem_kib: 64 * 1024,
            time_cost: 3,
            lanes: 1,
        },
        aead: AeadSuite::XChaCha20Poly1305,
        salt: [0x55; 32],
        nonce: [0x66; 24],
    };

    VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: primary.clone(),
        duress: Some(DualVaultHeader { primary, decoy }),
    }
}

/// Standard decode helper for vault codec tests
fn decode_vault(
    bytes: &[u8],
    expected_version: u16,
) -> Result<vipervault_core::vault::ParsedVaultFile, VaultParseError> {
    decode_vault_file(
        Cursor::new(bytes),
        Some(expected_version),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
}

/// Deterministic test payload lengths used as a lightweight property matrix
fn payload_lengths() -> &'static [usize] {
    &[0, 1, 2, 7, 8, 31, 32, 63, 64, 255, 256, 1024]
}

/// Deterministic test format versions used as a lightweight property matrix
fn format_versions() -> &'static [u16] {
    &[1, 2, 7, 255, 1024, u16::MAX]
}

/// Deterministic test data generator
fn payload_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}

fn backup_kdf() -> BackupKdfPolicy {
    BackupKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Encrypted vault storage must roundtrip exactly across a payload-size and version matrix
#[test]
fn encrypted_vault_roundtrip_preserves_payload_and_version_matrix() {
    for &version in format_versions() {
        for &len in payload_lengths() {
            let header = header_minimal();
            let payload = payload_bytes(len);
            let storage = VaultStorage::Encrypted {
                ciphertext: payload.clone(),
            };

            let encoded = encode_vault_storage(&header, &storage, version).expect("encode");
            let parsed = decode_vault(&encoded, version).expect("decode");

            assert_eq!(parsed.format_version, version);
            assert_eq!(parsed.mode, StorageMode::Encrypted);
            assert_eq!(parsed.payload, payload);
            assert_eq!(parsed.header.schema_version, header.schema_version);
            assert_eq!(parsed.header.vault_id, header.vault_id);
            assert_eq!(parsed.header.crypto.salt, header.crypto.salt);
            assert_eq!(parsed.header.crypto.nonce, header.crypto.nonce);
            assert!(!parsed.header_bytes.is_empty());
        }
    }
}

/// Any trailing byte appended after a valid encrypted container must be rejected
#[test]
fn encrypted_vault_trailing_bytes_are_rejected_across_payload_matrix() {
    for &len in payload_lengths() {
        let header = header_minimal();
        let payload = payload_bytes(len);
        let storage = VaultStorage::Encrypted {
            ciphertext: payload,
        };

        let mut encoded = encode_vault_storage(&header, &storage, 1).expect("encode");
        encoded.push(0xAA);

        let err = decode_vault(&encoded, 1).unwrap_err();
        assert!(matches!(err, VaultParseError::TrailingBytes));
    }
}

/// Duress-enabled headers must never allow plaintext container encoding, across multiple versions
#[test]
fn duress_plaintext_export_is_denied_across_version_matrix() {
    let header = header_with_duress();
    let storage = VaultStorage::PlaintextJson {
        json: br#"{"entries":[]}"#.to_vec(),
    };

    for &version in format_versions() {
        let err = encode_vault_storage(&header, &storage, version).unwrap_err();
        assert!(matches!(err, VaultParseError::PlaintextNotAllowed));
    }
}

/// Signed backup encode/decode must preserve payload bytes exactly across a deterministic payload matrix
#[test]
fn signed_backup_roundtrip_preserves_exact_payload_matrix() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());

    for &len in &[0usize, 1, 2, 31, 32, 255, 256, 1024, 4096] {
        let payload = payload_bytes(len);

        let encoded =
            encode_signed_backup(policy, &password, &payload, backup_kdf()).expect("encode backup");
        let decoded = decode_signed_backup(policy, &password, &encoded).expect("decode backup");

        assert_eq!(decoded, payload);
        assert!(encoded.len() > payload.len());
    }
}

/// Representative mutations within a signed backup must never decode successfully to the original payload
#[test]
fn signed_backup_detects_representative_tampering_offsets() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let payload = payload_bytes(512);

    let encoded =
        encode_signed_backup(policy, &password, &payload, backup_kdf()).expect("encode backup");

    let candidate_offsets = [
        0usize,
        1,
        7,
        8,
        15,
        encoded.len() / 4,
        encoded.len() / 2,
        encoded.len().saturating_sub(70),
        encoded.len().saturating_sub(3),
        encoded.len().saturating_sub(1),
    ];

    for &offset in &candidate_offsets {
        if offset >= encoded.len() {
            continue;
        }

        let mut mutated = encoded.clone();
        mutated[offset] ^= 0x01;

        let result = decode_signed_backup(policy, &password, &mutated);
        assert!(result.is_err());

        if let Err(err) = result {
            assert!(matches!(
                err,
                BackupError::AuthFailed
                    | BackupError::InvalidFormat
                    | BackupError::Deserialize
                    | BackupError::UnsupportedVersion
            ));
        }
    }
}

/// Oversized signed backup payloads must be rejected at the boundary
#[test]
fn signed_backup_rejects_payload_above_hard_cap() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("pw".to_string());
    let oversized = vec![0u8; (MAX_BACKUP_PAYLOAD_LEN as usize) + 1];

    let err = encode_signed_backup(policy, &password, &oversized, backup_kdf()).unwrap_err();
    assert!(matches!(err, BackupError::PayloadTooLarge));
}
