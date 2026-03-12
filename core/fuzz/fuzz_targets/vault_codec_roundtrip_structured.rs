#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Emanuele Relmi

//! Structure-aware fuzz target for vault codec roundtrip behaviour
//!
//! # Security
//! This target explores encode/decode invariants using bounded structured
//! inputs rather than fully random byte slices
//!
//! The target remains useful for:
//! - format version handling
//! - encrypted/plaintext branch selection
//! - payload preservation on successful roundtrip
//! - deterministic header construction for a fixed fuzz input

#[path = "support/structured.rs"]
mod structured;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use structured::{fill_fixed, SmallBytes};
use uuid::Uuid;
use vipervault_core::vault::{
    decode_vault_file, encode_vault_storage, AeadSuite, CryptoHeader, KdfParams, StorageMode,
    VaultHeader, VaultStorage, MAX_VAULT_CONTAINER_PAYLOAD_LEN,
};

/// Storage branch selector
#[derive(Debug, Clone, Copy, Arbitrary)]
enum StorageKind {
    /// Ciphertext branch
    Encrypted,
    /// Plaintext branch
    Plaintext,
}

/// Structured model for vault codec roundtrip testing
#[derive(Debug, Clone, Arbitrary)]
struct StructuredVaultCodecCase {
    /// Whether a zero format version is requested
    use_zero_format_version: bool,

    /// Storage branch selector
    storage_kind: StorageKind,

    /// Source bytes used to derive deterministic header fields
    header_material: SmallBytes,

    /// Payload material
    payload: SmallBytes,

    /// Whether plaintext decoding is allowed
    allow_plaintext_decode: bool,
}

impl StructuredVaultCodecCase {
    /// Convert the case into a deterministic header
    fn build_header(&self) -> VaultHeader {
        let salt = fill_fixed::<32>(&self.header_material.0);
        let nonce = fill_fixed::<24>(&self.header_material.0);
        let uuid_bytes = fill_fixed::<16>(&self.header_material.0);

        VaultHeader {
            schema_version: 1,
            vault_id: Uuid::from_bytes(uuid_bytes),
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
            duress: None,
        }
    }
}

fuzz_target!(|case: StructuredVaultCodecCase| {
    let header = case.build_header();
    let format_version = if case.use_zero_format_version { 0 } else { 1 };

    let storage = match case.storage_kind {
        StorageKind::Encrypted => VaultStorage::Encrypted {
            ciphertext: case.payload.0.clone(),
        },
        StorageKind::Plaintext => VaultStorage::PlaintextJson {
            json: case.payload.0.clone(),
        },
    };

    let Ok(encoded) = encode_vault_storage(&header, &storage, format_version) else {
        return;
    };

    let allow_plaintext =
        case.allow_plaintext_decode && matches!(storage, VaultStorage::PlaintextJson { .. });

    let Ok(decoded) = decode_vault_file(
        Cursor::new(&encoded),
        Some(format_version),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        allow_plaintext,
    ) else {
        return;
    };

    assert_eq!(decoded.format_version, format_version);
    assert_eq!(decoded.header.schema_version, header.schema_version);
    assert_eq!(decoded.header.vault_id, header.vault_id);

    match storage {
        VaultStorage::Encrypted { ciphertext } => {
            assert_eq!(decoded.mode, StorageMode::Encrypted);
            assert_eq!(decoded.payload, ciphertext);
        }
        VaultStorage::PlaintextJson { json } => {
            assert_eq!(decoded.mode, StorageMode::PlaintextJson);
            assert_eq!(decoded.payload, json);
        }
    }
});
