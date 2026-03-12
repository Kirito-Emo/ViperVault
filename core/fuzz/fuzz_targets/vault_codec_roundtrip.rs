#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for vault codec roundtrip behavior
//!
//! # Security
//! This target exercises both vault encoding and vault decoding using
//! structured-fuzz-derived inputs \
//! The objective is to ensure that codec paths remain panic-free and that
//! successful roundtrips preserve core invariants

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::vault::codec::{encode_vault_storage, MAX_VAULT_CONTAINER_PAYLOAD_LEN};
use vipervault_core::vault::{
    decode_vault_file, AeadSuite, CryptoHeader, KdfParams, StorageMode, VaultHeader, VaultStorage,
};

/// Build a deterministic header using fuzz-derived salt and nonce bytes
fn build_header(data: &[u8]) -> VaultHeader {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];

    for (idx, b) in data.iter().copied().enumerate().take(32) {
        salt[idx] = b;
    }

    for (idx, b) in data.iter().copied().skip(32).enumerate().take(24) {
        nonce[idx] = b;
    }

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
            salt,
            nonce,
        },
        duress: None,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let header = build_header(data);
    let format_version = if data.len() > 1 {
        u16::from_le_bytes([data[0], data[1]])
    } else {
        1
    };

    let mode_selector = data.first().copied().unwrap_or(0) & 0x01;
    let payload = if data.len() > 64 {
        &data[64..]
    } else {
        &[][..]
    };

    let storage = if mode_selector == 0 {
        VaultStorage::Encrypted {
            ciphertext: payload.to_vec(),
        }
    } else {
        VaultStorage::PlaintextJson {
            json: payload.to_vec(),
        }
    };

    let encoded = encode_vault_storage(&header, &storage, format_version);
    let Ok(encoded) = encoded else {
        return;
    };

    let allow_plaintext = matches!(storage, VaultStorage::PlaintextJson { .. });

    let decoded = decode_vault_file(
        Cursor::new(&encoded),
        Some(format_version),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        allow_plaintext,
    );

    let Ok(decoded) = decoded else {
        return;
    };

    assert_eq!(decoded.format_version, format_version);
    assert_eq!(decoded.header.schema_version, header.schema_version);

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
