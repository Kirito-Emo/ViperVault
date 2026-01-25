// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy enforcement tests
//!
//! # Scope
//! These tests verify that security policies are enforced at decode time,
//! not at the raw codec layer
//!
//! # Security
//! - Plaintext vaults must NOT be decodable unless explicitly allowed
//! - Codec primitives are NOT responsible for policy decisions

use std::io::Cursor;
use vipervault_core::vault::{
    VaultHeader, VaultParseError, VaultStorage, decode_vault_file, encode_vault_storage,
};

/// Plaintext vault decoding must be denied unless explicitly allowed
#[test]
fn plaintext_decode_denied_by_codec() {
    let header = VaultHeader {
        schema_version: 1,
        vault_id: uuid::Uuid::new_v4(),
        crypto: dummy_crypto_header(),
    };

    let storage = VaultStorage::PlaintextJson {
        json: b"{}".to_vec(),
    };

    let encoded = encode_vault_storage(&header, &storage, 1).expect("encode plaintext vault");

    let res = decode_vault_file(
        Cursor::new(encoded),
        None,
        1024,
        /* allow_plaintext = */ false,
    );

    assert!(matches!(res, Err(VaultParseError::PlaintextNotAllowed)));
}

/// Plaintext vault decoding is allowed only when explicitly requested
#[test]
fn plaintext_decode_allowed_when_flag_is_set() {
    let header = VaultHeader {
        schema_version: 1,
        vault_id: uuid::Uuid::new_v4(),
        crypto: dummy_crypto_header(),
    };

    let storage = VaultStorage::PlaintextJson {
        json: b"{}".to_vec(),
    };

    let encoded = encode_vault_storage(&header, &storage, 1).expect("encode plaintext vault");

    let res = decode_vault_file(
        Cursor::new(encoded),
        None,
        1024,
        /* allow_plaintext = */ true,
    );

    assert!(res.is_ok());
}

/// Minimal dummy crypto header for plaintext-only tests
fn dummy_crypto_header() -> vipervault_core::vault::CryptoHeader {
    vipervault_core::vault::CryptoHeader {
        kdf: vipervault_core::vault::KdfParams::Argon2id {
            mem_kib: 1,
            time_cost: 1,
            lanes: 1,
        },
        aead: vipervault_core::vault::AeadSuite::XChaCha20Poly1305,
        salt: [0u8; vipervault_core::vault::SALT_LEN],
        nonce: [0u8; vipervault_core::vault::XCHACHA20_NONCE_LEN],
    }
}
