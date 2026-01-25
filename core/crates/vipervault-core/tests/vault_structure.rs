// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use uuid::Uuid;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, SALT_LEN, StorageMode, VaultHeader, VaultPayload,
    VaultStorage, XCHACHA20_NONCE_LEN,
};

/// Basic construction invariants
#[test]
fn vault_types_construction() {
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

    let payload = VaultPayload {
        entries: b"hello".to_vec(),
    };

    let storage = VaultStorage::Encrypted {
        ciphertext: vec![1, 2, 3],
    };

    // Just ensure enums/types behave as expected
    let mode = match &storage {
        VaultStorage::Encrypted { .. } => StorageMode::Encrypted,
        VaultStorage::PlaintextJson { .. } => StorageMode::PlaintextJson,
    };

    assert_eq!(mode, StorageMode::Encrypted);
    assert_eq!(payload.entries, b"hello");
    assert_eq!(header.crypto.salt.len(), SALT_LEN);
    assert_eq!(header.crypto.nonce.len(), XCHACHA20_NONCE_LEN);
}

/// Header JSON roundtrip test
#[test]
fn header_json_roundtrip() {
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

    let bytes = serde_json::to_vec(&header).expect("serialize header");
    let decoded: VaultHeader = serde_json::from_slice(&bytes).expect("deserialize header");

    assert_eq!(decoded.schema_version, header.schema_version);
    assert_eq!(decoded.vault_id, header.vault_id);

    // Verify crypto fields survive roundtrip
    match decoded.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => {
            assert_eq!(mem_kib, 64 * 1024);
            assert_eq!(time_cost, 3);
            assert_eq!(lanes, 1);
        }
        _ => panic!("unexpected KDF variant"),
    }

    assert_eq!(decoded.crypto.salt, salt);
    assert_eq!(decoded.crypto.nonce, nonce);
}
