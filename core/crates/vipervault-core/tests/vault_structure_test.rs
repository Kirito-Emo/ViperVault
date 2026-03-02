// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault structure tests
//!
//! # Scope
//! These tests validate structural invariants of the vault types:
//! - constant sizes (salt/nonce/magic/header bounds)
//! - enum discriminants for storage mode (wire compatibility)
//! - serde roundtrip for `VaultHeader` and `VaultPayload`
//! - header "minimal metadata" shape (keys present, no unexpected omissions)
//!
//! # Security
//! These invariants are important because they define the on-disk and in-memory trust boundary.
//! A regression in these constants or discriminants can break compatibility or weaken hardening.

use secrecy::ExposeSecret;
use serde_json::Value;
use uuid::Uuid;
use vipervault_core::entries::VaultEntry;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, MAX_HEADER_LEN, SALT_LEN, StorageMode, VaultHeader,
    VaultPayload, XCHACHA20_NONCE_LEN,
};

/// Salt length must remain 32 bytes
#[test]
fn salt_len_is_32() {
    assert_eq!(SALT_LEN, 32);
}

/// Nonce length must remain 24 bytes (XChaCha20-Poly1305)
#[test]
fn nonce_len_is_24() {
    assert_eq!(XCHACHA20_NONCE_LEN, 24);
}

/// Magic bytes must be 4 bytes and match expected literal
#[test]
fn magic_is_expected() {
    assert_eq!(MAGIC.len(), 4);
    assert_eq!(&MAGIC, b"VLT1");
}

/// Header length bound must remain strict (defense-in-depth)
#[test]
fn header_len_bound_is_reasonable() {
    const _: () = {
        // Current policy is 4096 bytes
        assert!(MAX_HEADER_LEN > 0);
        assert!(MAX_HEADER_LEN <= 4096);
    };
}

/// Storage mode discriminants must remain stable for file format compatibility
#[test]
fn storage_mode_discriminants_are_stable() {
    assert_eq!(StorageMode::Encrypted as u8, 1);
    assert_eq!(StorageMode::PlaintextJson as u8, 2);
}

/// VaultHeader must roundtrip via serde JSON
#[test]
fn vault_header_json_roundtrip() {
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
            salt: [7u8; SALT_LEN],
            nonce: [9u8; XCHACHA20_NONCE_LEN],
        },
    };

    let json = serde_json::to_vec(&header).expect("serialize header");
    let decoded: VaultHeader = serde_json::from_slice(&json).expect("deserialize header");

    assert_eq!(decoded.schema_version, header.schema_version);
    assert_eq!(decoded.vault_id, header.vault_id);

    // Crypto header must roundtrip
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
        _ => panic!("unsupported kdf algorithm"),
    }
}

/// VaultHeader serialized JSON must contain the expected top-level keys
///
/// # Security
/// Ensures the header remains minimal but structurally complete for unlocking
#[test]
fn vault_header_contains_expected_keys() {
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
            salt: [0u8; SALT_LEN],
            nonce: [0u8; XCHACHA20_NONCE_LEN],
        },
    };

    let v: Value = serde_json::to_value(&header).expect("to value");
    let obj = v.as_object().expect("header must be object");

    assert!(obj.contains_key("schema_version"));
    assert!(obj.contains_key("vault_id"));
    assert!(obj.contains_key("crypto"));

    // Crypto object must contain required keys
    let crypto = obj.get("crypto").unwrap().as_object().unwrap();
    assert!(crypto.contains_key("kdf"));
    assert!(crypto.contains_key("aead"));
    assert!(crypto.contains_key("salt"));
    assert!(crypto.contains_key("nonce"));
}

/// VaultPayload must roundtrip, including entries with secrets
#[test]
fn vault_payload_json_roundtrip_with_entry() {
    let entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "super-secret".to_string(),
        Some("note".to_string()),
    )
    .expect("entry");

    let payload = VaultPayload {
        entries: vec![entry],
    };

    let json = serde_json::to_vec(&payload).expect("serialize payload");
    let decoded: VaultPayload = serde_json::from_slice(&json).expect("deserialize payload");

    assert_eq!(decoded.entries.len(), 1);
    assert_eq!(
        decoded.entries[0].to_view().secret.expose_secret(),
        "super-secret"
    );
}
