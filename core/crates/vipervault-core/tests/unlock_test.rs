// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Unlock functional tests
//!
//! # Scope
//! These tests validate the functional correctness of the unlock flow:
//! - correct password unlocks the vault
//! - wrong password fails with `AuthFailed`
//! - tampering is detected (ciphertext/AAD mismatch => `AuthFailed`)
//! - invalid plaintext JSON produces `PayloadDecode`
//! - non-encrypted mode is rejected
//! - duress vaults unlock to either Primary or Decoy depending on the password
//!
//! # Security
//! The unlock API must not leak whether a failure was due to a wrong password
//! or to tampering; both must map to `AuthFailed`

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::core::{
    UnlockError, unlock_vault, unlock_vault_to_plaintext_json, unlock_vault_with_outcome,
};
use vipervault_core::crypto::aead::{encrypt_xchacha20poly1305, generate_xchacha20_nonce};
use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_duress_vault};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, MAX_VAULT_CONTAINER_PAYLOAD_LEN, ParsedVaultFile,
    StorageMode, VaultHeader, VaultPayload, decode_vault_file,
};

/// Build an encrypted vault container where AEAD AAD is exactly the stored `header_bytes`
///
/// # Security
/// This function constructs the container manually to guarantee that:
/// - AAD used for encryption matches the exact header bytes stored in the file
/// - tests do not rely on JSON re-serialization equivalence
fn build_encrypted_container_bytes(
    header: &VaultHeader,
    payload_plaintext: &[u8],
    password: &MasterPassword,
) -> Vec<u8> {
    let header_bytes = serde_json::to_vec(header).expect("header serialize");

    let (mem_kib, time_cost, lanes) = match header.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
        _ => unreachable!("unsupported KDF params in tests"),
    };

    let master_key =
        derive_master_key_from_password(password, &header.crypto.salt, mem_kib, time_cost, lanes)
            .expect("kdf");

    let ct = encrypt_xchacha20poly1305(
        &master_key,
        &header.crypto.nonce,
        payload_plaintext,
        &header_bytes,
    )
    .expect("encrypt");

    // Container format:
    // MAGIC (4)
    // FORMAT_VERSION (u16)
    // STORAGE_MODE (u8)
    // HEADER_LEN (u32)
    // HEADER_JSON bytes
    // PAYLOAD_LEN (u64)
    // PAYLOAD bytes
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(StorageMode::Encrypted as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

fn sample_payload(entry_id: Uuid) -> VaultPayload {
    let entry = VaultEntry::new_secure_note("note".to_string(), "secret".to_string())
        .expect("entry create");

    // Force a stable ID for assertions
    let mut entry = entry;
    entry.meta.id = entry_id;

    VaultPayload {
        entries: vec![entry],
    }
}

/// Correct password unlocks
#[test]
fn unlock_success_correct_password() {
    let password = MasterPassword::new("correct horse battery staple".to_string());
    let entry_id = Uuid::new_v4();
    let payload = sample_payload(entry_id);
    let payload_json = serde_json::to_vec(&payload).expect("payload json");
    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let unlocked = unlock_vault(&parsed, &password).expect("unlock");
    assert_eq!(unlocked.entries.len(), 1);
    assert_eq!(unlocked.entries[0].meta.id, entry_id);
}

/// Wrong password fails with `AuthFailed`
#[test]
fn unlock_fails_wrong_password() {
    let password = MasterPassword::new("correct horse battery staple".to_string());
    let wrong = MasterPassword::new("wrong password".to_string());
    let entry_id = Uuid::new_v4();
    let payload = sample_payload(entry_id);
    let payload_json = serde_json::to_vec(&payload).expect("payload json");
    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let err = unlock_vault(&parsed, &wrong).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Tampering of ciphertext produces `AuthFailed`
#[test]
fn unlock_fails_on_ciphertext_tamper() {
    let password = MasterPassword::new("pw".to_string());
    let payload = sample_payload(Uuid::new_v4());
    let payload_json = serde_json::to_vec(&payload).expect("payload json");
    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
        duress: None,
    };

    let mut bytes = build_encrypted_container_bytes(&header, &payload_json, &password);

    // Flip one byte inside payload bytes (near the end) to simulate tampering
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Tampering of AAD (header bytes) produces `AuthFailed`
#[test]
fn unlock_fails_on_header_aad_tamper() {
    let password = MasterPassword::new("pw".to_string());
    let payload = sample_payload(Uuid::new_v4());
    let payload_json = serde_json::to_vec(&payload).expect("payload json");
    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let mut parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    // Flip a byte in header_bytes (AAD) without changing the actual serialized header in the container
    // This simulates an in-memory AAD mismatch
    parsed.header_bytes[0] ^= 0x01;

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Invalid plaintext JSON produces `PayloadDecode`
#[test]
fn unlock_fails_on_invalid_payload_json() {
    let password = MasterPassword::new("pw".to_string());
    let payload_json = br#"{"not":"an array"}"#.to_vec(); // Payload bytes are NOT a valid JSON structure of `VaultPayload`
    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::PayloadDecode));
}

/// Non-encrypted mode is rejected by unlock API
#[test]
fn unlock_rejects_non_encrypted_mode() {
    let password = MasterPassword::new("pw".to_string());

    let parsed = ParsedVaultFile {
        format_version: 1,
        header: VaultHeader {
            schema_version: 1,
            vault_id: Uuid::new_v4(),
            crypto: CryptoHeader {
                kdf: KdfParams::Argon2id {
                    mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                    time_cost: DEFAULT_ARGON2ID_TIME_COST,
                    lanes: DEFAULT_ARGON2ID_LANES,
                },
                aead: AeadSuite::XChaCha20Poly1305,
                salt: generate_vault_salt().expect("salt"),
                nonce: generate_xchacha20_nonce().expect("nonce"),
            },
            duress: None,
        },
        header_bytes: b"{}".to_vec(),
        mode: StorageMode::PlaintextJson,
        payload: br#"[]"#.to_vec(),
    };

    let err = unlock_vault_to_plaintext_json(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Duress vault unlocks to Primary payload with the primary password
#[test]
fn duress_unlock_primary_password() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());
    let primary_payload = sample_payload(Uuid::new_v4());
    let decoy_payload = sample_payload(Uuid::new_v4());

    let kdf = VaultKdfPolicy {
        mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
        time_cost: DEFAULT_ARGON2ID_TIME_COST,
        lanes: DEFAULT_ARGON2ID_LANES,
    };

    let vf = create_duress_vault(
        &primary_pw,
        &decoy_pw,
        &primary_payload,
        &decoy_payload,
        1,
        kdf,
    )
    .expect("create duress vault");

    let bytes = vipervault_core::vault::codec::encode_vault_storage(&vf.header, &vf.storage, 1)
        .expect("encode");
    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let (outcome, unlocked) = unlock_vault_with_outcome(&parsed, &primary_pw).expect("unlock");
    assert!(matches!(outcome, UnlockOutcome::Primary));
    assert_eq!(unlocked.entries.len(), primary_payload.entries.len());
    assert_eq!(
        unlocked.entries[0].meta.id,
        primary_payload.entries[0].meta.id
    );
}

/// Duress vault unlocks to Decoy payload with the decoy password
#[test]
fn duress_unlock_decoy_password() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());
    let primary_payload = sample_payload(Uuid::new_v4());
    let decoy_payload = sample_payload(Uuid::new_v4());

    let kdf = VaultKdfPolicy {
        mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
        time_cost: DEFAULT_ARGON2ID_TIME_COST,
        lanes: DEFAULT_ARGON2ID_LANES,
    };

    let vf = create_duress_vault(
        &primary_pw,
        &decoy_pw,
        &primary_payload,
        &decoy_payload,
        1,
        kdf,
    )
    .expect("create duress vault");

    let bytes = vipervault_core::vault::codec::encode_vault_storage(&vf.header, &vf.storage, 1)
        .expect("encode");
    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let (outcome, unlocked) = unlock_vault_with_outcome(&parsed, &decoy_pw).expect("unlock");
    assert!(matches!(outcome, UnlockOutcome::Decoy));
    assert_eq!(unlocked.entries.len(), decoy_payload.entries.len());
    assert_eq!(
        unlocked.entries[0].meta.id,
        decoy_payload.entries[0].meta.id
    );
}

/// Boundary: an encrypted vault with an empty payload should unlock to an empty list
#[test]
fn unlock_empty_payload_is_ok() {
    let password = MasterPassword::new("pw".to_string());
    let payload = VaultPayload { entries: vec![] };
    let payload_json = serde_json::to_vec(&payload).expect("payload json");
    let salt = generate_vault_salt().expect("salt");
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt,
            nonce,
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    let unlocked = unlock_vault(&parsed, &password).expect("unlock");
    assert!(unlocked.entries.is_empty());
}

/// Attack: corrupted JSON envelope in duress mode must fail with `PayloadDecode` (not panic)
#[test]
fn duress_envelope_corrupted_json_is_payload_decode() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());
    let primary_payload = sample_payload(Uuid::new_v4());
    let decoy_payload = sample_payload(Uuid::new_v4());

    let kdf = VaultKdfPolicy {
        mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
        time_cost: DEFAULT_ARGON2ID_TIME_COST,
        lanes: DEFAULT_ARGON2ID_LANES,
    };

    let vf = create_duress_vault(
        &primary_pw,
        &decoy_pw,
        &primary_payload,
        &decoy_payload,
        1,
        kdf,
    )
    .expect("create duress vault");

    let bytes = vipervault_core::vault::codec::encode_vault_storage(&vf.header, &vf.storage, 1)
        .expect("encode");
    let mut parsed = decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode");

    // Overwrite the envelope with invalid JSON
    parsed.payload = b"{not-json".to_vec();

    let err = unlock_vault(&parsed, &primary_pw).unwrap_err();
    assert!(matches!(err, UnlockError::PayloadDecode));
}
