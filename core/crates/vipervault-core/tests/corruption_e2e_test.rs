// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Integration test: real-world corruption end-to-end
//!
//! # Scope
//! This test verifies that single-byte corruptions in the stored vault file
//! (ciphertext or authenticated header bytes) are detected end-to-end
//!
//! Covered scenarios:
//! - ciphertext single-byte tampering => unlock returns `AuthFailed`
//! - header-bytes (AAD) whitespace tampering => decode succeeds but unlock returns `AuthFailed`
//!
//! # Security
//! Ensures no oracle exists between "wrong password" and "tampering":
//! both must map to `AuthFailed` at the unlock layer

use std::io::Cursor;
use uuid::Uuid;
use vipervault_core::core::{UnlockError, unlock_vault};
use vipervault_core::crypto::aead::encrypt_xchacha20poly1305;
use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, StorageMode, VaultHeader, VaultPayload,
    decode_vault_file,
};

/// Build an encrypted container manually, using pretty JSON header bytes
/// to guarantee there is whitespace that can be tampered while remaining valid JSON
///
/// # Security
/// AEAD AAD = exact stored `header_bytes`
fn build_container_with_pretty_header(
    header: &VaultHeader,
    payload_plaintext: &[u8],
    password: &MasterPassword,
) -> Vec<u8> {
    let header_bytes = serde_json::to_string_pretty(header)
        .expect("header pretty json")
        .into_bytes();

    let (mem_kib, time_cost, lanes) = match header.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
        _ => panic!("unsupported kdf algorithm"),
    };

    let key =
        derive_master_key_from_password(password, &header.crypto.salt, mem_kib, time_cost, lanes)
            .expect("kdf");

    let ct =
        encrypt_xchacha20poly1305(&key, &header.crypto.nonce, payload_plaintext, &header_bytes)
            .expect("encrypt");

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes()); // format_version=1
    out.push(StorageMode::Encrypted as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

fn make_header() -> VaultHeader {
    VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().unwrap(),
            nonce: [7u8; 24],
        },
    }
}

fn parse(bytes: &[u8]) -> vipervault_core::vault::ParsedVaultFile {
    decode_vault_file(Cursor::new(bytes), Some(1), 16 * 1024 * 1024, false).expect("decode")
}

#[test]
fn ciphertext_single_byte_tamper_is_detected_end_to_end() {
    let password = MasterPassword::new("pw".to_string());
    let header = make_header();

    let entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "super-secret".to_string(),
        Some("note".to_string()),
    )
    .unwrap();

    let payload = VaultPayload {
        entries: vec![entry],
    };
    let pt = serde_json::to_vec(&payload).unwrap();

    let mut file_bytes = build_container_with_pretty_header(&header, &pt, &password);

    // Flip one byte near the end (ciphertext region)
    if let Some(last) = file_bytes.last_mut() {
        *last ^= 0xFF;
    }

    let parsed = parse(&file_bytes);
    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

#[test]
fn header_whitespace_tamper_is_detected_end_to_end() {
    let password = MasterPassword::new("pw".to_string());
    let header = make_header();

    let payload = VaultPayload { entries: vec![] };
    let pt = serde_json::to_vec(&payload).unwrap();

    let mut file_bytes = build_container_with_pretty_header(&header, &pt, &password);

    // Locate a whitespace byte inside the header JSON and change it to another whitespace
    // This keeps JSON valid but changes AAD bytes => must fail authentication
    //
    // Look for '\n' and change it to ' '
    let mut changed = false;

    // Header begins after: MAGIC(4) + version(2) + mode(1) + header_len(4)
    let header_len_off = 4 + 2 + 1;
    let header_off = header_len_off + 4;
    let header_len = u32::from_le_bytes(
        file_bytes[header_len_off..header_len_off + 4]
            .try_into()
            .unwrap(),
    ) as usize;

    let hdr_slice = &mut file_bytes[header_off..header_off + header_len];
    for b in hdr_slice.iter_mut() {
        if *b == b'\n' {
            *b = b' ';
            changed = true;
            break;
        }
    }
    assert!(
        changed,
        "expected pretty JSON to contain newline whitespace"
    );

    let parsed = parse(&file_bytes);
    let err = unlock_vault(&parsed, &password).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}
