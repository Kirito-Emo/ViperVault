// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault migration tests
//!
//! # Scope
//! These tests validate the migration path that converts a legacy encrypted vault
//! into a duress-enabled vault
//!
//! Covered scenarios:
//! - successful migration from legacy encrypted vault to duress-enabled vault
//! - preservation of `vault_id` and `schema_version`
//! - generation of a valid dual-unlock vault (primary + decoy)
//! - rejection of wrong primary password during migration
//! - rejection of plaintext vaults
//! - rejection of already-duress-enabled vaults
//! - rejection of corrupted legacy ciphertext
//!
//! # Security
//! Migration is a high-risk re-encryption boundary. These tests ensure that:
//! - legacy payload is decrypted only with the correct primary password
//! - fresh duress material is produced without losing identity metadata
//! - migrated vaults unlock correctly on both branches
//! - malformed or unsupported source vaults fail closed

use std::io::Cursor;
use vipervault_core::core::{UnlockError, unlock_vault_with_outcome};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_duress_vault, create_encrypted_vault};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::migrate::enable_duress_on_vault;
use vipervault_core::vault::{
    MAX_VAULT_CONTAINER_PAYLOAD_LEN, VaultFile, VaultParseError, VaultPayload, VaultStorage,
    decode_vault_file, encode_vault_storage,
};

fn vault_kdf() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

fn payload_with_note(title: &str, body: &str) -> VaultPayload {
    let entry = vipervault_core::entries::types::VaultEntry::new_secure_note(
        title.to_string(),
        body.to_string(),
    )
    .expect("entry");

    VaultPayload {
        entries: vec![entry],
    }
}

fn encode_decode(file: &VaultFile) -> vipervault_core::vault::ParsedVaultFile {
    let bytes = encode_vault_storage(&file.header, &file.storage, 1).expect("encode vault");
    decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode vault")
}

/// A legacy encrypted vault must migrate successfully to a duress-enabled vault
///
/// # Security
/// The migrated vault must preserve identity metadata while producing a valid
/// dual-unlock encrypted representation
#[test]
fn migrate_legacy_vault_to_duress_success() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());

    let primary_payload = payload_with_note("primary-title", "primary-secret");
    let decoy_payload = payload_with_note("decoy-title", "decoy-secret");

    let legacy =
        create_encrypted_vault(&primary_pw, &primary_payload, 7, vault_kdf()).expect("legacy");

    let original_vault_id = legacy.header.vault_id;
    let original_schema_version = legacy.header.schema_version;

    let migrated =
        enable_duress_on_vault(&legacy, &primary_pw, &decoy_pw, &decoy_payload, vault_kdf())
            .expect("migrate");

    assert_eq!(migrated.header.vault_id, original_vault_id);
    assert_eq!(migrated.header.schema_version, original_schema_version);
    assert!(migrated.header.duress.is_some());

    let parsed = encode_decode(&migrated);

    let (primary_outcome, primary_unlocked) =
        unlock_vault_with_outcome(&parsed, &primary_pw).expect("primary unlock");
    assert!(matches!(primary_outcome, UnlockOutcome::Primary));
    assert_eq!(primary_unlocked.entries.len(), 1);
    assert_eq!(
        primary_unlocked.entries[0].to_view().expose_title(),
        "primary-title"
    );
    assert_eq!(
        primary_unlocked.entries[0].to_view().expose_secret(),
        "primary-secret"
    );

    let (decoy_outcome, decoy_unlocked) =
        unlock_vault_with_outcome(&parsed, &decoy_pw).expect("decoy unlock");
    assert!(matches!(decoy_outcome, UnlockOutcome::Decoy));
    assert_eq!(decoy_unlocked.entries.len(), 1);
    assert_eq!(
        decoy_unlocked.entries[0].to_view().expose_title(),
        "decoy-title"
    );
    assert_eq!(
        decoy_unlocked.entries[0].to_view().expose_secret(),
        "decoy-secret"
    );
}

/// A wrong primary password must fail migration with coarse-grained `AuthFailed`
#[test]
fn migrate_rejects_wrong_primary_password() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let wrong_pw = MasterPassword::new("wrong-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());

    let primary_payload = payload_with_note("primary-title", "primary-secret");
    let decoy_payload = payload_with_note("decoy-title", "decoy-secret");

    let legacy =
        create_encrypted_vault(&primary_pw, &primary_payload, 1, vault_kdf()).expect("legacy");

    let err = enable_duress_on_vault(&legacy, &wrong_pw, &decoy_pw, &decoy_payload, vault_kdf())
        .unwrap_err();

    assert!(matches!(err, VaultParseError::AuthFailed));
}

/// Plaintext vaults must not be accepted as migration sources
#[test]
fn migrate_rejects_plaintext_vault() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());
    let decoy_payload = payload_with_note("decoy-title", "decoy-secret");

    let plaintext = VaultFile {
        header: create_encrypted_vault(
            &primary_pw,
            &payload_with_note("title", "secret"),
            1,
            vault_kdf(),
        )
        .expect("create header source")
        .header,
        storage: VaultStorage::PlaintextJson {
            json: br#"{"entries":[]}"#.to_vec(),
        },
    };

    let err = enable_duress_on_vault(
        &plaintext,
        &primary_pw,
        &decoy_pw,
        &decoy_payload,
        vault_kdf(),
    )
    .unwrap_err();

    assert!(matches!(err, VaultParseError::InvalidHeader));
}

/// Already-duress-enabled vaults must not be migrated again
#[test]
fn migrate_rejects_already_duress_enabled_vault() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());

    let primary_payload = payload_with_note("primary-title", "primary-secret");
    let decoy_payload = payload_with_note("decoy-title", "decoy-secret");

    let duress = create_duress_vault(
        &primary_pw,
        &decoy_pw,
        &primary_payload,
        &decoy_payload,
        1,
        vault_kdf(),
    )
    .expect("create duress");

    let err = enable_duress_on_vault(&duress, &primary_pw, &decoy_pw, &decoy_payload, vault_kdf())
        .unwrap_err();

    assert!(matches!(err, VaultParseError::InvalidHeader));
}

/// Corrupted legacy ciphertext must fail migration with coarse-grained `AuthFailed`
#[test]
fn migrate_rejects_corrupted_legacy_ciphertext() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());

    let primary_payload = payload_with_note("primary-title", "primary-secret");
    let decoy_payload = payload_with_note("decoy-title", "decoy-secret");

    let mut legacy =
        create_encrypted_vault(&primary_pw, &primary_payload, 1, vault_kdf()).expect("legacy");

    match &mut legacy.storage {
        VaultStorage::Encrypted { ciphertext } => {
            let last = ciphertext.len() - 1;
            ciphertext[last] ^= 0x01;
        }
        VaultStorage::PlaintextJson { .. } => unreachable!("legacy test vault must be encrypted"),
    }

    let err = enable_duress_on_vault(&legacy, &primary_pw, &decoy_pw, &decoy_payload, vault_kdf())
        .unwrap_err();

    assert!(matches!(err, VaultParseError::AuthFailed));
}

/// Migration must produce a vault that rejects unrelated passwords on both branches
///
/// # Security
/// Enabling duress must not weaken the no-oracle property of unlock
#[test]
fn migrated_vault_rejects_unrelated_password() {
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());
    let wrong_pw = MasterPassword::new("wrong-password".to_string());

    let primary_payload = payload_with_note("primary-title", "primary-secret");
    let decoy_payload = payload_with_note("decoy-title", "decoy-secret");

    let legacy =
        create_encrypted_vault(&primary_pw, &primary_payload, 1, vault_kdf()).expect("legacy");

    let migrated =
        enable_duress_on_vault(&legacy, &primary_pw, &decoy_pw, &decoy_payload, vault_kdf())
            .expect("migrate");

    let parsed = encode_decode(&migrated);

    let err = unlock_vault_with_outcome(&parsed, &wrong_pw).unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}
