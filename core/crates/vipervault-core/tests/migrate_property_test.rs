// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault migration property-style tests
//!
//! # Scope
//! These tests validate broader migration invariants across deterministic input
//! cases instead of relying only on a single fixed example
//!
//! Covered:
//! - migration preserves identity metadata across representative cases
//! - migration preserves primary payload semantics across representative cases
//! - migration preserves decoy payload semantics across representative cases
//! - migration always produces a duress-enabled encrypted vault
//! - migration rotates salts and nonces away from the legacy encrypted vault
//! - migrated vaults reject unrelated passwords across representative cases
//!
//! # Security
//! Migration is a sensitive re-encryption boundary \
//! These tests defend invariants that must remain stable across families of valid inputs

use std::io::Cursor;
use vipervault_core::core::{UnlockError, unlock_vault_with_outcome};
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_encrypted_vault};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::migrate::enable_duress_on_vault;
use vipervault_core::vault::{
    MAX_VAULT_CONTAINER_PAYLOAD_LEN, ParsedVaultFile, StorageMode, VaultFile, VaultPayload,
    decode_vault_file, encode_vault_storage,
};

/// Valid KDF policy accepted by the project security bounds
fn vault_kdf_policy() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Deterministic titles used to widen migration coverage
fn titles() -> &'static [&'static str] {
    &["alpha", "beta", "gamma", "prod-vault", "mfa-backup"]
}

/// Deterministic note bodies used to widen migration coverage
fn secrets() -> &'static [&'static str] {
    &["s1", "super-secret", "line1\\nline2", "0123456789abcdef"]
}

/// Build a payload with `count` deterministic secure-note entries
fn payload_with_entries(prefix: &str, count: usize) -> VaultPayload {
    let mut entries = Vec::with_capacity(count);

    for idx in 0..count {
        let title = format!("{prefix}-{}", titles()[idx % titles().len()]);
        let secret = format!("{prefix}-{}", secrets()[idx % secrets().len()]);

        let entry = VaultEntry::new_secure_note(title, secret).expect("entry");
        entries.push(entry);
    }

    VaultPayload { entries }
}

/// Encode and decode a vault file using the standard parser path
fn encode_decode(file: &VaultFile) -> ParsedVaultFile {
    let bytes = encode_vault_storage(&file.header, &file.storage, 1).expect("encode vault");
    decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode vault")
}

/// Representative migration cases
///
/// # Design
/// Each case performs multiple Argon2id derivations and full unlock checks for
/// both primary and decoy paths\
/// The matrix is intentionally small to keep test runtime bounded while still covering:
/// - empty primary and decoy payloads
/// - asymmetric primary/decoy payload sizes
/// - non-trivial multi-entry payloads
fn migration_cases() -> &'static [(usize, usize)] {
    &[(0, 0), (1, 2)]
}

/// Migration must preserve identity metadata and unlock semantics across a
/// representative bounded matrix
#[test]
fn migration_preserves_identity_and_unlock_semantics_matrix() {
    for &(primary_count, decoy_count) in migration_cases() {
        let primary_pw = MasterPassword::new(format!("primary-{primary_count}-{decoy_count}"));
        let decoy_pw = MasterPassword::new(format!("decoy-{primary_count}-{decoy_count}"));

        let primary_payload = payload_with_entries("primary", primary_count);
        let decoy_payload = payload_with_entries("decoy", decoy_count);

        let legacy = create_encrypted_vault(&primary_pw, &primary_payload, 7, vault_kdf_policy())
            .expect("legacy");

        let original_vault_id = legacy.header.vault_id;
        let original_schema_version = legacy.header.schema_version;
        let original_primary_salt = legacy.header.crypto.salt;
        let original_primary_nonce = legacy.header.crypto.nonce;

        let migrated = enable_duress_on_vault(
            &legacy,
            &primary_pw,
            &decoy_pw,
            &decoy_payload,
            vault_kdf_policy(),
        )
        .expect("migrate");

        assert_eq!(migrated.header.vault_id, original_vault_id);
        assert_eq!(migrated.header.schema_version, original_schema_version);
        assert!(migrated.header.duress.is_some());

        let parsed = encode_decode(&migrated);
        assert_eq!(parsed.mode, StorageMode::Encrypted);
        assert!(parsed.header.duress.is_some());

        let duress = parsed.header.duress.as_ref().expect("duress header");
        assert_ne!(parsed.header.crypto.salt, original_primary_salt);
        assert_ne!(parsed.header.crypto.nonce, original_primary_nonce);
        assert_ne!(duress.primary.salt, original_primary_salt);
        assert_ne!(duress.primary.nonce, original_primary_nonce);

        let (primary_outcome, primary_unlocked) =
            unlock_vault_with_outcome(&parsed, &primary_pw).expect("primary unlock");
        assert_eq!(primary_outcome, UnlockOutcome::Primary);
        assert_eq!(
            primary_unlocked.entries.len(),
            primary_payload.entries.len()
        );

        for (lhs, rhs) in primary_unlocked
            .entries
            .iter()
            .zip(primary_payload.entries.iter())
        {
            let lhs_view = lhs.to_view();
            let rhs_view = rhs.to_view();
            assert_eq!(lhs_view.expose_title(), rhs_view.expose_title());
            assert_eq!(lhs_view.expose_secret(), rhs_view.expose_secret());
        }

        let (decoy_outcome, decoy_unlocked) =
            unlock_vault_with_outcome(&parsed, &decoy_pw).expect("decoy unlock");
        assert_eq!(decoy_outcome, UnlockOutcome::Decoy);
        assert_eq!(decoy_unlocked.entries.len(), decoy_payload.entries.len());

        for (lhs, rhs) in decoy_unlocked
            .entries
            .iter()
            .zip(decoy_payload.entries.iter())
        {
            let lhs_view = lhs.to_view();
            let rhs_view = rhs.to_view();
            assert_eq!(lhs_view.expose_title(), rhs_view.expose_title());
            assert_eq!(lhs_view.expose_secret(), rhs_view.expose_secret());
        }
    }
}

/// Migration must reject unrelated passwords after re-encryption across a
/// representative bounded matrix
#[test]
fn migrated_vault_rejects_unrelated_password_matrix() {
    for &(primary_count, decoy_count) in migration_cases() {
        let primary_pw = MasterPassword::new(format!("primary-r-{primary_count}-{decoy_count}"));
        let decoy_pw = MasterPassword::new(format!("decoy-r-{primary_count}-{decoy_count}"));
        let wrong_pw = MasterPassword::new(format!("wrong-r-{primary_count}-{decoy_count}"));

        let primary_payload = payload_with_entries("primary-r", primary_count);
        let decoy_payload = payload_with_entries("decoy-r", decoy_count);

        let legacy = create_encrypted_vault(&primary_pw, &primary_payload, 1, vault_kdf_policy())
            .expect("legacy");

        let migrated = enable_duress_on_vault(
            &legacy,
            &primary_pw,
            &decoy_pw,
            &decoy_payload,
            vault_kdf_policy(),
        )
        .expect("migrate");

        let parsed = encode_decode(&migrated);
        let err = unlock_vault_with_outcome(&parsed, &wrong_pw).unwrap_err();
        assert!(matches!(err, UnlockError::AuthFailed));
    }
}
