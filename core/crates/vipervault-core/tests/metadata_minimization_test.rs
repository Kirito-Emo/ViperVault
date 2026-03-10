// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Metadata minimization tests
//!
//! # Scope
//! These tests validate that encrypted vault containers do not leak entry content
//! through plaintext metadata and that sensitive user data remains confined to
//! the encrypted payload
//!
//! Covered:
//! - encoded encrypted container must not expose entry titles
//! - encoded encrypted container must not expose usernames
//! - encoded encrypted container must not expose secrets
//! - encoded encrypted container must still expose only the necessary header fields
//!
//! # Security
//! Protects against offline metadata scraping from stolen vault files
//! Only the minimal unlock metadata (format/version/crypto params/vault_id) should be visible

use std::str;
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_duress_vault, create_encrypted_vault};
use vipervault_core::vault::{VaultPayload, encode_vault_storage};

fn make_payload() -> VaultPayload {
    let entry = VaultEntry::new_password(
        "GitHub Personal".to_string(),
        Some("octocat".to_string()),
        "super-secret-password".to_string(),
        Some("private note".to_string()),
    )
    .expect("entry");

    VaultPayload {
        entries: vec![entry],
    }
}

/// Encrypted container bytes must not reveal entry content strings
#[test]
fn encrypted_vault_does_not_leak_entry_content_in_plaintext() {
    let password = MasterPassword::new("pw".to_string());
    let payload = make_payload();

    let kdf = VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    };

    let vault = create_encrypted_vault(&password, &payload, 1, kdf).expect("create vault");
    let bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode");

    let haystack = String::from_utf8_lossy(&bytes);

    assert!(!haystack.contains("GitHub Personal"));
    assert!(!haystack.contains("octocat"));
    assert!(!haystack.contains("super-secret-password"));
    assert!(!haystack.contains("private note"));
}

/// Duress container must not reveal either primary or decoy entry content in plaintext
#[test]
fn duress_vault_does_not_leak_primary_or_decoy_content_in_plaintext() {
    let primary_pw = MasterPassword::new("primary".to_string());
    let decoy_pw = MasterPassword::new("decoy".to_string());

    let primary = VaultPayload {
        entries: vec![
            VaultEntry::new_password(
                "Primary title".to_string(),
                Some("primary-user".to_string()),
                "primary-secret".to_string(),
                Some("primary-note".to_string()),
            )
            .expect("primary entry"),
        ],
    };

    let decoy = VaultPayload {
        entries: vec![
            VaultEntry::new_password(
                "Decoy title".to_string(),
                Some("decoy-user".to_string()),
                "decoy-secret".to_string(),
                Some("decoy-note".to_string()),
            )
            .expect("decoy entry"),
        ],
    };

    let kdf = VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    };

    let vault = create_duress_vault(&primary_pw, &decoy_pw, &primary, &decoy, 1, kdf)
        .expect("create duress vault");

    let bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode");
    let haystack = String::from_utf8_lossy(&bytes);

    for needle in [
        "Primary title",
        "primary-user",
        "primary-secret",
        "primary-note",
        "Decoy title",
        "decoy-user",
        "decoy-secret",
        "decoy-note",
    ] {
        assert!(
            !haystack.contains(needle),
            "plaintext metadata leak detected for '{needle}'"
        );
    }
}

/// The encoded vault header must still contain the minimal structural metadata required for decoding
#[test]
fn encrypted_vault_still_contains_required_structural_metadata() {
    let password = MasterPassword::new("pw".to_string());
    let payload = VaultPayload { entries: vec![] };

    let kdf = VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    };

    let vault = create_encrypted_vault(&password, &payload, 1, kdf).expect("create vault");
    let bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode");

    let haystack = String::from_utf8_lossy(&bytes);

    // These are expected structural header keys, not user secrets
    assert!(haystack.contains("schema_version"));
    assert!(haystack.contains("vault_id"));
    assert!(haystack.contains("crypto"));
}

/// Boundary: even an empty payload must not introduce accidental user-content leakage
#[test]
fn empty_payload_vault_has_no_user_content_leakage() {
    let password = MasterPassword::new("pw".to_string());
    let payload = VaultPayload { entries: vec![] };

    let kdf = VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    };

    let vault = create_encrypted_vault(&password, &payload, 1, kdf).expect("create vault");
    let bytes = encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode");

    let haystack = str::from_utf8(&bytes).unwrap_or_default();

    assert!(!haystack.contains("entries"));
    assert!(!haystack.contains("secret"));
    assert!(!haystack.contains("title"));
    assert!(!haystack.contains("username"));
}
