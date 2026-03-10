// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entries hardening tests
//!
//! # Scope
//! These tests validate safe rejection of malformed or adversarial entry inputs:
//! - malformed JSON
//! - missing required fields
//! - invalid enum/type representations
//! - oversized user-controlled fields
//! - spoofing-oriented Unicode controls
//!
//! # Security
//! These tests ensure that deserialization and validation reject malformed
//! entries without panics and without constructing inconsistent objects.

use vipervault_core::entries::{
    EntryError, MAX_NOTE_LEN, MAX_PASSWORD_LEN, MAX_TITLE_LEN, VaultEntry,
};

/// Invalid JSON must be rejected
#[test]
fn invalid_json_is_rejected() {
    let data = br#"{"invalid": true}"#;

    let res: Result<VaultEntry, _> = serde_json::from_slice(data);
    assert!(res.is_err());
}

/// Random bytes must be rejected
#[test]
fn random_bytes_are_rejected() {
    let data = vec![0xAA, 0xBB, 0xCC, 0xDD];

    let res: Result<VaultEntry, _> = serde_json::from_slice(&data);
    assert!(res.is_err());
}

/// Missing mandatory fields must be rejected
#[test]
fn missing_fields_are_rejected() {
    let data = br#"{"title":"test"}"#;

    let res: Result<VaultEntry, _> = serde_json::from_slice(data);
    assert!(res.is_err());
}

/// Invalid type representation must be rejected
#[test]
fn invalid_type_representation_is_rejected() {
    let data = br#"{
        "meta": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "entry_type": "NotARealType"
        },
        "title": "x",
        "secret": "y"
    }"#;

    let res: Result<VaultEntry, _> = serde_json::from_slice(data);
    assert!(res.is_err());
}

/// Oversized title must be rejected by constructors
#[test]
fn oversized_title_is_rejected() {
    let title = "a".repeat(MAX_TITLE_LEN + 1);

    let err = VaultEntry::new_secure_note(title, "secret".to_string()).unwrap_err();
    assert!(matches!(err, EntryError::FieldTooLarge));
}

/// Oversized password must be rejected by constructors
#[test]
fn oversized_password_is_rejected() {
    let password = "a".repeat(MAX_PASSWORD_LEN + 1);

    let err = VaultEntry::new_password(
        "Title".to_string(),
        Some("user".to_string()),
        password,
        Some("note".to_string()),
    )
    .unwrap_err();

    assert!(matches!(err, EntryError::FieldTooLarge));
}

/// Oversized note must be rejected by constructors
#[test]
fn oversized_note_is_rejected() {
    let note = "a".repeat(MAX_NOTE_LEN + 1);

    let err = VaultEntry::new_password(
        "Title".to_string(),
        Some("user".to_string()),
        "secret".to_string(),
        Some(note),
    )
    .unwrap_err();

    assert!(matches!(err, EntryError::FieldTooLarge));
}

/// Spoofing-oriented Unicode control characters must be rejected in title
#[test]
fn suspicious_unicode_in_title_is_rejected() {
    let err = VaultEntry::new_secure_note("hello\u{202E}world".to_string(), "secret".to_string())
        .unwrap_err();

    assert!(matches!(err, EntryError::SuspiciousUnicode));
}

/// Constructors must not panic on very large but validly allocated inputs
///
/// # Security
/// This documents safe failure under memory-DoS style user input
#[test]
fn very_large_input_fails_safely() {
    let huge = "a".repeat(MAX_TITLE_LEN.saturating_add(8192));

    let res = VaultEntry::new_secure_note(huge, "secret".to_string());
    assert!(res.is_err());
}
