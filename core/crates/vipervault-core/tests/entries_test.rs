// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entries functional + hardening tests
//!
//! # Scope
//! These tests validate the entry model and validation utilities:
//! - field validation (standard/border/edge/limit)
//! - rejection of control characters
//! - rejection of bidi/invisible Unicode controls (spoofing mitigation)
//! - password permissiveness (only bounded + non-empty)
//! - serde JSON roundtrip for `VaultEntry` (manual DTO-based serde)
//!
//! # Security
//! The entry layer is a primary input validation boundary. These tests ensure:
//! - memory DoS protection via hard size limits
//! - spoofing mitigation via Unicode control rejection
//! - secrets are serializable only through the intended DTO pathway

use secrecy::ExposeSecret;
use vipervault_core::entries::{
    EntryError, MAX_NOTE_LEN, MAX_PASSWORD_LEN, MAX_TITLE_LEN, MAX_USERNAME_LEN, VaultEntry,
    validate_note, validate_password, validate_title, validate_username,
};

/// Build a string of exactly `len` bytes (ASCII) for deterministic boundary tests
fn ascii_string_of_len(len: usize) -> String {
    "a".repeat(len)
}

/// A representative set of bidi/invisible control characters commonly used for spoofing
fn suspicious_unicode_samples() -> Vec<char> {
    vec![
        '\u{202E}', // RLO (Right-to-Left Override)
        '\u{202D}', // LRO
        '\u{202A}', // LRE
        '\u{2066}', // LRI
        '\u{2067}', // RLI
        '\u{2068}', // FSI
        '\u{2069}', // PDI
        '\u{200E}', // LRM
        '\u{200F}', // RLM
        '\u{061C}', // ALM
        '\u{200B}', // zero-width space
        '\u{200C}', // zero-width non-joiner
        '\u{200D}', // zero-width joiner
        '\u{FEFF}', // zero-width no-break space (BOM)
    ]
}

/// Title: empty must be rejected
#[test]
fn title_empty_rejected() {
    let res = validate_title("");
    assert!(matches!(res, Err(EntryError::EmptyField)));
}

/// Title: boundary length must be accepted; overflow must be rejected
#[test]
fn title_length_bounds_enforced() {
    let ok = ascii_string_of_len(MAX_TITLE_LEN);
    assert!(validate_title(&ok).is_ok());

    let too_big = ascii_string_of_len(MAX_TITLE_LEN + 1);
    assert!(matches!(
        validate_title(&too_big),
        Err(EntryError::FieldTooLarge)
    ));
}

/// Title: control characters must be rejected
#[test]
fn title_control_chars_rejected() {
    let res = validate_title("hello\nworld");
    assert!(matches!(res, Err(EntryError::ForbiddenChars)));

    let res2 = validate_title("hello\tworld");
    assert!(matches!(res2, Err(EntryError::ForbiddenChars)));

    let res3 = validate_title("hello\u{0000}world");
    assert!(matches!(res3, Err(EntryError::ForbiddenChars)));
}

/// Title: suspicious Unicode controls must be rejected
#[test]
fn title_suspicious_unicode_rejected() {
    for ch in suspicious_unicode_samples() {
        let s = format!("ok{ch}ok");
        let res = validate_title(&s);
        assert!(
            matches!(res, Err(EntryError::SuspiciousUnicode)),
            "expected SuspiciousUnicode for U+{:04X}",
            ch as u32
        );
    }
}

/// Username: empty must be rejected if provided
#[test]
fn username_empty_rejected() {
    let res = validate_username("");
    assert!(matches!(res, Err(EntryError::EmptyField)));
}

/// Username: boundary length must be accepted; overflow must be rejected
#[test]
fn username_length_bounds_enforced() {
    let ok = ascii_string_of_len(MAX_USERNAME_LEN);
    assert!(validate_username(&ok).is_ok());

    let too_big = ascii_string_of_len(MAX_USERNAME_LEN + 1);
    assert!(matches!(
        validate_username(&too_big),
        Err(EntryError::FieldTooLarge)
    ));
}

/// Username: control characters must be rejected
#[test]
fn username_control_chars_rejected() {
    let res = validate_username("user\nname");
    assert!(matches!(res, Err(EntryError::ForbiddenChars)));
}

/// Username: suspicious Unicode controls must be rejected
#[test]
fn username_suspicious_unicode_rejected() {
    for ch in suspicious_unicode_samples() {
        let s = format!("user{ch}name");
        let res = validate_username(&s);
        assert!(
            matches!(res, Err(EntryError::SuspiciousUnicode)),
            "expected SuspiciousUnicode for U+{:04X}",
            ch as u32
        );
    }
}

/// Note: empty must be rejected if provided
#[test]
fn note_empty_rejected() {
    let res = validate_note("");
    assert!(matches!(res, Err(EntryError::EmptyField)));
}

/// Note: boundary length must be accepted; overflow must be rejected
#[test]
fn note_length_bounds_enforced() {
    let ok = ascii_string_of_len(MAX_NOTE_LEN);
    assert!(validate_note(&ok).is_ok());

    let too_big = ascii_string_of_len(MAX_NOTE_LEN + 1);
    assert!(matches!(
        validate_note(&too_big),
        Err(EntryError::FieldTooLarge)
    ));
}

/// Note: control characters must be rejected
///
/// # Security
/// Even if some UIs might allow newlines, the current policy rejects all `is_control()`
/// characters to reduce spoofing and rendering ambiguities
#[test]
fn note_control_chars_rejected() {
    let res = validate_note("line1\nline2");
    assert!(matches!(res, Err(EntryError::ForbiddenChars)));
}

/// Note: suspicious Unicode controls must be rejected
#[test]
fn note_suspicious_unicode_rejected() {
    for ch in suspicious_unicode_samples() {
        let s = format!("note{ch}note");
        let res = validate_note(&s);
        assert!(
            matches!(res, Err(EntryError::SuspiciousUnicode)),
            "expected SuspiciousUnicode for U+{:04X}",
            ch as u32
        );
    }
}

/// Password: empty must be rejected
#[test]
fn password_empty_rejected() {
    let res = validate_password("");
    assert!(matches!(res, Err(EntryError::EmptyField)));
}

/// Password: boundary length must be accepted; overflow must be rejected
#[test]
fn password_length_bounds_enforced() {
    let ok = ascii_string_of_len(MAX_PASSWORD_LEN);
    assert!(validate_password(&ok).is_ok());

    let too_big = ascii_string_of_len(MAX_PASSWORD_LEN + 1);
    assert!(matches!(
        validate_password(&too_big),
        Err(EntryError::FieldTooLarge)
    ));
}

/// Password: must remain permissive w.r.t. characters (no forbidden-char checks)
///
/// # Security
/// Rejecting characters in passwords can reduce password entropy
/// The current policy is "bounded + non-empty" only
#[test]
fn password_allows_symbols_and_unicode() {
    let s = "p@ßw0rd✅🙂🔥/\\\t\r\n"; // includes controls; password validator must NOT reject controls by design
    // NOTE: current implementation only checks empty/len, so this is OK as long as length > 0
    let res = validate_password(s);
    assert!(res.is_ok());
}

/// Creating a password entry must validate title/username/password/note according to policy
#[test]
fn new_password_entry_validates_fields() {
    // Valid case
    let ok = VaultEntry::new_password(
        "Title".to_string(),
        Some("user".to_string()),
        "secret".to_string(),
        Some("note".to_string()),
    );
    assert!(ok.is_ok());

    // Invalid title
    let bad_title = VaultEntry::new_password(
        "".to_string(),
        Some("user".to_string()),
        "secret".to_string(),
        Some("note".to_string()),
    );
    assert!(matches!(bad_title, Err(EntryError::EmptyField)));

    // Invalid username (empty)
    let bad_user = VaultEntry::new_password(
        "Title".to_string(),
        Some("".to_string()),
        "secret".to_string(),
        Some("note".to_string()),
    );
    assert!(matches!(bad_user, Err(EntryError::EmptyField)));

    // Invalid note (empty)
    let bad_note = VaultEntry::new_password(
        "Title".to_string(),
        Some("user".to_string()),
        "secret".to_string(),
        Some("".to_string()),
    );
    assert!(matches!(bad_note, Err(EntryError::EmptyField)));

    // Invalid password (empty)
    let bad_pw = VaultEntry::new_password(
        "Title".to_string(),
        Some("user".to_string()),
        "".to_string(),
        Some("note".to_string()),
    );
    assert!(matches!(bad_pw, Err(EntryError::EmptyField)));
}

/// `VaultEntry` must roundtrip through JSON serde correctly
///
/// # Security
/// `VaultEntry` does not derive serde automatically; this test ensures the manual DTO-based
/// serde implementation is correct and stable
#[test]
fn vault_entry_json_roundtrip() {
    let entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "super-secret".to_string(),
        Some("note".to_string()),
    )
    .expect("entry");

    let json = serde_json::to_vec(&entry).expect("serialize entry");
    let decoded: VaultEntry = serde_json::from_slice(&json).expect("deserialize entry");

    // Metadata must roundtrip
    assert_eq!(decoded.meta.id, entry.meta.id);
    assert_eq!(decoded.meta.entry_type, entry.meta.entry_type);

    // Secret must roundtrip (exposed via method)
    assert_eq!(
        decoded.to_view().secret.expose_secret(),
        entry.to_view().secret.expose_secret()
    );
}
