// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Interop import tests
//!
//! # Scope
//! These tests validate the plaintext interop quarantine and commit flow:
//! - valid otpauth import to quarantine
//! - decoy policy denial
//! - unsupported format rejection
//! - malformed URI rejection
//! - deduplication behavior
//! - commit into existing payload
//! - anti-DoS limits and invariant enforcement
//!
//! # Security
//! Interop import is the highest-risk parsing boundary because it accepts
//! plaintext, non-owned provider formats. These tests ensure that:
//! - policy gates are enforced
//! - malformed or oversized input is rejected
//! - duplicates are skipped deterministically
//! - only valid TOTP entries survive quarantine
//! - commit re-validates invariants and respects size limits

use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::{EntryType, VaultEntry};
use vipervault_core::import::{
    ImportError, ImportIntent, InteropFormat, commit_quarantined_import_into_payload,
    import_interop_quarantine,
};
use vipervault_core::vault::VaultPayload;
use vipervault_core::vault::duress::UnlockOutcome;

fn primary_policy() -> PolicyContext {
    PolicyContext::new(UnlockOutcome::Primary)
}

fn decoy_policy() -> PolicyContext {
    PolicyContext::new(UnlockOutcome::Decoy)
}

/// Return a known-good OTPAuth URI list accepted by the hardened parser
fn interop_bytes() -> &'static [u8] {
    br#"otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30
"#
}

/// A minimal valid TOTP otpauth URI list must parse into quarantine
#[test]
fn interop_quarantine_valid_otpauth_list() {
    let q = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        interop_bytes(),
    )
    .expect("quarantine import");

    assert!(matches!(q.format(), InteropFormat::OtpAuthTotpUriList));
    assert_eq!(q.payload().entries.len(), 1);
    assert_eq!(q.payload().entries[0].meta.entry_type, EntryType::Totp);
}

/// Decoy policy must deny plaintext interop import
#[test]
fn interop_quarantine_denied_in_decoy() {
    let err = import_interop_quarantine(
        decoy_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        interop_bytes(),
    )
    .unwrap_err();

    assert!(matches!(err, ImportError::PolicyDenied));
}

/// Unsupported interop formats must be rejected
#[test]
fn interop_quarantine_rejects_other_format() {
    let err = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::Other,
        b"anything",
    )
    .unwrap_err();

    assert!(matches!(err, ImportError::InvalidFormat));
}

/// Malformed URI input must be rejected
#[test]
fn interop_quarantine_rejects_invalid_uri() {
    let err = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        b"not-an-otpauth-uri",
    )
    .unwrap_err();

    assert!(matches!(err, ImportError::InvalidFormat));
}

/// Duplicate otpauth entries must be skipped deterministically
///
/// # Security
/// Deduplication is hash-based on issuer/account/secret and must avoid
/// keeping duplicates that can bloat the imported payload
#[test]
fn interop_quarantine_deduplicates_identical_entries() {
    let bytes = br#"otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30
otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30
"#;

    let q = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        bytes,
    )
    .expect("quarantine import");

    assert_eq!(q.payload().entries.len(), 1);
}

/// Empty input must be rejected by the anti-DoS boundary
#[test]
fn interop_quarantine_rejects_empty_input() {
    let err = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        b"",
    )
    .unwrap_err();

    assert!(matches!(err, ImportError::PayloadTooLarge));
}

/// Overlong single lines must be rejected
#[test]
fn interop_quarantine_rejects_overlong_line() {
    let too_long_label = "A".repeat(9000);
    let uri = format!(
        "otpauth://totp/{}?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
        too_long_label
    );

    let err = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        uri.as_bytes(),
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ImportError::PayloadTooLarge | ImportError::InvalidFormat
    ));
}

/// Bad TOTP parameters must be rejected during quarantine
#[test]
fn interop_quarantine_rejects_invalid_totp_parameters() {
    let bytes = br#"otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=9&period=30
"#;

    let err = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        bytes,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        ImportError::InvalidFormat | ImportError::InvalidData
    ));
}

/// Valid quarantined imports must commit into an existing payload
#[test]
fn interop_commit_into_existing_payload_success() {
    let q = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        interop_bytes(),
    )
    .expect("quarantine");

    let mut existing = VaultPayload {
        entries: vec![
            VaultEntry::new_secure_note("note".to_string(), "secret".to_string()).expect("entry"),
        ],
    };

    commit_quarantined_import_into_payload(primary_policy(), &mut existing, q).expect("commit");

    assert_eq!(existing.entries.len(), 2);
    assert_eq!(existing.entries[1].meta.entry_type, EntryType::Totp);
}

/// Commit must be denied in decoy mode
#[test]
fn interop_commit_denied_in_decoy() {
    let q = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        interop_bytes(),
    )
    .expect("quarantine");

    let mut existing = VaultPayload { entries: vec![] };

    let err = commit_quarantined_import_into_payload(decoy_policy(), &mut existing, q).unwrap_err();
    assert!(matches!(err, ImportError::PolicyDenied));
}
