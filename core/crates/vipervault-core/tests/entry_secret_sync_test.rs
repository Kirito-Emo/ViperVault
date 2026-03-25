// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entry secret synchronization tests
//!
//! # Purpose
//! These tests verify invariants where the current data model intentionally
//! mirrors secret material across multiple fields for compatibility reasons

use secrecy::ExposeSecret;
use vipervault_core::entries::{EntryUpdate, TotpAlgorithm, TotpSecret, VaultEntry};

/// Build a valid TOTP secret for testing
fn sample_totp(secret_b32: &str) -> TotpSecret {
    TotpSecret {
        issuer: None,
        account_name: None,
        secret_b32: secrecy::SecretString::new(secret_b32.to_string().into()),
        digits: 6,
        period_secs: 30,
        algorithm: TotpAlgorithm::Sha1,
    }
}

/// Secure-note creation must keep `note` and `secret` aligned
#[test]
fn new_secure_note_keeps_note_and_secret_aligned() {
    let entry = VaultEntry::new_secure_note("note".to_string(), "classified".to_string())
        .expect("create secure note");

    let note = entry
        .secret
        .note
        .as_ref()
        .expect("note field")
        .expose_secret();
    let secret = entry.secret.secret.expose_secret();

    assert_eq!(note, "classified");
    assert_eq!(secret, "classified");
}

/// TOTP creation must mirror the base32 secret into the primary secret field
#[test]
fn new_totp_keeps_primary_secret_synchronized() {
    let entry = VaultEntry::new_totp("totp".to_string(), sample_totp("JBSWY3DPEHPK3PXP"), None)
        .expect("create totp entry");

    let totp = entry.secret.totp.as_ref().expect("totp field");
    assert_eq!(
        entry.secret.secret.expose_secret(),
        totp.secret_b32.expose_secret()
    );
}

/// Updating the primary secret on a TOTP entry must update the embedded TOTP secret too
#[test]
fn set_secret_on_totp_updates_both_secret_fields() {
    let mut entry = VaultEntry::new_totp("totp".to_string(), sample_totp("JBSWY3DPEHPK3PXP"), None)
        .expect("create totp entry");

    entry
        .apply_update(EntryUpdate::SetSecret("MZXW6YTBOI======".to_string()))
        .expect("update totp secret");

    let totp = entry.secret.totp.as_ref().expect("totp field");
    assert_eq!(entry.secret.secret.expose_secret(), "MZXW6YTBOI======");
    assert_eq!(totp.secret_b32.expose_secret(), "MZXW6YTBOI======");
}

/// Replacing the TOTP block must also refresh the mirrored primary secret
#[test]
fn set_totp_updates_primary_secret_field() {
    let mut entry = VaultEntry::new_totp("totp".to_string(), sample_totp("JBSWY3DPEHPK3PXP"), None)
        .expect("create totp entry");

    entry
        .apply_update(EntryUpdate::SetTotp(Some(sample_totp("MZXW6YTBOI======"))))
        .expect("replace totp");

    let totp = entry.secret.totp.as_ref().expect("totp field");
    assert_eq!(entry.secret.secret.expose_secret(), "MZXW6YTBOI======");
    assert_eq!(totp.secret_b32.expose_secret(), "MZXW6YTBOI======");
}
