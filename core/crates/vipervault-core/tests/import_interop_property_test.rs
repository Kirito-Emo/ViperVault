// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Interop import property-style tests
//!
//! # Scope
//! These tests validate broader invariants of the plaintext interop quarantine
//! and commit flow using deterministic input matrices
//!
//! Covered:
//! - accepted RFC 4648 Base32 variants deduplicate to a single imported entry
//! - deduplication is stable across reordered duplicate input sets
//! - import preserves semantic TOTP parameters across multiple cases
//! - commit behaves associatively over multiple quarantined batches
//!
//! # Security
//! Interop import is a high-risk boundary because it accepts attacker-controlled plaintext \
//! These tests protect invariants that should remain stable across larger classes of accepted input

use secrecy::ExposeSecret;
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::{EntryType, VaultEntry};
use vipervault_core::import::{
    ImportIntent, InteropFormat, commit_quarantined_import_into_payload, import_interop_quarantine,
};
use vipervault_core::vault::VaultPayload;
use vipervault_core::vault::duress::UnlockOutcome;

fn primary_policy() -> PolicyContext {
    PolicyContext::new(UnlockOutcome::Primary)
}

/// Build a deterministic OTPAuth URI line
///
/// # Note
/// The provided secret must already satisfy the project's strict OTPAuth parser constraints
fn otpauth_line(
    label: &str,
    secret_b32: &str,
    issuer: &str,
    algorithm: &str,
    digits: u8,
    period: u32,
) -> String {
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}"
    )
}

/// Accepted RFC 4648 Base32 variants representing the same logical secret
///
/// # Note
/// These variants must be accepted both by the OTPAuth parser and by the strict
/// Base32 decoder used during quarantine deduplication
fn accepted_equivalent_secret_variants() -> &'static [&'static str] {
    &[
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
    ]
}

/// Deduplication must collapse accepted equivalent Base32 representations of
/// the same logical TOTP entry into a single quarantined entry
#[test]
fn interop_dedup_collapses_accepted_canonical_secret_variants() {
    let mut lines = Vec::new();

    for secret in accepted_equivalent_secret_variants() {
        lines.push(otpauth_line(
            "GitHub:octocat",
            secret,
            "GitHub",
            "SHA1",
            6,
            30,
        ));
    }

    let input = lines.join("\n");
    let q = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        input.as_bytes(),
    )
    .expect("quarantine");

    assert_eq!(q.payload().entries.len(), 1);
    let entry = &q.payload().entries[0];
    assert_eq!(entry.meta.entry_type, EntryType::Totp);

    let view = entry.to_view();
    assert_eq!(view.expose_title(), "GitHub");
    assert_eq!(view.expose_secret(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
}

/// Reordering duplicate-heavy input sets must not change the quarantined entry
/// count nor the semantic identity of the surviving entries
#[test]
fn interop_dedup_is_stable_across_reordered_duplicate_sets() {
    let a1 = otpauth_line(
        "GitHub:octocat",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "GitHub",
        "SHA1",
        6,
        30,
    );
    let a2 = otpauth_line(
        "GitHub:octocat",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
        "GitHub",
        "SHA1",
        6,
        30,
    );
    let b1 = otpauth_line(
        "Email:alice@example.com",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        "Email",
        "SHA256",
        8,
        60,
    );
    let b2 = otpauth_line(
        "Email:alice@example.com",
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP====",
        "Email",
        "SHA256",
        8,
        60,
    );

    let forward = format!("{a1}\n{a2}\n{b1}\n{b2}\n");
    let reverse = format!("{b2}\n{b1}\n{a2}\n{a1}\n");

    let q_forward = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        forward.as_bytes(),
    )
    .expect("forward quarantine");

    let q_reverse = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        reverse.as_bytes(),
    )
    .expect("reverse quarantine");

    assert_eq!(q_forward.payload().entries.len(), 2);
    assert_eq!(q_reverse.payload().entries.len(), 2);

    let mut forward_titles: Vec<String> = q_forward
        .payload()
        .entries
        .iter()
        .map(|e| e.to_view().expose_title().to_string())
        .collect();
    let mut reverse_titles: Vec<String> = q_reverse
        .payload()
        .entries
        .iter()
        .map(|e| e.to_view().expose_title().to_string())
        .collect();

    forward_titles.sort();
    reverse_titles.sort();

    assert_eq!(forward_titles, reverse_titles);
    assert_eq!(
        forward_titles,
        vec!["Email".to_string(), "GitHub".to_string()]
    );
}

/// Imported entries must preserve semantic TOTP parameters across a representative matrix
#[test]
fn interop_import_preserves_totp_semantics_matrix() {
    let cases = [
        (
            "GitHub:octocat",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "GitHub",
            "SHA1",
            6u8,
            30u32,
        ),
        (
            "Email:alice@example.com",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "Email",
            "SHA256",
            7u8,
            45u32,
        ),
        (
            "Vault:bob@example.com",
            "MFRGGZDFMZTWQ2LKNNWG23TPO5XXE3DE",
            "Vault",
            "SHA512",
            8u8,
            90u32,
        ),
    ];

    for (label, secret, issuer, algorithm, digits, period) in cases {
        let input = format!(
            "{}\n",
            otpauth_line(label, secret, issuer, algorithm, digits, period)
        );

        let q = import_interop_quarantine(
            primary_policy(),
            ImportIntent::UserConfirmed,
            InteropFormat::OtpAuthTotpUriList,
            input.as_bytes(),
        )
        .expect("quarantine");

        assert_eq!(q.payload().entries.len(), 1);

        let entry = &q.payload().entries[0];
        assert_eq!(entry.meta.entry_type, EntryType::Totp);

        let totp = entry.secret.totp.as_ref().expect("totp secret");
        assert_eq!(
            totp.issuer.as_ref().expect("issuer").expose_secret(),
            issuer
        );
        assert_eq!(totp.digits, digits);
        assert_eq!(totp.period_secs, period);

        let view = entry.to_view();
        assert_eq!(view.expose_title(), issuer);
    }
}

/// Committing quarantined batches in multiple steps must produce the same final
/// entry count as committing their concatenation once, when there are no
/// cross-batch duplicates
#[test]
fn interop_commit_is_associative_for_distinct_batches() {
    let batch_a = format!(
        "{}\n{}\n",
        otpauth_line(
            "GitHub:octocat",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "GitHub",
            "SHA1",
            6,
            30
        ),
        otpauth_line(
            "Email:alice@example.com",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "Email",
            "SHA256",
            8,
            60
        )
    );

    let batch_b = format!(
        "{}\n{}\n",
        otpauth_line(
            "Vault:bob@example.com",
            "MFRGGZDFMZTWQ2LKNNWG23TPO5XXE3DE",
            "Vault",
            "SHA512",
            7,
            45
        ),
        otpauth_line(
            "Forum:charlie@example.com",
            "ON2XEZLEON2XEZLEON2XEZLEON2XEZLE",
            "Forum",
            "SHA1",
            6,
            30
        )
    );

    let merged = format!("{batch_a}{batch_b}");

    let q_a = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        batch_a.as_bytes(),
    )
    .expect("q_a");

    let q_b = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        batch_b.as_bytes(),
    )
    .expect("q_b");

    let q_merged = import_interop_quarantine(
        primary_policy(),
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        merged.as_bytes(),
    )
    .expect("q_merged");

    let mut staged = VaultPayload {
        entries: vec![
            VaultEntry::new_secure_note("seed".to_string(), "seed-secret".to_string())
                .expect("seed entry"),
        ],
    };

    commit_quarantined_import_into_payload(primary_policy(), &mut staged, q_a).expect("commit a");
    commit_quarantined_import_into_payload(primary_policy(), &mut staged, q_b).expect("commit b");

    let mut merged_payload = VaultPayload {
        entries: vec![
            VaultEntry::new_secure_note("seed".to_string(), "seed-secret".to_string())
                .expect("seed entry"),
        ],
    };

    commit_quarantined_import_into_payload(primary_policy(), &mut merged_payload, q_merged)
        .expect("commit merged");

    assert_eq!(staged.entries.len(), merged_payload.entries.len());

    let staged_totp_count = staged
        .entries
        .iter()
        .filter(|e| e.meta.entry_type == EntryType::Totp)
        .count();
    let merged_totp_count = merged_payload
        .entries
        .iter()
        .filter(|e| e.meta.entry_type == EntryType::Totp)
        .count();

    assert_eq!(staged_totp_count, 4);
    assert_eq!(merged_totp_count, 4);
}
