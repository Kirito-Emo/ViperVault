#![no_main]

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Emanuele Relmi

//! Structure-aware fuzz target for OTPAuth export/parse roundtrips
//!
//! # Security
//! This target validates semantic roundtrip behaviour using bounded,
//! protocol-shaped inputs
//!
//! The target intentionally checks only invariants that are expected to be
//! stable across canonicalization boundaries
//!
//! In particular, the `account_name` field is treated carefully when
//! `issuer == None`, because some OTPAuth serializations may not preserve
//! that distinction in a strong roundtrip form

#[path = "support/structured.rs"]
mod structured;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use secrecy::{ExposeSecret, SecretString};
use structured::{
    digits_from_selector, period_from_selector, Base32Secret, SafeAccount, SafeDisplay,
    StructuredAlgorithm,
};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::types::TotpSecret;
use vipervault_core::otpauth::export::export_totp_otpauth_uri;
use vipervault_core::otpauth::totp::parse_totp_otpauth_uri;
use vipervault_core::vault::duress::UnlockOutcome;

/// Structure-aware model for OTPAuth roundtrip verification
#[derive(Debug, Clone, Arbitrary)]
struct StructuredOtpRoundtripCase {
    /// Fallback display title used by export
    title: SafeDisplay,

    /// Optional issuer component
    issuer: Option<SafeDisplay>,

    /// Optional account name component
    account: Option<SafeAccount>,

    /// Base32 secret material
    secret: Base32Secret,

    /// Algorithm selector
    algorithm: StructuredAlgorithm,

    /// Raw digits selector
    digits_selector: u8,

    /// Raw period selector
    period_selector: u8,
}

/// Assert issuer roundtrip semantics
///
/// # Notes
/// The issuer is expected to be preserved exactly when present and to remain
/// absent when not provided
fn assert_issuer_roundtrip(
    expected_issuer: Option<&str>,
    parsed: &TotpSecret,
) {
    match expected_issuer {
        Some(expected) => {
            let actual = parsed
                .issuer
                .as_ref()
                .expect("issuer must be preserved when originally present")
                .expose_secret();
            assert_eq!(actual, expected);
        }
        None => {
            assert!(parsed.issuer.is_none());
        }
    }
}

/// Assert account-name roundtrip semantics
///
/// # Notes
/// When an issuer is present, the account name is expected to survive the
/// roundtrip exactly
///
/// When no issuer is present, the exporter/parser pair may legally collapse
/// the distinction between "title" and "account name" \
/// In that case the account name is allowed to be either preserved or normalized away
fn assert_account_roundtrip(
    expected_issuer: Option<&str>,
    expected_account: Option<&str>,
    parsed: &TotpSecret,
) {
    match (expected_issuer, expected_account) {
        (Some(_), Some(expected)) => {
            let actual = parsed
                .account_name
                .as_ref()
                .expect("account name must be preserved when issuer is present")
                .expose_secret();
            assert_eq!(actual, expected);
        }
        (Some(_), None) => {
            assert!(parsed.account_name.is_none());
        }
        (None, Some(expected)) => {
            if let Some(actual) = parsed.account_name.as_ref() {
                assert_eq!(actual.expose_secret(), expected);
            }
        }
        (None, None) => {
            assert!(parsed.account_name.is_none());
        }
    }
}

fuzz_target!(|case: StructuredOtpRoundtripCase| {
    let title = case
        .issuer
        .as_ref()
        .map(|issuer| issuer.0.clone())
        .unwrap_or_else(|| case.title.0.clone());

    let issuer = case.issuer.as_ref().map(|s| s.0.clone());
    let account = case.account.as_ref().map(|s| s.0.clone());
    let digits = digits_from_selector(case.digits_selector);
    let period_secs = period_from_selector(case.period_selector);
    let algorithm = case.algorithm.into_totp();

    let totp = TotpSecret {
        issuer: issuer
            .as_ref()
            .map(|value| SecretString::new(value.clone().into())),
        account_name: account
            .as_ref()
            .map(|value| SecretString::new(value.clone().into())),
        secret_b32: SecretString::new(case.secret.0.clone().into()),
        digits,
        period_secs,
        algorithm,
    };

    let Ok(uri) = export_totp_otpauth_uri(&title, &totp) else {
        return;
    };

    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let Ok((parsed_title, reparsed)) = parse_totp_otpauth_uri(policy, &uri) else {
        return;
    };

    // Title is expected to remain stable across export/parse
    assert_eq!(parsed_title, title);

    // Core cryptographic and timing parameters must survive exactly
    assert_eq!(reparsed.secret_b32.expose_secret(), case.secret.0);
    assert_eq!(reparsed.digits, digits);
    assert_eq!(reparsed.period_secs, period_secs);
    assert_eq!(reparsed.algorithm, algorithm);

    // Metadata semantics are validated with protocol-aware rules
    assert_issuer_roundtrip(issuer.as_deref(), &reparsed);
    assert_account_roundtrip(issuer.as_deref(), account.as_deref(), &reparsed);
});