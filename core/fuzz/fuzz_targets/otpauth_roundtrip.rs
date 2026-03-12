#![no_main]

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for OTPAuth export/parse roundtrip
//!
//! # Security
//! This target exercises both URI export and URI parse on structured fuzz-derived TOTP parameters \
//! Successful roundtrips must preserve core semantics and must never panic

use libfuzzer_sys::fuzz_target;
use secrecy::{ExposeSecret, SecretString};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret};
use vipervault_core::otpauth::export::export_totp_otpauth_uri;
use vipervault_core::otpauth::totp::parse_totp_otpauth_uri;
use vipervault_core::vault::duress::UnlockOutcome;

/// Map fuzz byte to a supported TOTP algorithm
fn algorithm_from_byte(b: u8) -> TotpAlgorithm {
    match b % 3 {
        0 => TotpAlgorithm::Sha1,
        1 => TotpAlgorithm::Sha256,
        _ => TotpAlgorithm::Sha512,
    }
}

/// Map fuzz byte to a valid digit count
fn digits_from_byte(b: u8) -> u8 {
    6 + (b % 3)
}

/// Map fuzz bytes to a valid TOTP period
fn period_from_byte(b: u8) -> u32 {
    match b % 5 {
        0 => 30,
        1 => 45,
        2 => 60,
        3 => 90,
        _ => 120,
    }
}

/// Build a bounded ASCII-ish title that remains acceptable for the current project validators
fn title_from_bytes(data: &[u8]) -> String {
    if data.is_empty() {
        return "FuzzTitle".to_string();
    }

    let mut out = String::new();
    for b in data.iter().copied().take(24) {
        let ch = match b % 6 {
            0 => ((b % 26) + b'A') as char,
            1 => ((b % 26) + b'a') as char,
            2 => ((b % 10) + b'0') as char,
            3 => '-',
            4 => '_',
            _ => '.',
        };
        out.push(ch);
    }

    if out.is_empty() {
        "FuzzTitle".to_string()
    } else {
        out
    }
}

fuzz_target!(|data: &[u8]| {
    let title = title_from_bytes(data);
    let issuer = title.clone();
    let account = "fuzz_account";
    let algorithm = algorithm_from_byte(data.first().copied().unwrap_or(0));
    let digits = digits_from_byte(data.get(1).copied().unwrap_or(0));
    let period_secs = period_from_byte(data.get(2).copied().unwrap_or(0));

    let totp = TotpSecret {
        issuer: Some(SecretString::new(issuer.clone().into())),
        account_name: Some(SecretString::new(account.to_string().into())),
        secret_b32: SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string().into()),
        digits,
        period_secs,
        algorithm,
    };

    let uri = export_totp_otpauth_uri(&title, &totp);
    let Ok(uri) = uri else {
        return;
    };

    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let parsed = parse_totp_otpauth_uri(policy, &uri);
    let Ok((parsed_title, reparsed)) = parsed else {
        return;
    };

    assert_eq!(parsed_title, issuer);
    assert_eq!(
        reparsed.issuer.as_ref().expect("issuer").expose_secret(),
        issuer
    );
    assert_eq!(
        reparsed
            .account_name
            .as_ref()
            .expect("account")
            .expose_secret(),
        account
    );
    assert_eq!(reparsed.secret_b32.expose_secret(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert_eq!(reparsed.digits, digits);
    assert_eq!(reparsed.period_secs, period_secs);
    assert_eq!(reparsed.algorithm, algorithm);
});