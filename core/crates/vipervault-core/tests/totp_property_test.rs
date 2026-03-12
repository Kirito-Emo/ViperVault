// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! TOTP and OTPAuth property-style tests
//!
//! # Scope
//! These tests validate broader invariants of Base32 normalization, strict decoding,
//! OTPAuth export and OTPAuth parsing using deterministic matrices
//!
//! Covered:
//! - Base32 canonicalization idempotence
//! - normalization variants decode to the same raw secret bytes
//! - OTPAuth export/parse semantic roundtrip across parameter matrices
//! - exported URIs remain parseable across issuer/account combinations
//!
//! # Security
//! These tests protect parser and exporter invariants that are especially
//! important before fuzzing is introduced

use secrecy::{ExposeSecret, SecretString};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret};
use vipervault_core::otpauth::export::export_totp_otpauth_uri;
use vipervault_core::otpauth::totp::parse_totp_otpauth_uri;
use vipervault_core::totp::decode::{canonicalize_base32_for_export, decode_base32_secret_strict};
use vipervault_core::vault::duress::UnlockOutcome;

/// Primary session policy used by import-capable paths
fn primary_policy() -> PolicyContext {
    PolicyContext::new(UnlockOutcome::Primary)
}

/// Deterministic Base32 secret that satisfies the project entropy floor
const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// Canonicalization must be idempotent for representative inputs
#[test]
fn canonicalize_base32_is_idempotent_across_variants() {
    let variants = [
        SECRET_B32.to_string(),
        "gezdgnbvgy3tqojqgezdgnbvgy3tqojq".to_string(),
        "GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ".to_string(),
        " gezd gnbv gy3t qojq gezd gnbv gy3t qojq ".to_string(),
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====".to_string(),
        "gEzd-gNbv gy3tQojqGEZDgnbvGY3TQOJQ==".to_string(),
    ];

    for variant in variants {
        let once = canonicalize_base32_for_export(&variant).expect("canonicalize once");
        let twice = canonicalize_base32_for_export(&once).expect("canonicalize twice");
        assert_eq!(once, twice);
        assert_eq!(once, SECRET_B32);
    }
}

/// Normalization variants must decode to the same raw secret bytes after canonicalization
#[test]
fn normalized_base32_variants_decode_to_identical_raw_bytes() {
    let expected = decode_base32_secret_strict(SECRET_B32).expect("decode reference");

    let variants = [
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
        "GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
        "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
    ];

    for variant in variants {
        let canonical = canonicalize_base32_for_export(variant).expect("canonicalize");
        let decoded = decode_base32_secret_strict(&canonical).expect("decode canonical");
        assert_eq!(decoded.as_slice(), expected.as_slice());
    }
}

/// Build a deterministic `TotpSecret` for the export/parse matrix
fn build_totp(
    issuer: Option<&str>,
    account_name: Option<&str>,
    digits: u8,
    period_secs: u32,
    algorithm: TotpAlgorithm,
) -> TotpSecret {
    TotpSecret {
        issuer: issuer.map(|s| SecretString::new(s.to_string().into())),
        account_name: account_name.map(|s| SecretString::new(s.to_string().into())),
        secret_b32: SecretString::new(SECRET_B32.to_string().into()),
        digits,
        period_secs,
        algorithm,
    }
}

/// OTPAuth export followed by parse must preserve semantic TOTP parameters across
/// a representative parameter matrix
#[test]
fn otpauth_export_parse_roundtrip_preserves_semantics_matrix() {
    let cases = [
        (
            Some("GitHub"),
            Some("octocat"),
            6u8,
            30u32,
            TotpAlgorithm::Sha1,
        ),
        (
            Some("GitHub"),
            Some("octocat"),
            7u8,
            45u32,
            TotpAlgorithm::Sha256,
        ),
        (
            Some("GitHub"),
            Some("octocat"),
            8u8,
            120u32,
            TotpAlgorithm::Sha512,
        ),
        (Some("Vault"), None, 6u8, 30u32, TotpAlgorithm::Sha1),
        (None, None, 8u8, 60u32, TotpAlgorithm::Sha256),
    ];

    for (issuer, account, digits, period_secs, algorithm) in cases {
        let title = issuer.unwrap_or("Standalone Title");
        let totp = build_totp(issuer, account, digits, period_secs, algorithm);

        let uri = export_totp_otpauth_uri(title, &totp).expect("export");
        let (parsed_title, reparsed) =
            parse_totp_otpauth_uri(primary_policy(), &uri).expect("parse");

        match (issuer, account) {
            (Some(exported_issuer), Some(exported_account)) => {
                assert_eq!(parsed_title, exported_issuer);
                assert_eq!(
                    reparsed.issuer.as_ref().expect("issuer").expose_secret(),
                    exported_issuer
                );
                assert_eq!(
                    reparsed
                        .account_name
                        .as_ref()
                        .expect("account name")
                        .expose_secret(),
                    exported_account
                );
            }
            (Some(exported_issuer), None) => {
                assert_eq!(parsed_title, title);
                assert_eq!(
                    reparsed.issuer.as_ref().expect("issuer").expose_secret(),
                    exported_issuer
                );
                assert!(reparsed.account_name.is_none());
            }
            (None, None) => {
                assert_eq!(parsed_title, title);
                assert!(reparsed.issuer.is_none());
                assert!(reparsed.account_name.is_none());
            }
            (None, Some(_)) => {
                unreachable!("account-only export is not constructed in this matrix");
            }
        }

        assert_eq!(reparsed.secret_b32.expose_secret(), SECRET_B32);
        assert_eq!(reparsed.digits, digits);
        assert_eq!(reparsed.period_secs, period_secs);
        assert_eq!(reparsed.algorithm, algorithm);
    }
}

/// Exported URIs must remain parseable across titles that require percent encoding,
/// while preserving TOTP semantics
#[test]
fn otpauth_export_parse_preserves_semantics_for_percent_encoded_titles() {
    let titles = [
        "GitHub Personal",
        "Email / MFA",
        "Name_With-Mixed.Separators",
        "Team Vault (Prod)",
    ];

    for title in titles {
        let totp = build_totp(None, None, 6, 30, TotpAlgorithm::Sha1);
        let uri = export_totp_otpauth_uri(title, &totp).expect("export");
        let (parsed_title, reparsed) =
            parse_totp_otpauth_uri(primary_policy(), &uri).expect("parse");

        assert_eq!(parsed_title, title);
        assert!(reparsed.issuer.is_none());
        assert!(reparsed.account_name.is_none());
        assert_eq!(reparsed.secret_b32.expose_secret(), SECRET_B32);
        assert_eq!(reparsed.digits, 6);
        assert_eq!(reparsed.period_secs, 30);
        assert_eq!(reparsed.algorithm, TotpAlgorithm::Sha1);
    }
}
