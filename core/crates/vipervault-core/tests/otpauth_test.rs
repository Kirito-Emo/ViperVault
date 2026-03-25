// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! OTPAuth tests
//!
//! # Scope
//! These tests validate the `otpauth://totp/...` parsing and export logic:
//! - valid URI parsing
//! - issuer/account label splitting
//! - explicit issuer precedence over label issuer
//! - scheme/host/secret/algorithm validation
//! - decoy denial
//! - restrictive runtime-policy denial
//! - export roundtrip compatibility
//! - spoofing and anti-DoS boundaries
//!
//! # Security
//! OTPAuth parsing is an untrusted import boundary. These tests ensure that:
//! - malformed URIs are rejected safely
//! - dangerous Unicode or script-mixing inputs are rejected
//! - exported URIs preserve valid TOTP semantics
//! - decoy mode denies parsing at the policy boundary
//! - restrictive runtime states deny parsing conservatively

use secrecy::{ExposeSecret, SecretString};
use vipervault_core::core::{PolicyContext, RuntimeInspectionState};
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret};
use vipervault_core::otpauth::error::OtpAuthError;
use vipervault_core::otpauth::export::export_totp_otpauth_uri;
use vipervault_core::otpauth::totp::parse_totp_otpauth_uri;
use vipervault_core::vault::duress::UnlockOutcome;

/// Use deterministic policy construction for tests
fn primary_policy() -> PolicyContext {
    PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged)
}

/// Use deterministic policy construction for tests
fn decoy_policy() -> PolicyContext {
    PolicyContext::from_parts(UnlockOutcome::Decoy, RuntimeInspectionState::NotDebugged)
}

/// Restrictive runtime posture used to validate denial paths
fn unknown_runtime_policy() -> PolicyContext {
    PolicyContext::from_parts(UnlockOutcome::Primary, RuntimeInspectionState::Unknown)
}

/// Strongly restrictive runtime posture used to validate denial paths
fn tamper_policy() -> PolicyContext {
    PolicyContext::from_parts(
        UnlockOutcome::Primary,
        RuntimeInspectionState::TamperSuspected,
    )
}

/// A valid OTPAuth URI must parse successfully
#[test]
fn parse_valid_otpauth_uri_success() {
    let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    let (title, totp) = parse_totp_otpauth_uri(primary_policy(), uri).expect("parse otpauth");

    assert_eq!(title, "GitHub");
    assert_eq!(
        totp.issuer.as_ref().expect("issuer").expose_secret(),
        "GitHub"
    );
    assert_eq!(
        totp.account_name.as_ref().expect("account").expose_secret(),
        "octocat"
    );
    assert_eq!(totp.secret_b32.expose_secret(), "JBSWY3DPEHPK3PXP");
    assert_eq!(totp.digits, 6);
    assert_eq!(totp.period_secs, 30);
    assert!(matches!(totp.algorithm, TotpAlgorithm::Sha1));
}

/// If the label contains no issuer prefix, the full label must become the title
#[test]
fn parse_label_without_issuer_prefix() {
    let uri = "otpauth://totp/octocat@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30";

    let (title, totp) = parse_totp_otpauth_uri(primary_policy(), uri).expect("parse");

    assert_eq!(title, "octocat@example.com");
    assert!(totp.issuer.is_none());
    assert!(totp.account_name.is_none());
}

/// Explicit issuer parameter must override label issuer
///
/// # Security
/// This prevents ambiguity when a malicious or inconsistent label conflicts with
/// the authoritative issuer query parameter
#[test]
fn explicit_issuer_overrides_label_issuer() {
    let uri = "otpauth://totp/OldIssuer:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    let (title, totp) = parse_totp_otpauth_uri(primary_policy(), uri).expect("parse");

    assert_eq!(title, "OldIssuer");
    assert_eq!(
        totp.issuer.as_ref().expect("issuer").expose_secret(),
        "GitHub"
    );
    assert_eq!(
        totp.account_name.as_ref().expect("account").expose_secret(),
        "octocat"
    );
}

/// Decoy policy must deny OTPAuth parsing
#[test]
fn parse_otpauth_denied_in_decoy() {
    let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    let err = parse_totp_otpauth_uri(decoy_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}

/// Unknown runtime state must also deny OTPAuth parsing
#[test]
fn parse_otpauth_denied_under_unknown_runtime() {
    let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    let err = parse_totp_otpauth_uri(unknown_runtime_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}

/// Tamper-suspected runtime state must deny OTPAuth parsing
#[test]
fn parse_otpauth_denied_under_tamper_suspected_runtime() {
    let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    let err = parse_totp_otpauth_uri(tamper_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}

/// Invalid scheme must be rejected
#[test]
fn parse_otpauth_rejects_invalid_scheme() {
    let uri = "https://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP";

    let err = parse_totp_otpauth_uri(primary_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidUri));
}

/// Invalid host kind must be rejected
#[test]
fn parse_otpauth_rejects_non_totp_host() {
    let uri = "otpauth://hotp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP";

    let err = parse_totp_otpauth_uri(primary_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidUri));
}

/// Missing secret must be rejected
#[test]
fn parse_otpauth_rejects_missing_secret() {
    let uri = "otpauth://totp/GitHub:octocat?issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    let err = parse_totp_otpauth_uri(primary_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}

/// Unsupported algorithms must be rejected
#[test]
fn parse_otpauth_rejects_unsupported_algorithm() {
    let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=MD5&digits=6&period=30";

    let err = parse_totp_otpauth_uri(primary_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}

/// Dangerous script mixing in the title must be rejected
#[test]
fn parse_otpauth_rejects_script_mixing() {
    let uri = "otpauth://totp/GitHub\u{0430}:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    let err = parse_totp_otpauth_uri(primary_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}

/// Excessively long URIs must be rejected by the anti-DoS boundary
#[test]
fn parse_otpauth_rejects_oversized_uri() {
    let huge_label = "A".repeat(5000);
    let uri = format!(
        "otpauth://totp/{}?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
        huge_label
    );

    let err = parse_totp_otpauth_uri(primary_policy(), &uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidUri));
}

/// Percent-encoded label and query components must roundtrip into decoded values
#[test]
fn parse_otpauth_decodes_percent_encoded_components() {
    let uri = "otpauth://totp/GitHub%20Prod:octo%40cat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub%20Prod&algorithm=SHA1&digits=6&period=30";

    let (title, totp) = parse_totp_otpauth_uri(primary_policy(), uri).expect("parse");

    assert_eq!(title, "GitHub Prod");
    assert_eq!(
        totp.issuer.as_ref().expect("issuer").expose_secret(),
        "GitHub Prod"
    );
    assert_eq!(
        totp.account_name.as_ref().expect("account").expose_secret(),
        "octo@cat"
    );
}

/// All supported algorithms must parse successfully
#[test]
fn parse_otpauth_accepts_all_supported_algorithms() {
    let cases = [
        ("SHA1", TotpAlgorithm::Sha1),
        ("SHA256", TotpAlgorithm::Sha256),
        ("SHA512", TotpAlgorithm::Sha512),
    ];

    for (name, expected) in cases {
        let uri = format!(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm={name}&digits=6&period=30"
        );

        let (_, totp) = parse_totp_otpauth_uri(primary_policy(), &uri).expect("parse");
        assert!(matches!(
            (totp.algorithm, expected),
            (TotpAlgorithm::Sha1, TotpAlgorithm::Sha1)
                | (TotpAlgorithm::Sha256, TotpAlgorithm::Sha256)
                | (TotpAlgorithm::Sha512, TotpAlgorithm::Sha512)
        ));
    }
}

/// Boundary-valid digit counts must parse successfully
#[test]
fn parse_otpauth_accepts_boundary_valid_digits() {
    for digits in [6u8, 7u8, 8u8] {
        let uri = format!(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits={digits}&period=30"
        );

        let (_, totp) = parse_totp_otpauth_uri(primary_policy(), &uri).expect("parse");
        assert_eq!(totp.digits, digits);
    }
}

/// Boundary-invalid digit counts must be rejected
#[test]
fn parse_otpauth_rejects_invalid_digits_boundaries() {
    for digits in [0u8, 5u8, 9u8] {
        let uri = format!(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits={digits}&period=30"
        );

        let err = parse_totp_otpauth_uri(primary_policy(), &uri).unwrap_err();
        assert!(matches!(err, OtpAuthError::InvalidParams));
    }
}

/// Boundary-valid periods must parse successfully
#[test]
fn parse_otpauth_accepts_boundary_valid_periods() {
    for period in [10u32, 120u32] {
        let uri = format!(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period={period}"
        );

        let (_, totp) = parse_totp_otpauth_uri(primary_policy(), &uri).expect("parse");
        assert_eq!(totp.period_secs, period);
    }
}

/// Boundary-invalid periods must be rejected
#[test]
fn parse_otpauth_rejects_invalid_period_boundaries() {
    for period in [0u32, 9u32, 121u32] {
        let uri = format!(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period={period}"
        );

        let err = parse_totp_otpauth_uri(primary_policy(), &uri).unwrap_err();
        assert!(matches!(err, OtpAuthError::InvalidParams));
    }
}

/// Secrets with invalid non-base32 characters must be rejected
#[test]
fn parse_otpauth_rejects_invalid_secret_characters() {
    let uri = "otpauth://totp/GitHub:octocat?secret=JBSW!3DP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";

    let err = parse_totp_otpauth_uri(primary_policy(), uri).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}

/// A valid TOTP secret must export into a valid OTPAuth URI
#[test]
fn export_valid_totp_secret_success() {
    let totp = TotpSecret {
        issuer: Some(SecretString::new("GitHub".into())),
        account_name: Some(SecretString::new("octocat".into())),
        secret_b32: SecretString::new("JBSWY3DPEHPK3PXP".into()),
        digits: 6,
        period_secs: 30,
        algorithm: TotpAlgorithm::Sha1,
    };

    let uri = export_totp_otpauth_uri("GitHub", &totp).expect("export");

    assert!(uri.starts_with("otpauth://totp/"));
    assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
    assert!(uri.contains("issuer=GitHub"));
    assert!(uri.contains("algorithm=SHA1"));
    assert!(uri.contains("digits=6"));
    assert!(uri.contains("period=30"));
}

/// Exported URIs must roundtrip back into semantically equivalent TOTP data
#[test]
fn export_parse_roundtrip_is_semantically_consistent() {
    let totp = TotpSecret {
        issuer: Some(SecretString::new("GitHub".into())),
        account_name: Some(SecretString::new("octocat".into())),
        secret_b32: SecretString::new("JBSWY3DPEHPK3PXP".into()),
        digits: 6,
        period_secs: 30,
        algorithm: TotpAlgorithm::Sha256,
    };

    let uri = export_totp_otpauth_uri("GitHub", &totp).expect("export");
    let (title, reparsed) = parse_totp_otpauth_uri(primary_policy(), &uri).expect("parse");

    assert_eq!(title, "GitHub");
    assert_eq!(
        reparsed.issuer.as_ref().expect("issuer").expose_secret(),
        "GitHub"
    );
    assert_eq!(
        reparsed
            .account_name
            .as_ref()
            .expect("account")
            .expose_secret(),
        "octocat"
    );
    assert_eq!(reparsed.secret_b32.expose_secret(), "JBSWY3DPEHPK3PXP");
    assert_eq!(reparsed.digits, 6);
    assert_eq!(reparsed.period_secs, 30);
    assert!(matches!(reparsed.algorithm, TotpAlgorithm::Sha256));
}

/// Export/parse roundtrip must also preserve all supported algorithms
#[test]
fn export_parse_roundtrip_preserves_all_supported_algorithms() {
    let cases = [
        TotpAlgorithm::Sha1,
        TotpAlgorithm::Sha256,
        TotpAlgorithm::Sha512,
    ];

    for algorithm in cases {
        let totp = TotpSecret {
            issuer: Some(SecretString::new("GitHub".into())),
            account_name: Some(SecretString::new("octocat".into())),
            secret_b32: SecretString::new("JBSWY3DPEHPK3PXP".into()),
            digits: 6,
            period_secs: 30,
            algorithm,
        };

        let uri = export_totp_otpauth_uri("GitHub", &totp).expect("export");
        let (_, reparsed) = parse_totp_otpauth_uri(primary_policy(), &uri).expect("parse");

        assert!(matches!(
            (reparsed.algorithm, algorithm),
            (TotpAlgorithm::Sha1, TotpAlgorithm::Sha1)
                | (TotpAlgorithm::Sha256, TotpAlgorithm::Sha256)
                | (TotpAlgorithm::Sha512, TotpAlgorithm::Sha512)
        ));
    }
}

/// Invalid TOTP data must be rejected on export
#[test]
fn export_rejects_invalid_totp_secret() {
    let invalid = TotpSecret {
        issuer: None,
        account_name: None,
        secret_b32: SecretString::new("not valid base32!".into()),
        digits: 9,
        period_secs: 5,
        algorithm: TotpAlgorithm::Sha1,
    };

    let err = export_totp_otpauth_uri("Bad", &invalid).unwrap_err();
    assert!(matches!(err, OtpAuthError::InvalidParams));
}
