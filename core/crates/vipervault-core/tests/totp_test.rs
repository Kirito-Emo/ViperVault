// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! TOTP engine tests
//!
//! # Scope
//! These tests validate the TOTP engine:
//! - strict Base32 decoding
//! - raw RFC 6238 code generation
//! - generation from stored `TotpSecret`
//! - verification across time windows
//! - formatting with fixed-width decimal output
//! - parameter bounds for digits and period
//! - algorithm coverage (SHA1 / SHA256 / SHA512)
//!
//! # Security
//! TOTP generation is a sensitive MFA boundary. These tests ensure that:
//! - malformed secrets are rejected safely
//! - bounded parameters are enforced
//! - verification does not accept values outside the intended window
//! - formatted OTP strings preserve leading zeros and fixed width
//! - all supported algorithms remain functional

use secrecy::SecretString;
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret};
use vipervault_core::totp::decode::{
    MAX_SECRET_B32_LEN, MIN_SECRET_RAW_LEN, canonicalize_base32_for_export,
    decode_base32_secret_strict,
};
use vipervault_core::totp::engine::{
    MAX_DIGITS, MAX_PERIOD_SECS, MIN_DIGITS, MIN_PERIOD_SECS, totp_generate_formatted,
    totp_generate_from_secret, totp_generate_raw, totp_verify,
};
use vipervault_core::totp::error::TotpError;
use vipervault_core::totp::format::format_totp_code;

/// RFC 6238 shared secret used in deterministic tests
///
/// This Base32 string decodes to the ASCII bytes:
/// `12345678901234567890`
const SECRET_B32_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// Build a valid TOTP secret
fn valid_totp(algorithm: TotpAlgorithm) -> TotpSecret {
    TotpSecret {
        issuer: Some(SecretString::new("GitHub".into())),
        account_name: Some(SecretString::new("octocat".into())),
        secret_b32: SecretString::new(SECRET_B32_SHA1.into()),
        digits: 6,
        period_secs: 30,
        algorithm,
    }
}

/// Strict Base32 decoding must succeed for a valid RFC 4648 secret
#[test]
fn decode_base32_secret_success() {
    let decoded = decode_base32_secret_strict(SECRET_B32_SHA1).expect("decode secret");

    assert!(decoded.len() >= MIN_SECRET_RAW_LEN);
    assert_eq!(decoded.as_slice(), b"12345678901234567890");
}

/// Empty Base32 secrets must be rejected
#[test]
fn decode_base32_rejects_empty_secret() {
    let err = decode_base32_secret_strict("").unwrap_err();
    assert!(matches!(err, TotpError::InvalidSecret));
}

/// Lowercase secrets must be rejected by the strict decoder
///
/// # Security
/// Strict decoding avoids ambiguity and keeps the accepted alphabet narrow
#[test]
fn decode_base32_rejects_lowercase_secret() {
    let err = decode_base32_secret_strict("gezdgnbvgy3tqojq").unwrap_err();
    assert!(matches!(err, TotpError::InvalidSecret));
}

/// Non-ASCII secrets must be rejected
#[test]
fn decode_base32_rejects_non_ascii_secret() {
    let err = decode_base32_secret_strict("GEZD🙂").unwrap_err();
    assert!(matches!(err, TotpError::InvalidSecret));
}

/// Secrets shorter than the entropy floor must be rejected after decoding
#[test]
fn decode_base32_rejects_too_short_decoded_secret() {
    let short_b32 = "JBSWY3DP";
    let err = decode_base32_secret_strict(short_b32).unwrap_err();
    assert!(matches!(err, TotpError::InvalidSecret));
}

/// Oversized Base32 secrets must be rejected by the anti-DoS boundary
#[test]
fn decode_base32_rejects_oversized_secret() {
    let oversized = "A".repeat(MAX_SECRET_B32_LEN + 1);
    let err = decode_base32_secret_strict(&oversized).unwrap_err();
    assert!(matches!(err, TotpError::InvalidSecret));
}

/// Canonicalization for export must:
/// - strip whitespace
/// - strip hyphens
/// - uppercase letters
/// - strip trailing '=' padding
#[test]
fn canonicalize_base32_for_export_normalizes_input() {
    let canonical = canonicalize_base32_for_export("gezd-gnbv gy3tqojq====").expect("canonicalize");

    assert_eq!(canonical, "GEZDGNBVGY3TQOJQ");
}

/// Invalid canonicalization inputs must be rejected
#[test]
fn canonicalize_base32_rejects_invalid_input() {
    let err = canonicalize_base32_for_export("🙂").unwrap_err();
    assert!(matches!(err, TotpError::InvalidSecret));
}

/// Raw TOTP generation must succeed for SHA1 with valid parameters
#[test]
fn totp_generate_raw_sha1_success() {
    let secret = b"12345678901234567890";
    let code = totp_generate_raw(secret, 59, 30, 6, TotpAlgorithm::Sha1).expect("generate");

    assert!(code < 1_000_000);
}

/// Raw TOTP generation must succeed for SHA256 with valid parameters
#[test]
fn totp_generate_raw_sha256_success() {
    let secret = b"12345678901234567890";
    let code = totp_generate_raw(secret, 59, 30, 6, TotpAlgorithm::Sha256).expect("generate");

    assert!(code < 1_000_000);
}

/// Raw TOTP generation must succeed for SHA512 with valid parameters
#[test]
fn totp_generate_raw_sha512_success() {
    let secret = b"12345678901234567890";
    let code = totp_generate_raw(secret, 59, 30, 6, TotpAlgorithm::Sha512).expect("generate");

    assert!(code < 1_000_000);
}

/// Period below the minimum must be rejected
#[test]
fn totp_generate_raw_rejects_period_below_minimum() {
    let secret = b"12345678901234567890";
    let err =
        totp_generate_raw(secret, 59, MIN_PERIOD_SECS - 1, 6, TotpAlgorithm::Sha1).unwrap_err();

    assert!(matches!(err, TotpError::InvalidParams));
}

/// Period above the maximum must be rejected
#[test]
fn totp_generate_raw_rejects_period_above_maximum() {
    let secret = b"12345678901234567890";
    let err =
        totp_generate_raw(secret, 59, MAX_PERIOD_SECS + 1, 6, TotpAlgorithm::Sha1).unwrap_err();

    assert!(matches!(err, TotpError::InvalidParams));
}

/// Digits below the minimum must be rejected
#[test]
fn totp_generate_raw_rejects_digits_below_minimum() {
    let secret = b"12345678901234567890";
    let err = totp_generate_raw(secret, 59, 30, MIN_DIGITS - 1, TotpAlgorithm::Sha1).unwrap_err();

    assert!(matches!(err, TotpError::InvalidParams));
}

/// Digits above the maximum must be rejected
#[test]
fn totp_generate_raw_rejects_digits_above_maximum() {
    let secret = b"12345678901234567890";
    let err = totp_generate_raw(secret, 59, 30, MAX_DIGITS + 1, TotpAlgorithm::Sha1).unwrap_err();

    assert!(matches!(err, TotpError::InvalidParams));
}

/// Generation from a stored secret must succeed
#[test]
fn totp_generate_from_secret_success() {
    let totp = valid_totp(TotpAlgorithm::Sha1);

    let code = totp_generate_from_secret(&totp, 59).expect("generate from secret");
    assert!(code < 1_000_000);
}

/// Invalid stored secrets must be rejected during generation
#[test]
fn totp_generate_from_secret_rejects_invalid_secret() {
    let invalid = TotpSecret {
        issuer: None,
        account_name: None,
        secret_b32: SecretString::new("not-valid-base32!".into()),
        digits: 6,
        period_secs: 30,
        algorithm: TotpAlgorithm::Sha1,
    };

    let err = totp_generate_from_secret(&invalid, 59).unwrap_err();
    assert!(matches!(
        err,
        TotpError::InvalidParams | TotpError::InvalidSecret
    ));
}

/// Verification must accept the exact current code
#[test]
fn totp_verify_accepts_current_code() {
    let totp = valid_totp(TotpAlgorithm::Sha1);
    let code = totp_generate_from_secret(&totp, 1_700_000_000).expect("generate");

    let ok = totp_verify(&totp, 1_700_000_000, code, 0).expect("verify");
    assert!(ok);
}

/// Verification must reject a wrong code
#[test]
fn totp_verify_rejects_wrong_code() {
    let totp = valid_totp(TotpAlgorithm::Sha1);

    let ok = totp_verify(&totp, 1_700_000_000, 123456, 0).expect("verify");
    assert!(!ok);
}

/// Verification must accept a code within the allowed time window
#[test]
fn totp_verify_accepts_code_within_window() {
    let totp = valid_totp(TotpAlgorithm::Sha1);

    let earlier = 1_700_000_000u64;
    let code = totp_generate_from_secret(&totp, earlier).expect("generate");

    let later_same_window_family = earlier + 30;
    let ok = totp_verify(&totp, later_same_window_family, code, 1).expect("verify");

    assert!(ok);
}

/// Verification must reject a code outside the allowed time window
#[test]
fn totp_verify_rejects_code_outside_window() {
    let totp = valid_totp(TotpAlgorithm::Sha1);

    let earlier = 1_700_000_000u64;
    let code = totp_generate_from_secret(&totp, earlier).expect("generate");

    let far_later = earlier + 30 * 5;
    let ok = totp_verify(&totp, far_later, code, 1).expect("verify");

    assert!(!ok);
}

/// Excessive windows must be rejected
///
/// # Security
/// Large verification windows reduce security and increase CPU work
#[test]
fn totp_verify_rejects_excessive_window() {
    let totp = valid_totp(TotpAlgorithm::Sha1);

    let err = totp_verify(&totp, 1_700_000_000, 123456, 11).unwrap_err();
    assert!(matches!(err, TotpError::InvalidParams));
}

/// Formatting must preserve fixed width and leading zeros
#[test]
fn format_totp_code_preserves_leading_zeros() {
    let formatted = format_totp_code(42, 6).expect("format");
    assert_eq!(formatted.as_str(), "000042");
}

/// Formatting must reject unsupported digit widths
#[test]
fn format_totp_code_rejects_invalid_digits() {
    let err = format_totp_code(42, 9).unwrap_err();
    assert!(matches!(err, TotpError::InvalidParams));
}

/// Formatted generation must return a fixed-width decimal OTP string
#[test]
fn totp_generate_formatted_returns_fixed_width_code() {
    let totp = valid_totp(TotpAlgorithm::Sha256);

    let formatted = totp_generate_formatted(&totp, 1_700_000_000).expect("generate formatted");
    assert_eq!(formatted.len(), 6);
    assert!(formatted.chars().all(|c| c.is_ascii_digit()));
}
