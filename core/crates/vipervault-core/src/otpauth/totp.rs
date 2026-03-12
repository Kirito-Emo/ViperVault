// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! `otpauth://totp/...` parsing
//!
//! # Supported format
//! `otpauth://totp/<label>?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30`
//!
//! # Notes
//! Labels are treated as user-visible title and `issuer` and `account_name` are
//! separately parsed when possible
//!
//! # Security hardening
//! - Policy-gated
//! - Bounded URI length and query pairs (anti-DoS)
//! - Strict algorithm allowlist (SHA1/SHA256/SHA512)
//! - Issuer mismatch policy: prefer explicit `issuer=` parameter over label issuer
//! - Validates issuer/account/title against spoofing controls
//! - Rejects gross script mixing (basic homograph mitigation)

use super::error::OtpAuthError;
use crate::core::policy::PolicyContext;
use crate::entries::error::EntryError;
use crate::entries::types::{TotpAlgorithm, TotpSecret};
use crate::entries::validate::{validate_title, validate_username};
use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use url::Url;

/// Maximum accepted OTPAuth URI length (anti-DoS)
pub const MAX_OTP_AUTH_URI_LEN: usize = 4096;

/// Maximum number of query pairs processed (anti-DoS)
pub const MAX_QUERY_PAIRS: usize = 64;

/// Parse an `otpauth://totp/...` URI into a `(title, TotpSecret)`
///
/// # Returns
/// - `title`: recommended entry title for `VaultEntry::new_totp`
/// - `secret`: validated `TotpSecret`
///
/// # Security
/// Denied by the centralized session/runtime policy
pub fn parse_totp_otpauth_uri(
    policy: PolicyContext,
    uri: &str,
) -> Result<(String, TotpSecret), OtpAuthError> {
    if !policy.allow_otpauth_import() {
        return Err(OtpAuthError::InvalidParams);
    }

    if uri.is_empty() || uri.len() > MAX_OTP_AUTH_URI_LEN {
        return Err(OtpAuthError::InvalidUri);
    }

    let url = Url::parse(uri).map_err(|_| OtpAuthError::InvalidUri)?;

    if url.scheme() != "otpauth" {
        return Err(OtpAuthError::InvalidUri);
    }

    if url.host_str() != Some("totp") {
        return Err(OtpAuthError::InvalidUri);
    }

    // Path contains the label: "/Label" (percent-encoded)
    let raw_path = url.path().trim_start_matches('/');
    if raw_path.is_empty() {
        return Err(OtpAuthError::InvalidUri);
    }

    let decoded_label = percent_decode_str(raw_path)
        .decode_utf8()
        .map_err(|_| OtpAuthError::InvalidUri)?;

    // Some URIs use "Issuer:Account" as label
    let (issuer_from_label, account_from_label, title) = split_label(&decoded_label);

    // Query params
    let mut secret_b32: Option<String> = None;
    let mut issuer_param: Option<String> = None;
    let mut algorithm: TotpAlgorithm = TotpAlgorithm::Sha1;
    let mut digits: u8 = 6;
    let mut period_secs: u32 = 30;

    let mut pairs_seen = 0usize;
    for (k, v) in url.query_pairs() {
        pairs_seen += 1;
        if pairs_seen > MAX_QUERY_PAIRS {
            return Err(OtpAuthError::InvalidParams);
        }

        match k.as_ref() {
            "secret" => secret_b32 = Some(v.to_string()),
            "issuer" => issuer_param = Some(v.to_string()),
            "algorithm" => {
                algorithm = match v.as_ref() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => return Err(OtpAuthError::InvalidParams),
                };
            }
            "digits" => {
                digits = v.parse::<u8>().map_err(|_| OtpAuthError::InvalidParams)?;
            }
            "period" => {
                period_secs = v.parse::<u32>().map_err(|_| OtpAuthError::InvalidParams)?;
            }
            // Ignore unknown keys for compatibility
            _ => {}
        }
    }

    let secret_b32 = secret_b32.ok_or(OtpAuthError::InvalidParams)?;

    // Issuer policy:
    // - Prefer explicit issuer parameter
    // - Only fall back to label issuer if issuer parameter is missing
    let issuer_final = issuer_param.or(issuer_from_label);

    // Validate title/account/issuer using existing validators (bidi/zero-width/control)
    // Also apply a basic "script mixing" rule to reduce common homograph tricks
    validate_title(&title).map_err(map_entry_error)?;
    reject_script_mixing(&title).map_err(map_entry_error)?;

    if let Some(ref acc) = account_from_label {
        validate_username(acc).map_err(map_entry_error)?;
        reject_script_mixing(acc).map_err(map_entry_error)?;
    }

    if let Some(ref iss) = issuer_final {
        // Issuer is a display string, validate like a title
        validate_title(iss).map_err(map_entry_error)?;
        reject_script_mixing(iss).map_err(map_entry_error)?;
    }

    let totp = TotpSecret {
        issuer: issuer_final.map(|s| SecretString::new(s.into())),
        account_name: account_from_label.map(|s| SecretString::new(s.into())),
        secret_b32: SecretString::new(secret_b32.into()),
        digits,
        period_secs,
        algorithm,
    };

    // Type-level validation (includes strict alphabet and bounds)
    totp.validate().map_err(map_entry_error)?;

    Ok((title, totp))
}

/// Split a decoded otpauth label into optional issuer/account and a recommended title
///
/// Common patterns:
/// - "Issuer:account@example.com"
/// - "account@example.com"
///
/// Chosen options are:
/// - title = issuer if present, else full label
/// - account_name = account part if present
fn split_label(label: &str) -> (Option<String>, Option<String>, String) {
    let label = label.trim();

    if let Some((issuer, account)) = label.split_once(':') {
        let issuer = issuer.trim();
        let account = account.trim();

        let issuer_opt = (!issuer.is_empty()).then(|| issuer.to_string());
        let account_opt = (!account.is_empty()).then(|| account.to_string());

        let title = issuer_opt.clone().unwrap_or_else(|| label.to_string());
        return (issuer_opt, account_opt, title);
    }

    (None, None, label.to_string())
}

/// Reject gross homograph-style script mixing
///
/// # Security
/// Most common spoofing pattern targeted (ASCII mixed with Cyrillic/Greek letters) \
/// It does not attempt full Unicode confusable detection
fn reject_script_mixing(s: &str) -> Result<(), EntryError> {
    let mut has_ascii_alnum = false;
    let mut has_cyrillic = false;
    let mut has_greek = false;

    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            has_ascii_alnum = true;
            continue;
        }

        let u = ch as u32;
        // Cyrillic block + Cyrillic supplement (rough)
        if (0x0400..=0x04FF).contains(&u) || (0x0500..=0x052F).contains(&u) {
            has_cyrillic = true;
        }
        // Greek + Coptic (rough)
        if (0x0370..=0x03FF).contains(&u) {
            has_greek = true;
        }
    }

    if has_ascii_alnum && (has_cyrillic || has_greek) {
        return Err(EntryError::SuspiciousUnicode);
    }

    Ok(())
}

fn map_entry_error(_: EntryError) -> OtpAuthError {
    // Avoid leaking parsing details
    OtpAuthError::InvalidParams
}
