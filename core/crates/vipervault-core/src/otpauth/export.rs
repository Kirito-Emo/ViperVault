// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! OTPAuth export utilities
//!
//! - TOTP only
//! - Generates `otpauth://totp/...` URIs for migration/sharing
//!
//! # Security notes
//! - Returned URI contains the shared secret: treat it as highly sensitive
//! - Use only at explicit user request and avoid logging

use super::error::OtpAuthError;
use crate::entries::types::{TotpAlgorithm, TotpSecret};
use crate::totp::decode::canonicalize_base32_for_export;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use secrecy::ExposeSecret;

/// Generate an `otpauth://totp/...` URI from a [`TotpSecret`]
///
/// ## Parameters
/// - `title`: user-visible label (entry title)
/// - `totp`: TOTP configuration
///
/// ## Security note
/// The returned string embeds the secret
pub fn export_totp_otpauth_uri(title: &str, totp: &TotpSecret) -> Result<String, OtpAuthError> {
    totp.validate().map_err(|_| OtpAuthError::InvalidParams)?;

    let label = utf8_percent_encode(title, NON_ALPHANUMERIC).to_string();
    let issuer: Option<String> = totp.issuer.as_ref().map(|s| s.expose_secret().to_string());
    let account: Option<String> = totp
        .account_name
        .as_ref()
        .map(|s| s.expose_secret().to_string());

    // Prefer `Issuer:Account` label if both are available
    let label_path = match (issuer.as_deref(), account.as_deref()) {
        (Some(iss), Some(acc)) => {
            let combined = format!("{iss}:{acc}");
            utf8_percent_encode(&combined, NON_ALPHANUMERIC).to_string()
        }
        _ => label,
    };

    let alg = match totp.algorithm {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    };

    // Canonicalize secret for maximum interoperability (uppercase, strip '=', remove whitespace/hyphens)
    let secret = canonicalize_base32_for_export(totp.secret_b32.expose_secret())
        .map_err(|_| OtpAuthError::InvalidParams)?;

    // Build query parameters
    let mut query: Vec<(String, String)> = vec![
        ("secret".to_string(), secret),
        ("algorithm".to_string(), alg.to_string()),
        ("digits".to_string(), totp.digits.to_string()),
        ("period".to_string(), totp.period_secs.to_string()),
    ];

    if let Some(iss) = issuer {
        query.push(("issuer".to_string(), iss));
    }

    let query_str = query
        .into_iter()
        .map(|(k, v)| {
            let k_enc = utf8_percent_encode(&k, NON_ALPHANUMERIC).to_string();
            let v_enc = utf8_percent_encode(&v, NON_ALPHANUMERIC).to_string();
            format!("{k_enc}={v_enc}")
        })
        .collect::<Vec<_>>()
        .join("&");

    Ok(format!("otpauth://totp/{label_path}?{query_str}"))
}
