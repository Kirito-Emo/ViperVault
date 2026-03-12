#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Emanuele Relmi

//! Structure-aware fuzz target for `otpauth://totp/...` parsing
//!
//! # Security
//! This target exercises URI parsing using protocol-shaped inputs rather than
//! raw random byte streams
//!
//! The objective is to explore:
//! - valid and near-valid URI layouts
//! - parameter-presence combinations
//! - label/issuer/account interactions
//! - bounded semantic variations
//!
//! The parser must remain panic-free for all generated cases

#[path = "support/structured.rs"]
mod structured;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use structured::{Base32Secret, SafeAccount, SafeDisplay, StructuredAlgorithm};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::otpauth::totp::parse_totp_otpauth_uri;
use vipervault_core::vault::duress::UnlockOutcome;

/// URI scheme selector
#[derive(Debug, Clone, Copy, Arbitrary)]
enum SchemeKind {
    /// Expected scheme
    OtpAuth,
    /// Alternative but invalid scheme
    Http,
    /// Deliberately invalid scheme token
    Garbage,
}

/// URI host selector
#[derive(Debug, Clone, Copy, Arbitrary)]
enum HostKind {
    /// Expected host for the parser
    Totp,
    /// Valid otpauth host, but wrong parser family
    Hotp,
    /// Deliberately invalid host token
    Garbage,
}

/// Structure-aware model for OTPAuth URI generation
#[derive(Debug, Clone, Arbitrary)]
struct StructuredOtpUriCase {
    /// URI scheme kind
    scheme: SchemeKind,

    /// URI host kind
    host: HostKind,

    /// Optional issuer encoded in the label path
    label_issuer: Option<SafeDisplay>,

    /// Optional account encoded in the label path
    label_account: Option<SafeAccount>,

    /// Fallback label when issuer/account split is not used
    bare_label: SafeDisplay,

    /// Optional explicit issuer query parameter
    explicit_issuer: Option<SafeDisplay>,

    /// Secret query parameter
    secret: Base32Secret,

    /// Whether the `secret=` query pair is included
    include_secret: bool,

    /// Whether the `algorithm=` query pair is included
    include_algorithm: bool,

    /// Whether the `digits=` query pair is included
    include_digits: bool,

    /// Whether the `period=` query pair is included
    include_period: bool,

    /// Algorithm selector
    algorithm: StructuredAlgorithm,

    /// Raw digits selector
    digits_selector: u8,

    /// Raw period selector
    period_selector: u8,
}

impl StructuredOtpUriCase {
    /// Build a URI string from the structured case
    fn build_uri(&self) -> String {
        let scheme = match self.scheme {
            SchemeKind::OtpAuth => "otpauth",
            SchemeKind::Http => "http",
            SchemeKind::Garbage => "not-a-real-scheme",
        };

        let host = match self.host {
            HostKind::Totp => "totp",
            HostKind::Hotp => "hotp",
            HostKind::Garbage => "garbage",
        };

        let label = match (&self.label_issuer, &self.label_account) {
            (Some(issuer), Some(account)) => format!("{}:{}", issuer.0, account.0),
            _ => self.bare_label.0.clone(),
        };

        let mut query = Vec::new();

        if self.include_secret {
            query.push(format!("secret={}", self.secret.0));
        }

        if let Some(issuer) = &self.explicit_issuer {
            query.push(format!("issuer={}", issuer.0));
        }

        if self.include_algorithm {
            let algorithm = match self.algorithm {
                StructuredAlgorithm::Sha1 => "SHA1",
                StructuredAlgorithm::Sha256 => "SHA256",
                StructuredAlgorithm::Sha512 => "SHA512",
            };
            query.push(format!("algorithm={algorithm}"));
        }

        if self.include_digits {
            let digits = structured::digits_from_selector(self.digits_selector);
            query.push(format!("digits={digits}"));
        }

        if self.include_period {
            let period = structured::period_from_selector(self.period_selector);
            query.push(format!("period={period}"));
        }

        let mut uri = format!("{scheme}://{host}/{label}");
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(&query.join("&"));
        }

        uri
    }
}

fuzz_target!(|case: StructuredOtpUriCase| {
    let uri = case.build_uri();
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let _ = parse_totp_otpauth_uri(policy, &uri);
});
