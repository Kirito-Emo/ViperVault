// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Interoperability import (plaintext exports) with quarantine
//!
//! # Threat model
//! - Plaintext exports are highly sensitive
//! - They are also untrusted inputs (DoS, spoofing, data poisoning)
//!
//! # Security design
//! - Requires explicit user intent
//! - Denied in decoy mode
//! - Denied under anti-debug soft policy
//! - Bounded input size and bounded record count
//! - Bounded per-line length (anti-DoS)
//! - Parsed payload must pass internal invariants before commit
//! - Quarantine keeps only the parsed payload (no raw bytes retained)

use super::ImportError;
use crate::core::policy::PolicyContext;
use crate::entries::types::{EntryType, VaultEntry};
use crate::totp::decode::{canonicalize_base32_for_export, decode_base32_secret_strict};
use crate::vault::VaultPayload;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Maximum accepted interop import bytes (anti-DoS)
pub const MAX_INTEROP_IMPORT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Maximum number of entries allowed from an interop import (anti-DoS)
pub const MAX_INTEROP_ENTRIES: usize = 100_000;

/// Maximum accepted line length (anti-DoS)
pub const MAX_INTEROP_LINE_LEN: usize = 8 * 1024; // 8 KiB

/// Maximum aggregate bytes of user-visible text accepted from interop import (anti-DoS / RAM hygiene)
///
/// Counts UTF-8 byte lengths of:
/// - title
/// - issuer
/// - account_name
pub const MAX_INTEROP_AGG_TEXT_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

/// User intent required to import plaintext exports
///
/// # Security
/// This is meant to be produced only after an explicit confirmation step in the UI layer
#[derive(Debug, Clone, Copy)]
pub enum ImportIntent {
    /// Explicit user confirmation has been collected
    UserConfirmed,
}

/// Supported interop formats
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum InteropFormat {
    /// Provider-agnostic OTPAuth URI list (TOTP only)
    OtpAuthTotpUriList,
    /// Placeholder for future implementations
    Other,
}

/// Quarantined import result
///
/// # Security
/// Holds sensitive material (never logged)
#[derive(Debug)]
pub struct QuarantinedImport {
    format: InteropFormat,
    payload: VaultPayload,
}

impl QuarantinedImport {
    /// Return the parsed payload
    pub fn payload(&self) -> &VaultPayload {
        &self.payload
    }

    /// Consume and return the payload for commit
    pub fn into_payload(self) -> VaultPayload {
        self.payload
    }

    /// Return the interop format
    pub fn format(&self) -> InteropFormat {
        self.format
    }
}

/// Import plaintext data into quarantine
///
/// # Security
/// Denied by the centralized session/runtime policy
pub fn import_interop_quarantine(
    policy: PolicyContext,
    intent: ImportIntent,
    format: InteropFormat,
    bytes: &[u8],
) -> Result<QuarantinedImport, ImportError> {
    if !policy.allow_plaintext_import() {
        return Err(ImportError::PolicyDenied);
    }

    match intent {
        ImportIntent::UserConfirmed => {}
    }

    if bytes.is_empty() || bytes.len() > MAX_INTEROP_IMPORT_BYTES {
        return Err(ImportError::PayloadTooLarge);
    }

    let payload = match format {
        InteropFormat::OtpAuthTotpUriList => parse_otpauth_totp_list(policy, bytes)?,
        InteropFormat::Other => return Err(ImportError::InvalidFormat),
    };

    validate_payload_invariants(&payload)?;

    Ok(QuarantinedImport { format, payload })
}

/// Commit a quarantined import into an existing payload
///
/// # Security
/// - Denied by the centralized session/runtime policy
/// - Does not attempt deduplication at commit time
pub fn commit_quarantined_import_into_payload(
    policy: PolicyContext,
    existing: &mut VaultPayload,
    quarantined: QuarantinedImport,
) -> Result<(), ImportError> {
    if !policy.allow_plaintext_import() {
        return Err(ImportError::PolicyDenied);
    }

    let mut incoming = quarantined.into_payload().entries;
    if existing.entries.len().saturating_add(incoming.len()) > MAX_INTEROP_ENTRIES {
        return Err(ImportError::PayloadTooLarge);
    }

    existing.entries.append(&mut incoming);

    Ok(())
}

/// Deduplication key for imported TOTP entries
///
/// # Security
/// Stores only hashes, never plaintext issuer/account/secret
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TotpDedupKey {
    issuer_h: [u8; 32],
    account_h: [u8; 32],
    secret_h: [u8; 32],
}

/// Parse a newline-separated list of `otpauth://totp/...` URIs
///
/// # Security
/// - Bounded number of lines
/// - Bounded per-line length (anti-DoS)
/// - Deduplicates by `(issuer, account, secret-hash)`
/// - Each URI is parsed via the hardened OTPAuth parser
fn parse_otpauth_totp_list(
    policy: PolicyContext,
    bytes: &[u8],
) -> Result<VaultPayload, ImportError> {
    let s = std::str::from_utf8(bytes).map_err(|_| ImportError::InvalidFormat)?;

    let mut entries: Vec<VaultEntry> = Vec::new();
    let mut seen: HashSet<TotpDedupKey> = HashSet::new();

    let mut agg_text_bytes: usize = 0;

    for (idx, line) in s.lines().enumerate() {
        if idx >= MAX_INTEROP_ENTRIES {
            return Err(ImportError::PayloadTooLarge);
        }

        if line.len() > MAX_INTEROP_LINE_LEN {
            return Err(ImportError::PayloadTooLarge);
        }

        let uri = line.trim();
        if uri.is_empty() {
            continue;
        }

        if uri.len() > crate::otpauth::totp::MAX_OTP_AUTH_URI_LEN {
            return Err(ImportError::InvalidFormat);
        }

        let (title, totp) = crate::otpauth::totp::parse_totp_otpauth_uri(policy, uri)
            .map_err(|_| ImportError::InvalidFormat)?;

        // Aggregate text size cap (DoS/RAM hygiene)
        agg_text_bytes = agg_text_bytes
            .saturating_add(title.len())
            .saturating_add(
                totp.issuer
                    .as_ref()
                    .map(|s| s.expose_secret().len())
                    .unwrap_or(0),
            )
            .saturating_add(
                totp.account_name
                    .as_ref()
                    .map(|s| s.expose_secret().len())
                    .unwrap_or(0),
            );

        if agg_text_bytes > MAX_INTEROP_AGG_TEXT_BYTES {
            return Err(ImportError::PayloadTooLarge);
        }

        // Dedup key:
        // - Hash issuer/account as bytes (or empty)
        // - Decode secret strictly and hash raw bytes (normalizes padding/casing)
        let issuer_h = sha256_fixed(
            totp.issuer
                .as_ref()
                .map(|s| s.expose_secret().as_bytes())
                .unwrap_or(b""),
        );

        let account_h = sha256_fixed(
            totp.account_name
                .as_ref()
                .map(|s| s.expose_secret().as_bytes())
                .unwrap_or(b""),
        );

        let canonical_secret_b32 = canonicalize_base32_for_export(totp.secret_b32.expose_secret())
            .map_err(|_| ImportError::InvalidFormat)?;

        decode_base32_secret_strict(&canonical_secret_b32)
            .map_err(|_| ImportError::InvalidFormat)?;

        let secret_h = sha256_fixed(canonical_secret_b32.as_bytes());

        let key = TotpDedupKey {
            issuer_h,
            account_h,
            secret_h,
        };

        if !seen.insert(key) {
            // Duplicate entry, skip deterministically
            continue;
        }

        let mut totp = totp;
        totp.secret_b32 = SecretString::new(canonical_secret_b32.clone().into());

        let entry =
            VaultEntry::new_totp(title, totp, None).map_err(|_| ImportError::InvalidData)?;
        entries.push(entry);
    }

    Ok(VaultPayload { entries })
}

/// Validate payload invariants for quarantined interop imports
fn validate_payload_invariants(payload: &VaultPayload) -> Result<(), ImportError> {
    if payload.entries.len() > MAX_INTEROP_ENTRIES {
        return Err(ImportError::PayloadTooLarge);
    }

    for entry in &payload.entries {
        if entry.meta.entry_type != EntryType::Totp {
            return Err(ImportError::InvalidData);
        }

        let Some(ref totp) = entry.secret.totp else {
            return Err(ImportError::InvalidData);
        };

        totp.validate().map_err(|_| ImportError::InvalidData)?;

        if entry.secret.secret.expose_secret() != totp.secret_b32.expose_secret() {
            return Err(ImportError::InvalidData);
        }
    }

    Ok(())
}

/// Compute a fixed SHA-256 digest
fn sha256_fixed(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
