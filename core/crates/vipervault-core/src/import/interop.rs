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
//! - Denied in decoy
//! - Denied under anti-debug soft policy
//! - Bounded input size and bounded record count
//! - Bounded per-line length (anti-DoS)
//! - Parsed payload must pass internal invariants before commit
//! - Quarantine keeps only the parsed payload (no raw bytes retained)

use super::ImportError;
use crate::core::{allow_clipboard_under_soft_policy, policy::PolicyContext};
use crate::entries::types::{EntryType, VaultEntry};
use crate::totp::decode::decode_base32_secret_strict;
use crate::vault::VaultPayload;
use secrecy::ExposeSecret;
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

/// Supported interop formats (future-proof)
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum InteropFormat {
    /// Provider-agnostic otpauth URI list (TOTP only)
    OtpAuthTotpUriList,
    /// Placeholder for future implementations
    Other,
}

/// Quarantined import result
///
/// # Security
/// - Holds sensitive material (never logged)
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

    /// Return the format
    pub fn format(&self) -> InteropFormat {
        self.format
    }
}

/// Import plaintext data into quarantine
///
/// # Security
/// - Denied in decoy mode
/// - Denied under anti-debug soft policy
pub fn import_interop_quarantine(
    policy: PolicyContext,
    intent: ImportIntent,
    format: InteropFormat,
    bytes: &[u8],
) -> Result<QuarantinedImport, ImportError> {
    if policy.is_decoy() {
        return Err(ImportError::PolicyDenied);
    }

    // Soft-policy (when a debugger is detected, sensitive operations are denied)
    if !allow_clipboard_under_soft_policy() {
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
/// - Denied in decoy mode
/// - Denied under anti-debug soft policy
/// - Re-validates invariants after merge
/// - Does not attempt deduplication at commit time (deterministic)
pub fn commit_quarantined_import_into_payload(
    policy: PolicyContext,
    existing: &mut VaultPayload,
    quarantined: QuarantinedImport,
) -> Result<(), ImportError> {
    if policy.is_decoy() {
        return Err(ImportError::PolicyDenied);
    }

    if !allow_clipboard_under_soft_policy() {
        return Err(ImportError::PolicyDenied);
    }

    let mut incoming = quarantined.into_payload().entries;
    if existing.entries.len().saturating_add(incoming.len()) > MAX_INTEROP_ENTRIES {
        return Err(ImportError::PayloadTooLarge);
    }

    existing.entries.append(&mut incoming);

    validate_payload_invariants(existing)?;

    Ok(())
}

/// Dedup key for interop-imported TOTP entries
///
/// # Security
/// Stores only hashes, never plaintext issuer/account/secret
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TotpDedupKey {
    issuer_h: [u8; 32],
    account_h: [u8; 32],
    secret_h: [u8; 32],
}

/// Minimal parser: a newline-separated list of `otpauth://totp/...` URIs
///
/// # Security
/// - Bounded number of lines
/// - Bounded per-line length (anti-DoS)
/// - Deduplicates by (issuer, account, secret-hash)
/// - Each URI is parsed via the hardened otpauth parser (policy-gated)
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

        let secret_raw = decode_base32_secret_strict(totp.secret_b32.expose_secret())
            .map_err(|_| ImportError::InvalidFormat)?;
        let secret_h = sha256_fixed(secret_raw.as_slice());

        let key = TotpDedupKey {
            issuer_h,
            account_h,
            secret_h,
        };

        if !seen.insert(key) {
            // Duplicate entry, skip deterministically
            continue;
        }

        let entry =
            VaultEntry::new_totp(title, totp, None).map_err(|_| ImportError::InvalidData)?;
        entries.push(entry);
    }

    Ok(VaultPayload { entries })
}

/// Validate payload invariants (strict for interop quarantine)
fn validate_payload_invariants(payload: &VaultPayload) -> Result<(), ImportError> {
    if payload.entries.len() > MAX_INTEROP_ENTRIES {
        return Err(ImportError::PayloadTooLarge);
    }

    for e in &payload.entries {
        if e.meta.entry_type != EntryType::Totp {
            return Err(ImportError::InvalidData);
        }

        let Some(ref t) = e.secret.totp else {
            return Err(ImportError::InvalidData);
        };

        // Validate TOTP parameters (bounds + strict alphabet)
        t.validate().map_err(|_| ImportError::InvalidData)?;

        // Basic consistency check: keep secret fields aligned
        if e.secret.secret.expose_secret() != t.secret_b32.expose_secret() {
            return Err(ImportError::InvalidData);
        }
    }

    Ok(())
}

fn sha256_fixed(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    let out = h.finalize();
    out.into()
}
