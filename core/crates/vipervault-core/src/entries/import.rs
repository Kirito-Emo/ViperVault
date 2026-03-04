// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entry import helpers
//!
//! - TOTP import from `otpauth://` URIs policy-controlled
//!
//! # Security notes
//! - Parsing is strict and validated
//! - Errors are coarse-grained to avoid becoming an oracle
//! - Returned entries keep secrets wrapped and ready for vault encryption
//! - Decoy sessions must deny importing real secrets by default

use crate::core::policy::PolicyContext;
use crate::entries::error::EntryError;
use crate::entries::types::VaultEntry;
use crate::otpauth::totp::parse_totp_otpauth_uri;

/// Create a new TOTP vault entry from an `otpauth://totp/...` URI with policy enforcement
///
/// ## Parameters
/// - `policy`: the PolicyContext
/// - `uri`: the `otpauth://` URI (typically from QR scanning or clipboard)
/// - `note`: optional note to attach to the entry
///
/// ## Returns
/// A `VaultEntry` with `EntryType::Totp` and validated [`crate::entries::types::TotpSecret`]
///
/// ## Security note
/// The returned entry must only be persisted inside an encrypted vault payload
/// - Denies import in decoy mode (safe default)
/// - Strict parsing rejects malformed or suspicious inputs
pub fn import_totp_from_otpauth_uri_with_policy(
    policy: PolicyContext,
    uri: &str,
    note: Option<String>,
) -> Result<VaultEntry, EntryError> {
    let (title, totp) = parse_totp_otpauth_uri(policy, uri).map_err(|_| EntryError::InvalidType)?;
    VaultEntry::new_totp(title, totp, note)
}
