// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Base32 decoding utilities for TOTP
//!
//! # Security notes
//! - Strict decoding: RFC 4648 base32 alphabet
//! - Bounded length to avoid DoS allocations
//! - Result is stored in `Zeroizing<Vec<u8>>`
//! - Enforces a minimum secret length after decoding (entropy floor)

use super::error::TotpError;
use base32ct::{Base32, Encoding};
use zeroize::Zeroizing;

/// Maximum accepted Base32 secret length (characters)
pub const MAX_SECRET_B32_LEN: usize = 1024;

/// Minimum decoded secret length (bytes)
///
/// Enforce a baseline entropy floor
pub const MIN_SECRET_RAW_LEN: usize = 16;

/// Decode a Base32 secret into raw bytes (strict RFC 4648)
///
/// ## Accepted format
/// - RFC 4648 Base32 alphabet (A-Z, 2-7) with optional '=' padding
/// - No spaces, no hyphens, no lowercase
pub fn decode_base32_secret_strict(secret_b32: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    if secret_b32.is_empty() || secret_b32.len() > MAX_SECRET_B32_LEN {
        return Err(TotpError::InvalidSecret);
    }

    if !secret_b32.is_ascii() {
        return Err(TotpError::InvalidSecret);
    }

    // Allocate output buffer with the maximum possible decoded length for this input
    let max_out = (secret_b32.len() * 5).div_ceil(8);
    let mut out = vec![0u8; max_out];

    let decoded_len = {
        let decoded = Base32::decode(secret_b32.as_bytes(), &mut out)
            .map_err(|_| TotpError::InvalidSecret)?;
        decoded.len()
    };
    out.truncate(decoded_len);

    if out.len() < MIN_SECRET_RAW_LEN {
        return Err(TotpError::InvalidSecret);
    }

    Ok(Zeroizing::new(out))
}

/// Canonicalize a stored Base32 secret for export
///
/// # Security
/// - Uppercases ASCII letters
/// - Strips whitespace and hyphens
/// - Strips trailing '=' padding
///
/// # Note
/// This function is intended for export only
pub fn canonicalize_base32_for_export(secret_b32: &str) -> Result<String, TotpError> {
    if secret_b32.is_empty() || secret_b32.len() > MAX_SECRET_B32_LEN {
        return Err(TotpError::InvalidSecret);
    }

    if !secret_b32.is_ascii() {
        return Err(TotpError::InvalidSecret);
    }

    let mut s: String = secret_b32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    while s.ends_with('=') {
        s.pop();
    }

    if s.is_empty() {
        return Err(TotpError::InvalidSecret);
    }

    Ok(s)
}
