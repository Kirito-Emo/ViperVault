// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! TOTP formatting helpers
//!
//! # Security notes
//! - The returned string is `Zeroizing<String>` to reduce secret lifetime in memory
//! - Leading zeros are preserved to match expected OTP length
//! - Callers should avoid logging formatted OTP values

use super::error::TotpError;
use zeroize::Zeroizing;

/// Format a numeric TOTP code into a fixed-width decimal string
///
/// ## Parameters
/// - `code`: the numeric code returned by the engine
/// - `digits`: fixed width (typically 6 or 8)
///
/// ## Security note
/// OTP values are short-lived secrets; always treat them as sensitive
pub fn format_totp_code(code: u32, digits: u8) -> Result<Zeroizing<String>, TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidParams);
    }

    // Ensure the numeric value fits the requested digit width
    let modulo = 10u32
        .checked_pow(digits as u32)
        .ok_or(TotpError::InvalidParams)?;
    let normalized = code % modulo;

    Ok(Zeroizing::new(format!(
        "{:0width$}",
        normalized,
        width = digits as usize
    )))
}
