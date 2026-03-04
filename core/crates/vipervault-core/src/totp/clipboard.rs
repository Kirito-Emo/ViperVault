// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Secure TOTP clipboard integration
//!
//! # Security design
//! - OTP is generated on demand
//! - Formatted OTP is handled as `Zeroizing<String>`
//! - Clipboard is cleared automatically after timeout by `ClipboardGuard`
//! - Clipboard is denied under active debugger (soft policy)

use super::engine::totp_generate_formatted;
use super::error::TotpError;
use crate::clipboard::guard::ClipboardGuard;
use crate::core::antidebug::allow_clipboard_under_soft_policy;
use crate::entries::types::TotpSecret;
use secrecy::SecretString;
use std::time::Duration;
use zeroize::Zeroizing;

/// Default clipboard timeout for OTP
pub const DEFAULT_OTP_CLIPBOARD_TIMEOUT_SECS: u64 = 30;

/// Generate a formatted TOTP code and copy it to clipboard with auto-clear
///
/// ## Parameters
/// - `totp`: TOTP configuration stored in vault
/// - `unix_time_secs`: current unix timestamp seconds
/// - `clipboard`: clipboard guard instance
/// - `timeout`: optional timeout override
///
/// ## Security notes
/// - Denied if debugger detected (soft policy)
/// - Avoid logging or persisting the generated OTP
pub fn totp_generate_and_copy_to_clipboard(
    totp: &TotpSecret,
    unix_time_secs: u64,
    clipboard: &mut ClipboardGuard,
    timeout: Option<Duration>,
) -> Result<(), TotpError> {
    if !allow_clipboard_under_soft_policy() {
        return Err(TotpError::InvalidParams);
    }

    let formatted: Zeroizing<String> = totp_generate_formatted(totp, unix_time_secs)?;
    let timeout = timeout.unwrap_or(Duration::from_secs(DEFAULT_OTP_CLIPBOARD_TIMEOUT_SECS));

    // Convert into `SecretString` because ClipboardGuard expects a secret wrapper
    // The guard is responsible for managing clipboard lifetime and auto-clear
    let otp_secret = SecretString::new(formatted.to_string().into());

    clipboard.copy_with_timeout(&otp_secret, timeout);

    Ok(())
}
