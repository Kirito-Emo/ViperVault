// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! TOTP generation and verification (RFC 6238)
//!
//! # Security notes
//! - Uses RustCrypto HMAC implementations
//! - Avoids generic `Digest` bounds (prevents digest version conflicts)
//! - Decodes secrets strictly using `base32ct`
//! - Uses bounded parameters (digits/period/window)

use super::decode::decode_base32_secret_strict;
use super::error::TotpError;
use super::format::format_totp_code;
use crate::entries::types::{TotpAlgorithm, TotpSecret};
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Minimum and maximum acceptable period (seconds)
pub const MIN_PERIOD_SECS: u32 = 10;
pub const MAX_PERIOD_SECS: u32 = 120;

/// Supported digits (TOTP typically uses 6 or 8)
pub const MIN_DIGITS: u8 = 6;
pub const MAX_DIGITS: u8 = 8;

/// Generate a TOTP code for a given unix time using a decoded secret
pub fn totp_generate_raw(
    secret_raw: &[u8],
    unix_time_secs: u64,
    period_secs: u32,
    digits: u8,
    algorithm: TotpAlgorithm,
) -> Result<u32, TotpError> {
    validate_params(period_secs, digits)?;

    let counter = unix_time_secs / period_secs as u64;
    let msg = counter.to_be_bytes();

    match algorithm {
        TotpAlgorithm::Sha1 => {
            let mac = hmac_sha1(secret_raw, &msg)?;
            dynamic_truncate(&mac, digits)
        }

        TotpAlgorithm::Sha256 => {
            let mac = hmac_sha256(secret_raw, &msg)?;
            dynamic_truncate(&mac, digits)
        }

        TotpAlgorithm::Sha512 => {
            let mac = hmac_sha512(secret_raw, &msg)?;
            dynamic_truncate(&mac, digits)
        }
    }
}

/// Generate a TOTP code from a stored [`TotpSecret`]
pub fn totp_generate_from_secret(totp: &TotpSecret, unix_time_secs: u64) -> Result<u32, TotpError> {
    totp.validate().map_err(|_| TotpError::InvalidParams)?;
    validate_params(totp.period_secs, totp.digits)?;

    let secret_raw: Zeroizing<Vec<u8>> =
        decode_base32_secret_strict(totp.secret_b32.expose_secret())?;

    totp_generate_raw(
        secret_raw.as_slice(),
        unix_time_secs,
        totp.period_secs,
        totp.digits,
        totp.algorithm,
    )
}

/// Verify a user-provided TOTP code using a time window
///
/// `window = 1` means check counters in [-1, 0, +1] steps
///
/// ## Security note
/// Returns only a boolean and does not reveal where the match happened
pub fn totp_verify(
    totp: &TotpSecret,
    unix_time_secs: u64,
    code: u32,
    window: u8,
) -> Result<bool, TotpError> {
    totp.validate().map_err(|_| TotpError::InvalidParams)?;
    validate_params(totp.period_secs, totp.digits)?;

    // Safety bound: large windows degrade security and increase CPU cost
    if window > 10 {
        return Err(TotpError::InvalidParams);
    }

    let secret_raw: Zeroizing<Vec<u8>> =
        decode_base32_secret_strict(totp.secret_b32.expose_secret())?;

    let base_counter = unix_time_secs / totp.period_secs as u64;

    // Side-channel hygiene: do not early-return on match
    let mut any_match: u8 = 0;

    for i in 0..=(window as i32 * 2) {
        let offset = i - window as i32;
        let counter = if offset.is_negative() {
            base_counter.saturating_sub(offset.wrapping_abs() as u64)
        } else {
            base_counter.saturating_add(offset as u64)
        };

        let msg = counter.to_be_bytes();

        let expected = match totp.algorithm {
            TotpAlgorithm::Sha1 => {
                dynamic_truncate(&hmac_sha1(secret_raw.as_slice(), &msg)?, totp.digits)?
            }

            TotpAlgorithm::Sha256 => {
                dynamic_truncate(&hmac_sha256(secret_raw.as_slice(), &msg)?, totp.digits)?
            }

            TotpAlgorithm::Sha512 => {
                dynamic_truncate(&hmac_sha512(secret_raw.as_slice(), &msg)?, totp.digits)?
            }
        };

        any_match |= (expected == code) as u8;
    }

    Ok(any_match != 0)
}

fn validate_params(period_secs: u32, digits: u8) -> Result<(), TotpError> {
    if !(MIN_PERIOD_SECS..=MAX_PERIOD_SECS).contains(&period_secs) {
        return Err(TotpError::InvalidParams);
    }

    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(TotpError::InvalidParams);
    }

    Ok(())
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> Result<[u8; 20], TotpError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| TotpError::CryptoFailure)?;
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.into())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; 32], TotpError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| TotpError::CryptoFailure)?;
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.into())
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> Result<[u8; 64], TotpError> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| TotpError::CryptoFailure)?;
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.into())
}

/// RFC 4226 dynamic truncation + modulo
fn dynamic_truncate(mac: &[u8], digits: u8) -> Result<u32, TotpError> {
    if mac.len() < 20 {
        return Err(TotpError::CryptoFailure);
    }

    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    if offset + 4 > mac.len() {
        return Err(TotpError::CryptoFailure);
    }

    let bin_code: u32 = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);

    let modulo = 10u32
        .checked_pow(digits as u32)
        .ok_or(TotpError::InvalidParams)?;
    Ok(bin_code % modulo)
}

/// Generate a formatted TOTP code (fixed-width, leading zeros preserved)
///
/// ## Security note
/// Returns `Zeroizing<String>` to reduce lifetime of the OTP in memory
pub fn totp_generate_formatted(
    totp: &TotpSecret,
    unix_time_secs: u64,
) -> Result<Zeroizing<String>, TotpError> {
    let code = totp_generate_from_secret(totp, unix_time_secs)?;
    format_totp_code(code, totp.digits)
}
