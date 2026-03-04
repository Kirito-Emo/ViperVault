// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! TOTP errors

use thiserror::Error;

/// TOTP engine errors
///
/// ## Security note
/// Errors are coarse-grained to avoid revealing sensitive details
#[derive(Debug, Error)]
pub enum TotpError {
    /// Invalid configuration or parameters
    #[error("invalid parameters")]
    InvalidParams,

    /// Base32 secret is malformed or unsupported
    #[error("invalid secret encoding")]
    InvalidSecret,

    /// Crypto failure (generic)
    #[error("crypto failure")]
    CryptoFailure,
}
