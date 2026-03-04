// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! OTPAuth parser errors

use thiserror::Error;

/// OTPAuth parsing errors
///
/// ## Security note
/// Errors are intentionally coarse-grained
#[derive(Debug, Error)]
pub enum OtpAuthError {
    /// Generic parse failure
    #[error("parse error")]
    ParseError,

    /// Malformed or unsupported URI
    #[error("invalid otpauth uri")]
    InvalidUri,

    /// Unsupported or unsafe parameters
    #[error("invalid parameters")]
    InvalidParams,

    /// Export denied by policy (e.g. decoy vault).
    #[error("operation denied by policy")]
    PolicyDenied,
}
