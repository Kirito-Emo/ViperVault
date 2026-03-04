// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Import errors
//!
//! # Security
//! Coarse-grained errors to avoid creating authentication/tamper oracles

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    /// Operation denied by policy (decoy or anti-debug soft policy)
    #[error("operation denied by policy")]
    PolicyDenied,

    /// Authentication failed (wrong password OR tampered data)
    #[error("authentication failed")]
    AuthFailed,

    /// Invalid or unsupported input format
    #[error("invalid format")]
    InvalidFormat,

    /// Payload too large (anti-DoS)
    #[error("payload too large")]
    PayloadTooLarge,

    /// Parsed content is invalid for the expected schema
    #[error("invalid data")]
    InvalidData,
}
