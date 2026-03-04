// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometric errors
//!
//! # Security
//! - Coarse-grained errors to avoid side-channel oracles

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BiometricError {
    /// Biometric operations are denied by policy (decoy, anti-debug soft policy)
    #[error("operation denied by policy")]
    PolicyDenied,

    /// Biometric backend is unavailable or not configured on the platform
    #[error("biometrics unavailable")]
    Unavailable,

    /// Biometric authentication failed or user canceled
    #[error("authentication failed")]
    AuthFailed,

    /// The backend returned invalid data
    #[error("invalid backend response")]
    InvalidResponse,

    /// Operation is not supported for this vault (e.g. duress enabled)
    #[error("operation not supported")]
    NotSupported,
}
