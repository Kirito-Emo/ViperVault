// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Errors for signed backup container

use thiserror::Error;

/// Errors for signed backup encoding/decoding
#[derive(Debug, Error)]
pub enum BackupError {
    /// Operation denied by policy (e.g. decoy vault)
    #[error("operation denied by policy")]
    PolicyDenied,

    /// Invalid or unsupported backup format
    #[error("invalid backup format")]
    InvalidFormat,

    /// Backup version not supported
    #[error("unsupported backup version")]
    UnsupportedVersion,

    /// Backup payload too large (DoS guard)
    #[error("payload too large")]
    PayloadTooLarge,

    /// Serialization failure
    #[error("serialization error")]
    Serialize,

    /// Deserialization failure
    #[error("deserialization error")]
    Deserialize,

    /// Signature verification failed or password is wrong
    ///
    /// # Security
    /// Not distinguishing between "wrong password" and "tampered backup" is necessary to avoid oracle behavior
    #[error("authentication failed")]
    AuthFailed,
}
