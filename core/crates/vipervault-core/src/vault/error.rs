// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use std::io;

/// Errors returned while parsing/serializing the vault container.
///
/// # Security
/// Errors are intentionally generic to avoid leaking details.
#[derive(Debug, thiserror::Error)]
pub enum VaultParseError {
    /// The container magic does not match the expected value.
    #[error("invalid magic")]
    InvalidMagic,

    /// The container format version is unsupported.
    #[error("unsupported format version")]
    UnsupportedVersion,

    /// The payload storage mode is unsupported.
    #[error("unsupported storage mode")]
    UnsupportedStorageMode,

    /// Plaintext payloads are not allowed in this context.
    #[error("plaintext mode not allowed")]
    PlaintextNotAllowed,

    /// The serialized header exceeds hard bounds.
    #[error("header too large")]
    HeaderTooLarge,

    /// The payload exceeds hard bounds.
    #[error("payload too large")]
    PayloadTooLarge,

    /// The file contains extra trailing bytes (tampering/padding).
    #[error("trailing bytes detected")]
    TrailingBytes,

    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// JSON encode/serialize failed.
    #[error("serialize error")]
    Serialize,

    /// JSON decode/deserialize failed.
    #[error("deserialize error")]
    Deserialize,
}
