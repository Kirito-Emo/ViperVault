// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault errors
//!
//! This module defines all errors related to vault parsing, encoding and on-disk storage operations

use std::io;
use thiserror::Error;

/// Errors while parsing or encoding vault structures
#[derive(Debug, Error)]
pub enum VaultParseError {
    /// Magic bytes do not match the expected vault format
    #[error("invalid magic")]
    InvalidMagic,

    /// Vault format version is not supported by this build
    #[error("unsupported format version")]
    UnsupportedVersion,

    /// Storage mode is plaintext but plaintext vaults are not allowed
    #[error("plaintext storage mode is not allowed")]
    PlaintextNotAllowed,

    /// Storage mode is not recognized or not supported
    #[error("unsupported storage mode")]
    UnsupportedStorageMode,

    /// Vault header exceeds the maximum allowed size
    #[error("header too large")]
    HeaderTooLarge,

    /// Encrypted payload exceeds the maximum allowed size
    #[error("payload too large")]
    PayloadTooLarge,

    /// Ciphertext exceeds allowed bounds
    #[error("ciphertext too large")]
    CiphertextTooLarge,

    /// Extra unexpected bytes found after decoding the vault
    #[error("trailing bytes after vault data")]
    TrailingBytes,

    /// I/O error during parsing or encoding
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Serialization failure
    #[error("serialize error")]
    Serialize,

    /// Deserialization failure
    #[error("deserialize error")]
    Deserialize,
}

/// Errors while reading or writing vault files on disk
#[derive(Debug, Error)]
pub enum VaultStorageError {
    /// Provided path is invalid or has no parent directory
    #[error("invalid path")]
    InvalidPath,

    /// I/O error during file operations
    #[error("io error: {0}")]
    Io(io::Error),

    /// File lock acquisition or release failed
    #[error("file lock error: {0}")]
    Lock(io::Error),
}
