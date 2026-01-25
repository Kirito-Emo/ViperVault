// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Secret helpers
//!
//! # Security
//! This module provides small wrappers around `secrecy` and `zeroize` to make
//! secret handling consistent across the codebase

use secrecy::{ExposeSecret, SecretBox, SecretString};
use zeroize::{Zeroize, Zeroizing};

/// Wrapper for the master password
///
/// # Security
/// - Stored as `SecretString`
/// - Exposed only at trusted boundaries (KDF)
#[derive(Debug)]
pub struct MasterPassword(pub SecretString);

impl MasterPassword {
    /// Create a new master password from a `String`
    pub fn new(password: String) -> Self {
        Self(SecretString::new(password.into()))
    }

    /// Borrow the underlying secret
    pub fn as_secret(&self) -> &SecretString {
        &self.0
    }

    /// Expose the password as `&str`
    ///
    /// # Security
    /// Use only when strictly necessary (KDF)
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

/// 32-byte key material (e.g. derived master key, AEAD key)
///
/// # Security
/// Stored in `Zeroizing<[u8; 32]>` so memory is wiped on drop
#[derive(Debug)]
pub struct KeyMaterial(pub Zeroizing<[u8; 32]>);

impl KeyMaterial {
    /// Create key material from a fixed-size array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Arbitrary secret bytes that must be wiped on drop
///
/// For buffers that cannot be fixed-size arrays
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Secret binary blob stored on the heap with automatic zeroization
///
/// # Security
/// `Vec<u8>` alone does not guarantee wiping. Wrapping it in `Zeroizing`
/// ensures the underlying bytes are overwritten on drop
pub type SecretBlob = SecretBox<Zeroizing<Vec<u8>>>;

/// Ensure a buffer is zeroized in-place
///
/// Prefer `Zeroizing<T>` when possible; this is for explicit wipe needs
pub fn wipe_vec(mut v: Vec<u8>) {
    v.zeroize();
}
