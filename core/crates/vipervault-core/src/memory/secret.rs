// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

/// Wrapper for the master password bytes
///
/// # Security
/// - Prevents accidental logging via `Debug`/`Display`
/// - Ensures the underlying memory is wiped on drop
/// - Keeps password material as raw bytes
///
/// # Notes
/// - This type is intended for short-lived use during unlock only
/// - It cannot wipe OS keyboard buffers or other copies made outside this process
pub struct MasterPassword(SecretBox<[u8]>);

impl MasterPassword {
    /// Creates a [`MasterPassword`] from UTF-8 text
    ///
    /// # Security
    /// This converts the password into bytes and wipes the original `String` buffer
    pub fn from_string(mut password: String) -> Self {
        let bytes = password.as_bytes().to_vec();
        // Best-effort wipe of the original String buffer.
        password.zeroize();
        Self::from_bytes(bytes)
    }

    /// Creates a [`MasterPassword`] from raw bytes
    ///
    /// # Security
    /// Prefer this in internal code paths to avoid extra conversions/copies
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        // Convert Vec<u8> into a boxed slice for a stable, wipe-on-drop allocation.
        let boxed: Box<[u8]> = bytes.into_boxed_slice();
        Self(SecretBox::new(boxed))
    }

    /// Returns the password bytes
    ///
    /// # Security
    /// The returned slice is a view into the secret; avoid cloning unless necessary
    pub fn as_bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterPassword(**redacted**)")
    }
}
