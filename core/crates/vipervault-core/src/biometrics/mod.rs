// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometric unlock support
//!
//! # Design
//! The core never performs platform biometric operations directly
//! Instead, it relies on a backend (provided via FFI) that can:
//! - prompt the user (Android BiometricPrompt / iOS LocalAuthentication),
//! - unseal a previously stored 32-byte vault master key,
//! - return it to the core as `KeyMaterial`
//!
//! # Security
//! - Biometrics are used as a gate to retrieve a key, not as a KDF
//! - Returned key material must be kept short-lived and wiped on drop

pub mod error;
pub mod ffi;
use crate::memory::KeyMaterial;
pub use error::BiometricError;

/// Backend abstraction for platform biometric operations
pub trait BiometricBackend: Send + Sync {
    /// Returns true if biometrics are available and configured
    fn is_available(&self) -> bool;

    /// Authenticate the user and unseal the vault master key
    ///
    /// # Parameters
    /// - `vault_id`: stable identifier
    ///
    /// # Returns
    /// 32-byte `KeyMaterial` on success
    fn unseal_master_key(&self, vault_id: &[u8]) -> Result<KeyMaterial, BiometricError>;
}
