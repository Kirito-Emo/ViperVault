// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometric unlock integration
//!
//! # Security
//! - Denied in decoy policy
//! - Denied under restrictive runtime policy
//! - Not supported for duress-enabled vaults
//! - Master key is held in [`crate::memory::KeyMaterial`] and zeroized on drop
//! - Decrypted plaintext JSON is kept in a protected buffer until handed to the
//!   runtime lock manager
//! - Biometric unlock establishes a biometric-strength session rather than a
//!   strong master-password session

use crate::biometrics::{BiometricBackend, BiometricError};
use crate::core::policy::PolicyContext;
use crate::core::session::AuthenticationStrength;
use crate::core::VaultLockManager;
use crate::crypto::aead::decrypt_xchacha20poly1305;
use crate::memory::{KeyMaterial, SecretBytes};
use crate::vault::{ParsedVaultFile, StorageMode};
use std::time::Duration;

impl VaultLockManager {
    /// Unlock with a provided master key through the biometric path
    ///
    /// # Security
    /// - Only supports encrypted vaults
    /// - Not supported for duress-enabled vaults
    /// - Uses `header_bytes` as AEAD AAD to prevent header tampering
    /// - Denied by the centralized runtime policy
    pub async fn unlock_with_master_key(
        &self,
        policy: PolicyContext,
        parsed: &ParsedVaultFile,
        master_key: &KeyMaterial,
        timeout: Duration,
    ) -> Result<(), BiometricError> {
        if !policy.allow_biometric_unlock() {
            return Err(BiometricError::PolicyDenied);
        }

        let plaintext_json = unlock_vault_to_plaintext_json_with_master_key(parsed, master_key)?;
        // Biometric-path unlocks should not masquerade as strong master-password sessions
        self.unlock_with_plaintext_json_with_strength(
            plaintext_json,
            timeout,
            AuthenticationStrength::Biometric,
        )
            .await;
        Ok(())
    }

    /// Perform a high-level biometric unlock using the provided backend
    ///
    /// # Security
    /// - Denied by the centralized runtime policy
    /// - Not supported for duress-enabled vaults
    /// - The backend only releases a previously stored master key
    pub async fn unlock_with_biometrics(
        &self,
        policy: PolicyContext,
        parsed: &ParsedVaultFile,
        backend: &dyn BiometricBackend,
        vault_id: &[u8],
        timeout: Duration,
    ) -> Result<(), BiometricError> {
        if !policy.allow_biometric_unlock() {
            return Err(BiometricError::PolicyDenied);
        }

        if !backend.is_available() {
            return Err(BiometricError::Unavailable);
        }

        let mk = backend.unseal_master_key(vault_id)?;
        self.unlock_with_master_key(policy, parsed, &mk, timeout)
            .await
    }
}

/// Decrypt vault plaintext JSON using a provided master key
///
/// # Security
/// - Only supports encrypted vaults
/// - Not supported for duress-enabled vaults
/// - Maps failures to `AuthFailed` to avoid creating an oracle
/// - Returns the plaintext in a protected buffer
fn unlock_vault_to_plaintext_json_with_master_key(
    parsed: &ParsedVaultFile,
    master_key: &KeyMaterial,
) -> Result<SecretBytes, BiometricError> {
    if parsed.mode != StorageMode::Encrypted {
        return Err(BiometricError::AuthFailed);
    }

    // Duress-enabled vaults must use the password flow to preserve coercion semantics
    if parsed.header.duress.is_some() {
        return Err(BiometricError::NotSupported);
    }

    decrypt_xchacha20poly1305(
        master_key,
        &parsed.header.crypto.nonce,
        &parsed.payload,
        &parsed.header_bytes,
    )
    .map_err(|_| BiometricError::AuthFailed)
}
