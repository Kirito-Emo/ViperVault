// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometric unlock integration
//!
//! # Security
//! - Denied in decoy policy
//! - Denied under anti-debug soft policy
//! - Not supported for duress-enabled vaults (fallback to password unlock)
//! - Master key is held in `KeyMaterial` (zeroized on drop)

use crate::biometrics::{BiometricBackend, BiometricError};
use crate::core::VaultLockManager;
use crate::core::policy::PolicyContext;
use crate::crypto::aead::decrypt_xchacha20poly1305;
use crate::memory::KeyMaterial;
use crate::vault::{ParsedVaultFile, StorageMode};
use std::time::Duration;
use zeroize::Zeroizing;

impl VaultLockManager {
    /// Unlock with a provided master key (biometrics path)
    ///
    /// # Security
    /// - Only supports non-duress encrypted vaults
    /// - Uses `header_bytes` as AAD to prevent header tampering
    /// - Denied under soft-policy debugger detection
    pub async fn unlock_with_master_key(
        &self,
        policy: PolicyContext,
        parsed: &ParsedVaultFile,
        master_key: &KeyMaterial,
        timeout: Duration,
    ) -> Result<(), BiometricError> {
        if policy.is_decoy() {
            return Err(BiometricError::PolicyDenied);
        }

        if !crate::core::allow_clipboard_under_soft_policy() {
            return Err(BiometricError::PolicyDenied);
        }

        let pt = unlock_vault_to_plaintext_json_with_master_key(parsed, master_key)?;
        self.unlock_with_plaintext_json(pt.to_vec(), timeout).await;
        Ok(())
    }

    /// High-level biometric unlock
    ///
    /// # Security
    /// - Denied in decoy policy
    /// - Denied under soft-policy debugger detection
    /// - Not supported for duress-enabled vaults
    pub async fn unlock_with_biometrics(
        &self,
        policy: PolicyContext,
        parsed: &ParsedVaultFile,
        backend: &dyn BiometricBackend,
        vault_id: &[u8],
        timeout: Duration,
    ) -> Result<(), BiometricError> {
        if policy.is_decoy() {
            return Err(BiometricError::PolicyDenied);
        }

        if !crate::core::allow_clipboard_under_soft_policy() {
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
/// - Maps failures to `AuthFailed` (no oracle)
fn unlock_vault_to_plaintext_json_with_master_key(
    parsed: &ParsedVaultFile,
    master_key: &KeyMaterial,
) -> Result<Zeroizing<Vec<u8>>, BiometricError> {
    if parsed.mode != StorageMode::Encrypted {
        return Err(BiometricError::AuthFailed);
    }

    // Duress-enabled vaults must use password flow to preserve coercion semantics
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
