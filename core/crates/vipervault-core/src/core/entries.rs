// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! CRUD operations for vault entries
//!
//! # Security model
//! The manager stores decrypted data as `plaintext_json` (`Zeroizing<Vec<u8>>`)
//! Operations deserialize the payload temporarily, mutate it and immediately
//! re-serialize back to `plaintext_json` to minimize secret exposure
//!
//! Sensitive in-session operations are authorized through the manager-owned
//! session policy rather than relying on caller-supplied policy objects

use crate::clipboard::guard::ClipboardGuard;
use crate::core::VaultLockManager;
use crate::core::session::SensitiveOperation;
use crate::entries::{EntryError, EntrySummary, EntryUpdate, EntryView, VaultEntry};
use crate::totp::clipboard::totp_generate_and_copy_to_clipboard;
use secrecy::SecretString;
use std::time::Duration;
use uuid::Uuid;

impl VaultLockManager {
    /// Add a new entry to the unlocked vault
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `DuplicateEntry` if an entry with the same ID exists
    pub async fn add_entry(&self, entry: VaultEntry) -> Result<(), EntryError> {
        self.with_unlocked_payload_mut(|payload| {
            if payload.entries.iter().any(|e| e.meta.id == entry.meta.id) {
                return Err(EntryError::DuplicateEntry);
            }
            payload.entries.push(entry);
            Ok(())
        })
        .await
        .unwrap_or(Err(EntryError::VaultLocked))
    }

    /// Update an existing entry by replacing the whole object
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `EntryNotFound` if the entry does not exist
    pub async fn update_entry(
        &self,
        entry_id: Uuid,
        new_entry: VaultEntry,
    ) -> Result<(), EntryError> {
        self.with_unlocked_payload_mut(|payload| {
            let slot = payload
                .entries
                .iter_mut()
                .find(|e| e.meta.id == entry_id)
                .ok_or(EntryError::EntryNotFound)?;

            *slot = new_entry;
            Ok(())
        })
        .await
        .unwrap_or(Err(EntryError::VaultLocked))
    }

    /// Apply a granular update to an existing entry
    ///
    /// # Security
    /// - Validation is enforced inside `VaultEntry::apply_update`
    /// - Works only when the vault is unlocked
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `EntryNotFound` if the entry does not exist
    /// - validation errors depending on the update
    pub async fn update_entry_fields(
        &self,
        entry_id: Uuid,
        update: EntryUpdate,
    ) -> Result<(), EntryError> {
        self.with_unlocked_payload_mut(|payload| {
            let entry = payload
                .entries
                .iter_mut()
                .find(|e| e.meta.id == entry_id)
                .ok_or(EntryError::EntryNotFound)?;

            entry.apply_update(update)?;
            Ok(())
        })
        .await
        .unwrap_or(Err(EntryError::VaultLocked))
    }

    /// Delete an entry
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `EntryNotFound` if the entry does not exist
    pub async fn delete_entry(&self, entry_id: Uuid) -> Result<(), EntryError> {
        self.with_unlocked_payload_mut(|payload| {
            let original_len = payload.entries.len();
            payload.entries.retain(|e| e.meta.id != entry_id);

            if payload.entries.len() == original_len {
                return Err(EntryError::EntryNotFound);
            }
            Ok(())
        })
        .await
        .unwrap_or(Err(EntryError::VaultLocked))
    }

    /// List entry summaries for UI display
    ///
    /// # Security
    /// - Returns only a minimal set of fields needed for listing
    /// - Titles are returned as `SecretString` to reduce accidental exposure
    ///
    /// Returns `None` if the vault is locked
    pub async fn list_entries(&self) -> Option<Vec<EntrySummary>> {
        self.with_unlocked_payload(|payload| {
            payload.entries.iter().map(|e| e.to_summary()).collect()
        })
        .await
    }

    /// Retrieve a full decrypted entry view by ID
    ///
    /// # Security
    /// - Returns sensitive data only if the vault is unlocked
    /// - The returned value owns its secrets and wipes them on drop
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `EntryNotFound` if the entry does not exist
    pub async fn get_entry(&self, entry_id: Uuid) -> Result<EntryView, EntryError> {
        self.with_unlocked_payload(|payload| {
            payload
                .entries
                .iter()
                .find(|e| e.meta.id == entry_id)
                .map(|e| e.to_view())
                .ok_or(EntryError::EntryNotFound)
        })
        .await
        .unwrap_or(Err(EntryError::VaultLocked))
    }

    /// Retrieve a full decrypted entry view for a specific sensitive operation
    ///
    /// # Security
    /// This method uses manager-owned policy and session state to enforce:
    /// - unlocked state
    /// - centralized runtime policy
    /// - strong re-authentication requirements
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `PolicyDenied` if policy forbids the operation in the current session
    /// - `ReauthRequired` if strong re-authentication is currently required
    /// - `EntryNotFound` if the entry does not exist
    pub async fn get_entry_for_operation(
        &self,
        entry_id: Uuid,
        operation: SensitiveOperation,
    ) -> Result<EntryView, EntryError> {
        self.authorize_sensitive_operation(operation).await?;
        self.get_entry(entry_id).await
    }

    /// Reveal the secret of an entry through a manager-aware sensitive boundary
    ///
    /// # Security
    /// - Requires the vault to be unlocked
    /// - Enforces manager-owned runtime policy
    /// - Enforces strong re-authentication for secret reveal
    /// - Returns a wrapped secret rather than a raw plaintext string
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `PolicyDenied` if policy forbids the operation in the current session
    /// - `ReauthRequired` if strong re-authentication is currently required
    /// - `EntryNotFound` if the entry does not exist
    /// - `InvalidType` if the selected entry does not expose a direct secret
    pub async fn reveal_entry_secret(&self, entry_id: Uuid) -> Result<SecretString, EntryError> {
        self.reveal_entry_secret_for_operation(entry_id, SensitiveOperation::RevealSecret)
            .await
    }

    /// Reveal the secret of an entry for a specific sensitive operation
    ///
    /// # Design
    /// This keeps the operation explicit so callers can distinguish among
    /// reveal, copy and other exposure-prone semantics while sharing a single
    /// manager-owned authorization path
    ///
    /// # Security
    /// The returned secret is copied into a fresh `SecretString` wrapper
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `PolicyDenied` if policy forbids the operation in the current session
    /// - `ReauthRequired` if strong re-authentication is currently required
    /// - `EntryNotFound` if the entry does not exist
    /// - `InvalidType` if the selected entry does not expose a direct secret
    pub async fn reveal_entry_secret_for_operation(
        &self,
        entry_id: Uuid,
        operation: SensitiveOperation,
    ) -> Result<SecretString, EntryError> {
        let entry = self.get_entry_for_operation(entry_id, operation).await?;

        let secret = entry.expose_secret();
        if secret.is_empty() {
            return Err(EntryError::InvalidType);
        }

        Ok(SecretString::new(secret.to_owned().into()))
    }

    /// Copy the secret of an entry to clipboard through a manager-aware
    /// sensitive boundary
    ///
    /// # Security
    /// - Requires the vault to be unlocked
    /// - Enforces manager-owned runtime policy
    /// - Enforces strong re-authentication for secret copy
    /// - Uses `ClipboardGuard` for timeout-based auto-clear
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `PolicyDenied` if policy forbids the operation in the current session
    /// - `ReauthRequired` if strong re-authentication is currently required
    /// - `EntryNotFound` if the entry does not exist
    /// - `InvalidType` if the selected entry does not expose a direct secret
    pub async fn copy_entry_secret(
        &self,
        entry_id: Uuid,
        clipboard: &mut ClipboardGuard,
        timeout: Duration,
    ) -> Result<(), EntryError> {
        self.copy_entry_secret_for_operation(
            entry_id,
            SensitiveOperation::CopySecret,
            clipboard,
            timeout,
        )
        .await
    }

    /// Copy the secret of an entry for a specific sensitive operation
    ///
    /// # Design
    /// This shares the same manager-aware enforcement path used by reveal, while
    /// keeping copy semantics explicit for policy refinement
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `PolicyDenied` if policy forbids the operation in the current session
    /// - `ReauthRequired` if strong re-authentication is currently required
    /// - `EntryNotFound` if the entry does not exist
    /// - `InvalidType` if the selected entry does not expose a direct secret
    pub async fn copy_entry_secret_for_operation(
        &self,
        entry_id: Uuid,
        operation: SensitiveOperation,
        clipboard: &mut ClipboardGuard,
        timeout: Duration,
    ) -> Result<(), EntryError> {
        let secret = self
            .reveal_entry_secret_for_operation(entry_id, operation)
            .await?;

        clipboard.copy_with_timeout(&secret, timeout);
        Ok(())
    }

    /// Copy the current TOTP code of an entry to clipboard through a
    /// manager-aware sensitive boundary
    ///
    /// # Security
    /// - Requires the vault to be unlocked
    /// - Enforces manager-owned runtime policy
    /// - Enforces strong re-authentication for TOTP copy
    /// - Uses `ClipboardGuard` for timeout-based auto-clear
    /// - Delegates OTP generation to the low-level TOTP primitive only after
    ///   session checks have succeeded
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `PolicyDenied` if policy forbids the operation in the current session
    /// - `ReauthRequired` if strong re-authentication is currently required
    /// - `EntryNotFound` if the entry does not exist
    /// - `InvalidType` if the selected entry is not a TOTP entry
    /// - `InvalidData` if the stored TOTP configuration is inconsistent
    pub async fn copy_entry_totp(
        &self,
        entry_id: Uuid,
        unix_time_secs: u64,
        clipboard: &mut ClipboardGuard,
        timeout: Option<Duration>,
    ) -> Result<(), EntryError> {
        self.copy_entry_totp_for_operation(
            entry_id,
            SensitiveOperation::CopyTotp,
            unix_time_secs,
            clipboard,
            timeout,
        )
        .await
    }

    /// Copy the current TOTP code of an entry for a specific sensitive operation
    ///
    /// # Design
    /// This keeps the operation explicit so callers can distinguish between TOTP
    /// reveal/copy semantics while sharing the same manager-owned authorization path
    ///
    /// # Errors
    /// - `VaultLocked` if the vault is locked
    /// - `PolicyDenied` if policy forbids the operation in the current session
    /// - `ReauthRequired` if strong re-authentication is currently required
    /// - `EntryNotFound` if the entry does not exist
    /// - `InvalidType` if the selected entry is not a TOTP entry
    /// - `InvalidData` if the stored TOTP configuration is inconsistent
    pub async fn copy_entry_totp_for_operation(
        &self,
        entry_id: Uuid,
        operation: SensitiveOperation,
        unix_time_secs: u64,
        clipboard: &mut ClipboardGuard,
        timeout: Option<Duration>,
    ) -> Result<(), EntryError> {
        self.authorize_sensitive_operation(operation).await?;

        let entry = self.get_entry(entry_id).await?;
        let totp = entry.totp.as_ref().ok_or(EntryError::InvalidType)?;

        totp_generate_and_copy_to_clipboard(totp, unix_time_secs, clipboard, timeout)
            .map_err(|_| EntryError::InvalidData)
    }
}
