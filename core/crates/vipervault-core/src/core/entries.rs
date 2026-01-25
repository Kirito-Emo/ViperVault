// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! CRUD operations for vault entries
//!
//! # Security model
//! The manager stores decrypted data as `plaintext_json` (`Zeroizing<Vec<u8>>`)
//! Operations deserialize the payload temporarily, mutate it, and immediately
//! re-serialize back to `plaintext_json` to minimize secret exposure

use crate::core::VaultLockManager;
use crate::entries::{EntryError, EntrySummary, EntryUpdate, EntryView, VaultEntry};
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
}
