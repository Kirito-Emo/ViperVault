// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Integration test: CRUD operations on an unlocked vault
//!
//! Verifies:
//! - add / update / delete entry
//! - duplicate detection
//! - payload integrity after mutations

use std::time::Duration;
use vipervault_core::core::VaultLockManager;
use vipervault_core::entries::{EntryUpdate, VaultEntry};
use vipervault_core::vault::VaultPayload;

#[tokio::test]
async fn crud_add_update_delete_entry() {
    let manager = VaultLockManager::new();

    // Unlock with empty payload
    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload { entries: vec![] }).unwrap(),
            Duration::from_secs(60),
        )
        .await;

    // Add
    let entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "initial-secret".to_string(),
        Some("note".to_string()),
    )
    .unwrap();

    let id = entry.meta.id;
    manager.add_entry(entry).await.expect("add entry");

    let summaries = manager.list_entries().await.unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].expose_title(), "GitHub");

    // Update (granular)
    manager
        .update_entry_fields(id, EntryUpdate::SetSecret("updated-secret".to_string()))
        .await
        .expect("update secret");

    let view = manager.get_entry(id).await.expect("get entry");
    assert_eq!(view.expose_secret(), "updated-secret");

    // Delete
    manager.delete_entry(id).await.expect("delete entry");
    let summaries = manager.list_entries().await.unwrap();
    assert!(summaries.is_empty());
}

#[tokio::test]
async fn crud_duplicate_entry_rejected() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload { entries: vec![] }).unwrap(),
            Duration::from_secs(60),
        )
        .await;

    let entry =
        VaultEntry::new_password("Test".to_string(), None, "secret".to_string(), None).unwrap();

    let id = entry.meta.id;
    manager.add_entry(entry).await.unwrap();

    // Force duplicate ID
    let mut dup =
        VaultEntry::new_password("Other".to_string(), None, "other".to_string(), None).unwrap();
    dup.meta.id = id;

    let err = manager.add_entry(dup).await.unwrap_err();
    assert!(matches!(
        err,
        vipervault_core::entries::EntryError::DuplicateEntry
    ));
}
