// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Integration test: CRUD operations on an unlocked vault
//!
//! Verifies:
//! - add / update / delete entry
//! - duplicate detection
//! - payload integrity after mutations
//! - locked-state failures
//! - not-found failures
//! - replacement updates
//! - summary/view consistency after mutations
//!
//! # Security
//! CRUD operations must:
//! - fail safely when the vault is locked
//! - preserve payload consistency across sequential mutations
//! - never resurrect removed entries
//! - validate updated fields through the normal entry validation boundary

use secrecy::ExposeSecret;
use std::time::Duration;
use vipervault_core::core::VaultLockManager;
use vipervault_core::entries::{EntryError, EntryUpdate, VaultEntry};
use vipervault_core::vault::VaultPayload;

/// Serialize an empty payload as plaintext JSON bytes
fn empty_payload_json() -> Vec<u8> {
    serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize payload")
}

/// Create a representative password entry
fn make_password_entry(
    title: &str,
    username: Option<&str>,
    secret: &str,
    note: Option<&str>,
) -> VaultEntry {
    VaultEntry::new_password(
        title.to_string(),
        username.map(str::to_string),
        secret.to_string(),
        note.map(str::to_string),
    )
    .expect("entry")
}

/// Add / update / delete must work on an unlocked vault
#[tokio::test]
async fn crud_add_update_delete_entry() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(60))
        .await;

    // Add
    let entry = make_password_entry(
        "GitHub",
        Some("octocat"),
        "initial-secret",
        Some("initial-note"),
    );

    let id = entry.meta.id;
    manager.add_entry(entry).await.expect("add entry");

    let summaries = manager.list_entries().await.expect("list entries");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, id);
    assert_eq!(summaries[0].expose_title(), "GitHub");

    // Update secret
    manager
        .update_entry_fields(id, EntryUpdate::SetSecret("updated-secret".to_string()))
        .await
        .expect("update secret");

    let view = manager
        .get_entry(id)
        .await
        .expect("get entry after secret update");
    assert_eq!(view.expose_title(), "GitHub");
    assert_eq!(view.expose_secret(), "updated-secret");

    // Update multiple fields
    manager
        .update_entry_fields(
            id,
            EntryUpdate::Replace {
                title: Some("GitHub Personal".to_string()),
                note: Some(Some("rotated note".to_string())),
                username: Some(Some("octocat2".to_string())),
                secret: Some("rotated-secret".to_string()),
                extra: None,
                totp: None,
            },
        )
        .await
        .expect("replace update");

    let view = manager
        .get_entry(id)
        .await
        .expect("get entry after replace");
    assert_eq!(view.expose_title(), "GitHub Personal");
    assert_eq!(view.expose_secret(), "rotated-secret");
    assert_eq!(
        view.username.expect("username must exist").expose_secret(),
        "octocat2"
    );
    assert_eq!(
        view.note.expect("note must exist").expose_secret(),
        "rotated note"
    );

    // Delete
    manager.delete_entry(id).await.expect("delete entry");

    let summaries = manager
        .list_entries()
        .await
        .expect("list entries after delete");
    assert!(summaries.is_empty());

    let err = manager.get_entry(id).await.unwrap_err();
    assert!(matches!(err, EntryError::EntryNotFound));
}

/// Duplicate entry IDs must be rejected
#[tokio::test]
async fn crud_duplicate_entry_rejected() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(60))
        .await;

    let entry = make_password_entry("Test", None, "secret", None);
    let id = entry.meta.id;
    manager.add_entry(entry).await.expect("add entry");

    let mut dup = make_password_entry("Other", None, "other", None);
    dup.meta.id = id;

    let err = manager.add_entry(dup).await.unwrap_err();
    assert!(matches!(err, EntryError::DuplicateEntry));
}

/// All CRUD operations must fail with `VaultLocked` when the vault is locked
#[tokio::test]
async fn crud_operations_fail_when_locked() {
    let manager = VaultLockManager::new();

    let entry = make_password_entry("Locked", None, "secret", None);
    let id = entry.meta.id;

    let err = manager.add_entry(entry).await.unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));

    let err = manager
        .update_entry_fields(id, EntryUpdate::SetSecret("new-secret".to_string()))
        .await
        .unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));

    let err = manager.delete_entry(id).await.unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));

    let err = manager.get_entry(id).await.unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));

    assert!(manager.list_entries().await.is_none());
}

/// Updating a non-existing entry must fail with `EntryNotFound`
#[tokio::test]
async fn update_non_existing_entry_is_rejected() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(60))
        .await;

    let random_id = uuid::Uuid::new_v4();

    let err = manager
        .update_entry_fields(random_id, EntryUpdate::SetTitle("new title".to_string()))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::EntryNotFound));
}

/// Deleting a non-existing entry must fail with `EntryNotFound`
#[tokio::test]
async fn delete_non_existing_entry_is_rejected() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(60))
        .await;

    let random_id = uuid::Uuid::new_v4();

    let err = manager.delete_entry(random_id).await.unwrap_err();
    assert!(matches!(err, EntryError::EntryNotFound));
}

/// Whole-entry replacement must preserve the requested ID and replace the content
#[tokio::test]
async fn update_entry_replaces_whole_object() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(60))
        .await;

    let original = make_password_entry("Old", Some("old-user"), "old-secret", Some("old-note"));
    let id = original.meta.id;
    manager.add_entry(original).await.expect("add original");

    let mut replacement =
        make_password_entry("New", Some("new-user"), "new-secret", Some("new-note"));
    replacement.meta.id = id;

    manager
        .update_entry(id, replacement)
        .await
        .expect("replace whole entry");

    let view = manager.get_entry(id).await.expect("get replaced entry");
    assert_eq!(view.expose_title(), "New");
    assert_eq!(view.expose_secret(), "new-secret");
    assert_eq!(
        view.username.expect("username must exist").expose_secret(),
        "new-user"
    );
    assert_eq!(
        view.note.expect("note must exist").expose_secret(),
        "new-note"
    );
}

/// Invalid field updates must be rejected and must not corrupt the stored entry
#[tokio::test]
async fn invalid_update_is_rejected_without_corrupting_entry() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(60))
        .await;

    let entry = make_password_entry("Title", Some("user"), "secret", Some("note"));
    let id = entry.meta.id;
    manager.add_entry(entry).await.expect("add entry");

    // Invalid empty title
    let err = manager
        .update_entry_fields(id, EntryUpdate::SetTitle("".to_string()))
        .await
        .unwrap_err();

    assert!(matches!(err, EntryError::EmptyField));

    // Original value must remain intact
    let view = manager
        .get_entry(id)
        .await
        .expect("get entry after failed update");
    assert_eq!(view.expose_title(), "Title");
    assert_eq!(view.expose_secret(), "secret");
    assert_eq!(
        view.username.expect("username must exist").expose_secret(),
        "user"
    );
}

/// Sequential mutations on multiple entries must preserve payload consistency
#[tokio::test]
async fn multiple_entries_remain_consistent_after_sequential_mutations() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(60))
        .await;

    let a = make_password_entry("A", Some("ua"), "sa", None);
    let b = make_password_entry("B", Some("ub"), "sb", Some("nb"));

    let id_a = a.meta.id;
    let id_b = b.meta.id;

    manager.add_entry(a).await.expect("add a");
    manager.add_entry(b).await.expect("add b");

    manager
        .update_entry_fields(id_a, EntryUpdate::SetSecret("sa2".to_string()))
        .await
        .expect("update a");

    manager.delete_entry(id_b).await.expect("delete b");

    let summaries = manager.list_entries().await.expect("list entries");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, id_a);
    assert_eq!(summaries[0].expose_title(), "A");

    let view_a = manager.get_entry(id_a).await.expect("get a");
    assert_eq!(view_a.expose_secret(), "sa2");

    let err_b = manager.get_entry(id_b).await.unwrap_err();
    assert!(matches!(err_b, EntryError::EntryNotFound));
}
