// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Concurrent integration tests for unlock + auto-lock + CRUD behavior
//!
//! # Scope
//! These tests validate that lock-state transitions and CRUD operations remain
//! coherent under concurrent or interleaved execution patterns
//!
//! Covered:
//! - concurrent reads while unlocked
//! - CRUD visibility before and after auto-lock
//! - interleaved activity and mutation
//! - operations after auto-lock fail safely
//!
//! # Security
//! Concurrency bugs around lock-state can expose secrets longer than intended
//! or allow stale unlocked state to leak across tasks

use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::advance;
use vipervault_core::core::VaultLockManager;
use vipervault_core::entries::{EntryError, EntryUpdate, VaultEntry};
use vipervault_core::vault::VaultPayload;

fn empty_payload_json() -> Vec<u8> {
    serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize")
}

async fn settle_runtime() {
    yield_now().await;
    yield_now().await;
    advance(Duration::ZERO).await;
    yield_now().await;
}

/// Concurrent reads while unlocked must observe a coherent payload
#[tokio::test(start_paused = true)]
async fn concurrent_reads_see_consistent_unlocked_state() {
    let manager = VaultLockManager::new();

    let entry =
        VaultEntry::new_secure_note("note".to_string(), "secret".to_string()).expect("entry");
    let id = entry.meta.id;

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&VaultPayload {
                entries: vec![entry],
            })
            .expect("serialize"),
            Duration::from_secs(10),
        )
        .await;

    settle_runtime().await;

    let (a, b) = tokio::join!(manager.get_entry(id), manager.get_entry(id));

    assert!(a.is_ok());
    assert!(b.is_ok());
    assert_eq!(a.expect("a").expose_title(), "note");
    assert_eq!(b.expect("b").expose_title(), "note");
}

/// CRUD changes must remain visible until auto-lock occurs, after which access must fail safely
#[tokio::test(start_paused = true)]
async fn crud_visibility_ends_after_auto_lock() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(3))
        .await;
    settle_runtime().await;

    let entry = VaultEntry::new_password("GitHub".to_string(), None, "secret".to_string(), None)
        .expect("entry");
    let id = entry.meta.id;

    manager.add_entry(entry).await.expect("add");
    assert_eq!(manager.list_entries().await.expect("list").len(), 1);

    advance(Duration::from_secs(4)).await;
    yield_now().await;

    let err = manager.get_entry(id).await.unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));

    assert!(manager.list_entries().await.is_none());
}

/// Interleaved activity and mutation must not break timer semantics
#[tokio::test(start_paused = true)]
async fn interleaved_activity_and_mutation_remain_coherent() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(3))
        .await;
    settle_runtime().await;

    let entry = VaultEntry::new_password(
        "Svc".to_string(),
        Some("user".to_string()),
        "pw".to_string(),
        None,
    )
    .expect("entry");
    let id = entry.meta.id;

    manager.add_entry(entry).await.expect("add");

    advance(Duration::from_secs(2)).await;
    manager.notify_activity();
    settle_runtime().await;

    manager
        .update_entry_fields(id, EntryUpdate::SetSecret("pw2".to_string()))
        .await
        .expect("update");

    advance(Duration::from_secs(2)).await;
    yield_now().await;

    let view = manager.get_entry(id).await.expect("still unlocked");
    assert_eq!(view.expose_secret(), "pw2");

    advance(Duration::from_secs(4)).await;
    yield_now().await;

    let err = manager.get_entry(id).await.unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));
}

/// Multiple sequential mutations before auto-lock must leave a coherent final state
#[tokio::test(start_paused = true)]
async fn sequential_mutations_before_auto_lock_leave_consistent_state() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(5))
        .await;
    settle_runtime().await;

    let entry_a =
        VaultEntry::new_password("A".to_string(), None, "sa".to_string(), None).expect("entry a");
    let entry_b =
        VaultEntry::new_password("B".to_string(), None, "sb".to_string(), None).expect("entry b");

    let id_a = entry_a.meta.id;
    let id_b = entry_b.meta.id;

    manager.add_entry(entry_a).await.expect("add a");
    manager.add_entry(entry_b).await.expect("add b");

    manager
        .update_entry_fields(id_a, EntryUpdate::SetSecret("sa2".to_string()))
        .await
        .expect("update a");

    manager.delete_entry(id_b).await.expect("delete b");

    let summaries = manager.list_entries().await.expect("list");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, id_a);

    let view_a = manager.get_entry(id_a).await.expect("get a");
    assert_eq!(view_a.expose_secret(), "sa2");

    advance(Duration::from_secs(6)).await;
    yield_now().await;

    let err = manager.get_entry(id_a).await.unwrap_err();
    assert!(matches!(err, EntryError::VaultLocked));
}
