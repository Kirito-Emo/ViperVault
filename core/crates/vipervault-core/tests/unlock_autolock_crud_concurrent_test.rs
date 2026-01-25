// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Integration test: unlock + auto-lock + concurrent CRUD
//!
//! # Scope
//! Verifies that concurrent CRUD operations are safe while the auto-lock timer expires
//!
//! # Security guarantees
//! - no panics
//! - no deadlocks
//! - CRUD does not resurrect unlocked state
//! - auto-lock always wins eventually

use std::sync::Arc;
use std::time::Duration;
use tokio::task::{spawn, yield_now};
use tokio::time::advance;
use vipervault_core::core::VaultLockManager;
use vipervault_core::entries::{EntryError, VaultEntry};
use vipervault_core::vault::VaultPayload;

/// Serialize an empty payload as plaintext JSON bytes
fn empty_payload_json() -> Vec<u8> {
    serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize payload")
}

#[tokio::test(start_paused = true)]
async fn concurrent_crud_while_auto_lock_triggers_is_safe() {
    let manager = Arc::new(VaultLockManager::new());

    // Unlock with a short timeout
    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(2))
        .await;

    assert!(manager.get_payload().await.is_some());

    let m = Arc::clone(&manager);

    // Spawn concurrent CRUD activity
    let crud_task = spawn(async move {
        for i in 0..20 {
            let entry = VaultEntry::new_password(
                format!("title-{i}"),
                Some(format!("user-{i}")),
                format!("secret-{i}"),
                None,
            )
            .expect("entry");

            // Attempt to add entry; may fail if auto-lock triggers
            match m.add_entry(entry).await {
                Ok(_) => {}
                Err(EntryError::VaultLocked) => break, // expected race outcome
                Err(e) => panic!("unexpected error: {e:?}"),
            }

            yield_now().await;
        }
    });

    // Let some CRUD happen
    advance(Duration::from_secs(1)).await;
    yield_now().await;

    // Advance past auto-lock deadline
    advance(Duration::from_secs(2)).await;
    yield_now().await;

    crud_task.await.expect("crud task");

    // Final state must be locked
    assert!(
        manager.get_payload().await.is_none(),
        "vault must be locked after timeout despite concurrent CRUD"
    );
}
