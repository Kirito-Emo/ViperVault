// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Auto-lock functional tests
//!
//! # Scope
//! These tests validate the normal (non-adversarial) behavior of the
//! `VaultLockManager` auto-lock logic:
//! - initial locked state
//! - unlock + timeout
//! - activity-based timer reset
//! - manual lock override
//! - re-unlock behavior
//!
//! # Security
//! These tests ensure that decrypted secrets are not kept in memory
//! longer than intended under normal usage.

use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::advance;
use vipervault_core::core::VaultLockManager;
use vipervault_core::vault::VaultPayload;

/// Serialize an empty payload as plaintext JSON bytes
fn empty_payload_json() -> Vec<u8> {
    serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize empty payload")
}

/// Serialize a payload with a single entry as plaintext JSON bytes
fn non_empty_payload_json() -> Vec<u8> {
    let entry = vipervault_core::entries::types::VaultEntry::new_secure_note(
        "note".to_string(),
        "secret".to_string(),
    )
    .expect("entry");

    serde_json::to_vec(&VaultPayload {
        entries: vec![entry],
    })
    .expect("serialize payload")
}

/// Allow spawned tasks to run and arm timers
async fn settle_runtime() {
    yield_now().await;
    yield_now().await;
    advance(Duration::ZERO).await;
    yield_now().await;
}

/// The vault must start in a locked state
#[tokio::test(start_paused = true)]
async fn starts_locked() {
    let manager = VaultLockManager::new();

    settle_runtime().await;

    assert!(
        manager.get_payload().await.is_none(),
        "vault must start locked"
    );
}

/// Unlocking the vault must auto-lock it after the timeout expires
#[tokio::test(start_paused = true)]
async fn unlock_then_auto_lock_after_timeout() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(2))
        .await;

    settle_runtime().await;

    // Before timeout: unlocked
    advance(Duration::from_secs(1)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_some());

    // After timeout: locked
    advance(Duration::from_secs(2)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// User activity must reset the auto-lock timer
#[tokio::test(start_paused = true)]
async fn activity_resets_auto_lock_timer() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(3))
        .await;

    settle_runtime().await;

    // Advance some time, but not enough to lock
    advance(Duration::from_secs(2)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_some());

    // Notify activity -> timer reset
    manager.notify_activity();
    settle_runtime().await;

    // Advance again; should still be unlocked
    advance(Duration::from_secs(2)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_some());

    // Quiet period longer than timeout -> lock
    advance(Duration::from_secs(4)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// Repeated activity must keep the vault unlocked until a quiet period occurs
#[tokio::test(start_paused = true)]
async fn repeated_activity_keeps_unlocked_until_quiet_period() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(2))
        .await;

    settle_runtime().await;

    for _ in 0..5 {
        advance(Duration::from_secs(1)).await;
        manager.notify_activity();
        settle_runtime().await;
        assert!(manager.get_payload().await.is_some());
    }

    // Quiet period
    advance(Duration::from_secs(3)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// Manual lock must immediately lock the vault and cancel auto-lock
#[tokio::test(start_paused = true)]
async fn manual_lock_is_immediate_and_cancels_timer() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(10))
        .await;

    settle_runtime().await;

    manager.lock().await;

    assert!(
        manager.get_payload().await.is_none(),
        "manual lock must be immediate"
    );

    // Even if time advances, vault must remain locked
    advance(Duration::from_secs(20)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// Re-unlocking after a manual or automatic lock must restart the timer
/// and replace the previous unlocked state
#[tokio::test(start_paused = true)]
async fn re_unlock_restarts_timer_and_replaces_state() {
    let manager = VaultLockManager::new();

    // First unlock
    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(2))
        .await;

    settle_runtime().await;

    advance(Duration::from_secs(3)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());

    // Re-unlock
    manager
        .unlock_with_plaintext_json(non_empty_payload_json(), Duration::from_secs(5))
        .await;

    settle_runtime().await;

    let payload = manager
        .get_payload()
        .await
        .expect("payload after re-unlock");
    assert_eq!(payload.entries.len(), 1);

    // Timer must apply to the new unlock
    advance(Duration::from_secs(6)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// Boundary: zero timeout must lock on the next timer turn
#[tokio::test(start_paused = true)]
async fn zero_timeout_locks_immediately_after_unlock_cycle() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::ZERO)
        .await;

    settle_runtime().await;

    assert!(manager.get_payload().await.is_none());
}

/// Unlocking while already unlocked must replace the payload and restart the timer
#[tokio::test(start_paused = true)]
async fn unlock_while_unlocked_replaces_payload_and_timer() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(2))
        .await;
    settle_runtime().await;

    advance(Duration::from_secs(1)).await;
    yield_now().await;
    assert_eq!(
        manager.get_payload().await.expect("payload").entries.len(),
        0
    );

    manager
        .unlock_with_plaintext_json(non_empty_payload_json(), Duration::from_secs(4))
        .await;
    settle_runtime().await;

    let payload = manager
        .get_payload()
        .await
        .expect("payload after replacement");
    assert_eq!(payload.entries.len(), 1);

    // The new timer must govern the state
    advance(Duration::from_secs(3)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_some());

    advance(Duration::from_secs(2)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}
