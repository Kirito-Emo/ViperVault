// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Auto-lock hardening tests
//!
//! # Scope
//! These tests exercise adversarial and edge-case scenarios:
//! - zero / tiny timeouts
//! - notification storms
//! - concurrent reads during state transitions
//! - race-like sequences (lock triggers while operations are in flight)
//!
//! # Security
//! Hardening goals:
//! - no panics
//! - no deadlocks
//! - state remains consistent under stress
//! - auto-lock remains effective even in edge timing conditions

use std::sync::Arc;
use std::time::Duration;
use tokio::task::{JoinHandle, yield_now};
use tokio::time::advance;
use vipervault_core::core::VaultLockManager;
use vipervault_core::vault::VaultPayload;

/// Serialize an empty payload as plaintext JSON bytes
///
/// This avoids involving encryption in auto-lock tests and keeps the focus
/// strictly on runtime state transitions
fn empty_payload_json() -> Vec<u8> {
    serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize empty payload")
}

/// Let spawned tasks run at least once so they can arm timers
///
/// # Why
/// With `start_paused = true`, it is possible to `advance()` time before a spawned task
/// has been polled and before it has registered its `sleep_until()` timer. In that case,
/// the task may compute its deadline using a later `Instant::now()`, causing the lock to
/// occur later than expected and making tests flaky
///
/// This helper ensures the auto-lock task has a chance to start and arm its timer
async fn settle_runtime() {
    yield_now().await; // Give the scheduler a turn
    yield_now().await; // A second yield improves determinism under heavier contention
    advance(Duration::ZERO).await; // Drive any timers scheduled at "now" (safe no-op in many cases)
    yield_now().await;
}

/// A zero timeout should cause the vault to lock immediately (or effectively immediately)
///
/// # Security
/// This validates that a zero-duration timeout does not leave secrets resident
/// in memory longer than a single scheduler turn
#[tokio::test(start_paused = true)]
async fn zero_timeout_locks_immediately() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::ZERO)
        .await;

    // Ensure the auto-lock task has started
    settle_runtime().await;

    // Allow timers scheduled at `now` to fire
    advance(Duration::ZERO).await;
    yield_now().await;

    assert!(
        manager.get_payload().await.is_none(),
        "vault must lock immediately with zero timeout"
    );
}

/// A very small timeout should still lock reliably
///
/// # Security
/// Tiny timeouts are a common source of race conditions; this test ensures
/// deterministic behavior under time freezing
#[tokio::test(start_paused = true)]
async fn tiny_timeout_locks_reliably() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_millis(1))
        .await;

    // Ensure the timer is armed before advancing time
    settle_runtime().await;

    // Advance past the tiny timeout
    advance(Duration::from_millis(2)).await;
    yield_now().await;

    assert!(
        manager.get_payload().await.is_none(),
        "vault must lock after tiny timeout expires"
    );
}

/// A notification storm must not deadlock and must keep the vault unlocked
/// while activity notifications continue to arrive
///
/// # Security
/// This simulates hostile or buggy UIs repeatedly resetting the timer
#[tokio::test(start_paused = true)]
async fn notify_storm_no_deadlock_and_effective_reset() {
    let manager = Arc::new(VaultLockManager::new());

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(5))
        .await;

    // Ensure the auto-lock task is running and has armed its timer
    settle_runtime().await;

    let m = Arc::clone(&manager);

    // Spawn a task that floods the manager with activity notifications
    let storm: JoinHandle<()> = tokio::spawn(async move {
        for _ in 0..1000 {
            m.notify_activity();
            yield_now().await;
        }
    });

    // While notifications keep arriving, advancing time must NOT lock the vault
    for _ in 0..5 {
        advance(Duration::from_secs(1)).await;
        yield_now().await;

        assert!(
            manager.get_payload().await.is_some(),
            "vault must remain unlocked while activity continues"
        );
    }

    storm.await.expect("storm task must complete");

    // After a sufficiently long quiet window, the vault must lock
    advance(Duration::from_secs(6)).await;
    yield_now().await;

    assert!(
        manager.get_payload().await.is_none(),
        "vault must lock after notifications stop"
    );
}

/// Concurrent `get_payload()` calls during auto-lock transition must not panic
/// and must only return valid `Option` values
///
/// # Security
/// This test ensures race safety between readers and the auto-lock task
#[tokio::test(start_paused = true)]
async fn concurrent_reads_during_auto_lock_no_panic() {
    let manager = Arc::new(VaultLockManager::new());

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(3))
        .await;

    // Ensure the timer is armed before advancing time
    settle_runtime().await;

    let m = Arc::clone(&manager);

    let reader: JoinHandle<()> = tokio::spawn(async move {
        for _ in 0..100 {
            let _ = m.get_payload().await;
            yield_now().await;
        }
    });

    // Move time past the timeout, allowing the lock transition
    // to occur while reads are still in flight
    advance(Duration::from_secs(4)).await;
    yield_now().await;

    reader.await.expect("reader task must complete");

    assert!(
        manager.get_payload().await.is_none(),
        "vault must be locked after timeout even with concurrent readers"
    );
}

/// If auto-lock triggers, a subsequent unlock must restore the unlocked state
///
/// # Security
/// This ensures auto-lock does not permanently poison the manager state
#[tokio::test(start_paused = true)]
async fn lock_then_unlock_restores_unlocked_state() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(2))
        .await;

    // Ensure the timer is armed before advancing time
    settle_runtime().await;

    advance(Duration::from_secs(3)).await;
    yield_now().await;

    assert!(
        manager.get_payload().await.is_none(),
        "vault must be locked after timeout"
    );

    // Unlock again after auto-lock
    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(10))
        .await;

    // Let the new auto-lock cycle arm its timer too
    settle_runtime().await;

    assert!(
        manager.get_payload().await.is_some(),
        "vault must be unlockable again after auto-lock"
    );
}

/// Rapid sequences of unlock, activity notification, and manual lock
/// must not panic and must end in a consistent state
///
/// # Security
/// This simulates aggressive UI behavior and defensive manual locking
#[tokio::test(start_paused = true)]
async fn rapid_state_transitions_are_consistent() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(1))
        .await;

    // Ensure the timer is armed before starting manipulating time
    settle_runtime().await;

    for _ in 0..10 {
        manager.notify_activity();
        advance(Duration::from_millis(100)).await;
        yield_now().await;

        assert!(
            manager.get_payload().await.is_some(),
            "vault must remain unlocked while activity continues"
        );
    }

    // Manual lock must override auto-lock logic
    manager.lock().await;

    assert!(
        manager.get_payload().await.is_none(),
        "manual lock must immediately lock the vault"
    );

    // Even after advancing time, the vault must remain locked
    advance(Duration::from_secs(10)).await;
    yield_now().await;

    assert!(
        manager.get_payload().await.is_none(),
        "vault must remain locked after manual lock"
    );
}
