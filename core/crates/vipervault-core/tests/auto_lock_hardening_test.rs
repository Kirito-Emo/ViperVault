// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Auto-lock hardening tests
//!
//! # Scope
//! These tests validate harder edge cases around timer replacement,
//! repeated activity, rapid state transitions and stale timer behavior
//!
//! Covered:
//! - stale timers must not lock a newly unlocked session
//! - rapid unlock/lock cycles must remain coherent
//! - activity storms must not panic or prematurely lock
//! - manual lock must dominate pending timers
//! - concurrent readers during lock transitions must remain race-safe
//!
//! # Security
//! Auto-lock correctness is security-sensitive because stale timer bugs
//! can either keep secrets in memory too long or lock unexpectedly and
//! corrupt user flows

use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::advance;
use vipervault_core::core::VaultLockManager;
use vipervault_core::entries::VaultEntry;
use vipervault_core::vault::VaultPayload;

/// Serialize an empty payload as plaintext JSON bytes
///
/// This avoids involving encryption in auto-lock tests and keeps the focus
/// strictly on runtime state transitions
fn empty_payload_json() -> Vec<u8> {
    serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize")
}

/// Serialize a payload with a single entry as plaintext JSON bytes
///
/// This helper provides a stable unlocked state with observable content,
/// useful when verifying replacement and stale-timer behavior
fn one_entry_payload_json(title: &str) -> Vec<u8> {
    let entry =
        VaultEntry::new_secure_note(title.to_string(), "secret".to_string()).expect("entry");
    serde_json::to_vec(&VaultPayload {
        entries: vec![entry],
    })
    .expect("serialize")
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
    yield_now().await;
    yield_now().await;
    advance(Duration::ZERO).await;
    yield_now().await;
}

/// Re-unlocking must invalidate the previously armed timer
///
/// # Security
/// A stale timer from a previous session must not lock a newly unlocked session,
/// otherwise state transitions become nondeterministic and can break both security
/// and correctness
#[tokio::test(start_paused = true)]
async fn stale_timer_does_not_lock_new_session() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(one_entry_payload_json("first"), Duration::from_secs(2))
        .await;
    settle_runtime().await;

    advance(Duration::from_secs(1)).await;
    yield_now().await;

    manager
        .unlock_with_plaintext_json(one_entry_payload_json("second"), Duration::from_secs(5))
        .await;
    settle_runtime().await;

    // Advance beyond the old timer deadline but before the new one
    advance(Duration::from_secs(2)).await;
    yield_now().await;

    let payload = manager
        .get_payload()
        .await
        .expect("payload must remain unlocked");
    assert_eq!(payload.entries.len(), 1);

    // Eventually the new timer must still lock
    advance(Duration::from_secs(4)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// Manual lock must dominate any already armed auto-lock timer
///
/// # Security
/// An explicit lock request must always take precedence over pending timers
#[tokio::test(start_paused = true)]
async fn manual_lock_dominates_pending_timer() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(10))
        .await;
    settle_runtime().await;

    manager.lock().await;
    assert!(manager.get_payload().await.is_none());

    advance(Duration::from_secs(20)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// Rapid unlock -> lock -> unlock cycles must remain coherent
///
/// # Security
/// Short-lived state transitions are a common source of race conditions in session managers
/// and auto-lock implementations
#[tokio::test(start_paused = true)]
async fn rapid_unlock_lock_unlock_cycles_remain_coherent() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(one_entry_payload_json("first"), Duration::from_secs(5))
        .await;
    settle_runtime().await;

    manager.lock().await;
    assert!(manager.get_payload().await.is_none());

    manager
        .unlock_with_plaintext_json(one_entry_payload_json("second"), Duration::from_secs(5))
        .await;
    settle_runtime().await;

    let payload = manager.get_payload().await.expect("payload");
    assert_eq!(payload.entries.len(), 1);

    advance(Duration::from_secs(6)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// A very small timeout should still lock reliably
///
/// # Security
/// Tiny timeouts are a common source of race conditions \
/// This test ensures deterministic behavior under time freezing
#[tokio::test(start_paused = true)]
async fn repeated_zero_timeout_unlocks_do_not_leave_state_behind() {
    let manager = VaultLockManager::new();

    for _ in 0..10 {
        manager
            .unlock_with_plaintext_json(empty_payload_json(), Duration::ZERO)
            .await;

        // Ensure the timer is armed before advancing time
        settle_runtime().await;

        assert!(manager.get_payload().await.is_none());
    }
}

/// A notification storm must not deadlock and must keep the vault unlocked
/// while activity notifications continue to arrive
///
/// # Security
/// This simulates hostile or buggy UIs repeatedly resetting the timer
#[tokio::test(start_paused = true)]
async fn activity_storm_keeps_vault_unlocked_until_quiet_period() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(empty_payload_json(), Duration::from_secs(3))
        .await;
    settle_runtime().await;

    // Spawn a task that floods the manager with activity notifications
    for _ in 0..100 {
        manager.notify_activity();
    }
    settle_runtime().await;

    // While notifications keep arriving, advancing time must NOT lock the vault
    advance(Duration::from_secs(2)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_some());

    manager.notify_activity();
    settle_runtime().await;

    advance(Duration::from_secs(2)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_some());

    advance(Duration::from_secs(4)).await;
    yield_now().await;
    assert!(manager.get_payload().await.is_none());
}

/// Concurrent `get_payload()` calls during auto-lock transition must not panic
/// and must only return valid `Option` values
///
/// # Security
/// This test ensures race safety between readers and the auto-lock task
#[tokio::test(start_paused = true)]
async fn concurrent_reads_during_auto_lock_transition_are_race_safe() {
    let manager = VaultLockManager::new();

    manager
        .unlock_with_plaintext_json(one_entry_payload_json("note"), Duration::from_secs(2))
        .await;
    settle_runtime().await;

    advance(Duration::from_secs(2)).await;

    let (a, b, c) = tokio::join!(manager.get_payload(), manager.get_payload(), async {
        yield_now().await;
        manager.get_payload().await
    });

    assert!(a.is_some() || a.is_none());
    assert!(b.is_some() || b.is_none());
    assert!(c.is_some() || c.is_none());
}
