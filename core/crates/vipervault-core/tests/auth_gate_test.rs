// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Authentication gate tests
//!
//! # Scope
//! These tests validate the behavior of the centralized authentication gate:
//! - delay is applied only to authentication failures
//! - non-auth errors are returned immediately
//! - successful primary operations reset the backoff state
//! - successful decoy operations do not reset the backoff state
//! - blocking mode preserves the same classification semantics
//!
//! # Security
//! The gate is the central throttling boundary for password-based flows \
//! These tests ensure that:
//! - brute-force attempts are slowed down
//! - malformed inputs do not cause artificial delays (availability)
//! - decoy success cannot be abused to clear the failure streak

use std::sync::Arc;
use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::advance;
use vipervault_core::core::auth_gate::AuthGate;
use vipervault_core::core::rate_limit::UnlockThrottlePolicy;

/// Test-local operation result kind
///
/// # Notes
/// This local enum keeps the tests focused on gate behavior rather than on any
/// specific vault or crypto implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestError {
    AuthFailed,
    ParseFailed,
}

/// Test-local outcome kind
///
/// # Notes
/// `PrimarySuccess` models a real successful unlock, while `DecoySuccess` models
/// a decoy unlock that must not reset the backoff state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestOutcome {
    PrimarySuccess,
    DecoySuccess,
}

/// Build a deterministic throttle policy for time-paused tests
///
/// # Notes
/// Production policy includes jitter and larger delays. Tests use no jitter and a tiny capped delay
/// so that timing behavior remains deterministic and fast
fn tiny_test_policy() -> UnlockThrottlePolicy {
    UnlockThrottlePolicy {
        quiet_period: Duration::from_secs(60),
        max_delay: Duration::from_millis(1),
        jitter_max: Duration::ZERO,
    }
}

/// Let spawned async tasks progress
async fn settle_runtime() {
    yield_now().await;
    yield_now().await;
    advance(Duration::ZERO).await;
    yield_now().await;
}

/// First and second auth failures should complete immediately under the default schedule
#[tokio::test(start_paused = true)]
async fn first_two_auth_failures_are_immediate() {
    let gate = AuthGate::new(tiny_test_policy());

    let r1 = gate
        .run(
            || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
            |e| matches!(e, TestError::AuthFailed),
            |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
        )
        .await;
    assert!(matches!(r1, Err(TestError::AuthFailed)));

    let r2 = gate
        .run(
            || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
            |e| matches!(e, TestError::AuthFailed),
            |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
        )
        .await;
    assert!(matches!(r2, Err(TestError::AuthFailed)));
}

/// Starting from the third consecutive auth failure, a delay must be applied
///
/// # Security
/// This is the central anti-brute-force behavior of the authentication gate
#[tokio::test(start_paused = true)]
async fn third_auth_failure_is_delayed() {
    let gate = Arc::new(AuthGate::new(tiny_test_policy()));

    for _ in 0..2 {
        let r = gate
            .run(
                || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
                |e| matches!(e, TestError::AuthFailed),
                |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
            )
            .await;
        assert!(matches!(r, Err(TestError::AuthFailed)));
    }

    let gate_for_task = Arc::clone(&gate);
    let handle = tokio::spawn(async move {
        gate_for_task
            .run(
                || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
                |e| matches!(e, TestError::AuthFailed),
                |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
            )
            .await
    });

    settle_runtime().await;
    assert!(
        !handle.is_finished(),
        "third auth failure must be delayed before completion"
    );

    advance(Duration::from_millis(1)).await;
    let r = handle.await.expect("join");
    assert!(matches!(r, Err(TestError::AuthFailed)));
}

/// Non-auth errors must not be delayed
///
/// # Security
/// Parse/format failures must return immediately to avoid turning malformed
/// inputs into availability attacks
#[tokio::test(start_paused = true)]
async fn non_auth_errors_are_not_delayed() {
    let gate = AuthGate::new(tiny_test_policy());

    for _ in 0..5 {
        let r = gate
            .run(
                || async { Err::<TestOutcome, _>(TestError::ParseFailed) },
                |e| matches!(e, TestError::AuthFailed),
                |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
            )
            .await;

        assert!(matches!(r, Err(TestError::ParseFailed)));
    }
}

/// A primary success must reset the failure streak
///
/// # Security
/// After a real successful authentication, the next auth failure must start
/// from a clean backoff state
#[tokio::test(start_paused = true)]
async fn primary_success_resets_failure_streak() {
    let gate = Arc::new(AuthGate::new(tiny_test_policy()));

    // Build a streak large enough that the next auth failure would be delayed
    for _ in 0..3 {
        let gate_for_task = Arc::clone(&gate);
        let handle = tokio::spawn(async move {
            gate_for_task
                .run(
                    || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
                    |e| matches!(e, TestError::AuthFailed),
                    |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
                )
                .await
        });

        settle_runtime().await;
        if !handle.is_finished() {
            advance(Duration::from_millis(1)).await;
        }
        let _ = handle.await.expect("join");
    }

    // Primary success must reset the limiter state
    let ok = gate
        .run(
            || async { Ok::<_, TestError>(TestOutcome::PrimarySuccess) },
            |e| matches!(e, TestError::AuthFailed),
            |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
        )
        .await;
    assert!(matches!(ok, Ok(TestOutcome::PrimarySuccess)));

    // After reset, the next auth failure should be immediate again
    let gate_for_task = Arc::clone(&gate);
    let handle = tokio::spawn(async move {
        gate_for_task
            .run(
                || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
                |e| matches!(e, TestError::AuthFailed),
                |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
            )
            .await
    });

    settle_runtime().await;
    assert!(
        handle.is_finished(),
        "auth failure after primary success should be immediate"
    );

    let r = handle.await.expect("join");
    assert!(matches!(r, Err(TestError::AuthFailed)));
}

/// A decoy success must NOT reset the failure streak
///
/// # Security
/// Otherwise a decoy unlock could be abused to clear the backoff state
#[tokio::test(start_paused = true)]
async fn decoy_success_does_not_reset_failure_streak() {
    let gate = Arc::new(AuthGate::new(tiny_test_policy()));

    // Build a streak large enough that the next auth failure is delayed
    for _ in 0..3 {
        let gate_for_task = Arc::clone(&gate);
        let handle = tokio::spawn(async move {
            gate_for_task
                .run(
                    || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
                    |e| matches!(e, TestError::AuthFailed),
                    |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
                )
                .await
        });

        settle_runtime().await;
        if !handle.is_finished() {
            advance(Duration::from_millis(1)).await;
        }
        let _ = handle.await.expect("join");
    }

    // Decoy success is successful, but must not reset the limiter state
    let ok = gate
        .run(
            || async { Ok::<_, TestError>(TestOutcome::DecoySuccess) },
            |e| matches!(e, TestError::AuthFailed),
            |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
        )
        .await;
    assert!(matches!(ok, Ok(TestOutcome::DecoySuccess)));

    let gate_for_task = Arc::clone(&gate);
    let handle = tokio::spawn(async move {
        gate_for_task
            .run(
                || async { Err::<TestOutcome, _>(TestError::AuthFailed) },
                |e| matches!(e, TestError::AuthFailed),
                |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
            )
            .await
    });

    settle_runtime().await;
    assert!(
        !handle.is_finished(),
        "auth failure after decoy success must remain delayed"
    );

    advance(Duration::from_millis(1)).await;
    let r = handle.await.expect("join");
    assert!(matches!(r, Err(TestError::AuthFailed)));
}

/// Blocking mode must apply the same classification rules
///
/// # Security
/// Non-async callers must preserve the same semantics:
/// - delay only on auth failure
/// - no delay on non-auth failure
/// - reset on primary success
#[test]
fn blocking_mode_preserves_classification_rules() {
    let gate = AuthGate::new(tiny_test_policy());

    let r1 = gate.run_blocking(
        || Err::<TestOutcome, _>(TestError::ParseFailed),
        |e| matches!(e, TestError::AuthFailed),
        |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
    );
    assert!(matches!(r1, Err(TestError::ParseFailed)));

    let r2 = gate.run_blocking(
        || Ok::<_, TestError>(TestOutcome::PrimarySuccess),
        |e| matches!(e, TestError::AuthFailed),
        |outcome| matches!(outcome, TestOutcome::PrimarySuccess),
    );
    assert!(matches!(r2, Ok(TestOutcome::PrimarySuccess)));
}
