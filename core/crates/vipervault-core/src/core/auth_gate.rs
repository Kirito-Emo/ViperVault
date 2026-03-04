// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Authentication throttling gate
//!
//! # Purpose
//! Centralize rate limiting for password-based operations to prevent bypasses
//!
//! # Security
//! - Applies delay only for authentication failures (wrong password OR tampering)
//! - Does not delay parse/format errors to avoid DoS via malformed inputs
//! - Provides an async implementation to avoid blocking the runtime

use crate::core::rate_limit::{UnlockRateLimiter, UnlockThrottlePolicy};
use std::future::Future;
use std::time::Duration;
use tokio::sync::Mutex;

/// Centralized gate for password-based operations
#[derive(Debug)]
pub struct AuthGate {
    limiter: Mutex<UnlockRateLimiter>,
    policy: UnlockThrottlePolicy,
}

impl AuthGate {
    /// Create a new gate with a given throttle policy
    pub fn new(policy: UnlockThrottlePolicy) -> Self {
        Self {
            limiter: Mutex::new(UnlockRateLimiter::default()),
            policy,
        }
    }

    /// Run a password-based operation under the gate (async sleep)
    ///
    /// ## Parameters
    /// - `op`: async operation that may return an auth failure
    /// - `is_auth_failure`: predicate that classifies "auth failed" errors
    /// - `should_reset_on_success`: predicate that decides whether a successful operation
    ///   should reset the backoff state (e.g. do not reset on decoy/duress unlock)
    ///
    /// # Security
    /// - Delays only on auth failures
    /// - Uses coarse-grained classification to avoid oracles
    /// - Avoids blocking the async runtime
    pub async fn run<T, E, Fut>(
        &self,
        op: impl FnOnce() -> Fut,
        is_auth_failure: impl Fn(&E) -> bool,
        should_reset_on_success: impl Fn(&T) -> bool,
    ) -> Result<T, E>
    where
        Fut: Future<Output = Result<T, E>>,
    {
        let res = op().await;

        match &res {
            Ok(v) => {
                if should_reset_on_success(v) {
                    let mut l = self.limiter.lock().await;
                    l.on_success();
                }
            }
            Err(e) if is_auth_failure(e) => {
                let delay: Duration = {
                    let mut l = self.limiter.lock().await;
                    l.on_failure_delay(self.policy)
                };

                tokio::time::sleep(delay).await;
            }
            Err(_) => {
                // No delay for non-auth errors
            }
        }

        res
    }

    /// Blocking version for non-async contexts
    pub fn run_blocking<T, E>(
        &self,
        op: impl FnOnce() -> Result<T, E>,
        is_auth_failure: impl Fn(&E) -> bool,
        should_reset_on_success: impl Fn(&T) -> bool,
    ) -> Result<T, E> {
        let res = op();

        match &res {
            Ok(v) => {
                if should_reset_on_success(v) {
                    let mut l = self.limiter.blocking_lock();
                    l.on_success();
                }
            }
            Err(e) if is_auth_failure(e) => {
                let delay: Duration = {
                    let mut l = self.limiter.blocking_lock();
                    l.on_failure_delay(self.policy)
                };

                std::thread::sleep(delay);
            }
            Err(_) => {}
        }

        res
    }
}
