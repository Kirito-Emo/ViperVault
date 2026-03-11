// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Rate limiting
//!
//! # Goals
//! - Slow down brute-force attempts without leaking sensitive details
//! - Keep state in-memory only (no persistent tracking)
//! - Remain configurable and proportional (security vs UX)
//!
//! # Security notes
//! - Apply delay only to authentication failures
//! - Do not differentiate failure reasons
//! - Add jitter to reduce deterministic timing fingerprints

use rand::Rng;
use std::time::{Duration, Instant};

/// Tuning parameters for unlock throttling
#[derive(Debug, Clone, Copy)]
pub struct UnlockThrottlePolicy {
    /// Quiet period after which the failure streak decays
    pub quiet_period: Duration,

    /// Maximum delay applied on failures
    pub max_delay: Duration,

    /// Random jitter added to each delay, inclusive
    pub jitter_max: Duration,
}

impl Default for UnlockThrottlePolicy {
    fn default() -> Self {
        Self {
            quiet_period: Duration::from_secs(60 * 10), // After this time without failures, reduce the streak (10 min)
            max_delay: Duration::from_secs(60), // Cap to avoid an attacker forcing long UI freezes (availability) (1 min)
            jitter_max: Duration::from_millis(1000), // Small random jitter to reduce timing fingerprinting (1 sec)
        }
    }
}

/// In-memory unlock rate limiter
///
/// # Design
/// - Backoff grows with consecutive failures (online guessing mitigation)
/// - Backoff is capped (availability)
/// - Quiet periods decay the streak (UX-friendly)
#[derive(Debug, Default)]
pub struct UnlockRateLimiter {
    failures: u32,
    last_failure: Option<Instant>,
}

impl UnlockRateLimiter {
    /// Register a successful unlock attempt
    ///
    /// # Security
    /// Successful authentication resets the failure streak
    pub fn on_success(&mut self) {
        self.failures = 0;
        self.last_failure = None;
    }

    /// Register a failed unlock attempt and compute the delay to apply
    ///
    /// # Security
    /// Caller should sleep for the returned duration before returning an auth error
    pub fn on_failure_delay(&mut self, policy: UnlockThrottlePolicy) -> Duration {
        let now = Instant::now();

        // Decay on quiet period to keep UX reasonable
        if let Some(last) = self.last_failure {
            let quiet = now.saturating_duration_since(last);
            if quiet >= policy.quiet_period {
                // Drop the streak by half
                self.failures /= 2;
            }
        }

        self.failures = self.failures.saturating_add(1);
        self.last_failure = Some(now);

        let base = password_delay_for_failures(self.failures);
        base.min(policy.max_delay)
            .saturating_add(jitter(policy.jitter_max))
    }

    /// Return the current failure count
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

/// Compute the progressive delay schedule for master-password failures
///
/// # Security
/// This schedule is moderate but cumulative:
/// repeated failures quickly become expensive while preserving usability
fn password_delay_for_failures(failures: u32) -> Duration {
    match failures {
        0..=2 => Duration::ZERO,
        3..=4 => Duration::from_secs(1),
        5..=6 => Duration::from_secs(5),
        7..=8 => Duration::from_secs(10),
        9..=10 => Duration::from_secs(15),
        11..=12 => Duration::from_secs(30),
        13..=15 => Duration::from_secs(60),
        _ => Duration::from_secs(300),
    }
}

/// Generate a uniform random jitter in the inclusive range `[0, max]`
fn jitter(max: Duration) -> Duration {
    let max_ms = max.as_millis();
    if max_ms == 0 {
        return Duration::ZERO;
    }

    let mut b = [0u8; 8];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut b);
    let r = u64::from_le_bytes(b);
    let j = r % (max_ms as u64 + 1);
    Duration::from_millis(j)
}
