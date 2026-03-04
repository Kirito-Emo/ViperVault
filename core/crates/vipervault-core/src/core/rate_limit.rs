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
//! - Apply delay only to authentication failures (wrong password OR tampering)
//! - Do not differentiate failure reasons
//! - Add jitter to avoid deterministic timing fingerprints

use rand::RngCore;
use std::time::{Duration, Instant};

/// Tuning parameters for unlock throttling
#[derive(Debug, Clone, Copy)]
pub struct UnlockThrottlePolicy {
    pub quiet_period: Duration, // Quiet period after which the failure streak decays
    pub max_delay: Duration,    // Maximum delay applied on failures
    pub jitter_max: Duration,   // Jitter range added to every delay, inclusive
}

impl Default for UnlockThrottlePolicy {
    fn default() -> Self {
        Self {
            quiet_period: Duration::from_secs(60), // After this time without failures, reduce the streak
            max_delay: Duration::from_secs(8), // Cap to avoid an attacker forcing long UI freezes (availability)
            jitter_max: Duration::from_millis(250), // Small random jitter to reduce timing fingerprinting
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

        // Progressive schedule (proportional):
        // - 1..=2: 0ms
        // - 3..=4: 500ms
        // - 5..=6: 1s
        // - 7..=8: 2s
        // - 9..=10: 4s
        // - 11+: exponential-ish growth, capped
        let base = match self.failures {
            0..=2 => Duration::from_millis(0),
            3..=4 => Duration::from_millis(500),
            5..=6 => Duration::from_secs(1),
            7..=8 => Duration::from_secs(2),
            9..=10 => Duration::from_secs(4),
            _ => Duration::from_secs(6),
        };

        // Extra growth beyond 10 failures: add 1s per failure, capped
        let extra = if self.failures > 10 {
            Duration::from_secs((self.failures - 10) as u64)
        } else {
            Duration::from_millis(0)
        };

        let mut delay = base.saturating_add(extra);
        if delay > policy.max_delay {
            delay = policy.max_delay;
        }

        delay.saturating_add(jitter(policy.jitter_max))
    }
}

fn jitter(max: Duration) -> Duration {
    if max == Duration::from_millis(0) {
        return Duration::from_millis(0);
    }

    // Convert to millis for uniform jitter selection
    let max_ms = max.as_millis();
    if max_ms == 0 {
        return Duration::from_millis(0);
    }

    let mut b = [0u8; 8];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut b);
    let r = u64::from_le_bytes(b);

    let j = r % (max_ms as u64 + 1);
    Duration::from_millis(j)
}
