// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault session concurrency tests
//!
//! # Scope
//! Validate concurrent access to the unlocked vault session object
//!
//! # Security
//! Session objects may be shared across async tasks
//! These tests ensure:
//! - concurrent readers do not panic
//! - payload access is race-safe
//! - outcome access is stable and consistent

use std::sync::Arc;
use tokio::task;
use vipervault_core::core::UnlockedVaultSession;
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::vault::VaultPayload;
use vipervault_core::vault::duress::UnlockOutcome;

fn sample_payload() -> VaultPayload {
    let entry =
        VaultEntry::new_secure_note("note".to_string(), "secret".to_string()).expect("entry");

    VaultPayload {
        entries: vec![entry],
    }
}

/// Concurrent payload reads must not panic
#[tokio::test]
async fn concurrent_payload_reads_are_safe() {
    let payload = sample_payload();
    let session = Arc::new(UnlockedVaultSession::new(UnlockOutcome::Primary, payload));

    let mut handles = Vec::new();

    for _ in 0..32 {
        let s = Arc::clone(&session);

        handles.push(task::spawn(async move {
            let payload = s.payload();
            payload.entries.len()
        }));
    }

    for h in handles {
        let len: usize = h.await.expect("join");
        assert_eq!(len, 1);
    }
}

/// Concurrent outcome reads must remain consistent
#[tokio::test]
async fn concurrent_outcome_reads_are_consistent() {
    let payload = sample_payload();
    let session = Arc::new(UnlockedVaultSession::new(UnlockOutcome::Primary, payload));

    let mut handles = Vec::new();

    for _ in 0..32 {
        let s = Arc::clone(&session);

        handles.push(task::spawn(async move {
            matches!(s.outcome(), UnlockOutcome::Primary)
        }));
    }

    for h in handles {
        let res: bool = h.await.expect("join");
        assert!(res);
    }
}
