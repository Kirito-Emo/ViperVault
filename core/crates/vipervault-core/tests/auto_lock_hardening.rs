// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use std::time::Duration;
use vipervault_core::core::VaultLockManager;
use vipervault_core::vault::VaultPayload;

/// Rapid unlocks should replace previous plaintext and reset timer
#[tokio::test]
async fn supports_rapid_reunlock() {
    let manager = VaultLockManager::new();

    let p1 = VaultPayload {
        entries: b"one".to_vec(),
    };
    manager
        .unlock_with_plaintext_json(serde_json::to_vec(&p1).unwrap(), Duration::from_millis(200))
        .await;

    let p2 = VaultPayload {
        entries: b"two".to_vec(),
    };
    manager
        .unlock_with_plaintext_json(serde_json::to_vec(&p2).unwrap(), Duration::from_millis(120))
        .await;

    let now = manager.get_payload().await.expect("must be unlocked");
    assert_eq!(now.entries, b"two");

    // After 150ms, it should be locked (based on the second timeout)
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(manager.get_payload().await.is_none());
}

/// Concurrent readers should not panic while auto-lock occurs
#[tokio::test]
async fn remains_stable_under_concurrent_reads() {
    let manager = std::sync::Arc::new(VaultLockManager::new());

    let payload = VaultPayload {
        entries: vec![0x42; 1024],
    };
    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).unwrap(),
            Duration::from_millis(80),
        )
        .await;

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let m = manager.clone();
        tasks.push(tokio::spawn(async move {
            // Some reads will happen before lock, some after.
            let _ = m.get_payload().await;
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(manager.get_payload().await.is_none());
}
