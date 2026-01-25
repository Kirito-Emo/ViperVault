// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use std::time::Duration;
use vipervault_core::core::VaultLockManager;
use vipervault_core::vault::VaultPayload;

/// Vault should auto-lock after the timeout expires
#[tokio::test]
async fn auto_lock_after_timeout() {
    let manager = VaultLockManager::new();

    let payload = VaultPayload {
        entries: b"very-secret".to_vec(),
    };

    // Unlock with a short timeout
    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize"),
            Duration::from_millis(100),
        )
        .await;

    // Immediately after unlock, payload must be accessible
    let before = manager.get_payload().await;
    assert!(before.is_some());
    assert_eq!(before.unwrap().entries, b"very-secret");

    // Wait longer than timeout
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Vault must be locked
    let after = manager.get_payload().await;
    assert!(after.is_none());
}

/// Auto-lock timer should reset on activity
#[tokio::test]
async fn auto_lock_resets_on_activity() {
    let manager = VaultLockManager::new();

    let payload = VaultPayload {
        entries: b"keep-alive".to_vec(),
    };

    manager
        .unlock_with_plaintext_json(
            serde_json::to_vec(&payload).expect("serialize"),
            Duration::from_millis(150),
        )
        .await;

    // Halfway through, notify activity
    tokio::time::sleep(Duration::from_millis(80)).await;
    manager.notify_activity();

    // Wait again, but still under reset window
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Vault should still be unlocked
    let mid = manager.get_payload().await;
    assert!(mid.is_some());

    // Now wait long enough without activity
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Vault must be locked
    let final_state = manager.get_payload().await;
    assert!(final_state.is_none());
}
