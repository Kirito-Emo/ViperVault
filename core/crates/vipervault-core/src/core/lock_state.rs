// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use zeroize::Zeroizing;

use crate::vault::VaultPayload;

/// Represents the runtime state of the vault
///
/// # Security
/// - In unlocked state we keep plaintext JSON bytes in memory
/// - Bytes are wrapped in `Zeroizing` so they are wiped on lock/timeout/drop
#[derive(Debug)]
pub enum VaultState {
    /// Vault is locked; no decrypted secrets in memory
    Locked,

    /// Vault is unlocked; decrypted payload JSON is held in memory
    Unlocked { plaintext_json: Zeroizing<Vec<u8>> },
}

/// Manages vault locking and auto-lock behavior
///
/// # Security
/// - Auto-lock timer wipes decrypted memory
/// - All state transitions go through this type
/// - The timer can be reset via `notify_activity()`
pub struct VaultLockManager {
    state: Arc<Mutex<VaultState>>,
    notify: Arc<Notify>,
    auto_lock_task: Mutex<Option<JoinHandle<()>>>,
}

impl VaultLockManager {
    /// Creates a new locked vault manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(VaultState::Locked)),
            notify: Arc::new(Notify::new()),
            auto_lock_task: Mutex::new(None),
        }
    }

    /// Unlocks the vault by storing decrypted plaintext JSON bytes in memory
    /// and starting (or restarting) the auto-lock timer
    ///
    /// # Security
    /// - Any previously unlocked state is dropped (wiped)
    /// - Timer resets on unlock
    pub async fn unlock_with_plaintext_json(&self, plaintext_json: Vec<u8>, timeout: Duration) {
        {
            let mut state = self.state.lock().await;
            *state = VaultState::Unlocked {
                plaintext_json: Zeroizing::new(plaintext_json),
            };
        }

        self.restart_auto_lock(timeout).await;
    }

    /// Returns the decrypted payload if unlocked
    ///
    /// # Security
    /// This deserializes from in-memory JSON each call
    ///
    /// # Errors
    /// Returns `None` if locked or if deserialization fails
    pub async fn get_payload(&self) -> Option<VaultPayload> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked { plaintext_json } => {
                serde_json::from_slice::<VaultPayload>(plaintext_json.as_slice()).ok()
            }
            VaultState::Locked => None,
        }
    }

    /// Forces immediate lock and wipes decrypted memory
    pub async fn lock(&self) {
        {
            let mut state = self.state.lock().await;
            *state = VaultState::Locked;
        }
        self.cancel_auto_lock().await;
    }

    /// Resets the auto-lock timer (call on user activity)
    pub fn notify_activity(&self) {
        self.notify.notify_one();
    }

    /// Cancels any existing auto-lock task
    async fn cancel_auto_lock(&self) {
        if let Some(task) = self.auto_lock_task.lock().await.take() {
            task.abort();
        }
    }

    /// Starts or restarts the auto-lock background task
    async fn restart_auto_lock(&self, timeout: Duration) {
        self.cancel_auto_lock().await;

        let state = Arc::clone(&self.state);
        let notify = Arc::clone(&self.notify);

        let task: JoinHandle<()> = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sleep(timeout) => {
                        let mut state = state.lock().await;
                        *state = VaultState::Locked;
                        break;
                    }
                    _ = notify.notified() => {
                        // Activity detected -> restart timer loop
                        continue;
                    }
                }
            }
        });

        *self.auto_lock_task.lock().await = Some(task);
    }
}
