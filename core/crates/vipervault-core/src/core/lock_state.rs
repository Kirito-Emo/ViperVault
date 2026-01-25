// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use crate::core::clamp_auto_lock_timeout_under_soft_policy;
use crate::vault::VaultPayload;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use zeroize::Zeroizing;

/// Represents the runtime state of the vault
///
/// # Security
/// - In unlocked state we keep plaintext JSON bytes in memory
/// - Bytes are wrapped in `Zeroizing` so they are wiped on lock/timeout/drop
#[derive(Debug)]
pub enum VaultState {
    Locked, // Vault is locked; no decrypted secrets in memory
    Unlocked { plaintext_json: Zeroizing<Vec<u8>> }, // Vault is unlocked; decrypted payload JSON is held in memory
}

/// Manages vault locking and auto-lock behavior
///
/// # Security
/// - Auto-lock timer wipes decrypted memory
/// - All state transitions go through this type
/// - The timer can be reset via `notify_activity()`
/// - Under debugging (soft policy) the auto-lock timeout is clamped to reduce exposure
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
    /// - Under debugging (soft policy), `timeout` may be clamped
    pub async fn unlock_with_plaintext_json(&self, plaintext_json: Vec<u8>, timeout: Duration) {
        {
            let mut state = self.state.lock().await;
            *state = VaultState::Unlocked {
                plaintext_json: Zeroizing::new(plaintext_json),
            };
        }

        // Apply soft policy: shorten exposure window if a debugger is detected
        let effective_timeout = clamp_auto_lock_timeout_under_soft_policy(timeout);

        self.restart_auto_lock(effective_timeout).await;
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

    /// Execute a mutable operation on the decrypted payload
    ///
    /// # Security
    /// The payload is deserialized from `plaintext_json`, mutated, then immediately
    /// re-serialized back into `plaintext_json`
    pub(crate) async fn with_unlocked_payload_mut<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut crate::vault::VaultPayload) -> R,
    {
        let mut state = self.state.lock().await;

        match &mut *state {
            VaultState::Unlocked { plaintext_json, .. } => {
                let mut payload: crate::vault::VaultPayload =
                    serde_json::from_slice(&plaintext_json[..]).ok()?;

                let result = f(&mut payload);

                let new_json = serde_json::to_vec(&payload).ok()?;
                plaintext_json.clear();
                plaintext_json.extend_from_slice(&new_json);

                Some(result)
            }
            _ => None,
        }
    }

    /// Execute a read-only operation on the decrypted payload
    pub(crate) async fn with_unlocked_payload<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&crate::vault::VaultPayload) -> R,
    {
        let state = self.state.lock().await;

        match &*state {
            VaultState::Unlocked { plaintext_json, .. } => {
                let payload: crate::vault::VaultPayload =
                    serde_json::from_slice(&plaintext_json[..]).ok()?;
                Some(f(&payload))
            }
            _ => None,
        }
    }
}
