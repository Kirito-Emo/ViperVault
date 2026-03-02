// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use crate::vault::VaultPayload;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};
use zeroize::Zeroizing;

/// Represents the runtime state of the vault
///
/// # Security
/// - In unlocked state keep plaintext JSON bytes in memory
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
/// - Activity can reset the timer via `notify_activity()`
///
/// # Design note
/// Intentionally rotate the `Notify` instance whenever the auto-lock task is restarted
/// This prevents "stale" notifications (emitted before the new task starts waiting) from being observed by the new cycle
pub struct VaultLockManager {
    state: Arc<Mutex<VaultState>>,

    /// Current notify handle for the active auto-lock cycle
    ///
    /// # Security
    /// This is rotated on each `restart_auto_lock()` so pending notifications
    /// from old cycles cannot reset the new timer
    notify: StdMutex<Arc<Notify>>,

    auto_lock_task: Mutex<Option<JoinHandle<()>>>,
}

impl VaultLockManager {
    /// Creates a new locked vault manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(VaultState::Locked)),
            notify: StdMutex::new(Arc::new(Notify::new())),
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
    ///
    /// # Security
    /// This does not expose any secret material; it only signals activity
    pub fn notify_activity(&self) {
        // Short critical section: read the current notify for the active cycle
        let notify = self.notify.lock().expect("notify mutex poisoned").clone();
        notify.notify_one();
    }

    /// Cancels any existing auto-lock task
    async fn cancel_auto_lock(&self) {
        if let Some(task) = self.auto_lock_task.lock().await.take() {
            task.abort();
        }
    }

    /// Starts or restarts the auto-lock background task
    ///
    /// # Security
    /// Uses a deadline-based timer (`sleep_until`) and rotates the `Notify`
    /// instance to ensure deterministic behavior and to prevent stale signals
    /// from resetting a fresh timer
    async fn restart_auto_lock(&self, timeout: Duration) {
        self.cancel_auto_lock().await;

        // Create a brand-new Notify for this auto-lock cycle and publish it
        let cycle_notify = Arc::new(Notify::new());
        {
            let mut guard = self.notify.lock().expect("notify mutex poisoned");
            *guard = Arc::clone(&cycle_notify);
        }

        let state = Arc::clone(&self.state);

        let task: JoinHandle<()> = tokio::spawn(async move {
            let mut deadline = Instant::now() + timeout;

            loop {
                tokio::select! {
                    _ = sleep_until(deadline) => {
                        let mut st = state.lock().await;
                        *st = VaultState::Locked;
                        break;
                    }
                    _ = cycle_notify.notified() => {
                        // Activity observed: push the deadline forward
                        deadline = Instant::now() + timeout;
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

impl Default for VaultLockManager {
    /// Create a new locked vault manager
    fn default() -> Self {
        Self::new()
    }
}
