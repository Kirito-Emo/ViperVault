// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Runtime vault lock state and auto-lock handling
//!
//! # Security
//! - Decrypted vault contents are kept in memory only while unlocked
//! - Plaintext JSON bytes are wrapped in [`crate::memory::SecretBytes`] so they
//!   are zeroized on lock, timeout, replacement, or drop
//! - Auto-lock uses generation tracking to prevent stale tasks from affecting a
//!   newer unlock cycle
//! - Unlocked state also carries session-security metadata so convenience
//!   unlocks can be distinguished from strong authentication

use crate::core::session::{AuthenticationStrength, RuntimeSecurityEvent, SensitiveOperation};
use crate::memory::SecretBytes;
use crate::vault::VaultPayload;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};
use zeroize::Zeroizing;

/// Represents the runtime state of the vault
///
/// # Security
/// - In unlocked state the plaintext vault JSON is retained in memory
/// - The plaintext buffer is wrapped in [`crate::memory::SecretBytes`] so the
///   underlying allocation is wiped on lock, timeout, replacement or drop
/// - Unlocked state also tracks the session authentication strength and whether
///   strong re-authentication has been explicitly required
#[derive(Debug)]
pub enum VaultState {
    /// Vault is locked; no decrypted secrets are retained in memory
    Locked,

    /// Vault is unlocked; decrypted payload JSON is held in memory together
    /// with session-security metadata
    Unlocked {
        /// Protected plaintext vault JSON bytes
        plaintext_json: SecretBytes,
        /// Authentication strength that established the current unlocked session
        auth_strength: AuthenticationStrength,
        /// Sticky flag indicating that strong re-authentication is required
        /// before sensitive operations may proceed
        strong_reauth_required: bool,
    },
}

/// Manages vault locking and auto-lock behaviour
///
/// # Security
/// - Auto-lock wipes decrypted memory
/// - All state transitions go through this type
/// - Activity can reset the timer via [`Self::notify_activity`]
/// - Each unlock or manual lock advances a generation counter so stale tasks
///   from prior cycles cannot affect the current session
///
/// # Design
/// The active [`Notify`] instance is rotated whenever the auto-lock task is restarted \
/// This prevents notifications emitted by an old cycle from being observed by a new cycle
pub struct VaultLockManager {
    state: Arc<Mutex<VaultState>>,

    /// Current notify handle for the active auto-lock cycle
    ///
    /// # Security
    /// This handle is rotated on each restart so stale notifications cannot
    /// reset the timer for a newer cycle
    notify: StdMutex<Arc<Notify>>,

    auto_lock_task: Mutex<Option<JoinHandle<()>>>,

    /// Monotonic generation identifier for unlock and timer cycles
    ///
    /// # Security
    /// A stale task may still resume transiently after `abort()` has been requested \
    /// The generation value prevents such tasks from locking or extending a newer session
    generation: Arc<AtomicU64>,
}

impl VaultLockManager {
    /// Create a new locked vault manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(VaultState::Locked)),
            notify: StdMutex::new(Arc::new(Notify::new())),
            auto_lock_task: Mutex::new(None),
            generation: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Advance the generation and return the freshly published value
    ///
    /// # Security
    /// Each new unlock or manual lock invalidates all previously spawned timer cycles
    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Unlock the vault by storing decrypted plaintext JSON bytes in memory and
    /// starting or restarting the auto-lock timer
    ///
    /// # Parameters
    /// - `plaintext_json`: decrypted vault JSON bytes; any input convertible into
    ///   [`crate::memory::SecretBytes`] is accepted so external callers can pass
    ///   existing `Vec<u8>` buffers ergonomically while the manager still stores
    ///   a protected buffer internally
    /// - `timeout`: inactivity window after which the vault must lock
    ///
    /// # Security
    /// - The plaintext is converted into a protected buffer immediately
    /// - Any previously unlocked state is dropped and zeroized
    /// - A fresh generation invalidates stale timer tasks from prior cycles
    ///
    /// # Design
    /// This compatibility entry point opens a session with [`AuthenticationStrength::Strong`]
    pub async fn unlock_with_plaintext_json<B>(&self, plaintext_json: B, timeout: Duration)
    where
        B: Into<SecretBytes>,
    {
        // Preserve the existing API and default it to strong authentication
        self.unlock_with_plaintext_json_with_strength(
            plaintext_json,
            timeout,
            AuthenticationStrength::Strong,
        )
            .await;
    }

    /// Unlock the vault with an explicit authentication strength
    ///
    /// # Security
    /// The current unlocked state records the session assurance level so
    /// sensitive operations can require strong re-authentication when needed
    pub async fn unlock_with_plaintext_json_with_strength<B>(
        &self,
        plaintext_json: B,
        timeout: Duration,
        auth_strength: AuthenticationStrength,
    ) where
        B: Into<SecretBytes>,
    {
        let generation = self.next_generation();
        let plaintext_json = plaintext_json.into();

        {
            let mut state = self.state.lock().await;
            *state = VaultState::Unlocked {
                plaintext_json,
                auth_strength,
                // Non-strong sessions start with strong re-authentication required
                // for sensitive follow-up operations
                strong_reauth_required: !auth_strength.is_strong(),
            };
        }

        self.restart_auto_lock(timeout, generation).await;
    }

    /// Return the decrypted payload if the vault is unlocked
    ///
    /// # Security
    /// This deserializes from the in-memory plaintext JSON buffer for each call
    ///
    /// # Errors
    /// Returns `None` if the vault is locked or if deserialization fails
    pub async fn get_payload(&self) -> Option<VaultPayload> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked { plaintext_json, .. } => {
                serde_json::from_slice::<VaultPayload>(plaintext_json.as_slice()).ok()
            }
            VaultState::Locked => None,
        }
    }

    /// Return the authentication strength of the current unlocked session
    pub async fn current_authentication_strength(&self) -> Option<AuthenticationStrength> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked { auth_strength, .. } => Some(*auth_strength),
            VaultState::Locked => None,
        }
    }

    /// Return `true` when strong re-authentication is currently required before
    /// sensitive operations may proceed
    pub async fn strong_reauth_required(&self) -> Option<bool> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked {
                strong_reauth_required,
                ..
            } => Some(*strong_reauth_required),
            VaultState::Locked => None,
        }
    }

    /// Mark the current unlocked session as requiring strong re-authentication
    ///
    /// # Security
    /// This is intended for future runtime events such as backgrounding,
    /// device-lock transitions, or quick-unlock invalidation
    pub async fn mark_strong_reauth_required(&self) -> bool {
        let mut state = self.state.lock().await;
        match &mut *state {
            VaultState::Unlocked {
                strong_reauth_required,
                ..
            } => {
                *strong_reauth_required = true;
                true
            }
            VaultState::Locked => false,
        }
    }

    /// Clear the strong re-authentication requirement for the current unlocked session
    ///
    /// # Security
    /// Callers should use this only after an explicit strong re-authentication
    /// step has completed successfully
    pub async fn clear_strong_reauth_requirement(&self) -> bool {
        let mut state = self.state.lock().await;
        match &mut *state {
            VaultState::Unlocked {
                strong_reauth_required,
                ..
            } => {
                *strong_reauth_required = false;
                true
            }
            VaultState::Locked => false,
        }
    }

    /// Return `true` when the current unlocked session should require strong
    /// re-authentication for the given sensitive operation
    pub async fn requires_strong_reauth_for(&self, operation: SensitiveOperation) -> Option<bool> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked {
                auth_strength,
                strong_reauth_required,
                ..
            } => Some(
                *strong_reauth_required
                    || (!auth_strength.is_strong() && operation.requires_strong_reauth()),
            ),
            VaultState::Locked => None,
        }
    }

    /// Apply a runtime security event to the current unlocked session
    ///
    /// # Security
    /// Some events force an immediate full lock, while others preserve the
    /// unlocked state but require strong re-authentication before sensitive
    /// follow-up actions
    pub async fn handle_runtime_security_event(&self, event: RuntimeSecurityEvent) {
        if event.forces_lock() {
            self.lock().await;
            return;
        }

        if event.requires_strong_reauth() {
            let _ = self.mark_strong_reauth_required().await;
        }
    }

    /// Force an immediate lock and wipe decrypted memory
    ///
    /// # Security
    /// Advancing the generation before cancellation ensures any stale background
    /// timer that might still resume cannot affect a future unlock cycle
    pub async fn lock(&self) {
        self.next_generation();

        {
            let mut state = self.state.lock().await;
            *state = VaultState::Locked;
        }

        self.cancel_auto_lock().await;
    }

    /// Reset the auto-lock timer after user activity
    ///
    /// # Security
    /// A poisoned mutex is handled conservatively to preserve availability
    /// without losing the active notify handle
    pub fn notify_activity(&self) {
        let notify_arc = match self.notify.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        notify_arc.notify_one();
    }

    /// Cancel any existing auto-lock task
    async fn cancel_auto_lock(&self) {
        if let Some(task) = self.auto_lock_task.lock().await.take() {
            task.abort();
        }
    }

    /// Start or restart the auto-lock background task
    ///
    /// # Parameters
    /// - `timeout`: quiet period after which the vault must lock
    /// - `generation`: current unlock generation captured at unlock time
    ///
    /// # Security
    /// Uses a deadline-based timer, rotates the [`Notify`] instance to ensure deterministic
    /// behaviour and checks the captured generation before applying any state transition \
    /// This prevents stale tasks from prior cycles from locking a newer session
    async fn restart_auto_lock(&self, timeout: Duration, generation: u64) {
        self.cancel_auto_lock().await;

        // Create a brand-new Notify for this auto-lock cycle and publish it
        let cycle_notify = Arc::new(Notify::new());
        {
            let mut guard = self
                .notify
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *guard = Arc::clone(&cycle_notify);
        }

        let state = Arc::clone(&self.state);
        let generation_ref = Arc::clone(&self.generation);

        let task: JoinHandle<()> = tokio::spawn(async move {
            let mut deadline = Instant::now() + timeout;

            loop {
                tokio::select! {
                    _ = sleep_until(deadline) => {
                        let mut st = state.lock().await;

                        if generation_ref.load(Ordering::SeqCst) == generation {
                            *st = VaultState::Locked;
                        }

                        break;
                    }
                    _ = cycle_notify.notified() => {
                        if generation_ref.load(Ordering::SeqCst) != generation {
                            break;
                        }

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
    /// The payload is deserialized from the protected plaintext JSON buffer,
    /// mutated and then immediately re-serialized back into a newly protected buffer \
    /// Replacing the old buffer ensures the previous plaintext allocation is zeroized
    /// as soon as it is dropped
    pub(crate) async fn with_unlocked_payload_mut<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut VaultPayload) -> R,
    {
        let mut state = self.state.lock().await;

        match &mut *state {
            VaultState::Unlocked { plaintext_json, .. } => {
                let mut payload: VaultPayload =
                    serde_json::from_slice(plaintext_json.as_slice()).ok()?;

                let result = f(&mut payload);

                let new_json: SecretBytes = Zeroizing::new(serde_json::to_vec(&payload).ok()?);
                *plaintext_json = new_json;

                Some(result)
            }
            VaultState::Locked => None,
        }
    }

    /// Execute a read-only operation on the decrypted payload
    ///
    /// # Security
    /// This helper avoids exposing the raw plaintext JSON buffer to callers
    pub(crate) async fn with_unlocked_payload<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&VaultPayload) -> R,
    {
        let state = self.state.lock().await;

        match &*state {
            VaultState::Unlocked { plaintext_json, .. } => {
                let payload: VaultPayload =
                    serde_json::from_slice(plaintext_json.as_slice()).ok()?;
                Some(f(&payload))
            }
            VaultState::Locked => None,
        }
    }
}

impl Default for VaultLockManager {
    /// Create a new locked vault manager
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::VaultLockManager;
    use crate::core::session::{AuthenticationStrength, RuntimeSecurityEvent, SensitiveOperation};
    use crate::vault::VaultPayload;
    use std::time::Duration;

    /// The compatibility unlock path must still create a strong session
    #[tokio::test]
    async fn compatibility_unlock_defaults_to_strong_authentication() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
            )
            .await;

        assert_eq!(
            manager.current_authentication_strength().await,
            Some(AuthenticationStrength::Strong)
        );
        assert_eq!(manager.strong_reauth_required().await, Some(false));
        assert_eq!(
            manager
                .requires_strong_reauth_for(SensitiveOperation::Export)
                .await,
            Some(false)
        );
    }

    /// Explicit biometric unlock must preserve the weaker session assurance and
    /// require strong re-authentication for sensitive operations
    #[tokio::test]
    async fn biometric_session_metadata_is_preserved() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json_with_strength(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
                AuthenticationStrength::Biometric,
            )
            .await;

        assert_eq!(
            manager.current_authentication_strength().await,
            Some(AuthenticationStrength::Biometric)
        );
        assert_eq!(manager.strong_reauth_required().await, Some(true));
        assert_eq!(
            manager
                .requires_strong_reauth_for(SensitiveOperation::CopySecret)
                .await,
            Some(true)
        );
    }

    /// Sticky strong re-authentication requirements must be settable and
    /// clearable on an unlocked session
    #[tokio::test]
    async fn strong_reauth_requirement_can_be_set_and_cleared() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
            )
            .await;

        assert_eq!(manager.strong_reauth_required().await, Some(false));
        assert!(manager.mark_strong_reauth_required().await);
        assert_eq!(manager.strong_reauth_required().await, Some(true));
        assert!(manager.clear_strong_reauth_requirement().await);
        assert_eq!(manager.strong_reauth_required().await, Some(false));
    }

    /// Backgrounding should preserve the unlocked session but require strong re-authentication
    #[tokio::test]
    async fn background_event_marks_strong_reauth_required() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
            )
            .await;

        manager
            .handle_runtime_security_event(RuntimeSecurityEvent::AppBackgrounded)
            .await;

        assert!(
            manager.get_payload().await.is_some(),
            "vault should remain unlocked after background event"
        );
        assert_eq!(manager.strong_reauth_required().await, Some(true));
    }

    /// Device-lock style events should immediately relock the vault
    #[tokio::test]
    async fn device_locked_event_forces_full_lock() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
            )
            .await;

        manager
            .handle_runtime_security_event(RuntimeSecurityEvent::DeviceLocked)
            .await;

        assert!(manager.get_payload().await.is_none());
        assert!(manager.current_authentication_strength().await.is_none());
        assert!(manager.strong_reauth_required().await.is_none());
    }
}
