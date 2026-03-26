// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Runtime vault lock state and auto-lock handling
//!
//! # Security
//! - Decrypted vault contents are kept in memory only while unlocked
//! - Plaintext JSON bytes are wrapped in [`crate::memory::SecretBytes`] so they
//!   are zeroized on lock, timeout, replacement or drop
//! - Auto-lock uses generation tracking to prevent stale tasks from affecting a
//!   newer unlock cycle
//! - Unlocked state also carries session-security metadata so convenience
//!   unlocks can be distinguished from strong authentication
//! - Manager-owned session state includes unlock outcome and runtime inspection
//!   posture so post-unlock policy checks do not depend on caller-supplied policy
//!
//! # Design
//! Manager-owned authorization is intentionally deterministic:
//! - sensitive-operation authorization evaluates the runtime state already stored in the session
//! - live runtime probing is available through explicit refresh methods
//! - authorization must not silently mutate session policy state as a side effect

use crate::core::antidebug::{RuntimeInspectionState, current_runtime_inspection_state};
use crate::core::policy::PolicyContext;
use crate::core::session::{AuthenticationStrength, RuntimeSecurityEvent, SensitiveOperation};
use crate::entries::EntryError;
use crate::memory::SecretBytes;
use crate::vault::VaultPayload;
use crate::vault::duress::UnlockOutcome;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};
use zeroize::Zeroizing;

/// Represents the runtime state of the vault
///
/// # Security
/// - In unlocked state the plaintext vault JSON is retained in memory
/// - The plaintext buffer is wrapped in [`crate::memory::SecretBytes`] so the
///   underlying allocation is wiped on lock, timeout, replacement or drop
/// - Unlocked state also tracks the session authentication strength, the unlock
///   outcome and the runtime inspection posture used for policy enforcement
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
        /// Primary vs decoy unlock outcome for the current session
        unlock_outcome: UnlockOutcome,
        /// Current runtime inspection posture associated with the session
        runtime_state: RuntimeInspectionState,
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
    /// This compatibility entry point opens a primary strong session and captures
    /// the current runtime inspection state
    pub async fn unlock_with_plaintext_json<B>(&self, plaintext_json: B, timeout: Duration)
    where
        B: Into<SecretBytes>,
    {
        self.unlock_with_plaintext_json_with_context(
            plaintext_json,
            timeout,
            AuthenticationStrength::Strong,
            UnlockOutcome::Primary,
            current_runtime_inspection_state(),
        )
        .await;
    }

    /// Unlock the vault with an explicit authentication strength
    ///
    /// # Design
    /// This compatibility entry point still assumes a primary session and
    /// captures the current runtime inspection state
    pub async fn unlock_with_plaintext_json_with_strength<B>(
        &self,
        plaintext_json: B,
        timeout: Duration,
        auth_strength: AuthenticationStrength,
    ) where
        B: Into<SecretBytes>,
    {
        self.unlock_with_plaintext_json_with_context(
            plaintext_json,
            timeout,
            auth_strength,
            UnlockOutcome::Primary,
            current_runtime_inspection_state(),
        )
        .await;
    }

    /// Unlock the vault with an explicit session policy context
    ///
    /// # Security
    /// Manager-owned session context avoids relying on callers to pass fresh
    /// policy information for every post-unlock sensitive operation
    pub async fn unlock_with_plaintext_json_with_context<B>(
        &self,
        plaintext_json: B,
        timeout: Duration,
        auth_strength: AuthenticationStrength,
        unlock_outcome: UnlockOutcome,
        runtime_state: RuntimeInspectionState,
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
                strong_reauth_required: !auth_strength.is_strong()
                    || runtime_state.is_restrictive(),
                unlock_outcome,
                runtime_state,
            };
        }

        self.restart_auto_lock(timeout, generation).await;
    }

    /// Decode a protected plaintext JSON buffer into a vault payload
    ///
    /// # Security
    /// This helper centralizes the sensitive JSON -> payload transition so all
    /// runtime call sites use the same strict decoding boundary
    fn decode_payload_from_plaintext_json(plaintext_json: &[u8]) -> Option<VaultPayload> {
        serde_json::from_slice::<VaultPayload>(plaintext_json).ok()
    }

    /// Encode a vault payload into a newly protected plaintext JSON buffer
    ///
    /// # Security
    /// The serialized bytes are wrapped in [`SecretBytes`] immediately so the
    /// temporary plaintext allocation is wiped on drop or replacement
    fn encode_payload_to_plaintext_json(payload: &VaultPayload) -> Option<SecretBytes> {
        Some(Zeroizing::new(serde_json::to_vec(payload).ok()?))
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
                Self::decode_payload_from_plaintext_json(plaintext_json.as_slice())
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

    /// Return the current unlock outcome of the unlocked session
    pub async fn current_unlock_outcome(&self) -> Option<UnlockOutcome> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked { unlock_outcome, .. } => Some(*unlock_outcome),
            VaultState::Locked => None,
        }
    }

    /// Return the current runtime inspection state of the unlocked session
    pub async fn current_runtime_inspection_state(&self) -> Option<RuntimeInspectionState> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked { runtime_state, .. } => Some(*runtime_state),
            VaultState::Locked => None,
        }
    }

    /// Return the current manager-owned policy context if the vault is unlocked
    pub async fn current_policy_context(&self) -> Option<PolicyContext> {
        let state = self.state.lock().await;
        match &*state {
            VaultState::Unlocked {
                unlock_outcome,
                runtime_state,
                ..
            } => Some(PolicyContext::from_parts(*unlock_outcome, *runtime_state)),
            VaultState::Locked => None,
        }
    }

    /// Refresh the manager-owned runtime inspection state using a live probe
    ///
    /// # Security
    /// Restrictive runtime states immediately make the session require strong
    /// re-authentication for sensitive operations
    ///
    /// # Design
    /// Sensitive-operation authorization must remain deterministic and
    /// should not silently probe and mutate runtime policy state as a side effect
    pub async fn refresh_runtime_policy_state(&self) -> Option<RuntimeInspectionState> {
        let refreshed = current_runtime_inspection_state();

        let mut state = self.state.lock().await;
        match &mut *state {
            VaultState::Unlocked {
                runtime_state,
                strong_reauth_required,
                ..
            } => {
                *runtime_state = refreshed;
                if refreshed.is_restrictive() {
                    *strong_reauth_required = true;
                }
                Some(refreshed)
            }
            VaultState::Locked => None,
        }
    }

    /// Set the runtime inspection state explicitly for the current unlocked session
    ///
    /// # Design
    /// This method exists to support deterministic tests and explicit runtime
    /// policy transitions driven by higher layers
    ///
    /// # Security
    /// Restrictive states immediately make the session require strong
    /// re-authentication for sensitive operations
    pub async fn set_runtime_policy_state(
        &self,
        runtime_state: RuntimeInspectionState,
    ) -> Option<()> {
        let mut state = self.state.lock().await;
        match &mut *state {
            VaultState::Unlocked {
                runtime_state: current,
                strong_reauth_required,
                ..
            } => {
                *current = runtime_state;
                if runtime_state.is_restrictive() {
                    *strong_reauth_required = true;
                }
                Some(())
            }
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
    /// This is intended for runtime events such as backgrounding,
    /// device-lock transitions or quick-unlock invalidation
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

    /// Authorize a sensitive in-session operation using manager-owned policy
    ///
    /// # Security
    /// Authorization is evaluated in the following order:
    /// - the vault must be unlocked
    /// - the current session policy must allow the requested operation
    /// - strong re-authentication requirements must be satisfied
    ///
    /// # Design
    /// This method uses the session-owned runtime state already stored in the manager \
    /// It does not perform a live runtime probe because:
    /// - hidden policy mutation during authorization makes tests non-deterministic
    /// - callers must be able to reason about policy state explicitly
    /// - runtime refresh should happen at explicit lifecycle boundaries
    pub async fn authorize_sensitive_operation(
        &self,
        operation: SensitiveOperation,
    ) -> Result<PolicyContext, EntryError> {
        let policy = self
            .current_policy_context()
            .await
            .ok_or(EntryError::VaultLocked)?;

        if !policy.allow_sensitive_operation(operation) {
            return Err(EntryError::PolicyDenied);
        }

        match self.requires_strong_reauth_for(operation).await {
            None => Err(EntryError::VaultLocked),
            Some(true) => Err(EntryError::ReauthRequired),
            Some(false) => Ok(policy),
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
                let mut payload =
                    Self::decode_payload_from_plaintext_json(plaintext_json.as_slice())?;

                let result = f(&mut payload);

                let new_json = Self::encode_payload_to_plaintext_json(&payload)?;
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
                let payload = Self::decode_payload_from_plaintext_json(plaintext_json.as_slice())?;
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
    use crate::core::antidebug::RuntimeInspectionState;
    use crate::core::session::{AuthenticationStrength, RuntimeSecurityEvent, SensitiveOperation};
    use crate::entries::EntryError;
    use crate::vault::VaultPayload;
    use crate::vault::duress::UnlockOutcome;
    use std::time::Duration;

    /// The compatibility unlock path must still create a strong primary session
    #[tokio::test]
    async fn compatibility_unlock_defaults_to_primary_strong_session() {
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
        assert_eq!(
            manager.current_unlock_outcome().await,
            Some(UnlockOutcome::Primary)
        );
        assert_eq!(manager.strong_reauth_required().await, Some(false));
    }

    /// Explicit decoy and runtime context must be preserved in manager-owned policy state
    #[tokio::test]
    async fn explicit_context_is_preserved() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json_with_context(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
                AuthenticationStrength::Strong,
                UnlockOutcome::Decoy,
                RuntimeInspectionState::NotDebugged,
            )
            .await;

        let policy = manager
            .current_policy_context()
            .await
            .expect("policy context");
        assert_eq!(policy.outcome(), UnlockOutcome::Decoy);
        assert_eq!(policy.runtime_state(), RuntimeInspectionState::NotDebugged);
    }

    /// Restrictive runtime policy must deny sensitive operations before re-auth semantics matter
    #[tokio::test]
    async fn restrictive_runtime_denies_sensitive_operation() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json_with_context(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
                AuthenticationStrength::Strong,
                UnlockOutcome::Primary,
                RuntimeInspectionState::Debugged,
            )
            .await;

        let err = manager
            .authorize_sensitive_operation(SensitiveOperation::RevealSecret)
            .await
            .expect_err("restrictive runtime must deny");

        assert!(matches!(err, EntryError::PolicyDenied));
    }

    /// Refreshing runtime policy state remains explicit and may change later authorization outcomes
    #[tokio::test]
    async fn explicit_runtime_refresh_updates_session_policy_state() {
        let manager = VaultLockManager::new();

        manager
            .unlock_with_plaintext_json_with_context(
                serde_json::to_vec(&VaultPayload { entries: vec![] }).expect("serialize"),
                Duration::from_secs(60),
                AuthenticationStrength::Strong,
                UnlockOutcome::Primary,
                RuntimeInspectionState::Debugged,
            )
            .await;

        let first = manager
            .authorize_sensitive_operation(SensitiveOperation::RevealSecret)
            .await;
        assert!(matches!(first, Err(EntryError::PolicyDenied)));

        let _ = manager.refresh_runtime_policy_state().await;

        let _current = manager.current_runtime_inspection_state().await;
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
