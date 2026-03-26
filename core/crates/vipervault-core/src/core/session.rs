// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Unlocked session model and authentication-strength metadata
//!
//! # Design
//! This module models:
//! - the unlocked vault session returned by password-based unlock flows
//! - the strength of the authentication that established a session
//! - which sensitive operations should require strong re-authentication
//! - which runtime security events should degrade or invalidate session posture
//!
//! # Security
//! A vault being "unlocked" is not sufficient, by itself, to decide whether a
//! sensitive operation should be allowed without re-authentication

use crate::vault::VaultPayload;
use crate::vault::duress::UnlockOutcome;

/// Authentication strength associated with the current session
///
/// # Security
/// The variants are ordered conceptually from strongest to weakest assurance:
/// - [`Self::Strong`]: full master-password or equivalent strong unlock
/// - [`Self::Biometric`]: biometric unlock of previously protected key material
/// - [`Self::QuickUnlock`]: local convenience unlock with reduced assurance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticationStrength {
    /// Strong authentication, typically the master password
    Strong,

    /// Biometric unlock of already provisioned local secrets
    Biometric,

    /// Local convenience unlock with reduced assurance
    QuickUnlock,
}

impl AuthenticationStrength {
    /// Return `true` when the authentication strength counts as strong
    pub fn is_strong(self) -> bool {
        matches!(self, Self::Strong)
    }
}

/// Sensitive operation categories used to determine whether strong
/// re-authentication is required
///
/// # Security
/// These categories are product-level rather than UI-specific, so the core
/// can enforce consistent behaviour regardless of the calling layer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SensitiveOperation {
    /// Plaintext or secret export
    Export,

    /// Signed-backup transfer/import flows
    SignedBackupTransfer,

    /// Reveal a stored secret to the UI
    RevealSecret,

    /// Copy a stored secret to clipboard or equivalent boundary
    CopySecret,

    /// Copy or reveal a TOTP code
    CopyTotp,

    /// Change security-critical settings or posture
    ChangeSecuritySettings,
}

impl SensitiveOperation {
    /// Return `true` when this operation should require strong re-authentication
    /// for non-strong sessions
    pub fn requires_strong_reauth(self) -> bool {
        match self {
            Self::Export
            | Self::SignedBackupTransfer
            | Self::RevealSecret
            | Self::CopySecret
            | Self::CopyTotp
            | Self::ChangeSecuritySettings => true,
        }
    }
}

/// Runtime security events that can degrade or invalidate session posture
///
/// # Security
/// Some events merely require strong re-authentication, while others should
/// invalidate convenience unlocks or force a full lock
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeSecurityEvent {
    /// The app moved to the background
    AppBackgrounded,

    /// The device or app session became locked
    DeviceLocked,

    /// The enrolled biometric set changed
    BiometricSetChanged,

    /// Quick unlock was invalidated by local policy or storage changes
    QuickUnlockInvalidated,

    /// The runtime posture became restrictive or suspicious
    RuntimeBecameRestrictive,
}

impl RuntimeSecurityEvent {
    /// Return `true` when this event should force a full lock immediately
    pub fn forces_lock(self) -> bool {
        matches!(
            self,
            Self::DeviceLocked
                | Self::BiometricSetChanged
                | Self::QuickUnlockInvalidated
                | Self::RuntimeBecameRestrictive
        )
    }

    /// Return `true` when this event should at least require strong
    /// re-authentication if the session remains unlocked
    pub fn requires_strong_reauth(self) -> bool {
        matches!(self, Self::AppBackgrounded)
    }
}

/// Represents a successfully unlocked vault session
///
/// # Security
/// This type carries:
/// - the unlocked payload
/// - the unlock outcome (`Primary` or `Decoy`)
/// - the authentication strength that established the session
///
/// Stronger session metadata is required so sensitive follow-up operations can
/// distinguish between fully authenticated sessions and convenience unlocks
#[derive(Debug)]
pub struct UnlockedVaultSession {
    outcome: UnlockOutcome,
    payload: VaultPayload,
    // Track the authentication strength that established the session so callers
    // can enforce re-authentication for sensitive operations when needed
    auth_strength: AuthenticationStrength,
}

impl UnlockedVaultSession {
    /// Create a new unlocked session using strong authentication
    ///
    /// # Design
    /// This preserves compatibility with the existing password-based unlock
    /// flows, which should establish a strong session by default
    pub fn new(outcome: UnlockOutcome, payload: VaultPayload) -> Self {
        Self {
            outcome,
            payload,
            // Password-based unlocks remain strong by default
            auth_strength: AuthenticationStrength::Strong,
        }
    }

    /// Create a new unlocked session with an explicit authentication strength
    ///
    /// # Design
    /// This constructor exists so future biometric and quick-unlock flows can
    /// create sessions without pretending to be strong master-password unlocks
    pub fn with_strength(
        outcome: UnlockOutcome,
        payload: VaultPayload,
        auth_strength: AuthenticationStrength,
    ) -> Self {
        Self {
            outcome,
            payload,
            auth_strength,
        }
    }

    /// Return the unlock outcome for this session
    pub fn outcome(&self) -> UnlockOutcome {
        self.outcome
    }

    /// Return `true` when this is the decoy session
    pub fn is_decoy(&self) -> bool {
        matches!(self.outcome, UnlockOutcome::Decoy)
    }

    /// Borrow the decrypted vault payload
    pub fn payload(&self) -> &VaultPayload {
        &self.payload
    }

    /// Consume the session and return the decrypted vault payload
    pub fn into_payload(self) -> VaultPayload {
        self.payload
    }

    /// Return the authentication strength that established this session
    pub fn auth_strength(&self) -> AuthenticationStrength {
        self.auth_strength
    }

    /// Return `true` when the session was established through strong authentication
    pub fn is_strong(&self) -> bool {
        self.auth_strength.is_strong()
    }

    /// Return `true` when this session should require strong re-authentication
    /// before the given sensitive operation
    ///
    /// # Security
    /// Non-strong sessions must not be treated as equivalent to full
    /// master-password authentication for exposure-prone operations
    pub fn requires_strong_reauth_for(&self, operation: SensitiveOperation) -> bool {
        !self.is_strong() && operation.requires_strong_reauth()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticationStrength, RuntimeSecurityEvent, SensitiveOperation, UnlockedVaultSession,
    };
    use crate::vault::VaultPayload;
    use crate::vault::duress::UnlockOutcome;

    /// Strong sessions must not require strong re-authentication for sensitive
    /// operations solely because of session strength
    #[test]
    fn strong_session_does_not_require_extra_strong_reauth() {
        let session =
            UnlockedVaultSession::new(UnlockOutcome::Primary, VaultPayload { entries: vec![] });

        assert!(session.is_strong());
        assert_eq!(session.auth_strength(), AuthenticationStrength::Strong);
        assert!(!session.requires_strong_reauth_for(SensitiveOperation::Export));
        assert!(!session.requires_strong_reauth_for(SensitiveOperation::CopyTotp));
    }

    /// Biometric sessions must require strong re-authentication for sensitive operations
    #[test]
    fn biometric_session_requires_strong_reauth_for_sensitive_ops() {
        let session = UnlockedVaultSession::with_strength(
            UnlockOutcome::Primary,
            VaultPayload { entries: vec![] },
            AuthenticationStrength::Biometric,
        );

        assert!(!session.is_strong());
        assert!(session.requires_strong_reauth_for(SensitiveOperation::Export));
        assert!(session.requires_strong_reauth_for(SensitiveOperation::CopySecret));
    }

    /// Quick-unlock sessions must require strong re-authentication for
    /// exposure-prone follow-up operations
    #[test]
    fn quick_unlock_requires_strong_reauth_for_sensitive_ops() {
        let session = UnlockedVaultSession::with_strength(
            UnlockOutcome::Primary,
            VaultPayload { entries: vec![] },
            AuthenticationStrength::QuickUnlock,
        );

        assert!(!session.is_strong());
        assert!(session.requires_strong_reauth_for(SensitiveOperation::RevealSecret));
        assert!(session.requires_strong_reauth_for(SensitiveOperation::ChangeSecuritySettings));
    }

    /// Decoy sessions must still report their outcome independently from auth strength
    #[test]
    fn decoy_session_reports_decoy_outcome() {
        let session = UnlockedVaultSession::with_strength(
            UnlockOutcome::Decoy,
            VaultPayload { entries: vec![] },
            AuthenticationStrength::Strong,
        );

        assert!(session.is_decoy());
        assert_eq!(session.outcome(), UnlockOutcome::Decoy);
    }

    /// Runtime security events must keep their lock vs re-auth semantics stable
    #[test]
    fn runtime_event_semantics_remain_stable() {
        assert!(RuntimeSecurityEvent::DeviceLocked.forces_lock());
        assert!(RuntimeSecurityEvent::BiometricSetChanged.forces_lock());
        assert!(RuntimeSecurityEvent::QuickUnlockInvalidated.forces_lock());
        assert!(RuntimeSecurityEvent::RuntimeBecameRestrictive.forces_lock());
        assert!(RuntimeSecurityEvent::AppBackgrounded.requires_strong_reauth());
        assert!(!RuntimeSecurityEvent::DeviceLocked.requires_strong_reauth());
    }
}
