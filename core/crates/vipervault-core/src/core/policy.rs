// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy context for sensitive operations
//!
//! # Design
//! Upper layers should pass a [`PolicyContext`] when invoking sensitive APIs \
//! This provides defence-in-depth: even if a caller forgets to restrict a
//! feature, the core still applies the policy consistently
//!
//! The centralized policy matrix is derived from:
//! - unlock outcome (`Primary` vs `Decoy`)
//! - runtime inspection state (`RuntimeInspectionState`)
//!
//! # Security
//! - Decoy sessions must deny exfiltration-oriented operations by default
//! - Restrictive runtime states must degrade sensitive capabilities
//! - Policy decisions should remain deterministic and directly testable

use crate::core::antidebug::{current_runtime_inspection_state, RuntimeInspectionState};
use crate::vault::duress::UnlockOutcome;

/// Context describing security-relevant state for policy enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyContext {
    outcome: UnlockOutcome,
    runtime_state: RuntimeInspectionState,
}

impl PolicyContext {
    /// Construct a policy context from an unlock outcome
    pub fn new(outcome: UnlockOutcome) -> Self {
        Self {
            outcome,
            // Capture the current runtime inspection state at construction time
            // so all policy decisions for this context remain deterministic
            runtime_state: current_runtime_inspection_state(),
        }
    }

    /// Construct a policy context from explicit components
    ///
    /// # Design
    /// This constructor is intended for tests and deterministic policy
    /// evaluation without relying on live runtime probing
    pub fn from_parts(outcome: UnlockOutcome, runtime_state: RuntimeInspectionState) -> Self {
        Self {
            outcome,
            runtime_state,
        }
    }

    /// Return the unlock outcome represented by this policy context
    pub fn outcome(&self) -> UnlockOutcome {
        self.outcome
    }

    /// Return the runtime inspection state represented by this policy context
    pub fn runtime_state(&self) -> RuntimeInspectionState {
        self.runtime_state
    }

    /// Return `true` when the current session is the decoy vault
    pub fn is_decoy(&self) -> bool {
        self.outcome == UnlockOutcome::Decoy
    }

    /// Return `true` when the runtime posture is restrictive
    ///
    /// # Security
    /// `Unknown` is treated conservatively and therefore counts as restrictive
    pub fn is_runtime_restrictive(&self) -> bool {
        self.runtime_state.is_restrictive()
    }

    /// Evaluate whether plaintext or secret export is allowed for a given runtime state
    ///
    /// # Parameters
    /// - `state`: runtime inspection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and the runtime state is clean
    ///
    /// # Security
    /// Export-oriented operations materially reduce the cost of exfiltration and
    /// must therefore be denied in decoy mode and under restrictive runtime states
    pub fn allow_secret_export_for_state(&self, state: RuntimeInspectionState) -> bool {
        !self.is_decoy() && matches!(state, RuntimeInspectionState::NotDebugged)
    }

    /// Evaluate whether plaintext or secret export is allowed under the runtime soft policy
    pub fn allow_secret_export(&self) -> bool {
        self.allow_secret_export_for_state(self.runtime_state)
    }

    /// Evaluate whether plaintext export is allowed under the runtime policy
    pub fn allow_plaintext_export(&self) -> bool {
        self.allow_secret_export()
    }

    /// Evaluate whether plaintext import is allowed for a given runtime state
    ///
    /// # Parameters
    /// - `state`: runtime inspection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and the runtime state is clean
    ///
    /// # Security
    /// Plaintext import is both sensitive and attacker-controlled \
    /// It must be denied in decoy sessions and under restrictive runtime states
    pub fn allow_plaintext_import_for_state(&self, state: RuntimeInspectionState) -> bool {
        !self.is_decoy() && matches!(state, RuntimeInspectionState::NotDebugged)
    }

    /// Evaluate whether plaintext import is allowed under the runtime soft policy
    pub fn allow_plaintext_import(&self) -> bool {
        self.allow_plaintext_import_for_state(self.runtime_state)
    }

    /// Evaluate whether biometric unlock is allowed for a given runtime state
    ///
    /// # Parameters
    /// - `state`: runtime inspection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and the runtime state is clean
    ///
    /// # Security
    /// Biometric unlock reduces friction for privileged access paths \
    /// It must remain unavailable in decoy sessions and under restrictive runtime states
    pub fn allow_biometric_unlock_for_state(&self, state: RuntimeInspectionState) -> bool {
        !self.is_decoy() && matches!(state, RuntimeInspectionState::NotDebugged)
    }

    /// Evaluate whether biometric unlock is allowed under the runtime soft policy
    pub fn allow_biometric_unlock(&self) -> bool {
        self.allow_biometric_unlock_for_state(self.runtime_state)
    }

    /// Evaluate whether signed backup transfer is allowed for a given runtime state
    ///
    /// # Parameters
    /// - `state`: runtime inspection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and the runtime state is clean
    ///
    /// # Security
    /// Signed backup flows move whole encrypted vault containers and remain highly sensitive \
    /// They must be denied in decoy sessions and under restrictive runtime states
    pub fn allow_signed_backup_transfer_for_state(&self, state: RuntimeInspectionState) -> bool {
        !self.is_decoy() && matches!(state, RuntimeInspectionState::NotDebugged)
    }

    /// Evaluate whether signed backup transfer is allowed under the runtime soft policy
    pub fn allow_signed_backup_transfer(&self) -> bool {
        self.allow_signed_backup_transfer_for_state(self.runtime_state)
    }

    /// Evaluate whether OTPAuth parsing/import is allowed for a given runtime state
    ///
    /// # Parameters
    /// - `state`: runtime inspection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and the runtime state is clean
    ///
    /// # Security
    /// OTPAuth import parses attacker-controlled plaintext secrets and must
    /// therefore remain unavailable in decoy sessions and under restrictive runtime states
    pub fn allow_otpauth_import_for_state(&self, state: RuntimeInspectionState) -> bool {
        !self.is_decoy() && matches!(state, RuntimeInspectionState::NotDebugged)
    }

    /// Evaluate whether OTPAuth parsing/import is allowed under the runtime soft policy
    pub fn allow_otpauth_import(&self) -> bool {
        self.allow_otpauth_import_for_state(self.runtime_state)
    }

    /// Evaluate whether clipboard copy is allowed for a given runtime state
    ///
    /// # Security
    /// Clipboard is an exposure-prone boundary and is denied in decoy mode and
    /// under restrictive runtime states
    pub fn allow_clipboard_copy_for_state(&self, state: RuntimeInspectionState) -> bool {
        !self.is_decoy() && matches!(state, RuntimeInspectionState::NotDebugged)
    }

    /// Evaluate whether clipboard copy is allowed under the runtime soft policy
    pub fn allow_clipboard_copy(&self) -> bool {
        self.allow_clipboard_copy_for_state(self.runtime_state)
    }

    /// Evaluate whether TOTP copy/reveal is allowed under the runtime policy
    ///
    /// # Security
    /// TOTP disclosure uses the same clipboard-style exposure boundary and is
    /// therefore governed by the same runtime rule set
    pub fn allow_totp_copy(&self) -> bool {
        self.allow_clipboard_copy()
    }

    /// Return `true` when runtime policy should force a shorter auto-lock posture
    pub fn requires_short_autolock(&self) -> bool {
        self.runtime_state.is_restrictive()
    }

    /// Return `true` when stronger re-authentication should be required for
    /// sensitive operations
    pub fn requires_strong_reauth_for_sensitive_ops(&self) -> bool {
        self.runtime_state.is_restrictive()
    }

    /// Return `true` when the runtime posture indicates stronger tamper risk
    pub fn is_tamper_suspected(&self) -> bool {
        self.runtime_state.is_tamper_suspected()
    }
}

/// Evaluate whether plaintext or secret export is allowed under the runtime
/// compatibility helper
///
/// # Security
/// This remains a compatibility layer for existing call sites \
/// It still applies the centralized runtime policy conservatively
pub fn allow_export_under_soft_policy() -> bool {
    PolicyContext::from_parts(UnlockOutcome::Primary, current_runtime_inspection_state())
        .allow_plaintext_export()
}

/// Evaluate whether clipboard exposure is allowed under the runtime
/// compatibility helper
///
/// # Security
/// This remains a compatibility layer for existing clipboard call sites and
/// denies clipboard exposure under restrictive runtime states
pub fn allow_clipboard_under_soft_policy() -> bool {
    PolicyContext::from_parts(UnlockOutcome::Primary, current_runtime_inspection_state())
        .allow_clipboard_copy()
}
