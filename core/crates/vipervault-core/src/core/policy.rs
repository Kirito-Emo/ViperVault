// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy context for sensitive operations
//!
//! # Design
//! This module exposes the centralized policy matrix used by the core to decide
//! whether sensitive operations should be allowed under:
//! - a primary or decoy unlock outcome
//! - the current runtime inspection state
//! - the product-level sensitive operation category
//!
//! The intended architecture is:
//! - pre-unlock and standalone flows may receive an explicit [`PolicyContext`]
//! - post-unlock / in-session flows should derive policy from the manager-owned
//!   session state instead of trusting callers to pass a fresh policy object
//!
//! # Security
//! - Decoy sessions must deny exposure-prone and exfiltration-oriented actions
//! - Restrictive runtime states must degrade or deny sensitive capabilities
//! - Ambiguous runtime states are treated conservatively
//! - Policy decisions should remain deterministic and directly testable

use crate::core::antidebug::{RuntimeInspectionState, current_runtime_inspection_state};
use crate::core::session::SensitiveOperation;
use crate::vault::duress::UnlockOutcome;

/// Context describing security-relevant state for policy enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyContext {
    outcome: UnlockOutcome,
    runtime_state: RuntimeInspectionState,
}

impl PolicyContext {
    /// Construct a policy context from an unlock outcome
    ///
    /// # Design
    /// The current runtime inspection state is captured at construction time so
    /// the resulting context remains deterministic for the lifetime of that value
    pub fn new(outcome: UnlockOutcome) -> Self {
        Self {
            outcome,
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

    /// Return `true` when the runtime posture indicates stronger tamper risk
    pub fn is_tamper_suspected(&self) -> bool {
        self.runtime_state.is_tamper_suspected()
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

    /// Evaluate whether plaintext or secret export is allowed under the runtime policy
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

    /// Evaluate whether plaintext import is allowed under the runtime policy
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

    /// Evaluate whether biometric unlock is allowed under the runtime policy
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

    /// Evaluate whether signed backup transfer is allowed under the runtime policy
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

    /// Evaluate whether OTPAuth parsing/import is allowed under the runtime policy
    pub fn allow_otpauth_import(&self) -> bool {
        self.allow_otpauth_import_for_state(self.runtime_state)
    }

    /// Evaluate whether clipboard exposure is allowed for a given runtime state
    ///
    /// # Security
    /// Clipboard is an exposure-prone boundary and is denied in decoy mode and
    /// under restrictive runtime states
    pub fn allow_clipboard_copy_for_state(&self, state: RuntimeInspectionState) -> bool {
        !self.is_decoy() && matches!(state, RuntimeInspectionState::NotDebugged)
    }

    /// Evaluate whether clipboard exposure is allowed under the runtime policy
    pub fn allow_clipboard_copy(&self) -> bool {
        self.allow_clipboard_copy_for_state(self.runtime_state)
    }

    /// Evaluate whether TOTP copy/reveal is allowed under the runtime policy
    ///
    /// # Security
    /// TOTP disclosure uses the same exposure boundary as clipboard copy and is
    /// therefore governed by the same runtime rule set
    pub fn allow_totp_copy(&self) -> bool {
        self.allow_clipboard_copy()
    }

    /// Evaluate whether direct secret reveal is allowed under the runtime policy
    ///
    /// # Security
    /// Secret reveal is exposure-prone and therefore denied in decoy sessions
    /// and under restrictive runtime states
    pub fn allow_secret_reveal(&self) -> bool {
        !self.is_decoy() && matches!(self.runtime_state, RuntimeInspectionState::NotDebugged)
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

    /// Evaluate whether a given sensitive operation is permitted by policy
    ///
    /// # Security
    /// This helper centralizes the product-level operation matrix so the core
    /// can make deterministic allow/deny decisions without duplicating logic
    pub fn allow_sensitive_operation(&self, operation: SensitiveOperation) -> bool {
        match operation {
            SensitiveOperation::Export => self.allow_plaintext_export(),
            SensitiveOperation::SignedBackupTransfer => self.allow_signed_backup_transfer(),
            SensitiveOperation::RevealSecret => self.allow_secret_reveal(),
            SensitiveOperation::CopySecret => self.allow_clipboard_copy(),
            SensitiveOperation::CopyTotp => self.allow_totp_copy(),
            SensitiveOperation::ChangeSecuritySettings => {
                !self.is_decoy() && !self.is_runtime_restrictive()
            }
        }
    }
}

/// Return the current runtime policy context for a primary session
///
/// # Design
/// This helper is intended for standalone, non-session-bound operations that do
/// not run under a live manager-owned session context
pub fn current_primary_runtime_policy() -> PolicyContext {
    PolicyContext::from_parts(UnlockOutcome::Primary, current_runtime_inspection_state())
}

/// Evaluate whether plaintext export is allowed under the current runtime policy
///
/// # Design
/// This helper exists for standalone codec flows that do not run under an
/// unlocked manager session
pub fn allow_plaintext_export_under_runtime_policy() -> bool {
    current_primary_runtime_policy().allow_plaintext_export()
}

/// Evaluate whether clipboard exposure is allowed under the current runtime policy
///
/// # Design
/// This helper exists for standalone exposure boundaries that are not yet bound
/// to a live manager session
pub fn allow_clipboard_exposure_under_runtime_policy() -> bool {
    current_primary_runtime_policy().allow_clipboard_copy()
}
