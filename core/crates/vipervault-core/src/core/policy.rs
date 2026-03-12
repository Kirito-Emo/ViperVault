// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy context for sensitive operations
//!
//! # Design
//! Upper layers should pass a [`PolicyContext`] when invoking sensitive APIs \
//! This provides defense-in-depth: even if a caller forgets to restrict a
//! feature, the core still applies the policy consistently
//!
//! The centralized policy matrix is derived from:
//! - unlock outcome (`Primary` vs `Decoy`)
//! - runtime debugger status (`DebugStatus`)
//!
//! # Security
//! - Decoy sessions must deny exfiltration-oriented operations by default
//! - Active debugging must degrade sensitive capabilities through a soft policy
//! - Policy decisions should remain deterministic and directly testable

use crate::core::antidebug::DebugStatus;
use crate::vault::duress::UnlockOutcome;

/// Context describing security-relevant state for policy enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyContext {
    outcome: UnlockOutcome,
}

impl PolicyContext {
    /// Construct a policy context from an unlock outcome
    pub fn new(outcome: UnlockOutcome) -> Self {
        Self { outcome }
    }

    /// Return the unlock outcome represented by this policy context
    pub fn outcome(&self) -> UnlockOutcome {
        self.outcome
    }

    /// Return `true` when the current session is the decoy vault
    pub fn is_decoy(&self) -> bool {
        self.outcome == UnlockOutcome::Decoy
    }

    /// Evaluate whether plaintext or secret export is allowed for a given debugger status
    ///
    /// # Parameters
    /// - `status`: debugger detection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and active debugging has not been detected
    ///
    /// # Security
    /// Export-oriented operations materially reduce the cost of exfiltration and
    /// must therefore be denied in decoy mode and under active debugging
    pub fn allow_secret_export_for_status(&self, status: DebugStatus) -> bool {
        !self.is_decoy() && !matches!(status, DebugStatus::Debugged)
    }

    /// Evaluate whether plaintext or secret export is allowed under the runtime soft policy
    pub fn allow_secret_export(&self) -> bool {
        self.allow_secret_export_for_status(crate::core::detect_debugging())
    }

    /// Evaluate whether plaintext import is allowed for a given debugger status
    ///
    /// # Parameters
    /// - `status`: debugger detection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and active debugging has not been detected
    ///
    /// # Security
    /// Plaintext import is both sensitive and attacker-controlled \
    /// It must be denied in decoy sessions and under active debugging
    pub fn allow_plaintext_import_for_status(&self, status: DebugStatus) -> bool {
        !self.is_decoy() && !matches!(status, DebugStatus::Debugged)
    }

    /// Evaluate whether plaintext import is allowed under the runtime soft policy
    pub fn allow_plaintext_import(&self) -> bool {
        self.allow_plaintext_import_for_status(crate::core::detect_debugging())
    }

    /// Evaluate whether biometric unlock is allowed for a given debugger status
    ///
    /// # Parameters
    /// - `status`: debugger detection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and active debugging has not been detected
    ///
    /// # Security
    /// Biometric unlock reduces friction for privileged access paths \
    /// It must remain unavailable in decoy sessions and under active debugging
    pub fn allow_biometric_unlock_for_status(&self, status: DebugStatus) -> bool {
        !self.is_decoy() && !matches!(status, DebugStatus::Debugged)
    }

    /// Evaluate whether biometric unlock is allowed under the runtime soft policy
    pub fn allow_biometric_unlock(&self) -> bool {
        self.allow_biometric_unlock_for_status(crate::core::detect_debugging())
    }

    /// Evaluate whether signed backup transfer is allowed for a given debugger status
    ///
    /// # Parameters
    /// - `status`: debugger detection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and active debugging has not been detected
    ///
    /// # Security
    /// Signed backup flows move whole encrypted vault containers and remain highly sensitive \
    /// They must be denied in decoy sessions and under active debugging
    pub fn allow_signed_backup_transfer_for_status(&self, status: DebugStatus) -> bool {
        !self.is_decoy() && !matches!(status, DebugStatus::Debugged)
    }

    /// Evaluate whether signed backup transfer is allowed under the runtime soft policy
    pub fn allow_signed_backup_transfer(&self) -> bool {
        self.allow_signed_backup_transfer_for_status(crate::core::detect_debugging())
    }

    /// Evaluate whether OTPAuth parsing/import is allowed for a given debugger status
    ///
    /// # Parameters
    /// - `status`: debugger detection outcome used for policy evaluation
    ///
    /// # Returns
    /// `true` only when the session is not decoy and active debugging has not been detected
    ///
    /// # Security
    /// OTPAuth import parses attacker-controlled plaintext secrets and must
    /// therefore remain unavailable in decoy sessions and under active debugging
    pub fn allow_otpauth_import_for_status(&self, status: DebugStatus) -> bool {
        !self.is_decoy() && !matches!(status, DebugStatus::Debugged)
    }

    /// Evaluate whether OTPAuth parsing/import is allowed under the runtime soft policy
    pub fn allow_otpauth_import(&self) -> bool {
        self.allow_otpauth_import_for_status(crate::core::detect_debugging())
    }
}
