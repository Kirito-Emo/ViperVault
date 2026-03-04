// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy context for sensitive operations
//!
//! # Design
//! Upper layers (app/UI) should pass a `PolicyContext` when calling sensitive APIs
//! This enables defense-in-depth: even if the UI forgets to restrict a feature, the core
//! still enforces the policy
//!
//! # Security notes
//! - Decoy sessions must deny secret sharing/export by default

use crate::vault::duress::UnlockOutcome;

/// Context describing security-relevant state for policy enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyContext {
    outcome: UnlockOutcome,
}

impl PolicyContext {
    /// Policy context from an unlock outcome
    pub fn new(outcome: UnlockOutcome) -> Self {
        Self { outcome }
    }

    /// Returns true if current session is the decoy vault
    pub fn is_decoy(&self) -> bool {
        self.outcome == UnlockOutcome::Decoy
    }

    /// Policy: allow exporting secrets (e.g. OTPAuth URI, plaintext export)
    ///
    /// # Security note
    /// Decoy mode should be as "non-exfiltratable" as possible by default
    pub fn allow_secret_export(&self) -> bool {
        !self.is_decoy()
    }
}
