// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Unlocked vault session
//!
//! # Design
//! This module provides a small session object that carries:
//! - The decrypted vault payload
//! - The unlock outcome (primary vs decoy)
//!
//! This is intended to help upper layers (app/UI) enforce security policies consistently
//!
//! # Security notes
//! - `UnlockOutcome::Decoy` should trigger stricter restrictions in the UI
//! - The session is an in-memory representation; persistence must remain encrypted

use crate::vault::duress::UnlockOutcome;
use crate::vault::VaultPayload;

/// An unlocked vault session
#[derive(Debug)]
pub struct UnlockedVaultSession {
    outcome: UnlockOutcome,
    payload: VaultPayload,
}

impl UnlockedVaultSession {
    /// Create a new session
    pub fn new(outcome: UnlockOutcome, payload: VaultPayload) -> Self {
        Self { outcome, payload }
    }

    /// Returns whether this session is the decoy vault
    pub fn is_decoy(&self) -> bool {
        self.outcome == UnlockOutcome::Decoy
    }

    /// Returns the unlock outcome (primary vs decoy)
    pub fn outcome(&self) -> UnlockOutcome {
        self.outcome
    }

    /// Returns a reference to the decrypted payload
    pub fn payload(&self) -> &VaultPayload {
        &self.payload
    }

    /// Returns a mutable reference to the decrypted payload
    ///
    /// # Security
    /// Mutations should be validated and persisted only via the encrypted save flow
    pub fn payload_mut(&mut self) -> &mut VaultPayload {
        &mut self.payload
    }

    /// Policy: allow plaintext export (unsafe)
    ///
    /// # Security rationale
    /// - Plaintext export is always sensitive
    /// - In decoy mode is hard-denied by default
    pub fn allow_plaintext_export(&self) -> bool {
        !self.is_decoy()
    }

    /// Policy: allow sharing secrets (e.g. OTPAuth export)
    ///
    /// # Notes
    /// In decoy mode, exporting is often counterproductive; the safe default is denied
    pub fn allow_secret_sharing(&self) -> bool {
        !self.is_decoy()
    }
}
