#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for plaintext interop quarantine import
//!
//! # Security
//! This target exercises a high-risk plaintext import boundary that accepts
//! attacker-controlled OTPAuth URI lists\
//! Arbitrary input must never trigger panics, hangs or invalid memory behavior

use libfuzzer_sys::fuzz_target;
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::import::{import_interop_quarantine, ImportIntent, InteropFormat};
use vipervault_core::vault::duress::UnlockOutcome;

fuzz_target!(|data: &[u8]| {
    let policy = PolicyContext::new(UnlockOutcome::Primary);

    let _ = import_interop_quarantine(
        policy,
        ImportIntent::UserConfirmed,
        InteropFormat::OtpAuthTotpUriList,
        data,
    );
});
