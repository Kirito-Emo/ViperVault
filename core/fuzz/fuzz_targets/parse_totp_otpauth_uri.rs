#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for OTPAuth TOTP URI parsing
//!
//! # Security
//! This target exercises the plaintext URI parsing boundary used for OTP import \
//! Arbitrary attacker-controlled strings must never trigger panics, hangs or
//! invalid memory behavior

use libfuzzer_sys::fuzz_target;
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::otpauth::totp::parse_totp_otpauth_uri;
use vipervault_core::vault::duress::UnlockOutcome;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let _ = parse_totp_otpauth_uri(policy, input);
});
