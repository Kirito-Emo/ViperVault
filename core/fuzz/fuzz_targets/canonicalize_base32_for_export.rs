#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for Base32 canonicalization
//!
//! # Security
//! This target exercises the normalization boundary for attacker-controlled
//! Base32 secrets \
//! Arbitrary text input must never trigger panics, hangs or invalid memory behavior

use libfuzzer_sys::fuzz_target;
use vipervault_core::totp::decode::canonicalize_base32_for_export;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let _ = canonicalize_base32_for_export(input);
});
