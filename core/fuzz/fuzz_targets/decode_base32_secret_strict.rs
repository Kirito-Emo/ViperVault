#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for strict Base32 secret decoding
//!
//! # Security
//! This target exercises strict secret decoding for untrusted plaintext input \
//! Arbitrary strings must never trigger panics, hangs or invalid memory
//! behavior

use libfuzzer_sys::fuzz_target;
use vipervault_core::totp::decode::decode_base32_secret_strict;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let _ = decode_base32_secret_strict(input);
});
