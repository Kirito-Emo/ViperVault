#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for signed backup decoding
//!
//! # Security
//! This target exercises the signed backup parsing and verification boundary \
//! Arbitrary byte streams must never trigger panics, hangs or invalid memory behavior

use libfuzzer_sys::fuzz_target;
use vipervault_core::backup::decode_signed_backup;
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::duress::UnlockOutcome;

fuzz_target!(|data: &[u8]| {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new("fuzz-password".to_string());

    let _ = decode_signed_backup(policy, &password, data);
});
