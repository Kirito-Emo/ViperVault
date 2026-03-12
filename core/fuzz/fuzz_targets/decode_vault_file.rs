#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for vault container decoding
//!
//! # Security
//! This target exercises the primary untrusted-byte parsing boundary for vault containers \
//! The objective is to ensure that arbitrary byte streams never trigger panics,
//! hangs or memory-safety issues

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vipervault_core::vault::{decode_vault_file, MAX_VAULT_CONTAINER_PAYLOAD_LEN};

fuzz_target!(|data: &[u8]| {
    let _ = decode_vault_file(
        Cursor::new(data),
        None,
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    );
});
