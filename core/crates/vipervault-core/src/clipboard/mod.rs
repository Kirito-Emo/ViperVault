// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Clipboard auto-clear support
//!
//! # Security
//! - Secrets are copied to clipboard only temporarily
//! - Clipboard is cleared after a timeout
//! - Clear happens only if clipboard still contains the same value
//! - Secret copies kept for comparisons are wiped on drop (`Zeroizing<String>`)
//!
//! This design prevents overwriting user clipboard data and limits secret exposure

pub mod ffi;
pub mod guard;

pub use guard::*;
