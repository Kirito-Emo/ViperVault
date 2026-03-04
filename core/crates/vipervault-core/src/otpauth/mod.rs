// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! OTPAuth import utilities
//!
//! - TOTP only (no HOTP)
//! - Strict parsing to avoid ambiguous inputs
//! - Produces `TotpSecret` compatible with the vault entry model

pub mod error;
pub mod export;
pub mod totp;
