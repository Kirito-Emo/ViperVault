// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! TOTP (RFC 6238) engine
//!
//! # Security notes
//! - Uses RustCrypto (HMAC + SHA1/SHA2)
//! - Performs strict Base32 decoding with bounded inputs
//! - Keeps decoded secret in `Zeroizing<Vec<u8>>`
//! - Avoids detailed error distinctions that could become an oracle

pub mod clipboard;
pub mod decode;
pub mod engine;
pub mod error;
pub mod format;
