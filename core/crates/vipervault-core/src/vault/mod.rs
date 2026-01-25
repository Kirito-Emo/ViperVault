// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

pub mod codec;
pub mod error;
pub mod storage;
pub mod types;

/// Magic bytes to quickly identify the file format
pub const MAGIC: [u8; 4] = *b"VLT1";

/// Hard limit to avoid unbounded allocations from untrusted input
pub const MAX_HEADER_LEN: u32 = 4096;

// Public API re-exports
pub use codec::*;
pub use error::VaultParseError;
pub use error::*;
pub use storage::*;
pub use types::*;
