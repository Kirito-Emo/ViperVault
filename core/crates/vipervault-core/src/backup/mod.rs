// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Signed backup container
//!
//! # Goals
//! - Provide integrity for exported backups (tamper detection)
//! - Require the master password to verify (prevents attacker from swapping public keys)
//!
//! # Security notes
//! - Backup bytes are sensitive, so they are treated as secret material
//! - In decoy sessions, export/import should be denied by policy

pub mod codec;
pub mod error;
pub mod types;

pub use codec::{decode_signed_backup, encode_signed_backup};
pub use error::BackupError;
pub use types::{BackupHeader, BackupKdfPolicy};
