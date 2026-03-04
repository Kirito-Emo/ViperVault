// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Types for signed backup container

use serde::{Deserialize, Serialize};

/// Backup container magic
pub const BACKUP_MAGIC: [u8; 8] = *b"VVBAKUP1";

/// Backup container version
pub const BACKUP_VERSION: u16 = 1;

/// Hard cap for container payload to limit allocations (bytes)
pub const MAX_BACKUP_PAYLOAD_LEN: u64 = 64 * 1024 * 1024; // 64 MiB

/// KDF policy used for deriving the backup signing key seed
///
/// # Security notes
/// - This is independent from the vault KDF params
/// - Backups are infrequent; using strong params is acceptable
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BackupKdfPolicy {
    pub mem_kib: u32,   // Argon2id memory cost in KiB
    pub time_cost: u32, // Argon2id time cost (iterations)
    pub lanes: u32,     // Argon2id lanes
}

/// Backup header stored in cleartext
///
/// # Security
/// - Contains no user secrets
/// - It is authenticated via signature together with the payload bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHeader {
    pub version: u16,         // Backup format version
    pub kdf: BackupKdfPolicy, // KDF policy for deriving signing key
    pub salt: [u8; 32],       // Salt for deriving signing key (32 bytes)
}
