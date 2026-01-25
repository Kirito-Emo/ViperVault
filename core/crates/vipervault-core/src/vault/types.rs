// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The number of bytes used for the vault KDF salt
///
/// # Notes
/// - 32 bytes is a common and safe salt size for password-based KDFs
pub const SALT_LEN: usize = 32;

/// The number of bytes used for XChaCha20-Poly1305 nonce
///
/// # Notes
/// - XChaCha20-Poly1305 uses a 24-byte nonce
pub const XCHACHA20_NONCE_LEN: usize = 24;

/// Vault storage mode for the payload
///
/// # Security
/// - `Encrypted` is the default and recommended mode
/// - `PlaintextJson` MUST be treated as an explicit "unsafe export" option
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum StorageMode {
    /// Payload is AEAD-encrypted bytes
    Encrypted = 1,

    /// Payload is plaintext JSON bytes (unsafe export)
    PlaintextJson = 2,
}

/// Vault file container: minimal public header + payload
///
/// # Security
/// - The header MUST NOT contain sensitive user data (privacy)
/// - Payload is encrypted by default; plaintext is an explicit unsafe option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    /// Non-secret metadata required to parse and decrypt (if encrypted)
    pub header: VaultHeader,

    /// Payload storage (encrypted or plaintext JSON)
    pub storage: VaultStorage,
}

/// Payload storage container
///
/// # Notes
/// This separates the on-disk representation from in-memory decrypted structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultStorage {
    /// AEAD-encrypted payload bytes
    Encrypted { ciphertext: Vec<u8> },

    /// Plaintext JSON payload bytes (unsafe export)
    PlaintextJson { json: Vec<u8> },
}

/// Parsed vault container with raw header bytes
///
/// # Security
/// - `header_bytes` MUST be used as AEAD AAD when decrypting
/// - Do not re-serialize JSON for AAD, as JSON is not canonical
#[derive(Debug, Clone)]
pub struct ParsedVaultFile {
    /// Container format version
    pub format_version: u16,

    /// Parsed header object
    pub header: VaultHeader,

    /// Raw header bytes exactly as stored in the file (AAD)
    pub header_bytes: Vec<u8>,

    /// Storage mode (encrypted / plaintext)
    pub mode: StorageMode,

    /// Payload bytes (ciphertext or plaintext json bytes)
    pub payload: Vec<u8>,
}

/// Minimal header stored in cleartext
///
/// # Privacy
/// Keep this structure *minimal* to avoid metadata leakage
///
/// # Security
/// This header must be authenticated when encrypting/decrypting (e.g., as AEAD AAD),
/// so attackers cannot tamper with KDF params, salt, nonce, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Version of the decrypted payload schema
    ///
    /// # Notes
    /// - This enables migrations while keeping the container format stable
    pub schema_version: u16,

    /// Vault unique identifier (non-secret)
    pub vault_id: Uuid,

    /// Crypto parameters required to derive keys and decrypt
    pub crypto: CryptoHeader,
}

/// Crypto parameters stored in cleartext
///
/// # Security
/// - `salt` and `nonce` are NOT secret, but MUST be unique per vault encryption
/// - Any tampering must be detected by authenticating the header via AEAD AAD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHeader {
    /// Key derivation function parameters
    pub kdf: KdfParams,

    /// Authenticated encryption scheme used to protect the payload
    pub aead: AeadSuite,

    /// KDF salt (non-secret)
    pub salt: [u8; SALT_LEN],

    /// AEAD nonce (non-secret)
    pub nonce: [u8; XCHACHA20_NONCE_LEN],
}

/// Supported KDF configurations
///
/// # Notes
/// Marked as `non_exhaustive` so new KDFs can be added without breaking downstream code
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KdfParams {
    /// Argon2id parameters (memory / time / parallelism)
    Argon2id {
        /// Memory cost in KiB
        mem_kib: u32,
        /// Time cost (iterations)
        time_cost: u32,
        /// Degree of parallelism
        lanes: u32,
    },
}

/// Supported AEAD suites
///
/// # Notes
/// Marked as `non_exhaustive` to allow future algorithm agility
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AeadSuite {
    XChaCha20Poly1305,
}

/// Decrypted vault content
///
/// # Security
/// This structure is serialized to JSON only inside the trusted boundary: after decrypt / before encrypt
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultPayload {
    /// All vault entries
    pub entries: Vec<crate::entries::VaultEntry>,
}
