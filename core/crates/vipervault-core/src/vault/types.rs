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
    Encrypted = 1,     // Payload is AEAD-encrypted bytes
    PlaintextJson = 2, // Payload is plaintext JSON bytes (unsafe export)
}

/// Vault file container: minimal public header + payload
///
/// # Security
/// - The header MUST NOT contain sensitive user data (privacy)
/// - Payload is encrypted by default; plaintext is an explicit unsafe option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub header: VaultHeader, // Non-secret metadata required to parse and decrypt (if encrypted)
    pub storage: VaultStorage, // Payload storage (encrypted or plaintext JSON)
}

/// Payload storage container
///
/// # Notes
/// This separates the on-disk representation from in-memory decrypted structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultStorage {
    Encrypted { ciphertext: Vec<u8> }, // AEAD-encrypted payload bytes
    PlaintextJson { json: Vec<u8> },   // Plaintext JSON payload bytes (unsafe export)
}

/// Parsed vault container with raw header bytes
///
/// # Security
/// - `header_bytes` MUST be used as AEAD AAD when decrypting
/// - Do not re-serialize JSON for AAD, as JSON is not canonical
#[derive(Debug, Clone)]
pub struct ParsedVaultFile {
    pub format_version: u16,   // Container format version
    pub header: VaultHeader,   // Parsed header object
    pub header_bytes: Vec<u8>, // Raw header bytes exactly as stored in the file (AAD)
    pub mode: StorageMode,     // Storage mode (encrypted / plaintext)
    pub payload: Vec<u8>,      // Payload bytes (ciphertext or plaintext json bytes)
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

    pub vault_id: Uuid,       // Vault unique identifier (non-secret)
    pub crypto: CryptoHeader, // Crypto parameters required to derive keys and decrypt (legacy single payload)

    /// Optional duress configuration (dual payload)
    ///
    /// # Backward compatibility
    /// - `#[serde(default)]` allows old vault headers (without this field) to deserialize
    #[serde(default)]
    pub duress: Option<DualVaultHeader>,
}

/// Duress/decoy header section
///
/// # Notes
/// When present, the vault payload bytes are expected to be a JSON-serialized
/// [`DualCiphertextEnvelope`] (not a raw ciphertext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualVaultHeader {
    pub primary: CryptoHeader,
    pub decoy: CryptoHeader,
}

/// Envelope stored in `ParsedVaultFile.payload` when duress mode is enabled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualCiphertextEnvelope {
    pub primary_ct: Vec<u8>,
    pub decoy_ct: Vec<u8>,
}

/// Crypto parameters stored in cleartext
///
/// # Security
/// - `salt` and `nonce` are NOT secret, but MUST be unique per vault encryption
/// - Any tampering must be detected by authenticating the header via AEAD AAD
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHeader {
    pub kdf: KdfParams,                   // Key derivation function parameters
    pub aead: AeadSuite, // Authenticated encryption scheme used to protect the payload
    pub salt: [u8; SALT_LEN], // KDF salt (non-secret)
    pub nonce: [u8; XCHACHA20_NONCE_LEN], // AEAD nonce (non-secret)
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
        mem_kib: u32,   // Memory cost in KiB
        time_cost: u32, // Time cost (iterations)
        lanes: u32,     // Degree of parallelism
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
