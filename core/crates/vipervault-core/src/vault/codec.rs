// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault container codec
//!
//! # Security
//! - Plaintext export is denied under the runtime policy helper
//! - Duress-enabled vaults must not be exported as plaintext
//! - Raw header bytes are preserved exactly as stored because they are used as
//!   AEAD AAD

use crate::core::allow_plaintext_export_under_runtime_policy;
use crate::vault::{
    MAGIC, MAX_HEADER_LEN, ParsedVaultFile, StorageMode, VaultHeader, VaultParseError, VaultStorage,
};
use std::io::{Read, Write};

/// Hard cap for vault container payload to limit allocations from untrusted input (bytes)
pub const MAX_VAULT_CONTAINER_PAYLOAD_LEN: u64 = 16 * 1024 * 1024; // 16 MiB

/// Encode a vault container
///
/// # Security
/// - Plaintext export is denied under the runtime policy helper
/// - Duress-enabled vaults must not be exported as plaintext
pub fn encode_vault_storage(
    header: &VaultHeader,
    storage: &VaultStorage,
    format_version: u16,
) -> Result<Vec<u8>, VaultParseError> {
    if format_version == 0 {
        return Err(VaultParseError::UnsupportedVersion);
    }

    if header.duress.is_some() && matches!(storage, VaultStorage::PlaintextJson { .. }) {
        return Err(VaultParseError::PlaintextNotAllowed);
    }

    if matches!(storage, VaultStorage::PlaintextJson { .. })
        && !allow_plaintext_export_under_runtime_policy()
    {
        return Err(VaultParseError::PlaintextNotAllowed);
    }

    let (mode, payload_bytes) = match storage {
        VaultStorage::Encrypted { ciphertext } => (StorageMode::Encrypted, ciphertext.as_slice()),
        VaultStorage::PlaintextJson { json } => (StorageMode::PlaintextJson, json.as_slice()),
    };

    let header_bytes = serialize_header_json(header)?;
    if header_bytes.len() as u32 > MAX_HEADER_LEN {
        return Err(VaultParseError::HeaderTooLarge);
    }

    let mut out = Vec::with_capacity(4 + 2 + 1 + 4 + header_bytes.len() + 8 + payload_bytes.len());

    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&format_version.to_le_bytes());
    out.push(mode as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(payload_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(payload_bytes);

    Ok(out)
}

/// Decode a vault container from a reader
///
/// # Parameters
/// - `expected_format_version`:
///   - `Some(v)`: decoding fails unless container version == `v`
///   - `None`: any non-zero version is accepted
/// - `max_payload_len`: hard upper bound to prevent unbounded allocations
/// - `allow_plaintext`: if false, plaintext payloads are rejected
///
/// # Security
/// - Plaintext payloads are rejected under runtime policy
/// - Header bytes are preserved for AEAD AAD usage
/// - Duress + plaintext is rejected
pub fn decode_vault_file(
    mut input: impl Read,
    expected_format_version: Option<u16>,
    max_payload_len: u64,
    allow_plaintext: bool,
) -> Result<ParsedVaultFile, VaultParseError> {
    // MAGIC
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(VaultParseError::InvalidMagic);
    }

    // FORMAT_VERSION
    let format_version = read_u16_le(&mut input)?;
    if format_version == 0 {
        return Err(VaultParseError::UnsupportedVersion);
    }

    if let Some(expected) = expected_format_version
        && format_version != expected
    {
        return Err(VaultParseError::UnsupportedVersion);
    }

    // STORAGE_MODE
    let storage_mode_raw = read_u8(&mut input)?;
    let mode = match storage_mode_raw {
        1 => StorageMode::Encrypted,
        2 => {
            if !allow_plaintext || !allow_plaintext_export_under_runtime_policy() {
                return Err(VaultParseError::PlaintextNotAllowed);
            }
            StorageMode::PlaintextJson
        }
        _ => return Err(VaultParseError::UnsupportedStorageMode),
    };

    // HEADER_LEN
    let header_len = read_u32_le(&mut input)?;
    if header_len > MAX_HEADER_LEN {
        return Err(VaultParseError::HeaderTooLarge);
    }

    let header_len_usize =
        usize::try_from(header_len).map_err(|_| VaultParseError::HeaderTooLarge)?;

    // HEADER_JSON
    let mut header_bytes = vec![0u8; header_len_usize];
    input.read_exact(&mut header_bytes)?;

    let header = deserialize_header_json(&header_bytes)?;

    if header.duress.is_some() && mode == StorageMode::PlaintextJson {
        return Err(VaultParseError::PlaintextNotAllowed);
    }

    // PAYLOAD_LEN
    let payload_len = read_u64_le(&mut input)?;
    if payload_len > max_payload_len {
        return Err(VaultParseError::PayloadTooLarge);
    }

    let payload_len_usize =
        usize::try_from(payload_len).map_err(|_| VaultParseError::PayloadTooLarge)?;

    // PAYLOAD
    let mut payload = vec![0u8; payload_len_usize];
    input.read_exact(&mut payload)?;

    // Reject trailing bytes (tampering/padding)
    let mut extra = [0u8; 1];
    if input.read(&mut extra)? != 0 {
        return Err(VaultParseError::TrailingBytes);
    }

    Ok(ParsedVaultFile {
        format_version,
        header,
        header_bytes,
        mode,
        payload,
    })
}

/// Convenience helper: encode and write a vault container to a writer
///
/// # Security
/// - This function does not bypass policy
/// - Plaintext export remains subject to runtime policy checks enforced by [`encode_vault_storage`]
#[allow(dead_code)]
pub(crate) fn write_vault_storage(
    mut out: impl Write,
    header: &VaultHeader,
    storage: &VaultStorage,
    format_version: u16,
) -> Result<(), VaultParseError> {
    let bytes = encode_vault_storage(header, storage, format_version)?;
    out.write_all(&bytes)?;
    Ok(())
}

/// Serialize a header into JSON bytes
///
/// # Security
/// The resulting bytes are not secret, but they are integrity-critical because
/// they are later used as AEAD AAD
fn serialize_header_json(header: &VaultHeader) -> Result<Vec<u8>, VaultParseError> {
    serde_json::to_vec(header).map_err(|_| VaultParseError::Serialize)
}

/// Deserialize a header from JSON bytes
fn deserialize_header_json(bytes: &[u8]) -> Result<VaultHeader, VaultParseError> {
    serde_json::from_slice(bytes).map_err(|_| VaultParseError::Deserialize)
}

/// Read a little-endian `u16`
fn read_u16_le(mut r: impl Read) -> Result<u16, VaultParseError> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// Read a little-endian `u32`
fn read_u32_le(mut r: impl Read) -> Result<u32, VaultParseError> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Read a little-endian `u64`
fn read_u64_le(mut r: impl Read) -> Result<u64, VaultParseError> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Read a single byte
fn read_u8(mut r: impl Read) -> Result<u8, VaultParseError> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}
