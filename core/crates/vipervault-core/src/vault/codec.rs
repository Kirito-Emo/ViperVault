// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use crate::vault::{
    MAGIC, MAX_HEADER_LEN, ParsedVaultFile, StorageMode, VaultHeader, VaultParseError, VaultStorage,
};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

/// Encodes a vault container as:
/// `MAGIC(4) | FORMAT_VERSION(u16 LE) | STORAGE_MODE(u8) | HEADER_LEN(u32 LE) | HEADER_JSON | PAYLOAD_LEN(u64 LE) | PAYLOAD`
///
/// # Security
/// - This module only packs/unpacks bytes
/// - Encryption is handled elsewhere
/// - Temporary buffers are wiped on drop where relevant
///
/// # Errors
/// Returns [`VaultParseError`] on unsupported versions, serialization failure, or size violations
pub fn encode_vault_storage(
    header: &VaultHeader,
    storage: &VaultStorage,
    format_version: u16,
) -> Result<Vec<u8>, VaultParseError> {
    if format_version == 0 {
        return Err(VaultParseError::UnsupportedVersion);
    }

    let (mode, payload_bytes) = match storage {
        VaultStorage::Encrypted { ciphertext } => (StorageMode::Encrypted, ciphertext.as_slice()),
        VaultStorage::PlaintextJson { json } => (StorageMode::PlaintextJson, json.as_slice()),
    };

    // Wipe intermediate header bytes on drop
    let header_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(serialize_header_json(header)?);
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

/// Decodes a vault container from a reader
///
/// # Parameters
/// - `expected_format_version`:
///   - `Some(v)`: decoding fails unless container version == `v`
///   - `None`: any non-zero version is accepted
/// - `max_payload_len`: hard upper bound to prevent unbounded allocations
/// - `allow_plaintext`: if false, plaintext payloads are rejected
///
/// # Security
/// - Length-prefixed parsing + hard bounds
/// - Rejects trailing bytes (tampering/padding)
/// - Returns raw `header_bytes` for AEAD AAD usage (JSON is not canonical)
///
/// # Errors
/// Returns [`VaultParseError`] on invalid input, unsupported modes, bounds violations, or tampering
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
    if let Some(expected) = expected_format_version {
        if format_version != expected {
            return Err(VaultParseError::UnsupportedVersion);
        }
    }

    // STORAGE_MODE
    let storage_mode_raw = read_u8(&mut input)?;
    let mode = match storage_mode_raw {
        1 => StorageMode::Encrypted,
        2 => {
            if !allow_plaintext {
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

    // HEADER_JSON (read into a zeroizing buffer)
    let mut header_buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; header_len as usize]);
    input.read_exact(&mut header_buf)?;

    // Keep exact header bytes for AEAD AAD (JSON is not canonical)
    let header_bytes: Vec<u8> = header_buf.to_vec();

    let header = match deserialize_header_json(&header_buf) {
        Ok(h) => h,
        Err(e) => {
            header_buf.zeroize();
            return Err(e);
        }
    };

    // PAYLOAD_LEN
    let payload_len = read_u64_le(&mut input)?;
    if payload_len > max_payload_len {
        return Err(VaultParseError::PayloadTooLarge);
    }

    // PAYLOAD
    let mut payload = vec![0u8; payload_len as usize];
    input.read_exact(&mut payload)?;

    // Reject trailing bytes (tampering/padding)
    let mut extra = [0u8; 1];
    match input.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err(VaultParseError::TrailingBytes),
        Err(e) => return Err(VaultParseError::Io(e)),
    }

    Ok(ParsedVaultFile {
        format_version,
        header,
        header_bytes,
        mode,
        payload,
    })
}

/// Convenience helper: writes a vault container to a writer
///
/// # Errors
/// Returns [`VaultParseError`] if encoding fails or the writer fails
pub fn write_vault_storage(
    mut out: impl Write,
    header: &VaultHeader,
    storage: &VaultStorage,
    format_version: u16,
) -> Result<(), VaultParseError> {
    let bytes = encode_vault_storage(header, storage, format_version)?;
    out.write_all(&bytes)?;
    Ok(())
}

/// Serializes a header into JSON bytes
///
/// # Notes
/// JSON is not canonical; for AEAD AAD use the raw bytes stored in the file
fn serialize_header_json(header: &VaultHeader) -> Result<Vec<u8>, VaultParseError> {
    serde_json::to_vec(header).map_err(|_| VaultParseError::Serialize)
}

/// Deserializes a header from JSON bytes
fn deserialize_header_json(bytes: &[u8]) -> Result<VaultHeader, VaultParseError> {
    serde_json::from_slice(bytes).map_err(|_| VaultParseError::Deserialize)
}

/// Reads a little-endian u16
fn read_u16_le(mut r: impl Read) -> Result<u16, VaultParseError> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// Reads a little-endian u32
fn read_u32_le(mut r: impl Read) -> Result<u32, VaultParseError> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Reads a little-endian u64
fn read_u64_le(mut r: impl Read) -> Result<u64, VaultParseError> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Reads a single byte
fn read_u8(mut r: impl Read) -> Result<u8, VaultParseError> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}
