#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Structure-aware fuzz target for signed backup decoding
//!
//! # Purpose
//! This target starts from a valid signed backup container and then applies
//! targeted field-level mutations to exercise parser states that are difficult
//! to reach with raw byte fuzzing alone
//!
//! # Security
//! The signed backup parser must reject malformed but near-valid containers
//! without panicking and without accidentally accepting corrupted lengths,
//! signatures or trailing bytes

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vipervault_core::backup::{decode_signed_backup, encode_signed_backup, BackupKdfPolicy};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::duress::UnlockOutcome;

/// Fuzz password used to generate valid containers
const FUZZ_PASSWORD: &str = "fuzz-password";

/// Maximum payload length used by the structured generator
///
/// # Design
/// The objective is parser exploration rather than stress-testing allocator limits
const MAX_PAYLOAD_LEN: usize = 8 * 1024;

/// Maximum trailing length appended by trailing-byte mutations
const MAX_TRAILING_LEN: usize = 256;

/// Structured mutation kind applied to an otherwise valid signed backup
#[derive(Debug, Clone, Copy, Arbitrary)]
enum MutationKind {
    /// Leave the container untouched and assert roundtrip success
    None,

    /// Replace the declared version with an unsupported value
    UnsupportedVersion,

    /// Shrink the declared header length by one byte
    HeaderLenShrink,

    /// Grow the declared header length by one byte
    HeaderLenGrow,

    /// Flip one byte inside the header JSON
    HeaderJsonFlip,

    /// Shrink the declared payload length by one byte
    PayloadLenShrink,

    /// Grow the declared payload length by one byte
    PayloadLenGrow,

    /// Flip one byte inside the payload
    PayloadFlip,

    /// Replace signature length with 63
    SigLenShort,

    /// Replace signature length with 65
    SigLenLong,

    /// Flip one byte inside the signature
    SigFlip,

    /// Append trailing bytes after the signature
    AppendTrailing,
}

/// Structured input used by the fuzz target
#[derive(Debug, Clone, Arbitrary)]
struct StructuredSignedBackupCase {
    /// Payload bytes wrapped into a valid signed backup before mutation
    payload: Vec<u8>,

    /// Mutation applied after valid encoding
    mutation: MutationKind,

    /// Generic tweak byte used to select flip positions
    tweak: u8,

    /// Optional trailing bytes used by `AppendTrailing`
    trailing: Vec<u8>,
}

/// Byte ranges for the key fields of a valid signed backup container
#[derive(Debug, Clone, Copy)]
struct BackupOffsets {
    /// Version field range
    version_start: usize,
    version_end: usize,

    /// Header length field range
    header_len_start: usize,
    header_len_end: usize,

    /// Header JSON range
    header_json_start: usize,
    header_json_end: usize,

    /// Payload length field range
    payload_len_start: usize,
    payload_len_end: usize,

    /// Payload bytes range
    payload_start: usize,
    payload_end: usize,

    /// Signature length field range
    sig_len_start: usize,
    sig_len_end: usize,

    /// Signature bytes range
    sig_start: usize,
    sig_end: usize,
}

impl StructuredSignedBackupCase {
    /// Return a bounded payload for valid-container generation
    fn bounded_payload(&self) -> Vec<u8> {
        let mut payload = self.payload.clone();
        payload.truncate(MAX_PAYLOAD_LEN);
        payload
    }

    /// Return bounded trailing bytes
    fn bounded_trailing(&self) -> Vec<u8> {
        let mut trailing = self.trailing.clone();
        trailing.truncate(MAX_TRAILING_LEN);
        trailing
    }
}

/// Build the KDF policy used by the target
fn backup_kdf() -> BackupKdfPolicy {
    BackupKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build a valid signed backup container from the provided payload
fn build_valid_signed_backup(payload: &[u8]) -> Vec<u8> {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new(FUZZ_PASSWORD.to_string());

    encode_signed_backup(policy, &password, payload, backup_kdf()).expect("valid signed backup")
}

/// Locate the important field ranges inside a valid signed backup container
fn locate_offsets(bytes: &[u8]) -> Option<BackupOffsets> {
    if bytes.len() < 8 + 2 + 4 + 8 + 2 + 64 {
        return None;
    }

    let version_start = 8usize;
    let version_end = version_start.checked_add(2)?;

    let header_len_start = version_end;
    let header_len_end = header_len_start.checked_add(4)?;

    let header_len = u32::from_le_bytes(
        bytes
            .get(header_len_start..header_len_end)?
            .try_into()
            .ok()?,
    ) as usize;

    let header_json_start = header_len_end;
    let header_json_end = header_json_start.checked_add(header_len)?;

    let payload_len_start = header_json_end;
    let payload_len_end = payload_len_start.checked_add(8)?;

    let payload_len = u64::from_le_bytes(
        bytes
            .get(payload_len_start..payload_len_end)?
            .try_into()
            .ok()?,
    ) as usize;

    let payload_start = payload_len_end;
    let payload_end = payload_start.checked_add(payload_len)?;

    let sig_len_start = payload_end;
    let sig_len_end = sig_len_start.checked_add(2)?;

    let sig_len =
        u16::from_le_bytes(bytes.get(sig_len_start..sig_len_end)?.try_into().ok()?) as usize;

    let sig_start = sig_len_end;
    let sig_end = sig_start.checked_add(sig_len)?;

    if sig_end != bytes.len() {
        return None;
    }

    Some(BackupOffsets {
        version_start,
        version_end,
        header_len_start,
        header_len_end,
        header_json_start,
        header_json_end,
        payload_len_start,
        payload_len_end,
        payload_start,
        payload_end,
        sig_len_start,
        sig_len_end,
        sig_start,
        sig_end,
    })
}

/// Read a little-endian `u32`
fn read_u32_le(bytes: &[u8], start: usize, end: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(start..end)?.try_into().ok()?))
}

/// Read a little-endian `u64`
fn read_u64_le(bytes: &[u8], start: usize, end: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(start..end)?.try_into().ok()?))
}

/// Write a little-endian `u32`
fn write_u32_le(bytes: &mut [u8], start: usize, end: usize, value: u32) -> Option<()> {
    bytes
        .get_mut(start..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

/// Write a little-endian `u64`
fn write_u64_le(bytes: &mut [u8], start: usize, end: usize, value: u64) -> Option<()> {
    bytes
        .get_mut(start..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

/// Write a little-endian `u16`
fn write_u16_le(bytes: &mut [u8], start: usize, end: usize, value: u16) -> Option<()> {
    bytes
        .get_mut(start..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

/// Apply a structured mutation to an otherwise valid container
fn apply_mutation(bytes: &mut Vec<u8>, mutation: MutationKind, tweak: u8, trailing: &[u8]) {
    let Some(offsets) = locate_offsets(bytes) else {
        return;
    };

    match mutation {
        MutationKind::None => {}

        MutationKind::UnsupportedVersion => {
            let _ = write_u16_le(bytes, offsets.version_start, offsets.version_end, 0xFFFF);
        }

        MutationKind::HeaderLenShrink => {
            let Some(header_len) =
                read_u32_le(bytes, offsets.header_len_start, offsets.header_len_end)
            else {
                return;
            };

            if header_len > 1 {
                let _ = write_u32_le(
                    bytes,
                    offsets.header_len_start,
                    offsets.header_len_end,
                    header_len - 1,
                );
            }
        }

        MutationKind::HeaderLenGrow => {
            let Some(header_len) =
                read_u32_le(bytes, offsets.header_len_start, offsets.header_len_end)
            else {
                return;
            };

            let _ = write_u32_le(
                bytes,
                offsets.header_len_start,
                offsets.header_len_end,
                header_len.saturating_add(1),
            );
        }

        MutationKind::HeaderJsonFlip => {
            if offsets.header_json_start < offsets.header_json_end {
                let span = offsets.header_json_end - offsets.header_json_start;
                let idx = offsets.header_json_start + (usize::from(tweak) % span);
                bytes[idx] ^= 0x01;
            }
        }

        MutationKind::PayloadLenShrink => {
            let Some(payload_len) =
                read_u64_le(bytes, offsets.payload_len_start, offsets.payload_len_end)
            else {
                return;
            };

            if payload_len > 0 {
                let _ = write_u64_le(
                    bytes,
                    offsets.payload_len_start,
                    offsets.payload_len_end,
                    payload_len - 1,
                );
            }
        }

        MutationKind::PayloadLenGrow => {
            let Some(payload_len) =
                read_u64_le(bytes, offsets.payload_len_start, offsets.payload_len_end)
            else {
                return;
            };

            let _ = write_u64_le(
                bytes,
                offsets.payload_len_start,
                offsets.payload_len_end,
                payload_len.saturating_add(1),
            );
        }

        MutationKind::PayloadFlip => {
            if offsets.payload_start < offsets.payload_end {
                let span = offsets.payload_end - offsets.payload_start;
                let idx = offsets.payload_start + (usize::from(tweak) % span);
                bytes[idx] ^= 0x01;
            }
        }

        MutationKind::SigLenShort => {
            let _ = write_u16_le(bytes, offsets.sig_len_start, offsets.sig_len_end, 63);
        }

        MutationKind::SigLenLong => {
            let _ = write_u16_le(bytes, offsets.sig_len_start, offsets.sig_len_end, 65);
        }

        MutationKind::SigFlip => {
            if offsets.sig_start < offsets.sig_end {
                let span = offsets.sig_end - offsets.sig_start;
                let idx = offsets.sig_start + (usize::from(tweak) % span);
                bytes[idx] ^= 0x01;
            }
        }

        MutationKind::AppendTrailing => {
            bytes.extend_from_slice(trailing);
        }
    }
}

fuzz_target!(|case: StructuredSignedBackupCase| {
    let payload = case.bounded_payload();
    let mut encoded = build_valid_signed_backup(&payload);
    let trailing = case.bounded_trailing();

    apply_mutation(&mut encoded, case.mutation, case.tweak, &trailing);

    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let password = MasterPassword::new(FUZZ_PASSWORD.to_string());

    let result = decode_signed_backup(policy, &password, &encoded);

    if matches!(case.mutation, MutationKind::None) {
        let decoded = result.expect("valid structured case must roundtrip");
        assert_eq!(decoded, payload);
    }
});
