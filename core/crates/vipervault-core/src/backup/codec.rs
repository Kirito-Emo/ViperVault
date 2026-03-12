// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Signed backup codec
//!
//! # Container format
//! [magic: 8]
//! [version: u16 le]
//! [header_len: u32 le]
//! [header_json: header_len]
//! [payload_len: u64 le]
//! [payload_bytes: payload_len]
//! [sig_len: u16 le]
//! [signature: sig_len]
//!
//! Signature is computed over all bytes from magic up to the end of payload bytes
//!
//! # Security
//! - Signature verification requires a password-derived signing key
//! - The implementation does not distinguish tamper from wrong password (`AuthFailed`)

use super::error::BackupError;
use super::types::{
    BACKUP_MAGIC, BACKUP_VERSION, BackupHeader, BackupKdfPolicy, MAX_BACKUP_PAYLOAD_LEN,
};
use crate::core::policy::PolicyContext;
use crate::crypto::kdf::derive_master_key_from_password;
use crate::memory::MasterPassword;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Encode a signed backup
///
/// # Parameters
/// - `policy`: session policy
/// - `password`: master password used to derive the signing key
/// - `vault_container_bytes`: exact vault container bytes
/// - `kdf`: backup KDF policy
///
/// # Errors
/// Returns a coarse-grained [`BackupError`] on failure
///
/// # Security
/// Denied by the centralized session/runtime policy
pub fn encode_signed_backup(
    policy: PolicyContext,
    password: &MasterPassword,
    vault_container_bytes: &[u8],
    kdf: BackupKdfPolicy,
) -> Result<Vec<u8>, BackupError> {
    if !policy.allow_signed_backup_transfer() {
        return Err(BackupError::PolicyDenied);
    }

    if (vault_container_bytes.len() as u64) > MAX_BACKUP_PAYLOAD_LEN {
        return Err(BackupError::PayloadTooLarge);
    }

    let mut salt = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| BackupError::Serialize)?;

    let header = BackupHeader {
        version: BACKUP_VERSION,
        kdf,
        salt,
    };

    let header_json = serde_json::to_vec(&header).map_err(|_| BackupError::Serialize)?;
    let header_len_u32: u32 = header_json
        .len()
        .try_into()
        .map_err(|_| BackupError::InvalidFormat)?;

    // Build bytes to be signed first
    let mut out = Vec::with_capacity(
        8 + 2 + 4 + header_json.len() + 8 + vault_container_bytes.len() + 2 + 64,
    );

    out.extend_from_slice(&BACKUP_MAGIC);
    out.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    out.extend_from_slice(&header_len_u32.to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&(vault_container_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(vault_container_bytes);

    // Sign all bytes
    let signing_key = derive_backup_signing_key(password, &header)?;
    let sig: Signature = signing_key.sign(&out);

    // Append signature
    out.extend_from_slice(&(64u16).to_le_bytes());
    out.extend_from_slice(sig.to_bytes().as_slice());

    Ok(out)
}

/// Decode a signed backup and return the vault container bytes
///
/// # Security
/// Returns `AuthFailed` if verification fails or the password is wrong \
/// Denied by the centralized session/runtime policy
pub fn decode_signed_backup(
    policy: PolicyContext,
    password: &MasterPassword,
    backup_bytes: &[u8],
) -> Result<Vec<u8>, BackupError> {
    if !policy.allow_signed_backup_transfer() {
        return Err(BackupError::PolicyDenied);
    }

    let mut cursor = 0usize;

    let magic = read_exact::<8>(backup_bytes, &mut cursor)?;
    if magic != BACKUP_MAGIC {
        return Err(BackupError::InvalidFormat);
    }

    let version = read_u16_le(backup_bytes, &mut cursor)?;
    if version != BACKUP_VERSION {
        return Err(BackupError::UnsupportedVersion);
    }

    let header_len = read_u32_le(backup_bytes, &mut cursor)? as usize;
    if header_len == 0 {
        return Err(BackupError::InvalidFormat);
    }

    let header_json = read_vec(backup_bytes, &mut cursor, header_len)?;
    let header: BackupHeader =
        serde_json::from_slice(&header_json).map_err(|_| BackupError::Deserialize)?;
    if header.version != BACKUP_VERSION {
        return Err(BackupError::UnsupportedVersion);
    }

    let payload_len = read_u64_le(backup_bytes, &mut cursor)?;
    if payload_len > MAX_BACKUP_PAYLOAD_LEN {
        return Err(BackupError::PayloadTooLarge);
    }

    let payload_len_usize: usize = payload_len
        .try_into()
        .map_err(|_| BackupError::InvalidFormat)?;

    let payload = read_vec(backup_bytes, &mut cursor, payload_len_usize)?;

    let sig_len = read_u16_le(backup_bytes, &mut cursor)?;
    if sig_len != 64 {
        return Err(BackupError::InvalidFormat);
    }

    let sig_bytes = read_vec(backup_bytes, &mut cursor, 64)?;
    if cursor != backup_bytes.len() {
        return Err(BackupError::InvalidFormat);
    }

    let sig = Signature::from_slice(&sig_bytes).map_err(|_| BackupError::InvalidFormat)?;

    // Verify signature over bytes before signature fields
    let signed_len = backup_bytes
        .len()
        .checked_sub(2 + 64)
        .ok_or(BackupError::InvalidFormat)?;

    let verifying_key: VerifyingKey = derive_backup_verifying_key(password, &header)?;
    verifying_key
        .verify(&backup_bytes[..signed_len], &sig)
        .map_err(|_| BackupError::AuthFailed)?;

    Ok(payload)
}

/// Derive the Ed25519 signing key from the master password
///
/// # Design
/// Argon2id derives a master key using `header.salt` and `header.kdf` \
/// HKDF-SHA256 expands that key into a 32-byte Ed25519 seed
fn derive_backup_signing_key(
    password: &MasterPassword,
    header: &BackupHeader,
) -> Result<SigningKey, BackupError> {
    let mk = derive_master_key_from_password(
        password,
        &header.salt,
        header.kdf.mem_kib,
        header.kdf.time_cost,
        header.kdf.lanes,
    )
    .map_err(|_| BackupError::AuthFailed)?;

    let seed = hkdf_expand_seed(mk.as_bytes())?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Derive the verifying key using the same password-based derivation path
///
/// # Security
/// This still derives the signing seed internally, but keeps the seed lifetime minimal
fn derive_backup_verifying_key(
    password: &MasterPassword,
    header: &BackupHeader,
) -> Result<VerifyingKey, BackupError> {
    let signing = derive_backup_signing_key(password, header)?;
    Ok(signing.verifying_key())
}

/// Expand a 32-byte Ed25519 seed from the master key using HKDF-SHA256
///
/// # Security
/// The returned seed is wrapped in [`Zeroizing`] to reduce residual memory exposure
fn hkdf_expand_seed(master_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"vipervault-backup-ed25519-seed", &mut okm[..])
        .map_err(|_| BackupError::Serialize)?;
    Ok(okm)
}

fn read_exact<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], BackupError> {
    let end = cursor.checked_add(N).ok_or(BackupError::InvalidFormat)?;
    if end > bytes.len() {
        return Err(BackupError::InvalidFormat);
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(out)
}

fn read_u16_le(bytes: &[u8], cursor: &mut usize) -> Result<u16, BackupError> {
    Ok(u16::from_le_bytes(read_exact::<2>(bytes, cursor)?))
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32, BackupError> {
    Ok(u32::from_le_bytes(read_exact::<4>(bytes, cursor)?))
}

fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> Result<u64, BackupError> {
    Ok(u64::from_le_bytes(read_exact::<8>(bytes, cursor)?))
}

fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>, BackupError> {
    let end = cursor.checked_add(len).ok_or(BackupError::InvalidFormat)?;
    if end > bytes.len() {
        return Err(BackupError::InvalidFormat);
    }

    let out = bytes[*cursor..end].to_vec();
    *cursor = end;
    Ok(out)
}
