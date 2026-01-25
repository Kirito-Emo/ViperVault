// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Authenticated encryption (AEAD)

use crate::memory::KeyMaterial;
use crate::vault::XCHACHA20_NONCE_LEN;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// Errors returned by the AEAD layer
///
/// # Security
/// Errors are intentionally generic to reduce leakage
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// OS RNG failure (extremely rare)
    #[error("os rng failure")]
    OsRng,

    /// Encryption failed
    #[error("encryption error")]
    Encrypt,

    /// Decryption failed (wrong key or tampered ciphertext/AAD)
    #[error("decryption error")]
    Decrypt,
}

/// Generates a fresh random XChaCha20-Poly1305 nonce
///
/// # Security
/// - Nonce MUST be unique per encryption under the same key
/// - Nonce is not secret; store it in the vault header
///
/// # Errors
/// Returns [`AeadError::OsRng`] if OS RNG fails
pub fn generate_xchacha20_nonce() -> Result<[u8; XCHACHA20_NONCE_LEN], AeadError> {
    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| AeadError::OsRng)?;
    Ok(nonce)
}

/// Encrypts plaintext using XChaCha20-Poly1305 with associated data
///
/// # Parameters
/// - `master_key`: 32-byte key (derived via Argon2id)
/// - `nonce`: 24-byte XChaCha nonce
/// - `plaintext`: data to encrypt (will be copied by the AEAD implementation)
/// - `aad`: associated data (e.g., serialized header bytes) authenticated but not encrypted
///
/// # Returns
/// Ciphertext bytes containing the authentication tag
///
/// # Security
/// - Authenticate the vault header by passing its serialized bytes as `aad`
/// - The returned ciphertext includes integrity protection (AEAD)
///
/// # Errors
/// Returns [`AeadError::Encrypt`] on failure
pub fn encrypt_xchacha20poly1305(
    key: &KeyMaterial,
    nonce: &[u8; XCHACHA20_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError::Encrypt)
}

/// Decrypts ciphertext using XChaCha20-Poly1305 with associated data
///
/// # Parameters
/// - `master_key`: 32-byte key (derived via Argon2id)
/// - `nonce`: 24-byte XChaCha nonce
/// - `ciphertext`: ciphertext bytes with auth tag
/// - `aad`: associated data that must match exactly (e.g., serialized header bytes)
///
/// # Returns
/// Plaintext wrapped in `Zeroizing<Vec<u8>>`
///
/// # Security
/// - If either ciphertext or AAD is modified, decryption fails
/// - Caller should deserialize plaintext immediately and avoid extra copies
///
/// # Errors
/// Returns [`AeadError::Decrypt`] if authentication fails (wrong key/tampering)
pub fn decrypt_xchacha20poly1305(
    key: &KeyMaterial,
    nonce: &[u8; XCHACHA20_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);

    let pt = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError::Decrypt)?;

    Ok(Zeroizing::new(pt))
}
