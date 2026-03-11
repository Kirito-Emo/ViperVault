// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Authenticated encryption (AEAD)

use crate::memory::KeyMaterial;
use crate::vault::XCHACHA20_NONCE_LEN;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::TryRng;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

/// Errors returned by the AEAD layer
///
/// # Security
/// Errors are intentionally generic to reduce leakage
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// System RNG failure
    #[error("sys rng failure")]
    SysRng,

    /// Encryption failed
    #[error("encryption error")]
    Encrypt,

    /// Decryption failed
    #[error("decryption error")]
    Decrypt,
}

/// Generates a fresh random XChaCha20-Poly1305 nonce
///
/// # Security
/// - Nonce MUST be unique per encryption under the same key
/// - This function relies on the operating system CSPRNG
///
/// # Errors
/// Returns [`AeadError::SysRng`] if the system RNG fails
pub fn generate_xchacha20_nonce() -> Result<[u8; XCHACHA20_NONCE_LEN], AeadError> {
    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| AeadError::SysRng)?;
    Ok(nonce)
}

/// Encrypts plaintext using XChaCha20-Poly1305 with associated data
///
/// # Parameters
/// - `key`: 32-byte key
/// - `nonce`: 24-byte XChaCha20 nonce
/// - `plaintext`: plaintext bytes
/// - `aad`: associated data authenticated but not encrypted
///
/// # Returns
/// Ciphertext including the authentication tag
///
/// # Security
/// - The caller should authenticate serialized header bytes through `aad`
/// - The returned ciphertext provides confidentiality and integrity
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
/// - `key`: 32-byte key
/// - `nonce`: 24-byte XChaCha20 nonce
/// - `ciphertext`: ciphertext including tag
/// - `aad`: associated data that must match exactly
///
/// # Returns
/// Plaintext wrapped in [`Zeroizing<Vec<u8>>`]
///
/// # Security
/// - Any modification to ciphertext or AAD causes decryption failure
/// - Callers should deserialize immediately and avoid unnecessary copies
///
/// # Errors
/// Returns [`AeadError::Decrypt`] if authentication fails
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
