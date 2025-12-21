// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::kdf::MASTER_KEY_LEN;
use crate::vault::XCHACHA20_NONCE_LEN;

/// Errors returned by the AEAD layer
///
/// # Security
/// Errors are intentionally generic to reduce leakage
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// OS RNG failure (extremely rare)
    #[error("os rng error")]
    OsRng,

    /// Encryption failed
    #[error("encryption error")]
    Encrypt,

    /// Decryption failed (wrong key or tampered ciphertext/AAD)
    #[error("decryption error")]
    Decrypt,

    /// Invalid nonce length
    #[error("invalid nonce")]
    InvalidNonce,

    /// Invalid key length
    #[error("invalid key")]
    InvalidKey,
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
    master_key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
    nonce: &[u8; XCHACHA20_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = xchacha_cipher_from_key(master_key)?;
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
/// Plaintext wrapped in [`Zeroizing`] to wipe it on drop
///
/// # Security
/// - If either ciphertext or AAD is modified, decryption fails
/// - Caller should deserialize plaintext immediately and avoid extra copies
///
/// # Errors
/// Returns [`AeadError::Decrypt`] if authentication fails (wrong key/tampering)
pub fn decrypt_xchacha20poly1305(
    master_key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
    nonce: &[u8; XCHACHA20_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    let cipher = xchacha_cipher_from_key(master_key)?;
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

/// Creates an XChaCha20-Poly1305 cipher instance from a 32-byte master key
///
/// # Errors
/// Returns [`AeadError::InvalidKey`] if the key is malformed (should not happen with correct KDF)
fn xchacha_cipher_from_key(
    master_key: &Zeroizing<[u8; MASTER_KEY_LEN]>,
) -> Result<XChaCha20Poly1305, AeadError> {
    // Ensure the key length matches the AEAD suite requirement
    if MASTER_KEY_LEN != 32 {
        return Err(AeadError::InvalidKey);
    }

    // Copy into a temporary Key type (wiped afterward)
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(master_key.as_ref());
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    // Wipe temporary key bytes (master_key itself is already Zeroizing)
    key_bytes.zeroize();

    Ok(cipher)
}
