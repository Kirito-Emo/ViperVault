// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! AEAD XChaCha20-Poly1305 functional tests
//!
//! # Scope
//! These tests verify the functional correctness of the AEAD layer,
//! independently from higher-level vault logic
//!
//! Covered scenarios:
//! - encrypt/decrypt roundtrip (small, empty, large plaintexts)
//! - nonce uniqueness guarantees
//! - authentication of associated data (AAD)
//! - absence of deterministic ciphertext reuse
//!
//! # Security
//! These tests ensure that:
//! - no plaintext corruption occurs
//! - AEAD properties (confidentiality + integrity) hold
//! - large payloads are handled safely without truncation

use vipervault_core::crypto::aead::{
    decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, generate_xchacha20_nonce,
};
use vipervault_core::memory::KeyMaterial;

/// Encrypt and decrypt a small plaintext successfully
#[test]
fn encrypt_decrypt_roundtrip_small_plaintext() {
    let key = KeyMaterial::new([42u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();
    let aad = b"header-bytes";
    let plaintext = b"super secret data";

    let ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
    let pt = decrypt_xchacha20poly1305(&key, &nonce, &ct, aad).unwrap();

    assert_eq!(pt.as_slice(), plaintext);
}

/// Encrypt and decrypt an empty plaintext
///
/// # Security
/// Empty messages are valid inputs and must be authenticated correctly
#[test]
fn encrypt_decrypt_roundtrip_empty_plaintext() {
    let key = KeyMaterial::new([0u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();
    let aad = b"aad";

    let ct = encrypt_xchacha20poly1305(&key, &nonce, b"", aad).unwrap();
    let pt = decrypt_xchacha20poly1305(&key, &nonce, &ct, aad).unwrap();

    assert!(pt.is_empty());
}

/// Encrypt and decrypt a medium-size plaintext
#[test]
fn encrypt_decrypt_roundtrip_medium_plaintext() {
    let key = KeyMaterial::new([7u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();
    let aad = b"aad";

    let plaintext = vec![0xAB; 8 * 1024]; // 8 KiB

    let ct = encrypt_xchacha20poly1305(&key, &nonce, &plaintext, aad).unwrap();
    let pt = decrypt_xchacha20poly1305(&key, &nonce, &ct, aad).unwrap();

    assert_eq!(pt.as_slice(), plaintext.as_slice());
}

/// Encrypt and decrypt a large plaintext buffer
///
/// # Security
/// This test ensures that large payloads (MiB-scale) are handled correctly
/// without truncation, overflow or unexpected allocation failures
#[test]
fn encrypt_decrypt_roundtrip_large_plaintext() {
    let key = KeyMaterial::new([9u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();
    let aad = b"aad";

    let plaintext = vec![0xCD; 2 * 1024 * 1024]; // 2 MiB

    let ct = encrypt_xchacha20poly1305(&key, &nonce, &plaintext, aad).unwrap();
    let pt = decrypt_xchacha20poly1305(&key, &nonce, &ct, aad).unwrap();

    assert_eq!(pt.as_slice(), plaintext.as_slice());
}

/// Different nonces must produce different ciphertexts even for identical plaintext and AAD
///
/// # Security
/// This property prevents deterministic encryption and nonce reuse issues
#[test]
fn different_nonce_produces_different_ciphertext() {
    let key = KeyMaterial::new([1u8; 32]);
    let aad = b"aad";
    let plaintext = b"same message";

    let nonce1 = generate_xchacha20_nonce().unwrap();
    let nonce2 = generate_xchacha20_nonce().unwrap();

    let ct1 = encrypt_xchacha20poly1305(&key, &nonce1, plaintext, aad).unwrap();
    let ct2 = encrypt_xchacha20poly1305(&key, &nonce2, plaintext, aad).unwrap();

    assert_ne!(ct1, ct2);
}

/// Associated data (AAD) must be authenticated
///
/// # Security
/// Any modification of AAD must cause decryption failure
#[test]
fn aad_is_authenticated() {
    let key = KeyMaterial::new([9u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();
    let plaintext = b"payload";

    let ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, b"aad-1").unwrap();

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad-2");
    assert!(res.is_err());
}
