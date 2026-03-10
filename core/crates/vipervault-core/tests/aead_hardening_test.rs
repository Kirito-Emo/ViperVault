// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! AEAD XChaCha20-Poly1305 hardening tests
//!
//! # Scope
//! These tests validate the integrity and misuse resistance properties of the AEAD layer:
//! - ciphertext tampering is rejected
//! - nonce/key/AAD mismatch is rejected
//! - truncation and malformed ciphertext are rejected
//!
//! # Security
//! Decryption must fail safely for all authentication failures and malformed inputs,
//! without returning partial plaintext

use vipervault_core::crypto::aead::{
    decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, generate_xchacha20_nonce,
};
use vipervault_core::memory::KeyMaterial;

/// Flipping one ciphertext byte must cause decryption failure
#[test]
fn ciphertext_tamper_is_rejected() {
    let key = KeyMaterial::new([1u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");
    let aad = b"aad";
    let plaintext = b"payload";

    let mut ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encrypt");
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, aad);
    assert!(res.is_err());
}

/// Using a different nonce must cause decryption failure
#[test]
fn wrong_nonce_is_rejected() {
    let key = KeyMaterial::new([2u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");
    let wrong_nonce = generate_xchacha20_nonce().expect("wrong nonce");
    let aad = b"aad";
    let plaintext = b"payload";

    let ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encrypt");

    let res = decrypt_xchacha20poly1305(&key, &wrong_nonce, &ct, aad);
    assert!(res.is_err());
}

/// Using a different key must cause decryption failure
#[test]
fn wrong_key_is_rejected() {
    let key = KeyMaterial::new([3u8; 32]);
    let wrong_key = KeyMaterial::new([4u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");
    let aad = b"aad";
    let plaintext = b"payload";

    let ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encrypt");

    let res = decrypt_xchacha20poly1305(&wrong_key, &nonce, &ct, aad);
    assert!(res.is_err());
}

/// Using different AAD must cause decryption failure
#[test]
fn wrong_aad_is_rejected() {
    let key = KeyMaterial::new([5u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");
    let plaintext = b"payload";

    let ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, b"aad-1").expect("encrypt");

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad-2");
    assert!(res.is_err());
}

/// Truncating the ciphertext must cause decryption failure
#[test]
fn truncated_ciphertext_is_rejected() {
    let key = KeyMaterial::new([6u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");
    let aad = b"aad";
    let plaintext = b"payload";

    let mut ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encrypt");
    ct.pop();

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, aad);
    assert!(res.is_err());
}

/// Empty ciphertext must be rejected
#[test]
fn empty_ciphertext_is_rejected() {
    let key = KeyMaterial::new([7u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let res = decrypt_xchacha20poly1305(&key, &nonce, b"", b"aad");
    assert!(res.is_err());
}

/// Single-byte ciphertext must be rejected
#[test]
fn undersized_ciphertext_is_rejected() {
    let key = KeyMaterial::new([8u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let res = decrypt_xchacha20poly1305(&key, &nonce, &[0xAA], b"aad");
    assert!(res.is_err());
}

/// Tampering near the beginning of the ciphertext must also be rejected
#[test]
fn prefix_tamper_is_rejected() {
    let key = KeyMaterial::new([9u8; 32]);
    let nonce = generate_xchacha20_nonce().expect("nonce");
    let aad = b"aad";
    let plaintext = b"payload";

    let mut ct = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encrypt");
    ct[0] ^= 0x80;

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, aad);
    assert!(res.is_err());
}
