// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! AEAD XChaCha20-Poly1305 hardening tests
//!
//! # Scope
//! These tests focus on misuse resistance and failure behavior of the AEAD layer
//! The goal is NOT to verify correctness (covered by functional tests),
//! but to ensure that:
//! - all authentication failures are handled safely
//! - no partial plaintext is ever returned
//! - no panics occur under malformed or adversarial inputs
//! - no information oracle is exposed through error behavior
//!
//! # Security properties validated
//! - Confidentiality under tampering
//! - Integrity under ciphertext / nonce / AAD modification
//! - Robust handling of malformed inputs

use vipervault_core::crypto::aead::{
    decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, generate_xchacha20_nonce,
};
use vipervault_core::memory::KeyMaterial;

/// Decryption must fail when using a wrong key
///
/// # Security
/// This prevents attackers from learning information via key mismatch
#[test]
fn decryption_fails_with_wrong_key() {
    let key_ok = KeyMaterial::new([1u8; 32]);
    let key_bad = KeyMaterial::new([2u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();

    let ct = encrypt_xchacha20poly1305(&key_ok, &nonce, b"secret", b"aad").unwrap();
    let res = decrypt_xchacha20poly1305(&key_bad, &nonce, &ct, b"aad");

    assert!(res.is_err());
}

/// Decryption must fail if the ciphertext is modified
///
/// # Security
/// Any bit-flip in the ciphertext must invalidate authentication
#[test]
fn tampered_ciphertext_is_rejected() {
    let key = KeyMaterial::new([3u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();

    let mut ct = encrypt_xchacha20poly1305(&key, &nonce, b"secret", b"aad").unwrap();
    ct[0] ^= 0xFF; // flip one bit

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad");
    assert!(res.is_err());
}

/// Decryption must fail if the nonce is modified
///
/// # Security
/// Nonce integrity is critical for AEAD schemes
#[test]
fn tampered_nonce_is_rejected() {
    let key = KeyMaterial::new([4u8; 32]);
    let mut nonce = generate_xchacha20_nonce().unwrap();

    let ct = encrypt_xchacha20poly1305(&key, &nonce, b"secret", b"aad").unwrap();
    nonce[0] ^= 0xAA; // corrupt nonce

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad");
    assert!(res.is_err());
}

/// Decryption must fail if the associated data (AAD) is modified
///
/// # Security
/// AAD is authenticated but not encrypted; any mismatch must be detected
#[test]
fn tampered_aad_is_rejected() {
    let key = KeyMaterial::new([5u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();

    let ct = encrypt_xchacha20poly1305(&key, &nonce, b"secret", b"aad-1").unwrap();
    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad-2");

    assert!(res.is_err());
}

/// Truncated ciphertext must be rejected
///
/// # Security
/// Ensures that no partial plaintext is ever returned
#[test]
fn truncated_ciphertext_is_rejected() {
    let key = KeyMaterial::new([6u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();

    let mut ct = encrypt_xchacha20poly1305(&key, &nonce, b"very secret data", b"aad").unwrap();
    ct.truncate(ct.len() / 2); // remove tail

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad");
    assert!(res.is_err());
}

/// Empty ciphertext must be rejected
///
/// # Security
/// Prevents degenerate cases from producing undefined behavior
#[test]
fn empty_ciphertext_is_rejected() {
    let key = KeyMaterial::new([7u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();

    let res = decrypt_xchacha20poly1305(&key, &nonce, &[], b"aad");
    assert!(res.is_err());
}

/// Ciphertext with only authentication tag length removed must be rejected
///
/// # Security
/// Ensures authentication tag is mandatory
#[test]
fn missing_authentication_tag_is_rejected() {
    let key = KeyMaterial::new([8u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();

    let mut ct = encrypt_xchacha20poly1305(&key, &nonce, b"secret", b"aad").unwrap();

    // Remove last bytes (Poly1305 tag is 16 bytes)
    if ct.len() > 16 {
        ct.truncate(ct.len() - 16);
    }

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad");
    assert!(res.is_err());
}

/// Large corrupted ciphertext must be rejected without panic
///
/// # Security
/// Ensures robustness against malformed large inputs
#[test]
fn large_corrupted_ciphertext_is_rejected() {
    let key = KeyMaterial::new([9u8; 32]);
    let nonce = generate_xchacha20_nonce().unwrap();

    let mut ct = encrypt_xchacha20poly1305(&key, &nonce, &vec![0xAA; 1024 * 1024], b"aad").unwrap();

    // Corrupt multiple bytes
    for i in (0..ct.len()).step_by(1024) {
        ct[i] ^= 0xFF;
    }

    let res = decrypt_xchacha20poly1305(&key, &nonce, &ct, b"aad");
    assert!(res.is_err());
}
