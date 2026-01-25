// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use vipervault_core::crypto::aead::{
    decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, generate_xchacha20_nonce,
};
use vipervault_core::crypto::kdf::MASTER_KEY_LEN;
use zeroize::Zeroizing;

/// Encrypt -> decrypt roundtrip succeeds with correct key, nonce and AAD
#[test]
fn aead_roundtrip() {
    let key = Zeroizing::new([0x11u8; MASTER_KEY_LEN]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let plaintext = b"super-secret-data";
    let aad = b"header-bytes";

    let ciphertext =
        encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encryption must succeed");

    let decrypted =
        decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).expect("decryption must succeed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

/// Changing AAD must cause authentication failure
#[test]
fn aead_rejects_wrong_aad() {
    let key = Zeroizing::new([0x22u8; MASTER_KEY_LEN]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let plaintext = b"secret";
    let aad_good = b"correct-header";
    let aad_bad = b"tampered-header";

    let ciphertext =
        encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad_good).expect("encryption");

    let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad_bad);

    assert!(result.is_err());
}

/// Tampering with ciphertext must be detected
#[test]
fn aead_detects_tampered_ciphertext() {
    let key = Zeroizing::new([0x33u8; MASTER_KEY_LEN]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let plaintext = b"attack-at-dawn";
    let aad = b"header";

    let mut ciphertext =
        encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encryption");

    // Flip a bit in the ciphertext
    ciphertext[0] ^= 0xFF;

    let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad);

    assert!(result.is_err());
}

/// Using a different nonce must fail decryption
#[test]
fn aead_rejects_wrong_nonce() {
    let key = Zeroizing::new([0x44u8; MASTER_KEY_LEN]);
    let nonce_good = generate_xchacha20_nonce().expect("nonce");
    let nonce_bad = generate_xchacha20_nonce().expect("nonce");

    let plaintext = b"top-secret";
    let aad = b"header";

    let ciphertext =
        encrypt_xchacha20poly1305(&key, &nonce_good, plaintext, aad).expect("encryption");

    let result = decrypt_xchacha20poly1305(&key, &nonce_bad, &ciphertext, aad);

    assert!(result.is_err());
}

/// Ciphertext must be larger than plaintext (auth tag included)
#[test]
fn aead_ciphertext_has_overhead() {
    let key = Zeroizing::new([0x55u8; MASTER_KEY_LEN]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let plaintext = b"data";
    let aad = b"header";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encryption");

    // XChaCha20-Poly1305 adds a 16-byte authentication tag
    assert!(ciphertext.len() > plaintext.len());
}
