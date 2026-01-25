// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

use vipervault_core::crypto::aead::{
    decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, generate_xchacha20_nonce,
};
use vipervault_core::crypto::kdf::MASTER_KEY_LEN;
use zeroize::Zeroizing;

/// Empty plaintext must be supported (still authenticates)
#[test]
fn roundtrip_empty_plaintext() {
    let key = Zeroizing::new([0xABu8; MASTER_KEY_LEN]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let plaintext: &[u8] = b"";
    let aad = b"header";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).expect("encrypt");
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).expect("decrypt");

    assert!(decrypted.is_empty());
}

/// Larger plaintext should still work reliably
#[test]
fn roundtrip_larger_plaintext() {
    let key = Zeroizing::new([0xCDu8; MASTER_KEY_LEN]);
    let nonce = generate_xchacha20_nonce().expect("nonce");

    let plaintext = vec![0x42u8; 64 * 1024]; // 64 KiB
    let aad = b"header";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, &plaintext, aad).expect("encrypt");
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).expect("decrypt");

    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}
