## 🧑‍💻 User Story
*As a* developer
*I want* to encrypt vault data with authenticated encryption
*So that* no attacker can read or tamper with my secrets.

## 📌 Description
- Use `chacha20poly1305` crate with XChaCha20-Poly1305
- Each vault encryption must use unique nonce (store safely)
- Encrypt/decrypt vault entries atomically

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a vault to encrypt
*When* XChaCha20-Poly1305 is applied
*Then* ciphertext is generated with a unique nonce and can be decrypted correctly
- **AC2:**
> *Given* corrupted ciphertext
*When* decryption is attempted
*Then* an integrity error is returned and plaintext is not revealed

## ✅ Definition of Done (DoD)
- [ ] Encryption/decryption implemented
- [ ] Nonces handled securely (no reuse)
- [ ] Integrity check on every decryption
- [ ] Unit tests for corrupted ciphertext rejection
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-CRYPTO-3**: AEAD encryption
- **Threat Model (Tampering/Disclosure)**: integrity + confidentiality
- **NIS2**: strong cryptographic primitives

## 🔗 References
- [[Derive master key from master password with Argon2id]]
- [Rust chacha20poly1305 crate](https://crates.io/crates/chacha20poly1305)