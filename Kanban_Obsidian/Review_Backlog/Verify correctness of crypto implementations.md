## 🧑‍💻 User Story
*As a* developer
*I want* to verify the correctness of cryptographic implementations
*So that* encryption, decryption, and key derivation are secure.

## 📌 Description
- Test Argon2id derivation, XChaCha20-Poly1305 encryption, and TOTP/HOTP generation
- Compare with test vectors and RFCs
- Ensure nonces, salts, and keys are handled securely

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* cryptographic primitives
*When* unit tests run
*Then* outputs match RFC/test vectors
- **AC2:**
> *Given* encrypted data
*When* decrypted with correct keys
*Then* original plaintext is recovered
- **AC3:**
> *Given* incorrect keys or tampered data
*When* decryption is attempted
*Then* an error is returned and no data is leaked

## ✅ Definition of Done (DoD)
- [ ] Unit tests for all cryptographic primitives
- [ ] Verification against known vectors
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **NIST SP 800-63B**: KDF compliance
- **OWASP MASVS-CRYPTO-3**: AEAD encryption
- **Threat Model (Tampering/Disclosure)**: ensures correctness

## 🔗 References
- [[Derive master key from master password with Argon2id]]
- [[Apply `XChaCha20-Poly1305` authenticated encryption]]