## 🧑‍💻 User Story
*As a* user
*I want* my TOTP secrets stored encrypted in the vault
*So that* they remain confidential and protected.

## 📌 Description
- Apply XChaCha20-Poly1305 encryption to TOTP secrets
- Enforce secure serialization and zeroization

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a TOTP secret
*When* stored in the vault
*Then* it is encrypted and zeroized after use
- **AC2:**
> *Given* an encrypted vault
*When* decrypted with the master password
*Then* TOTP secrets are accessible and correct

## ✅ Definition of Done (DoD)
- [ ] Encrypted storage for TOTP secrets
- [ ] Unit tests verify encryption/decryption
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-CRYPTO-3**: AEAD encryption
- **Threat Model (Tampering/Disclosure)**: ensures TOTP secret confidentiality

## 🔗 References
- [[Integrate TOTP HOTP library (`otpauth`)]]
- [[Apply `XChaCha20-Poly1305` authenticated encryption]]