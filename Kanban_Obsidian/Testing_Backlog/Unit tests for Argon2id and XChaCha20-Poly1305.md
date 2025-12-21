<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* developer

*I want* unit tests for Argon2id and XChaCha20-Poly1305

*So that* cryptography behaves correctly and securely.

## 📌 Description
- Implement Rust `#[test]` functions
- Verify encryption/decryption, KDF derivation, and error handling
- Include edge cases and invalid inputs

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* valid inputs
>
> *When* tests are executed
>
> *Then* encryption/decryption and key derivation succeed

- **AC2:**
> *Given* invalid or corrupted inputs
>
> *When* tests are executed
>
> *Then* appropriate errors are returned without leaking secrets

## ✅ Definition of Done (DoD)
- [ ] Unit tests implemented
- [ ] CI runs tests automatically
- [ ] Edge cases and invalid inputs covered
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-TEST-1**: unit testing for cryptography
- **Threat Model (Tampering/Disclosure)**: ensures correctness

## 🔗 References
- [[Derive master key from master password with Argon2id]]
- [[Apply `XChaCha20-Poly1305` authenticated encryption]]