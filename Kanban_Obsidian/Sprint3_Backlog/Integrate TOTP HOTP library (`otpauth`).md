<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* user

*I want* to use TOTP/HOTP for MFA

*So that* I can add an additional layer of authentication.

## 📌 Description
- Integrate `otpauth` Rust library
- Generate time-based and counter-based one-time passwords
- Store secrets encrypted in the vault

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a TOTP secret
>
> *When* generating a token
>
> *Then* a valid one-time password is produced according to RFC 6238

- **AC2:**
> *Given* a HOTP secret
>
> *When* generating a counter-based token
>
> *Then* the token increments correctly

- **AC3:**
> *Given* secrets stored in vault
>
> *When* vault is encrypted
>
> *Then* TOTP/HOTP secrets are protected

## ✅ Definition of Done (DoD)
- [ ] TOTP/HOTP integration implemented
- [ ] Unit tests for token generation
- [ ] Secrets encrypted in vault
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **NIST SP 800-63B**: MFA compliance
- **OWASP MASVS-CRYPTO-3**: secure key storage

## 🔗 References
- [Rust otpauth crate](https://crates.io/crates/otpauth)
- [[Define `Vault` structure (UUID, versioning, metadata)]]