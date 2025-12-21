<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* developer

*I want* security tests for MFA, duress mode, and backup

*So that* I can verify the vault behaves securely under all scenarios.

## 📌 Description
- Automated tests for TOTP/HOTP
- Verify decoy vault behavior
- Validate backup integrity and decryption

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* MFA is configured
>
> *When* generating tokens
>
> *Then* tokens are correct and verified

- **AC2:**
> *Given* duress mode is used
>
> *When* vault is unlocked
>
> *Then* decoy vault appears and real vault remains secure

- **AC3:**
> *Given* a backup file
>
> *When* imported
>
> *Then* vault restores correctly and integrity is preserved

## ✅ Definition of Done (DoD)
- [ ] Automated security tests implemented
- [ ] Unit/integration tests passing
- [ ] CI runs tests on each commit
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-TEST-1**: security unit testing
- **Threat Model (Tampering/Disclosure)**: verifies security features

## 🔗 References
- [[Integrate TOTP HOTP library (`otpauth`)]]
- [[Manage “decoy vault” with coercion password]]
- [[Export encrypted vault as `.vlt`]]
- [[Import vault with signature validation + decryption]]