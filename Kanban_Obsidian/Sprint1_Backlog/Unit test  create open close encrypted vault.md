<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* developer

*I want* automated tests for vault creation and unlocking

*So that* I can verify correctness and security of the core.

## 📌 Description
Write tests for:
- Empty vault creation
- Unlock with correct password
- Unlock fails with wrong password
- Encrypted vault integrity

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* an empty vault
> 
> *When* it is created
> 
> *Then* the vault initializes correctly and metadata is valid

- **AC2:**
> *Given* the vault is locked
> 
> *When* unlocked with the correct password
> 
> *Then* secrets are accessible

- **AC3:**
> *Given* the vault is locked
> 
> *When* unlocked with an incorrect password
> 
> *Then* access is denied

- **AC4:**
> *Given* an encrypted vault
> 
> *When* the vault is serialized and deserialized
> 
> *Then* data integrity is preserved

## ✅ Definition of Done (DoD)
- [ ] Unit tests implemented with Rust `#[test]`
- [ ] CI runs tests automatically
- [ ] Tests cover valid + invalid edge cases
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-TEST-1**: unit testing for security features
- **Threat Model (Tampering/Disclosure)**: ensures encryption/decryption correctness

## 🔗 References
- [[Define `Vault` structure (UUID, versioning, metadata)]]
- [[Implement `unlock_vault(password)` with error handling]]