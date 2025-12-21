<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* user

*I want* my master password securely converted into a key

*So that* my vault is resilient against brute-force attacks.

## 📌 Description
- Use `argon2` crate with Argon2id variant
- Parameters (tunable): memory ≥ 64MB; iterations ≥ 3; parallelism = 4
- Salt must be unique per vault and stored in metadata

## ✅ Acceptance Criteria (AC)
- **AC1:**
> *Given* a master password
> 
> *When* key derivation is performed using Argon2id
> 
> *Then* the derived key is unique, reproducible, and memory-zeroized after use

- **AC2:**
> *Given* an incorrect password
>
> *When* attempting to unlock the vault
>
> *Then* access is denied without revealing information

## ✅ Definition of Done (DoD)
- [ ] Argon2id implemented with secure defaults
- [ ] Salt stored securely in vault metadata
- [ ] Unit tests with correct/incorrect passwords
- [ ] RFC 9106 test vectors verified
- [ ] Memory zeroized after derivation
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **NIST SP 800-63B**: memory-hard password KDF
- **OWASP MASVS-CRYPTO-2**: strong key derivation
- **Threat Model (Brute Force)**: mitigates offline cracking attempts

## 🔗 References
- [[Define `Vault` structure (UUID, versioning, metadata)]]
- [Rust argon2 crate](https://crates.io/crates/argon2)
- [RFC 9106 – Argon2id]