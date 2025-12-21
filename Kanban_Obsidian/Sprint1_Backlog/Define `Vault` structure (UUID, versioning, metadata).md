<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* developer

*I want* to define a secure and extensible vault data structure

*So that* all sensitive entries can be stored consistently and safely.

## 📌 Description
- Create `Vault` struct with metadata: UUID, schema version, creation/update timestamp
- Support multiple entry types (Passwords, Notes, Cards, etc.) via `enum EntryType`
- Use `serde` for serialization, ensuring `zeroize` for sensitive fields
- All fields must be compatible with encryption layer (no plaintext secrets outside memory)

## ✅ Acceptance Criteria (AC)
- **AC1:** 
> *Given* an empty vault
> 
> *When* the Vault struct is created
> 
> *Then* it contains valid metadata and no entries

- **AC2:**
> *Given* multiple entry types
>
> *When* entries are added to the vault
>
> *Then* they are correctly categorized by EntryType enum

- **AC3:**
> *Given* the Vault struct is serialized
> 
> *When* deserialized
> 
> *Then* all sensitive fields are zeroized and data integrity is preserved

## ✅ Definition of Done (DoD)
- [ ] `Vault` struct defined and compiled
- [ ] Metadata validated and stored correctly
- [ ] Unit tests for creating an empty vault
- [ ] Serialization round-trip works with dummy data
- [ ] Sensitive fields implement `Zeroize`
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-STORAGE-2**: structured secure storage
- **GDPR data minimization**: only necessary metadata stored
- **Threat Model (Tampering)**: vault integrity protected

## 🔗 References
- [[Backlog_Sprints]]
- [Rust serde crate](https://crates.io/crates/serde)
- [Rust zeroize crate](https://docs.rs/zeroize)