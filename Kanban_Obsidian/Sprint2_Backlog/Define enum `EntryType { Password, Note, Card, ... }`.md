## 🧑‍💻 User Story
*As a* developer
*I want* to define an enum `EntryType`
*So that* I can categorize and extend vault entries consistently.

## 📌 Description
- Enum includes core variants: Password, Note, Card
- Serialization/deserialization works with vault
- Extendable for future entry types

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* the enum `EntryType` is defined
*When* an entry is assigned a type
*Then* it is correctly categorized and serialized
- **AC2:**
> *Given* multiple entry types
*When* entries are deserialized
*Then* each entry maintains its correct type

## ✅ Definition of Done (DoD)
- [ ] Enum implemented and compiled
- [ ] Unit tests verify all variants
- [ ] Serialization/deserialization tested
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-STORAGE-2**: structured storage
- **Threat Model (Data Integrity)**: type information preserved

## 🔗 References
- [[Define `Vault` structure (UUID, versioning, metadata)]]
- [Rust enums](https://doc.rust-lang.org/book/ch06-01-defining-an-enum.html)