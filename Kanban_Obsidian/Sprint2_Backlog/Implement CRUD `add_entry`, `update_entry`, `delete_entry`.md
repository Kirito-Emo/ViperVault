## 🧑‍💻 User Story
*As a* user
*I want* to add, update, and delete entries in the vault
*So that* I can manage my secrets securely.

## 📌 Description
- Implement add_entry, update_entry, delete_entry methods
- Operations must preserve vault integrity
- Encryption applied automatically

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* an empty vault
*When* a new entry is added
*Then* it appears in the vault with correct type and metadata
- **AC2:**
> *Given* an existing entry
*When* it is updated
*Then* the entry’s data changes accordingly
- **AC3:**
> *Given* an existing entry
*When* it is deleted
*Then* it is removed from the vault and memory is cleared

## ✅ Definition of Done (DoD)
- [ ] CRUD operations implemented
- [ ] Unit/integration tests for all operations
- [ ] Encryption applied to entries
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-STORAGE-2**: secure storage
- **Threat Model (Tampering)**: ensures data integrity

## 🔗 References
- [[Define enum `EntryType { Password, Note, Card, ... }`]]
- [[Define `Vault` structure (UUID, versioning, metadata)]]