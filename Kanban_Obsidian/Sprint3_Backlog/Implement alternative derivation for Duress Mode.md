## 🧑‍💻 User Story
*As a* user
*I want* an alternative key derivation for duress mode
*So that* I can unlock a decoy vault under coercion.

## 📌 Description
- Provide separate KDF parameters for duress password
- Vault unlock with duress password yields decoy vault
- Decoy vault contains benign entries only

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a duress password
*When* the vault is unlocked with it
*Then* a decoy vault is returned containing only non-sensitive entries
- **AC2:**
> *Given* the master password
*When* used to unlock the vault
*Then* the real vault is returned
- **AC3:**
> *Given* the decoy vault is unlocked
*When* an entry is added
*Then* it is stored only in the decoy vault

## ✅ Definition of Done (DoD)
- [ ] Duress mode derivation implemented
- [ ] Decoy vault logic verified
- [ ] Unit tests for duress vs real unlock
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **Threat Model (Coercion)**: protects user under duress
- **OWASP MASVS-STORAGE-2**: structured secure storage

## 🔗 References
- [[Derive master key from master password with Argon2id]]
- [[Define `Vault` structure (UUID, versioning, metadata)]]