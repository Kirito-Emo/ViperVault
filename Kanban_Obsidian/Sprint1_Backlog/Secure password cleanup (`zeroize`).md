## 🧑‍💻 User Story
*As a* developer
*I want* all password strings securely erased after use
*So that* no sensitive data remains in memory.

## 📌 Description
- Use `zeroize::Zeroize` for sensitive strings
- Apply cleanup after Argon2id derivation and vault unlock

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a master password or secret is in memory
*When* it is no longer needed
*Then* it is zeroized and removed from memory
- **AC2:**
> *Given* an unlocked vault
*When* secrets are accessed and then released
*Then* no plaintext remains in memory dumps or logs

## ✅ Definition of Done (DoD)
- [ ] Zeroize integrated for all secrets
- [ ] Unit tests verify cleanup
- [ ] No plaintext passwords persist in memory dumps
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MSTG-STORAGE-3**: memory cleanup
- **Threat Model (RAM Scraping)**: mitigates memory dump attacks

## 🔗 References
- [[Derive master key from master password with Argon2id]]
- [Rust zeroize crate](https://crates.io/crates/zeroize)