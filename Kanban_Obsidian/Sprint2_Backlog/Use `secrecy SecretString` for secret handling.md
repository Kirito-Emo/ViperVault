## 🧑‍💻 User Story
*As a* developer
*I want* secrets handled with `SecretString`
*So that* sensitive data is protected in memory.

## 📌 Description
- Wrap all secret strings in `SecretString`
- Ensure zeroization on drop

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a secret is stored
*When* SecretString is used
*Then* it remains protected in memory and zeroized on drop
- **AC2:**
> *Given* secrets are accessed
*When* they go out of scope
*Then* memory is cleared automatically

## ✅ Definition of Done (DoD)
- [ ] SecretString used for all sensitive strings
- [ ] Unit/integration tests confirm zeroization
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MSTG-STORAGE-3**: memory cleanup
- **Threat Model (RAM Scraping)**: prevents memory leaks

## 🔗 References
- [[Secure password cleanup (`zeroize`)]]
- [Rust secrecy crate](https://docs.rs/secrecy/)