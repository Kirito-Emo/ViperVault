## 🧑‍💻 User Story
*As a* user
*I want* the vault to interface with native clipboard APIs
*So that* I can copy secrets securely.

## 📌 Description
- Implement FFI bindings for Android and iOS
- Ensure secrets are not left in memory

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a secret is copied
*When* clipboard API is used
*Then* the secret is available in the system clipboard
- **AC2:**
> *Given* the secret is copied
*When* the application closes or auto-clear triggers
*Then* the clipboard is cleared securely

## ✅ Definition of Done (DoD)
- [ ] FFI bindings implemented
- [ ] Unit/integration tests passing
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-STORAGE-2**: protect in-memory secrets
- **Threat Model (RAM Scraping/Clipboard)**: prevents clipboard leaks

## 🔗 References
- [[Transactional writes with file locking]]
- [[Secure password cleanup (`zeroize`)]]
- [Tokio crate](https://crates.io/crates/tokio)
- [Rust FFI guide](https://doc.rust-lang.org/nomicon/ffi.html)