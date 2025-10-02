## 🧑‍💻 User Story
*As a* user
*I want* to unlock my vault with my master password
*So that* I can securely access stored secrets.

## 📌 Description
- Implement `unlock_vault(password: &str)`
- Derive key with Argon2id → decrypt with XChaCha20-Poly1305
- Return error for invalid credentials (constant-time comparison)

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* the vault is locked
*When* the correct master password is provided
*Then* the vault unlocks and secrets are accessible
- **AC2:**
> *Given* the vault is locked
*When* an incorrect master password is provided
*Then* the vault remains locked and an error is returned in constant time
- **AC3:**
> *Given* the vault has been unlocked
*When* accessing secrets
*Then* no sensitive data is leaked to logs or temporary memory

## ✅ Definition of Done (DoD)
- [ ] Function implemented with secure error handling
- [ ] Wrong passwords fail in constant time
- [ ] Unit tests for success/failure cases
- [ ] No sensitive data leaked in logs
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-AUTH-2**: secure authentication
- **Threat Model (Spoofing)**: password-only unlock with KDF
- **GDPR**: zero-knowledge (never transmits secrets)

## 🔗 References
- [[Apply `XChaCha20-Poly1305` authenticated encryption]]
- [[Derive master key from master password with Argon2id]]