## 🧑‍💻 User Story
*As a* user
*I want* the vault to auto-lock after inactivity
*So that* secrets remain safe if I leave my device unattended.

## 📌 Description
- Implement async timer (e.g., `tokio`)
- Trigger lock after configurable timeout
- Clear sensitive memory on lock

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* the vault is unlocked
*When* the idle timeout expires
*Then* the vault automatically locks and clears sensitive memory
- **AC2:**
> *Given* a configurable timeout
*When* the timeout value is changed
*Then* the auto-lock triggers according to the new timeout
- **AC3:**
> *Given* vault auto-lock triggers
*When* an operation is attempted on the vault
*Then* access is denied until the vault is unlocked

## ✅ Definition of Done (DoD)
- [ ] Auto-lock implemented with async timer
- [ ] Configurable timeout (default: 60s)
- [ ] Memory cleared on lock
- [ ] Unit tests simulate idle timeouts
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-AUTH-8**: session timeout
- **Threat Model (Device Theft/Loss)**: limits exposure

## 🔗 References
- [[Implement `unlock_vault(password)` with error handling]]
- [Tokio crate](https://crates.io/crates/tokio)