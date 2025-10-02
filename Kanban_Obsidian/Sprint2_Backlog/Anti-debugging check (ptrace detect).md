## 🧑‍💻 User Story
*As a* security-conscious developer
*I want* to detect if the process is being debugged
*So that* sensitive operations are protected.

## 📌 Description
- Implement ptrace/anti-debugging checks for Linux/Android/iOS
- Optionally terminate or alert if debugging detected

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* the vault process runs
*When* a debugger attaches
*Then* the process detects the debugging attempt
- **AC2:**
> *Given* debugging is detected
*When* an operation on secrets is attempted
*Then* the operation is blocked or memory cleared

## ✅ Definition of Done (DoD)
- [ ] Anti-debugging implemented
- [ ] Unit/integration tests verify detection
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-DEV-2**: anti-tampering
- **Threat Model (Debugger Attacks)**: prevents runtime secret exposure

## 🔗 References
- [[Automatic memory wipe on `Drop`]]
- [Linux ptrace documentation](https://man7.org/linux/man-pages/man2/ptrace.2.html)