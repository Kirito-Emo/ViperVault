<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* user

*I want* copied secrets to be automatically cleared from the clipboard

*So that* sensitive data is not left exposed on my device.

## 📌 Description
- Auto-clear clipboard after configurable timeout (default 30s)
- Integrate with FFI clipboard bindings

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a secret is copied to the clipboard
> 
> *When* 30 seconds pass
> 
> *Then* the clipboard is automatically cleared

- **AC2:**
> *Given* the timeout is configured differently
> 
> *When* the specified time elapses
> 
> *Then* the clipboard clears according to the new timeout

## ✅ Definition of Done (DoD)
- [ ] Clipboard auto-clear implemented
- [ ] Timeout configurable
- [ ] Unit tests verify auto-clear behavior
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-AUTH-8**: session timeout protection
- **Threat Model (Clipboard Exposure)**: minimizes secret exposure

## 🔗 References
- [[Rust → Android iOS Clipboard API binding]]
- [[Secure password cleanup (`zeroize`)]]
- [Tokio crate](https://crates.io/crates/tokio)