<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* user

*I want* to export my vault as an encrypted `.vlt` file

*So that* I can back it up safely.

## 📌 Description
- Apply encryption before export
- Include metadata for versioning
- Ensure integrity check

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a vault
>
> *When* exported
> 
> *Then* the `.vlt` file is encrypted and includes metadata

- **AC2:**
> *Given* the exported file
> 
> *When* imported later
> 
> *Then* vault data is restored correctly

## ✅ Definition of Done (DoD)
- [ ] Export function implemented
- [ ] Encryption and integrity verified
- [ ] Unit tests cover export/import
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-STORAGE-2**: secure storage
- **Threat Model (Backup/Disclosure)**: ensures backup confidentiality

## 🔗 References
- [[Apply `XChaCha20-Poly1305` authenticated encryption]]