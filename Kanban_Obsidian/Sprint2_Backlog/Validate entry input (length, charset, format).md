<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* user

*I want* vault entries to be validated

*So that* only correctly formatted data is stored securely.

## 📌 Description
- Validate entry fields: length, charset, format
- Reject invalid input before storage

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* an entry with valid data
> 
> *When* it is added to the vault
> 
> *Then* it is accepted and stored

- **AC2:**
> *Given* an entry with invalid data (e.g., too long, wrong charset)
> 
> *When* it is added
> 
> *Then* it is rejected with a validation error

## ✅ Definition of Done (DoD)
- [ ] Validation logic implemented
- [ ] Unit tests cover valid and invalid inputs
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-STORAGE-2**: validate inputs
- **Threat Model (Tampering/Input Injection)**: prevents malformed data storage

## 🔗 References
- [[Implement CRUD `add_entry`, `update_entry`, `delete_entry`]]
- [[Define enum `EntryType { Password, Note, Card, ... }`]]