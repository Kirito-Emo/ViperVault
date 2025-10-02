## 🧑‍💻 User Story
*As a* user
*I want* backups to contain minimal metadata
*So that* sensitive information is not leaked.

## 📌 Description
- Store only necessary fields for vault integrity
- Exclude timestamps or internal notes if not required

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a vault backup
*When* exported
*Then* only necessary metadata is included
- **AC2:**
> *Given* sensitive internal metadata
*When* backup occurs
*Then* it is excluded from the exported file

## ✅ Definition of Done (DoD)
- [ ] Metadata minimization implemented
- [ ] Unit tests verify backup content
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **GDPR data minimization**: store only necessary data
- **Threat Model (Backup/Disclosure)**: limits exposure

## 🔗 References
- [[Export encrypted vault as `.vlt`]]