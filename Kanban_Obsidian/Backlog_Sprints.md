---

kanban-plugin: board

---

## Sprint 1 – Core Foundations



## Sprint 2 – Vault Management & Local Security



## Sprint 3 – Advanced Features & MFA



## Review

- [ ] [[Review API design of the Rust core]]
- [ ] [[Verify correctness of crypto implementations]]
- [ ] [[Code review focusing on memory safety]]


## Testing

- [x] [[Unit tests for Argon2id and XChaCha20-Poly1305]]
- [x] [[Integration tests for CRUD + auto-lock]]
- [x] [[Stress test on file locking and race conditions]]
- [x] [[Security tests (MFA, duress, backup)]]
- [x] [[Fuzzing for vault parsing serialization]]


## Done

**Complete**
- [x] [[Define `Vault` structure (UUID, versioning, metadata)]]
- [x] [[Derive master key from master password with Argon2id]]
- [x] [[Apply `XChaCha20-Poly1305` authenticated encryption]]
- [x] [[Implement secure serialization deserialization (`serde + zeroize`)]]
- [x] [[Implement `unlock_vault(password)` with error handling]]
- [x] [[Secure password cleanup (`zeroize`)]]
- [x] [[Auto-lock vault via async timer (`tokio`)]]
- [x] [[Unit test  create open close encrypted vault]]
- [x] [[Define enum `EntryType { Password, Note, Card, ... }`]]
- [x] [[Implement CRUD `add_entry`, `update_entry`, `delete_entry`]]
- [x] [[Validate entry input (length, charset, format)]]
- [x] [[Transactional writes with file locking]]
- [x] [[Implement clipboard auto-clear (30s timeout)]]
- [x] [[Use `secrecy SecretString` for secret handling]]
- [x] [[Automatic memory wipe on `Drop`]]
- [x] [[Anti-debugging check (ptrace detect)]]
- [x] [[Rust → Android iOS Clipboard API binding]]
- [x] [[Integration tests  CRUD + vault integrity]]
- [x] [[Store TOTP secrets in encrypted vault]]
- [x] [[Integrate TOTP HOTP library (`otpauth`)]]
- [x] [[Implement alternative derivation for Duress Mode]]
- [x] [[Manage “decoy vault” with coercion password]]
- [x] [[Minimize unnecessary metadata in backup]]
- [x] [[Export encrypted vault as `.vlt`]]
- [x] [[Import vault with signature validation + decryption]]
- [x] [[Integrate biometrics via FFI (Android iOS API)]]




%% kanban:settings
```
{"kanban-plugin":"board","list-collapse":[null,null,null,null,null,false]}
```
%%