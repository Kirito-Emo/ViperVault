---

kanban-plugin: board

---

## Sprint 1 – Core Foundations



## Sprint 2 – Vault Management & Local Security

- [ ] [[Define enum `EntryType { Password, Note, Card, ... }`]]
- [ ] [[Implement CRUD `add_entry`, `update_entry`, `delete_entry`]]
- [ ] [[Validate entry input (length, charset, format)]]
- [ ] [[Transactional writes with file locking]]
- [ ] [[Rust → Android iOS Clipboard API binding]]
- [ ] [[Implement clipboard auto-clear (30s timeout)]]
- [ ] [[Use `secrecy SecretString` for secret handling]]
- [ ] [[Automatic memory wipe on `Drop`]]
- [ ] [[Anti-debugging check (ptrace detect)]]
- [ ] [[Integration tests  CRUD + vault integrity]]


## Sprint 3 – Advanced Features & MFA

- [ ] [[Implement alternative derivation for Duress Mode]]
- [ ] [[Manage “decoy vault” with coercion password]]
- [ ] [[Integrate TOTP HOTP library (`otpauth`)]]
- [ ] [[Store TOTP secrets in encrypted vault]]
- [ ] [[Integrate biometrics via FFI (Android iOS API)]]
- [ ] [[Export encrypted vault as `.vlt`]]
- [ ] [[Import vault with signature validation + decryption]]
- [ ] [[Minimize unnecessary metadata in backup]]
- [ ] [[Security tests (MFA, duress, backup)]]


## Review

- [ ] [[Review API design of the Rust core]]
- [ ] [[Verify correctness of crypto implementations]]
- [ ] [[Code review focusing on memory safety]]


## Testing

- [ ] [[Unit tests for Argon2id and XChaCha20-Poly1305]]
- [ ] [[Integration tests for CRUD + auto-lock]]
- [ ] [[Stress test on file locking and race conditions]]
- [ ] [[Fuzzing for vault parsing serialization]]


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




%% kanban:settings
```
{"kanban-plugin":"board","list-collapse":[null,null,null,null,null,false]}
```
%%