<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- SPDX-FileCopyrightText: 2025 Emanuele Relmi -->
## 🧑‍💻 User Story
*As a* user

*I want* to unlock the vault using biometrics

*So that* authentication is more convenient and secure.

## 📌 Description
- Implement FFI bindings to Android/iOS biometric APIs
- Integrate with vault unlock flow
- Ensure secrets remain protected in memory

## ✅ Acceptance Criteria (Given/When/Then)
- **AC1:**
> *Given* a registered biometric credential
>
> *When* the user authenticates
>
> *Then* the vault unlocks securely

- **AC2:**
> *Given* biometric unlock fails
>
> *When* fallback password is provided
>
> *Then* the vault unlocks only if the password is correct

## ✅ Definition of Done (DoD)
- [ ] Biometric FFI implemented
- [ ] Unit tests for success/failure scenarios
- [ ] Secrets remain protected in memory
- [ ] Documentation updated

## 🛡 Standards & Compliance
- **OWASP MASVS-AUTH-2**: secure authentication
- **Threat Model (Spoofing/Biometrics)**: prevents unauthorized access

## 🔗 References
- [[Implement `unlock_vault(password)` with error handling]]
- [Android BiometricPrompt](https://developer.android.com/training/sign-in/biometric-auth)
- [iOS LocalAuthentication](https://developer.apple.com/documentation/localauthentication)