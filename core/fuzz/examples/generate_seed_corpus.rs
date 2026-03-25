// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Generate deterministic seed corpora for fuzz targets
//!
//! # Purpose
//! This helper creates curated seed inputs under `corpus_seed/` so fuzzing can
//! start from representative valid and near-valid samples instead of relying
//! exclusively on random byte discovery
//!
//! # Security
//! Seed corpora improve coverage of structured parsers and reduce the time
//! needed to reach meaningful states

use std::fs;
use std::path::{Path, PathBuf};
use vipervault_core::backup::{encode_signed_backup, BackupKdfPolicy};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret, VaultEntry};
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{create_duress_vault, create_encrypted_vault, VaultKdfPolicy};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{encode_vault_storage, VaultPayload};

/// Root output directory for generated fuzz seed corpora
const CORPUS_SEED_ROOT: &str = "corpus_seed";

/// Password used to generate deterministic valid containers
const SEED_PASSWORD: &str = "seed-password";

/// Write a seed file to disk
fn write_seed(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).expect("create corpus seed directory");
    fs::write(dir.join(name), bytes).expect("write corpus seed");
}

/// Build the vault KDF policy used for deterministic seed generation
fn vault_kdf() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build the backup KDF policy used for deterministic seed generation
fn backup_kdf() -> BackupKdfPolicy {
    BackupKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Return a deterministic sample TOTP secret
fn sample_totp() -> TotpSecret {
    TotpSecret {
        issuer: Some(secrecy::SecretString::new("GitHub".to_string().into())),
        account_name: Some(secrecy::SecretString::new(
            "octocat@example.com".to_string().into(),
        )),
        secret_b32: secrecy::SecretString::new("JBSWY3DPEHPK3PXP".to_string().into()),
        digits: 6,
        period_secs: 30,
        algorithm: TotpAlgorithm::Sha1,
    }
}

/// Build a small deterministic payload with representative entries
fn sample_payload() -> VaultPayload {
    let password_entry = VaultEntry::new_password(
        "GitHub".to_string(),
        Some("octocat".to_string()),
        "super-secret-password".to_string(),
        Some("test note".to_string()),
    )
        .expect("password entry");

    let note_entry = VaultEntry::new_secure_note(
        "Recovery".to_string(),
        "offline backup code: 1234-5678".to_string(),
    )
        .expect("secure note entry");

    let totp_entry = VaultEntry::new_totp(
        "GitHub TOTP".to_string(),
        sample_totp(),
        Some("Primary MFA".to_string()),
    )
        .expect("totp entry");

    VaultPayload {
        entries: vec![password_entry, note_entry, totp_entry],
    }
}

/// Generate a valid encrypted vault container
fn encrypted_vault_container(password: &MasterPassword) -> Vec<u8> {
    let payload = sample_payload();
    let vault = create_encrypted_vault(password, &payload, 1, vault_kdf()).expect("create vault");
    encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode vault storage")
}

/// Build a valid duress-enabled encrypted vault container
fn duress_vault_container(primary: &MasterPassword, decoy: &MasterPassword) -> Vec<u8> {
    let primary_payload = sample_payload();
    let decoy_payload = VaultPayload { entries: vec![] };

    let vault = create_duress_vault(
        primary,
        decoy,
        &primary_payload,
        &decoy_payload,
        1,
        vault_kdf(),
    )
        .expect("create duress vault");

    encode_vault_storage(&vault.header, &vault.storage, 1).expect("encode duress vault storage")
}

/// Generate a valid signed backup wrapping the provided vault container bytes
fn signed_backup(password: &MasterPassword, vault_bytes: &[u8]) -> Vec<u8> {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    encode_signed_backup(policy, password, vault_bytes, backup_kdf()).expect("encode signed backup")
}

/// Return the output path for a target seed directory
fn target_dir(target: &str) -> PathBuf {
    Path::new(CORPUS_SEED_ROOT).join(target)
}

/// Generate seed corpus for `decode_vault_file`
fn generate_decode_vault_file_seeds(password: &MasterPassword) {
    let dir = target_dir("decode_vault_file");
    let encrypted = encrypted_vault_container(password);
    let duress =
        duress_vault_container(password, &MasterPassword::new("decoy-password".to_string()));

    write_seed(&dir, "valid_encrypted", &encrypted);
    write_seed(&dir, "valid_duress", &duress);

    let mut truncated = encrypted.clone();
    truncated.truncate(truncated.len().saturating_sub(8));
    write_seed(&dir, "truncated", &truncated);

    let mut bad_magic = encrypted.clone();
    bad_magic[..4].copy_from_slice(b"BAD!");
    write_seed(&dir, "bad_magic", &bad_magic);
}

/// Generate seed corpus for signed backup targets
fn generate_signed_backup_seeds(password: &MasterPassword) {
    let dir_plain = target_dir("decode_signed_backup");
    let dir_structured = target_dir("decode_signed_backup_structured");

    let vault_bytes = encrypted_vault_container(password);
    let valid = signed_backup(password, &vault_bytes);

    write_seed(&dir_plain, "valid_signed_backup", &valid);
    write_seed(&dir_structured, "valid_signed_backup", &valid);

    let mut truncated = valid.clone();
    truncated.truncate(truncated.len().saturating_sub(8));
    write_seed(&dir_plain, "truncated", &truncated);
    write_seed(&dir_structured, "truncated", &truncated);

    let mut tampered = valid.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0x01;
    }
    write_seed(&dir_plain, "tampered_signature", &tampered);
    write_seed(&dir_structured, "tampered_signature", &tampered);

    write_seed(&dir_plain, "empty", b"");
    write_seed(&dir_structured, "empty", b"");

    let mut bad_magic = valid.clone();
    bad_magic[..8].copy_from_slice(b"BADMAGIC");
    write_seed(&dir_plain, "bad_magic", &bad_magic);
    write_seed(&dir_structured, "bad_magic", &bad_magic);
}

/// Generate seed corpus for otpauth / base32 related targets
fn generate_otpauth_seeds() {
    let otpauth_targets = [
        "parse_totp_otpauth_uri",
        "parse_totp_otpauth_uri_structured",
        "otpauth_roundtrip",
        "otpauth_roundtrip_structured",
        "canonicalize_base32_for_export",
        "decode_base32_secret_strict",
    ];

    for target in otpauth_targets {
        let dir = target_dir(target);
        write_seed(
            &dir,
            "valid_otpauth_uri",
            b"otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30",
        );
        write_seed(&dir, "valid_base32", b"JBSWY3DPEHPK3PXP");
        write_seed(&dir, "invalid_base32", b"not-valid-base32!");
        write_seed(&dir, "empty", b"");
    }
}

/// Generate seed corpus for vault roundtrip / duress related structured targets
fn generate_vault_roundtrip_seeds(password: &MasterPassword) {
    let vault_bytes = encrypted_vault_container(password);
    let duress_bytes =
        duress_vault_container(password, &MasterPassword::new("decoy-password".to_string()));

    for target in [
        "vault_codec_roundtrip",
        "vault_codec_roundtrip_structured",
        "enable_duress_on_vault",
        "enable_duress_on_vault_structured",
        "import_interop_quarantine",
    ] {
        let dir = target_dir(target);
        write_seed(&dir, "valid_vault", &vault_bytes);
        write_seed(&dir, "valid_duress_vault", &duress_bytes);
        write_seed(&dir, "empty", b"");
    }
}

fn main() {
    let password = MasterPassword::new(SEED_PASSWORD.to_string());

    generate_decode_vault_file_seeds(&password);
    generate_signed_backup_seeds(&password);
    generate_otpauth_seeds();
    generate_vault_roundtrip_seeds(&password);
}
