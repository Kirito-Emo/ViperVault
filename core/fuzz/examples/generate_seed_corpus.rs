// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Seed corpus generator for fuzz targets
//!
//! # Purpose
//! This helper creates small, curated initial corpora for the project's fuzz targets \
//! The generated seeds are deterministic, compact and intended to accelerate coverage
//! of valid and near-valid states before mutation-based exploration takes over
//!
//! # Security
//! The generated corpus may contain valid vault containers and valid signed backups \
//! These files are test artifacts and must never be reused with real
//! production credentials or user data

use std::fs;
use std::path::{Path, PathBuf};
use vipervault_core::backup::{encode_signed_backup, BackupKdfPolicy};
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{create_encrypted_vault, VaultKdfPolicy};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{encode_vault_storage, VaultPayload};

/// Fuzz password used only for deterministic seed generation
///
/// # Security
/// This password is test-only and must never be used outside the fuzz corpus
const FUZZ_PASSWORD: &str = "fuzz-password";

/// Build the vault KDF policy used for corpus generation
fn vault_kdf_policy() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build the backup KDF policy used for corpus generation
fn backup_kdf_policy() -> BackupKdfPolicy {
    BackupKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Write bytes to a file, creating parent directories if necessary
fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directories");
    }

    fs::write(path, bytes).expect("write file");
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

    VaultPayload {
        entries: vec![password_entry, note_entry],
    }
}

/// Generate a valid encrypted vault container
fn generate_valid_vault_bytes() -> Vec<u8> {
    let password = MasterPassword::new(FUZZ_PASSWORD.to_string());
    let payload = sample_payload();

    let file = create_encrypted_vault(&password, &payload, 1, vault_kdf_policy())
        .expect("create encrypted vault");

    encode_vault_storage(&file.header, &file.storage, 1).expect("encode vault storage")
}

/// Generate a valid signed backup containing a valid vault container
fn generate_valid_signed_backup_bytes() -> Vec<u8> {
    let password = MasterPassword::new(FUZZ_PASSWORD.to_string());
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    let vault_bytes = generate_valid_vault_bytes();

    encode_signed_backup(policy, &password, &vault_bytes, backup_kdf_policy())
        .expect("encode signed backup")
}

/// Return the curated seed corpus root directory
fn corpus_seed_root() -> PathBuf {
    PathBuf::from("corpus_seed")
}

fn main() {
    let corpus_root = corpus_seed_root();

    let decode_vault_dir = corpus_root.join("decode_vault_file");
    let parse_otpauth_dir = corpus_root.join("parse_totp_otpauth_uri");
    let decode_base32_dir = corpus_root.join("decode_base32_secret_strict");
    let decode_backup_dir = corpus_root.join("decode_signed_backup");
    let interop_dir = corpus_root.join("import_interop_quarantine");
    let canonicalize_dir = corpus_root.join("canonicalize_base32_for_export");
    let vault_roundtrip_dir = corpus_root.join("vault_codec_roundtrip");
    let duress_dir = corpus_root.join("enable_duress_on_vault");
    let otpauth_roundtrip_dir = corpus_root.join("otpauth_roundtrip");

    for dir in [
        &decode_vault_dir,
        &parse_otpauth_dir,
        &decode_base32_dir,
        &decode_backup_dir,
        &interop_dir,
        &canonicalize_dir,
        &vault_roundtrip_dir,
        &duress_dir,
        &otpauth_roundtrip_dir,
    ] {
        fs::create_dir_all(dir).expect("create corpus dir");
    }

    // -------------------------------------------------------------------------
    // decode_vault_file corpus seeds
    // -------------------------------------------------------------------------

    let valid_vault = generate_valid_vault_bytes();
    write_file(&decode_vault_dir.join("valid_encrypted_vault.bin"), &valid_vault);

    let mut truncated_vault = valid_vault.clone();
    truncated_vault.truncate(truncated_vault.len().saturating_sub(8));
    write_file(
        &decode_vault_dir.join("truncated_encrypted_vault.bin"),
        &truncated_vault,
    );

    let mut trailing_vault = valid_vault.clone();
    trailing_vault.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    write_file(
        &decode_vault_dir.join("trailing_bytes_encrypted_vault.bin"),
        &trailing_vault,
    );

    write_file(&decode_vault_dir.join("empty.bin"), b"");
    write_file(&decode_vault_dir.join("magic_only.bin"), b"VLT1");

    // -------------------------------------------------------------------------
    // parse_totp_otpauth_uri corpus seeds
    // -------------------------------------------------------------------------

    write_file(
        &parse_otpauth_dir.join("valid_sha1.txt"),
        b"otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
    );

    write_file(
        &parse_otpauth_dir.join("valid_sha256.txt"),
        b"otpauth://totp/Email:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Email&algorithm=SHA256&digits=8&period=60",
    );

    write_file(
        &parse_otpauth_dir.join("missing_secret.txt"),
        b"otpauth://totp/GitHub:octocat?issuer=GitHub&algorithm=SHA1&digits=6&period=30",
    );

    write_file(
        &parse_otpauth_dir.join("wrong_scheme.txt"),
        b"https://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    );

    write_file(
        &parse_otpauth_dir.join("wrong_host.txt"),
        b"otpauth://hotp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    );

    // -------------------------------------------------------------------------
    // decode_base32_secret_strict corpus seeds
    // -------------------------------------------------------------------------

    write_file(
        &decode_base32_dir.join("valid_unpadded.txt"),
        b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    );

    write_file(
        &decode_base32_dir.join("valid_padded.txt"),
        b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
    );

    write_file(&decode_base32_dir.join("too_short.txt"), b"JBSWY3DPEHPK3PXP");
    write_file(&decode_base32_dir.join("invalid_chars.txt"), b"NOT_VALID_BASE32!");
    write_file(
        &decode_base32_dir.join("invalid_internal_padding.txt"),
        b"ABCD=EFGH",
    );

    // -------------------------------------------------------------------------
    // decode_signed_backup corpus seeds
    // -------------------------------------------------------------------------

    let valid_backup = generate_valid_signed_backup_bytes();
    write_file(
        &decode_backup_dir.join("valid_signed_backup.bin"),
        &valid_backup,
    );

    let mut truncated_backup = valid_backup.clone();
    truncated_backup.truncate(truncated_backup.len().saturating_sub(12));
    write_file(
        &decode_backup_dir.join("truncated_signed_backup.bin"),
        &truncated_backup,
    );

    let mut tampered_backup = valid_backup.clone();
    if let Some(last) = tampered_backup.last_mut() {
        *last ^= 0x01;
    }
    write_file(
        &decode_backup_dir.join("tampered_signed_backup.bin"),
        &tampered_backup,
    );

    write_file(&decode_backup_dir.join("empty.bin"), b"");
    write_file(&decode_backup_dir.join("magic_only.bin"), b"VVBAKUP1");

    // -------------------------------------------------------------------------
    // Additional fuzz target seed corpora
    // -------------------------------------------------------------------------

    write_file(
        &interop_dir.join("valid_list.txt"),
        b"otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA1&digits=6&period=30\n\
          otpauth://totp/Email:alice@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Email&algorithm=SHA256&digits=8&period=60\n",
    );

    write_file(
        &canonicalize_dir.join("valid_spaced.txt"),
        b"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
    );
    write_file(
        &canonicalize_dir.join("valid_hyphenated.txt"),
        b"GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
    );
    write_file(&canonicalize_dir.join("invalid.txt"), b"invalid!!");

    write_file(&vault_roundtrip_dir.join("small.bin"), b"\x01\x00seed");
    write_file(&vault_roundtrip_dir.join("empty.bin"), b"");
    write_file(&vault_roundtrip_dir.join("random.bin"), b"abc123xyz987");

    write_file(&duress_dir.join("empty.bin"), b"");
    write_file(&duress_dir.join("small.bin"), b"duress-seed");
    write_file(&duress_dir.join("random.bin"), b"\x00\x01\x02\x03migration\xff");

    write_file(&otpauth_roundtrip_dir.join("title_seed.txt"), b"GitHub");
    write_file(&otpauth_roundtrip_dir.join("mixed_seed.txt"), b"Vault_Prod-01");
}