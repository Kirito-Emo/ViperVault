#![no_main]
// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Emanuele Relmi

//! Structure-aware fuzz target for duress migration
//!
//! # Security
//! This target exercises duress migration using bounded semantic payloads \
//! The target is expensive because production KDF parameters are enforced by the project

#[path = "support/structured.rs"]
mod structured;
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use structured::{SafeDisplay, SmallBytes};
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{create_encrypted_vault, VaultKdfPolicy};
use vipervault_core::vault::migrate::enable_duress_on_vault;
use vipervault_core::vault::{
    decode_vault_file, encode_vault_storage, VaultPayload, MAX_VAULT_CONTAINER_PAYLOAD_LEN,
};

/// Structured secure-note payload model
#[derive(Debug, Clone, Arbitrary)]
struct StructuredPayloadCase {
    /// Entry title prefix
    prefix: SafeDisplay,

    /// Opaque source bytes for secret material
    material: SmallBytes,

    /// Number of entries requested
    entry_count: u8,
}

/// Structured migration case
#[derive(Debug, Clone, Arbitrary)]
struct StructuredMigrationCase {
    /// Primary payload
    primary: StructuredPayloadCase,
    /// Decoy payload
    decoy: StructuredPayloadCase,
}

/// Project-valid KDF policy
fn vault_kdf_policy() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build a bounded payload from structured fuzz input
fn build_payload(case: &StructuredPayloadCase) -> VaultPayload {
    let mut entries = Vec::new();
    let count = usize::from(case.entry_count % 4);

    for idx in 0..count {
        let title = format!("{}-{idx}", case.prefix.0);
        let secret_slice = case
            .material
            .0
            .chunks(16)
            .nth(idx)
            .unwrap_or_default()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let secret = format!("note-{secret_slice}");

        let Ok(entry) = VaultEntry::new_secure_note(title, secret) else {
            continue;
        };

        entries.push(entry);
    }

    VaultPayload { entries }
}

fuzz_target!(|case: StructuredMigrationCase| {
    let primary_pw = MasterPassword::new("primary-fuzz-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-fuzz-password".to_string());

    let primary_payload = build_payload(&case.primary);
    let decoy_payload = build_payload(&case.decoy);

    let Ok(legacy) = create_encrypted_vault(&primary_pw, &primary_payload, 1, vault_kdf_policy())
    else {
        return;
    };

    let Ok(migrated) = enable_duress_on_vault(
        &legacy,
        &primary_pw,
        &decoy_pw,
        &decoy_payload,
        vault_kdf_policy(),
    ) else {
        return;
    };

    let Ok(encoded) = encode_vault_storage(&migrated.header, &migrated.storage, 1) else {
        return;
    };

    let Ok(decoded) = decode_vault_file(
        Cursor::new(encoded),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    ) else {
        return;
    };

    assert!(decoded.header.duress.is_some());
});
