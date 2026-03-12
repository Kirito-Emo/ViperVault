#![no_main]

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Fuzz target for duress migration
//!
//! # Security
//! This target exercises the re-encryption and dual-header migration boundary \
//! Fuzz-derived payloads must never trigger panics, hangs or invalid memory
//! behavior across legacy creation, migration, encoding and re-decoding

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use vipervault_core::entries::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{create_encrypted_vault, VaultKdfPolicy};
use vipervault_core::vault::migrate::enable_duress_on_vault;
use vipervault_core::vault::{
    decode_vault_file, encode_vault_storage, VaultPayload, MAX_VAULT_CONTAINER_PAYLOAD_LEN,
};

/// Valid project KDF policy
fn vault_kdf_policy() -> VaultKdfPolicy {
    VaultKdfPolicy {
        mem_kib: 64 * 1024,
        time_cost: 3,
        lanes: 1,
    }
}

/// Build a bounded secure-note payload from fuzz-derived bytes
fn payload_from_bytes(prefix: &str, data: &[u8]) -> VaultPayload {
    let mut entries = Vec::new();

    for (idx, chunk) in data.chunks(16).take(4).enumerate() {
        let title = format!("{prefix}-entry-{idx}");
        let secret = format!("{prefix}-{:02x?}", chunk);

        let Ok(entry) = VaultEntry::new_secure_note(title, secret) else {
            continue;
        };

        entries.push(entry);
    }

    VaultPayload { entries }
}

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let primary_bytes = &data[..split];
    let decoy_bytes = &data[split..];

    let primary_pw = MasterPassword::new("primary-fuzz-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-fuzz-password".to_string());

    let primary_payload = payload_from_bytes("primary", primary_bytes);
    let decoy_payload = payload_from_bytes("decoy", decoy_bytes);

    let legacy = create_encrypted_vault(&primary_pw, &primary_payload, 1, vault_kdf_policy());
    let Ok(legacy) = legacy else {
        return;
    };

    let migrated = enable_duress_on_vault(
        &legacy,
        &primary_pw,
        &decoy_pw,
        &decoy_payload,
        vault_kdf_policy(),
    );

    let Ok(migrated) = migrated else {
        return;
    };

    let encoded = encode_vault_storage(&migrated.header, &migrated.storage, 1);
    let Ok(encoded) = encoded else {
        return;
    };

    let _ = decode_vault_file(
        Cursor::new(encoded),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    );
});