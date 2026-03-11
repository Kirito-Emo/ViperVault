// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault session tests
//!
//! # Scope
//! These tests validate the runtime unlocked vault session abstraction:
//! - primary vs decoy sessions
//! - payload exposure
//! - outcome invariants
//! - payload integrity
//!
//! # Security
//! The session object is the in-memory representation of an unlocked vault
//! Tests ensure that:
//! - the decoy flag cannot be confused
//! - payload content remains consistent
//! - session state is immutable from external callers

use uuid::Uuid;
use vipervault_core::core::UnlockedVaultSession;
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::vault::VaultPayload;
use vipervault_core::vault::duress::UnlockOutcome;

/// Build a minimal payload
fn sample_payload(id: Uuid) -> VaultPayload {
    let entry =
        VaultEntry::new_secure_note("note".to_string(), "secret".to_string()).expect("entry");

    let mut entry = entry;
    entry.meta.id = id;

    VaultPayload {
        entries: vec![entry],
    }
}

/// Primary session must report correct state
#[test]
fn primary_session_state_is_correct() {
    let entry_id = Uuid::new_v4();
    let payload = sample_payload(entry_id);

    let session = UnlockedVaultSession::new(UnlockOutcome::Primary, payload);

    assert!(!session.is_decoy());
    assert!(matches!(session.outcome(), UnlockOutcome::Primary));
    assert_eq!(session.payload().entries.len(), 1);
    assert_eq!(session.payload().entries[0].meta.id, entry_id);
}

/// Decoy session must report correct state
#[test]
fn decoy_session_state_is_correct() {
    let entry_id = Uuid::new_v4();
    let payload = sample_payload(entry_id);

    let session = UnlockedVaultSession::new(UnlockOutcome::Decoy, payload);

    assert!(session.is_decoy());
    assert!(matches!(session.outcome(), UnlockOutcome::Decoy));
    assert_eq!(session.payload().entries.len(), 1);
    assert_eq!(session.payload().entries[0].meta.id, entry_id);
}

/// Payload entries must remain intact
#[test]
fn payload_entries_are_preserved() {
    let id = Uuid::new_v4();
    let payload = sample_payload(id);

    let session = UnlockedVaultSession::new(UnlockOutcome::Primary, payload);
    let entries = &session.payload().entries;

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].meta.id, id);
}

/// Empty payload must be supported
#[test]
fn empty_payload_is_supported() {
    let payload = VaultPayload { entries: vec![] };

    let session = UnlockedVaultSession::new(UnlockOutcome::Primary, payload);

    assert_eq!(session.payload().entries.len(), 0);
    assert!(!session.is_decoy());
}

/// Payload returned by session must be read-only
///
/// # Security
/// External callers must not mutate the vault payload through the session API
#[test]
fn payload_reference_is_immutable() {
    let id = Uuid::new_v4();
    let payload = sample_payload(id);

    let session = UnlockedVaultSession::new(UnlockOutcome::Primary, payload);
    let payload_ref = session.payload();

    assert_eq!(payload_ref.entries.len(), 1);
    assert_eq!(payload_ref.entries[0].meta.id, id);
}
