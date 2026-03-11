// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Gated unlock tests
//!
//! # Scope
//! These tests validate the async gated unlock path:
//! - successful primary unlock
//! - successful decoy unlock
//! - wrong password rejection
//! - tamper rejection
//! - invalid payload rejection
//! - limiter reset on primary success
//! - no limiter reset on decoy success
//!
//! # Security
//! These tests ensure that:
//! - the async unlock entry point preserves coarse-grained error behavior
//! - heavy password-based operations are wrapped by the authentication gate
//! - decoy unlocks do not clear the accumulated backoff state

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::advance;
use uuid::Uuid;
use vipervault_core::core::auth_gate::AuthGate;
use vipervault_core::core::rate_limit::UnlockThrottlePolicy;
use vipervault_core::core::{UnlockError, unlock_session_gated};
use vipervault_core::crypto::aead::{encrypt_xchacha20poly1305, generate_xchacha20_nonce};
use vipervault_core::crypto::kdf::{
    DEFAULT_ARGON2ID_LANES, DEFAULT_ARGON2ID_MEM_KIB, DEFAULT_ARGON2ID_TIME_COST,
    derive_master_key_from_password, generate_vault_salt,
};
use vipervault_core::entries::types::VaultEntry;
use vipervault_core::memory::MasterPassword;
use vipervault_core::vault::create::{VaultKdfPolicy, create_duress_vault};
use vipervault_core::vault::duress::UnlockOutcome;
use vipervault_core::vault::{
    AeadSuite, CryptoHeader, KdfParams, MAGIC, MAX_VAULT_CONTAINER_PAYLOAD_LEN, ParsedVaultFile,
    StorageMode, VaultHeader, VaultPayload, decode_vault_file,
};

/// Build a deterministic throttle policy for time-paused tests
fn tiny_test_policy() -> UnlockThrottlePolicy {
    UnlockThrottlePolicy {
        quiet_period: Duration::from_secs(60),
        max_delay: Duration::from_millis(1),
        jitter_max: Duration::ZERO,
    }
}

/// Let spawned async tasks progress and arm any pending sleeps
async fn settle_runtime() {
    yield_now().await;
    yield_now().await;
    advance(Duration::ZERO).await;
    yield_now().await;
}

/// Build an encrypted vault container where AEAD AAD is exactly the stored `header_bytes`
///
/// # Security
/// This helper constructs the container manually so that:
/// - the stored raw header bytes are used as AAD
/// - tests do not depend on JSON re-serialization equivalence
fn build_encrypted_container_bytes(
    header: &VaultHeader,
    payload_plaintext: &[u8],
    password: &MasterPassword,
) -> Vec<u8> {
    let header_bytes = serde_json::to_vec(header).expect("header serialize");

    let (mem_kib, time_cost, lanes) = match header.crypto.kdf {
        KdfParams::Argon2id {
            mem_kib,
            time_cost,
            lanes,
        } => (mem_kib, time_cost, lanes),
        _ => unreachable!("unsupported KDF params in tests"),
    };

    let master_key =
        derive_master_key_from_password(password, &header.crypto.salt, mem_kib, time_cost, lanes)
            .expect("kdf");

    let ct = encrypt_xchacha20poly1305(
        &master_key,
        &header.crypto.nonce,
        payload_plaintext,
        &header_bytes,
    )
    .expect("encrypt");

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.push(StorageMode::Encrypted as u8);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    out.extend_from_slice(&ct);
    out
}

fn sample_payload(entry_id: Uuid) -> VaultPayload {
    let entry = VaultEntry::new_secure_note("note".to_string(), "secret".to_string())
        .expect("entry create");

    let mut entry = entry;
    entry.meta.id = entry_id;

    VaultPayload {
        entries: vec![entry],
    }
}

fn parse(bytes: &[u8]) -> ParsedVaultFile {
    decode_vault_file(
        Cursor::new(bytes),
        Some(1),
        MAX_VAULT_CONTAINER_PAYLOAD_LEN,
        false,
    )
    .expect("decode")
}

/// Successful primary unlock must return a non-decoy session
#[tokio::test]
async fn gated_unlock_primary_success() {
    let gate = AuthGate::new(tiny_test_policy());
    let password = MasterPassword::new("correct horse battery staple".to_string());

    let entry_id = Uuid::new_v4();
    let payload = sample_payload(entry_id);
    let payload_json = serde_json::to_vec(&payload).expect("payload json");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed = parse(&bytes);

    let session = unlock_session_gated(&gate, parsed, password)
        .await
        .expect("gated unlock");

    assert!(!session.is_decoy());
    assert!(matches!(session.outcome(), UnlockOutcome::Primary));
    assert_eq!(session.payload().entries.len(), 1);
    assert_eq!(session.payload().entries[0].meta.id, entry_id);
}

/// Successful decoy unlock must return a decoy session
#[tokio::test]
async fn gated_unlock_decoy_success() {
    let gate = AuthGate::new(tiny_test_policy());
    let primary_pw = MasterPassword::new("primary-password".to_string());
    let decoy_pw = MasterPassword::new("decoy-password".to_string());

    let primary_payload = sample_payload(Uuid::new_v4());
    let decoy_payload = sample_payload(Uuid::new_v4());

    let kdf = VaultKdfPolicy {
        mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
        time_cost: DEFAULT_ARGON2ID_TIME_COST,
        lanes: DEFAULT_ARGON2ID_LANES,
    };

    let vault = create_duress_vault(
        &primary_pw,
        &decoy_pw,
        &primary_payload,
        &decoy_payload,
        1,
        kdf,
    )
    .expect("create duress vault");

    let bytes =
        vipervault_core::vault::codec::encode_vault_storage(&vault.header, &vault.storage, 1)
            .expect("encode");
    let parsed = parse(&bytes);

    let session = unlock_session_gated(&gate, parsed, decoy_pw)
        .await
        .expect("decoy unlock");

    assert!(session.is_decoy());
    assert!(matches!(session.outcome(), UnlockOutcome::Decoy));
    assert_eq!(
        session.payload().entries[0].meta.id,
        decoy_payload.entries[0].meta.id
    );
}

/// Wrong password must fail with coarse-grained `AuthFailed`
#[tokio::test]
async fn gated_unlock_wrong_password_is_auth_failed() {
    let gate = AuthGate::new(tiny_test_policy());
    let password = MasterPassword::new("correct horse battery staple".to_string());
    let wrong = MasterPassword::new("wrong password".to_string());

    let payload = sample_payload(Uuid::new_v4());
    let payload_json = serde_json::to_vec(&payload).expect("payload json");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed = parse(&bytes);

    let err = unlock_session_gated(&gate, parsed, wrong)
        .await
        .unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Ciphertext tampering must fail with coarse-grained `AuthFailed`
#[tokio::test]
async fn gated_unlock_tamper_is_auth_failed() {
    let gate = AuthGate::new(tiny_test_policy());
    let password = MasterPassword::new("pw".to_string());

    let payload = sample_payload(Uuid::new_v4());
    let payload_json = serde_json::to_vec(&payload).expect("payload json");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    let mut bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    let parsed = parse(&bytes);

    let err = unlock_session_gated(&gate, parsed, password)
        .await
        .unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// Invalid decrypted JSON must fail with `PayloadDecode`
#[tokio::test]
async fn gated_unlock_invalid_payload_json_is_payload_decode() {
    let gate = AuthGate::new(tiny_test_policy());
    let password = MasterPassword::new("pw".to_string());

    let payload_json = br#"{"not":"a vault payload"}"#.to_vec();

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);
    let parsed = parse(&bytes);

    let err = unlock_session_gated(&gate, parsed, password)
        .await
        .unwrap_err();
    assert!(matches!(err, UnlockError::PayloadDecode));
}

/// A primary success through the gated unlock path must reset the backoff state
#[tokio::test(start_paused = true)]
async fn gated_primary_success_resets_limiter_state() {
    let gate = Arc::new(AuthGate::new(tiny_test_policy()));
    let password = MasterPassword::new("pw".to_string());
    let wrong = MasterPassword::new("wrong".to_string());

    let payload = sample_payload(Uuid::new_v4());
    let payload_json = serde_json::to_vec(&payload).expect("payload json");

    let header = VaultHeader {
        schema_version: 1,
        vault_id: Uuid::new_v4(),
        crypto: CryptoHeader {
            kdf: KdfParams::Argon2id {
                mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
                time_cost: DEFAULT_ARGON2ID_TIME_COST,
                lanes: DEFAULT_ARGON2ID_LANES,
            },
            aead: AeadSuite::XChaCha20Poly1305,
            salt: generate_vault_salt().expect("salt"),
            nonce: generate_xchacha20_nonce().expect("nonce"),
        },
        duress: None,
    };

    let bytes = build_encrypted_container_bytes(&header, &payload_json, &password);

    // Build an auth failure streak
    for _ in 0..3 {
        let parsed = parse(&bytes);
        let gate_for_task = Arc::clone(&gate);
        let handle = tokio::spawn(async move {
            unlock_session_gated(
                &gate_for_task,
                parsed,
                MasterPassword::new("wrong".to_string()),
            )
            .await
        });

        settle_runtime().await;
        if !handle.is_finished() {
            advance(Duration::from_millis(1)).await;
        }
        let err = handle.await.expect("join").unwrap_err();
        assert!(matches!(err, UnlockError::AuthFailed));
    }

    // Primary success must reset the limiter
    let parsed = parse(&bytes);
    let session = unlock_session_gated(&gate, parsed, password)
        .await
        .expect("primary unlock");
    assert!(!session.is_decoy());

    // After reset, the next wrong password must be immediate again
    let parsed = parse(&bytes);
    let gate_for_task = Arc::clone(&gate);
    let handle =
        tokio::spawn(async move { unlock_session_gated(&gate_for_task, parsed, wrong).await });

    settle_runtime().await;
    assert!(
        handle.is_finished(),
        "wrong password after primary success should be immediate"
    );

    let err = handle.await.expect("join").unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}

/// A decoy success through the gated unlock path must NOT reset the backoff state
#[tokio::test(start_paused = true)]
async fn gated_decoy_success_does_not_reset_limiter_state() {
    let gate = Arc::new(AuthGate::new(tiny_test_policy()));
    let primary_pw = MasterPassword::new("primary".to_string());
    let decoy_pw = MasterPassword::new("decoy".to_string());
    let wrong_pw = MasterPassword::new("wrong".to_string());

    let primary_payload = sample_payload(Uuid::new_v4());
    let decoy_payload = sample_payload(Uuid::new_v4());

    let kdf = VaultKdfPolicy {
        mem_kib: DEFAULT_ARGON2ID_MEM_KIB,
        time_cost: DEFAULT_ARGON2ID_TIME_COST,
        lanes: DEFAULT_ARGON2ID_LANES,
    };

    let vault = create_duress_vault(
        &primary_pw,
        &decoy_pw,
        &primary_payload,
        &decoy_payload,
        1,
        kdf,
    )
    .expect("create duress vault");

    let bytes =
        vipervault_core::vault::codec::encode_vault_storage(&vault.header, &vault.storage, 1)
            .expect("encode");

    // Build an auth failure streak
    for _ in 0..3 {
        let parsed = parse(&bytes);
        let gate_for_task = Arc::clone(&gate);
        let handle = tokio::spawn(async move {
            unlock_session_gated(
                &gate_for_task,
                parsed,
                MasterPassword::new("wrong".to_string()),
            )
            .await
        });

        settle_runtime().await;
        if !handle.is_finished() {
            advance(Duration::from_millis(1)).await;
        }
        let err = handle.await.expect("join").unwrap_err();
        assert!(matches!(err, UnlockError::AuthFailed));
    }

    // Decoy success must NOT reset the limiter
    let parsed = parse(&bytes);
    let session = unlock_session_gated(&gate, parsed, decoy_pw)
        .await
        .expect("decoy unlock");
    assert!(session.is_decoy());

    let parsed = parse(&bytes);
    let gate_for_task = Arc::clone(&gate);
    let handle =
        tokio::spawn(async move { unlock_session_gated(&gate_for_task, parsed, wrong_pw).await });

    settle_runtime().await;
    assert!(
        !handle.is_finished(),
        "wrong password after decoy success must remain delayed"
    );

    advance(Duration::from_millis(1)).await;
    let err = handle.await.expect("join").unwrap_err();
    assert!(matches!(err, UnlockError::AuthFailed));
}
