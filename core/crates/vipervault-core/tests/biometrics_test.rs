// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometrics contract tests
//!
//! # Scope
//! These tests validate the abstract biometric backend contract:
//! - availability reporting
//! - successful master key unseal
//! - coarse-grained failure mapping
//! - key length invariants at the trait boundary
//!
//! # Security
//! Biometrics are used only as a gate to release a previously stored
//! 32-byte master key. These tests ensure the backend abstraction:
//! - remains coarse-grained on failure
//! - returns valid key material on success
//! - does not blur availability/auth/policy distinctions

use vipervault_core::biometrics::{BiometricBackend, BiometricError};
use vipervault_core::memory::KeyMaterial;

/// Simple test backend used to exercise the trait contract
#[derive(Debug)]
struct StubBackend {
    available: bool,
    result: Result<[u8; 32], BiometricError>,
}

impl BiometricBackend for StubBackend {
    fn is_available(&self) -> bool {
        self.available
    }

    fn unseal_master_key(&self, vault_id: &[u8]) -> Result<KeyMaterial, BiometricError> {
        if vault_id.is_empty() {
            return Err(BiometricError::InvalidResponse);
        }

        match &self.result {
            Ok(bytes) => Ok(KeyMaterial::new(*bytes)),
            Err(BiometricError::PolicyDenied) => Err(BiometricError::PolicyDenied),
            Err(BiometricError::Unavailable) => Err(BiometricError::Unavailable),
            Err(BiometricError::AuthFailed) => Err(BiometricError::AuthFailed),
            Err(BiometricError::InvalidResponse) => Err(BiometricError::InvalidResponse),
            Err(BiometricError::NotSupported) => Err(BiometricError::NotSupported),
        }
    }
}

/// Availability must be reported faithfully by the backend
#[test]
fn backend_reports_availability() {
    let available = StubBackend {
        available: true,
        result: Ok([7u8; 32]),
    };
    let unavailable = StubBackend {
        available: false,
        result: Err(BiometricError::Unavailable),
    };

    assert!(available.is_available());
    assert!(!unavailable.is_available());
}

/// Successful unseal must return exactly 32 bytes of key material
#[test]
fn unseal_success_returns_key_material() {
    let backend = StubBackend {
        available: true,
        result: Ok([0xAB; 32]),
    };

    let key = backend
        .unseal_master_key(b"vault-id")
        .expect("unseal master key");

    assert_eq!(key.as_bytes().len(), 32);
    assert_eq!(key.as_bytes().as_slice(), &[0xAB; 32]);
}

/// Empty vault identifiers must be rejected by the backend contract
#[test]
fn empty_vault_id_is_invalid_response() {
    let backend = StubBackend {
        available: true,
        result: Ok([1u8; 32]),
    };

    let err = backend.unseal_master_key(b"").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
}

/// Unavailable backends must return `Unavailable`
#[test]
fn unavailable_is_preserved() {
    let backend = StubBackend {
        available: false,
        result: Err(BiometricError::Unavailable),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::Unavailable));
}

/// Authentication failures must remain coarse-grained
#[test]
fn auth_failed_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::AuthFailed),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::AuthFailed));
}

/// Policy denial must remain distinct from generic auth failure
#[test]
fn policy_denied_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::PolicyDenied),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::PolicyDenied));
}

/// Unsupported vault modes must return `NotSupported`
#[test]
fn not_supported_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::NotSupported),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::NotSupported));
}

/// Invalid backend responses must remain coarse-grained
#[test]
fn invalid_response_is_preserved() {
    let backend = StubBackend {
        available: true,
        result: Err(BiometricError::InvalidResponse),
    };

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
}
