// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy tests
//!
//! # Scope
//! These tests validate the security policy behavior associated with
//! primary vs decoy unlock outcomes.
//!
//! Covered:
//! - policy context classification
//! - decoy restrictions
//! - primary allowance for normal operations
//!
//! # Security
//! Decoy mode must reduce capabilities and deny sensitive operations
//! such as export-like flows.

use vipervault_core::core::policy::PolicyContext;
use vipervault_core::vault::duress::UnlockOutcome;

/// Primary outcome must produce a non-decoy policy context
#[test]
fn primary_outcome_is_not_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    assert!(!policy.is_decoy());
}

/// Decoy outcome must produce a decoy policy context
#[test]
fn decoy_outcome_is_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);
    assert!(policy.is_decoy());
}

/// Primary policy must allow secret export
///
/// # Security
/// Primary mode represents the fully authenticated session
#[test]
fn primary_policy_allows_secret_export() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);

    assert!(!policy.is_decoy());
    assert!(policy.allow_secret_export());
}

/// Decoy policy must deny secret export
///
/// # Security
/// Decoy mode must never be confused with primary mode
#[test]
fn decoy_policy_denies_secret_export() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);

    assert!(policy.is_decoy());
    assert!(!policy.allow_secret_export());
}

/// Constructing equal contexts from equal outcomes must be deterministic
#[test]
fn policy_context_construction_is_deterministic() {
    let p1 = PolicyContext::new(UnlockOutcome::Primary);
    let p2 = PolicyContext::new(UnlockOutcome::Primary);

    let d1 = PolicyContext::new(UnlockOutcome::Decoy);
    let d2 = PolicyContext::new(UnlockOutcome::Decoy);

    assert_eq!(p1, p2);
    assert_eq!(d1, d2);

    assert_eq!(p1.is_decoy(), p2.is_decoy());
    assert_eq!(d1.is_decoy(), d2.is_decoy());
    assert_eq!(p1.allow_secret_export(), p2.allow_secret_export());
    assert_eq!(d1.allow_secret_export(), d2.allow_secret_export());
}

/// Boundary: repeated construction must not leak state across contexts
#[test]
fn policy_context_has_no_cross_instance_state() {
    let primary = PolicyContext::new(UnlockOutcome::Primary);
    let decoy = PolicyContext::new(UnlockOutcome::Decoy);
    let primary_again = PolicyContext::new(UnlockOutcome::Primary);

    assert!(!primary.is_decoy());
    assert!(decoy.is_decoy());
    assert!(!primary_again.is_decoy());

    assert!(primary.allow_secret_export());
    assert!(!decoy.allow_secret_export());
    assert!(primary_again.allow_secret_export());
}
