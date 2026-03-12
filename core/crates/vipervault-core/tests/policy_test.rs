// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy tests
//!
//! # Scope
//! These tests validate the centralized security policy matrix associated with:
//! - primary vs decoy unlock outcomes
//! - debugger status soft-policy decisions
//!
//! Covered:
//! - policy context classification
//! - export policy
//! - plaintext import policy
//! - biometric unlock policy
//! - signed backup transfer policy
//! - OTPAuth import policy
//!
//! # Security
//! Decoy mode and active debugging must consistently deny sensitive operations \
//! The policy matrix must remain deterministic and free from accidental divergence
//! between individual capability checks

use vipervault_core::core::DebugStatus;
use vipervault_core::core::policy::PolicyContext;
use vipervault_core::vault::duress::UnlockOutcome;

/// Primary outcome must produce a non-decoy policy context
#[test]
fn primary_outcome_is_not_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);
    assert!(!policy.is_decoy());
    assert_eq!(policy.outcome(), UnlockOutcome::Primary);
}

/// Decoy outcome must produce a decoy policy context
#[test]
fn decoy_outcome_is_decoy() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);
    assert!(policy.is_decoy());
    assert_eq!(policy.outcome(), UnlockOutcome::Decoy);
}

/// Primary policy must allow all sensitive capabilities when no debugger is detected
#[test]
fn primary_policy_allows_sensitive_capabilities_when_not_debugged() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);

    assert!(policy.allow_secret_export_for_status(DebugStatus::NotDebugged));
    assert!(policy.allow_plaintext_import_for_status(DebugStatus::NotDebugged));
    assert!(policy.allow_biometric_unlock_for_status(DebugStatus::NotDebugged));
    assert!(policy.allow_signed_backup_transfer_for_status(DebugStatus::NotDebugged));
    assert!(policy.allow_otpauth_import_for_status(DebugStatus::NotDebugged));
}

/// Primary policy must deny all sensitive capabilities when a debugger is detected
#[test]
fn primary_policy_denies_sensitive_capabilities_when_debugged() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);

    assert!(!policy.allow_secret_export_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_plaintext_import_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_biometric_unlock_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_signed_backup_transfer_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_otpauth_import_for_status(DebugStatus::Debugged));
}

/// Primary policy must remain permissive when debugger status is unknown
#[test]
fn primary_policy_remains_permissive_when_debug_status_is_unknown() {
    let policy = PolicyContext::new(UnlockOutcome::Primary);

    assert!(policy.allow_secret_export_for_status(DebugStatus::Unknown));
    assert!(policy.allow_plaintext_import_for_status(DebugStatus::Unknown));
    assert!(policy.allow_biometric_unlock_for_status(DebugStatus::Unknown));
    assert!(policy.allow_signed_backup_transfer_for_status(DebugStatus::Unknown));
    assert!(policy.allow_otpauth_import_for_status(DebugStatus::Unknown));
}

/// Decoy policy must deny all sensitive capabilities even when no debugger is detected
#[test]
fn decoy_policy_denies_sensitive_capabilities_when_not_debugged() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);

    assert!(!policy.allow_secret_export_for_status(DebugStatus::NotDebugged));
    assert!(!policy.allow_plaintext_import_for_status(DebugStatus::NotDebugged));
    assert!(!policy.allow_biometric_unlock_for_status(DebugStatus::NotDebugged));
    assert!(!policy.allow_signed_backup_transfer_for_status(DebugStatus::NotDebugged));
    assert!(!policy.allow_otpauth_import_for_status(DebugStatus::NotDebugged));
}

/// Decoy policy must deny all sensitive capabilities when a debugger is detected
#[test]
fn decoy_policy_denies_sensitive_capabilities_when_debugged() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);

    assert!(!policy.allow_secret_export_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_plaintext_import_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_biometric_unlock_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_signed_backup_transfer_for_status(DebugStatus::Debugged));
    assert!(!policy.allow_otpauth_import_for_status(DebugStatus::Debugged));
}

/// Decoy policy must deny all sensitive capabilities when debugger status is unknown
#[test]
fn decoy_policy_denies_sensitive_capabilities_when_debug_status_is_unknown() {
    let policy = PolicyContext::new(UnlockOutcome::Decoy);

    assert!(!policy.allow_secret_export_for_status(DebugStatus::Unknown));
    assert!(!policy.allow_plaintext_import_for_status(DebugStatus::Unknown));
    assert!(!policy.allow_biometric_unlock_for_status(DebugStatus::Unknown));
    assert!(!policy.allow_signed_backup_transfer_for_status(DebugStatus::Unknown));
    assert!(!policy.allow_otpauth_import_for_status(DebugStatus::Unknown));
}

/// Equal contexts must produce equal policy decisions
#[test]
fn equal_contexts_produce_equal_policy_decisions() {
    let lhs = PolicyContext::new(UnlockOutcome::Primary);
    let rhs = PolicyContext::new(UnlockOutcome::Primary);

    for status in [
        DebugStatus::NotDebugged,
        DebugStatus::Debugged,
        DebugStatus::Unknown,
    ] {
        assert_eq!(
            lhs.allow_secret_export_for_status(status),
            rhs.allow_secret_export_for_status(status)
        );
        assert_eq!(
            lhs.allow_plaintext_import_for_status(status),
            rhs.allow_plaintext_import_for_status(status)
        );
        assert_eq!(
            lhs.allow_biometric_unlock_for_status(status),
            rhs.allow_biometric_unlock_for_status(status)
        );
        assert_eq!(
            lhs.allow_signed_backup_transfer_for_status(status),
            rhs.allow_signed_backup_transfer_for_status(status)
        );
        assert_eq!(
            lhs.allow_otpauth_import_for_status(status),
            rhs.allow_otpauth_import_for_status(status)
        );
    }
}

/// Capability decisions must remain aligned across all export/import-oriented paths
#[test]
fn sensitive_capability_decisions_remain_aligned_per_status() {
    for outcome in [UnlockOutcome::Primary, UnlockOutcome::Decoy] {
        let policy = PolicyContext::new(outcome);

        for status in [
            DebugStatus::NotDebugged,
            DebugStatus::Debugged,
            DebugStatus::Unknown,
        ] {
            let export = policy.allow_secret_export_for_status(status);
            let plaintext_import = policy.allow_plaintext_import_for_status(status);
            let biometric = policy.allow_biometric_unlock_for_status(status);
            let signed_backup = policy.allow_signed_backup_transfer_for_status(status);
            let otpauth = policy.allow_otpauth_import_for_status(status);

            assert_eq!(export, plaintext_import);
            assert_eq!(export, biometric);
            assert_eq!(export, signed_backup);
            assert_eq!(export, otpauth);
        }
    }
}

/// Repeated construction must not leak state across policy instances
///
/// # Security
/// Different instances constructed from the same outcome must remain identical \
/// Different outcomes must preserve their own classification independently of
/// any previously constructed instance
#[test]
fn policy_context_has_no_cross_instance_state() {
    let primary = PolicyContext::new(UnlockOutcome::Primary);
    let decoy = PolicyContext::new(UnlockOutcome::Decoy);
    let primary_again = PolicyContext::new(UnlockOutcome::Primary);
    let decoy_again = PolicyContext::new(UnlockOutcome::Decoy);

    assert_eq!(primary, primary_again);
    assert_eq!(decoy, decoy_again);

    assert!(!primary.is_decoy());
    assert!(decoy.is_decoy());
    assert!(!primary_again.is_decoy());
    assert!(decoy_again.is_decoy());

    for status in [
        DebugStatus::NotDebugged,
        DebugStatus::Debugged,
        DebugStatus::Unknown,
    ] {
        assert_eq!(
            primary.allow_secret_export_for_status(status),
            primary_again.allow_secret_export_for_status(status)
        );
        assert_eq!(
            primary.allow_plaintext_import_for_status(status),
            primary_again.allow_plaintext_import_for_status(status)
        );
        assert_eq!(
            primary.allow_biometric_unlock_for_status(status),
            primary_again.allow_biometric_unlock_for_status(status)
        );
        assert_eq!(
            primary.allow_signed_backup_transfer_for_status(status),
            primary_again.allow_signed_backup_transfer_for_status(status)
        );
        assert_eq!(
            primary.allow_otpauth_import_for_status(status),
            primary_again.allow_otpauth_import_for_status(status)
        );

        assert_eq!(
            decoy.allow_secret_export_for_status(status),
            decoy_again.allow_secret_export_for_status(status)
        );
        assert_eq!(
            decoy.allow_plaintext_import_for_status(status),
            decoy_again.allow_plaintext_import_for_status(status)
        );
        assert_eq!(
            decoy.allow_biometric_unlock_for_status(status),
            decoy_again.allow_biometric_unlock_for_status(status)
        );
        assert_eq!(
            decoy.allow_signed_backup_transfer_for_status(status),
            decoy_again.allow_signed_backup_transfer_for_status(status)
        );
        assert_eq!(
            decoy.allow_otpauth_import_for_status(status),
            decoy_again.allow_otpauth_import_for_status(status)
        );
    }
}
