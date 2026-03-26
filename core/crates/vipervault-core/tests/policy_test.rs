// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Policy tests
//!
//! # Purpose
//! These tests verify that the centralized runtime policy remains conservative
//! and deterministic across unlock outcomes, runtime inspection states and
//! sensitive operation categories

use vipervault_core::core::{PolicyContext, RuntimeInspectionState, SensitiveOperation};
use vipervault_core::vault::duress::UnlockOutcome;

/// Build a policy context for tests
fn policy(outcome: UnlockOutcome, runtime_state: RuntimeInspectionState) -> PolicyContext {
    PolicyContext::from_parts(outcome, runtime_state)
}

/// A clean primary session must allow sensitive operations
#[test]
fn primary_not_debugged_allows_sensitive_operations() {
    let policy = policy(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);

    assert_eq!(policy.outcome(), UnlockOutcome::Primary);
    assert_eq!(policy.runtime_state(), RuntimeInspectionState::NotDebugged);
    assert!(!policy.is_decoy());
    assert!(!policy.is_runtime_restrictive());
    assert!(!policy.is_tamper_suspected());

    assert!(policy.allow_biometric_unlock());
    assert!(policy.allow_clipboard_copy());
    assert!(policy.allow_totp_copy());
    assert!(policy.allow_secret_reveal());
    assert!(policy.allow_signed_backup_transfer());
    assert!(policy.allow_plaintext_export());
    assert!(policy.allow_plaintext_import());
    assert!(policy.allow_otpauth_import());

    assert!(policy.allow_sensitive_operation(SensitiveOperation::Export));
    assert!(policy.allow_sensitive_operation(SensitiveOperation::SignedBackupTransfer));
    assert!(policy.allow_sensitive_operation(SensitiveOperation::RevealSecret));
    assert!(policy.allow_sensitive_operation(SensitiveOperation::CopySecret));
    assert!(policy.allow_sensitive_operation(SensitiveOperation::CopyTotp));
    assert!(policy.allow_sensitive_operation(SensitiveOperation::ChangeSecuritySettings));

    assert!(!policy.requires_short_autolock());
    assert!(!policy.requires_strong_reauth_for_sensitive_ops());
}

/// A decoy session must deny exposure-prone operations even when the runtime is clean
#[test]
fn decoy_not_debugged_denies_sensitive_operations() {
    let policy = policy(UnlockOutcome::Decoy, RuntimeInspectionState::NotDebugged);

    assert_eq!(policy.outcome(), UnlockOutcome::Decoy);
    assert_eq!(policy.runtime_state(), RuntimeInspectionState::NotDebugged);
    assert!(policy.is_decoy());
    assert!(!policy.is_runtime_restrictive());
    assert!(!policy.is_tamper_suspected());

    assert!(!policy.allow_biometric_unlock());
    assert!(!policy.allow_clipboard_copy());
    assert!(!policy.allow_totp_copy());
    assert!(!policy.allow_secret_reveal());
    assert!(!policy.allow_signed_backup_transfer());
    assert!(!policy.allow_plaintext_export());
    assert!(!policy.allow_plaintext_import());
    assert!(!policy.allow_otpauth_import());

    assert!(!policy.allow_sensitive_operation(SensitiveOperation::Export));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::SignedBackupTransfer));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::RevealSecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopySecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopyTotp));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::ChangeSecuritySettings));

    assert!(!policy.requires_short_autolock());
    assert!(!policy.requires_strong_reauth_for_sensitive_ops());
}

/// A debugged runtime must deny sensitive operations
#[test]
fn primary_debugged_denies_sensitive_operations() {
    let policy = policy(UnlockOutcome::Primary, RuntimeInspectionState::Debugged);

    assert_eq!(policy.runtime_state(), RuntimeInspectionState::Debugged);
    assert!(!policy.is_decoy());
    assert!(policy.is_runtime_restrictive());
    assert!(!policy.is_tamper_suspected());

    assert!(!policy.allow_biometric_unlock());
    assert!(!policy.allow_clipboard_copy());
    assert!(!policy.allow_totp_copy());
    assert!(!policy.allow_secret_reveal());
    assert!(!policy.allow_signed_backup_transfer());
    assert!(!policy.allow_plaintext_export());
    assert!(!policy.allow_plaintext_import());
    assert!(!policy.allow_otpauth_import());

    assert!(!policy.allow_sensitive_operation(SensitiveOperation::Export));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::SignedBackupTransfer));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::RevealSecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopySecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopyTotp));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::ChangeSecuritySettings));

    assert!(policy.requires_short_autolock());
    assert!(policy.requires_strong_reauth_for_sensitive_ops());
}

/// An unknown runtime must be treated conservatively
#[test]
fn primary_unknown_denies_sensitive_operations() {
    let policy = policy(UnlockOutcome::Primary, RuntimeInspectionState::Unknown);

    assert_eq!(policy.runtime_state(), RuntimeInspectionState::Unknown);
    assert!(!policy.is_decoy());
    assert!(policy.is_runtime_restrictive());
    assert!(!policy.is_tamper_suspected());

    assert!(!policy.allow_biometric_unlock());
    assert!(!policy.allow_clipboard_copy());
    assert!(!policy.allow_totp_copy());
    assert!(!policy.allow_secret_reveal());
    assert!(!policy.allow_signed_backup_transfer());
    assert!(!policy.allow_plaintext_export());
    assert!(!policy.allow_plaintext_import());
    assert!(!policy.allow_otpauth_import());

    assert!(!policy.allow_sensitive_operation(SensitiveOperation::Export));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::SignedBackupTransfer));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::RevealSecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopySecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopyTotp));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::ChangeSecuritySettings));

    assert!(policy.requires_short_autolock());
    assert!(policy.requires_strong_reauth_for_sensitive_ops());
}

/// A tamper-suspected runtime must be treated as strongly restrictive
#[test]
fn primary_tamper_suspected_denies_sensitive_operations() {
    let policy = policy(
        UnlockOutcome::Primary,
        RuntimeInspectionState::TamperSuspected,
    );

    assert_eq!(
        policy.runtime_state(),
        RuntimeInspectionState::TamperSuspected
    );
    assert!(!policy.is_decoy());
    assert!(policy.is_runtime_restrictive());
    assert!(policy.is_tamper_suspected());

    assert!(!policy.allow_biometric_unlock());
    assert!(!policy.allow_clipboard_copy());
    assert!(!policy.allow_totp_copy());
    assert!(!policy.allow_secret_reveal());
    assert!(!policy.allow_signed_backup_transfer());
    assert!(!policy.allow_plaintext_export());
    assert!(!policy.allow_plaintext_import());
    assert!(!policy.allow_otpauth_import());

    assert!(!policy.allow_sensitive_operation(SensitiveOperation::Export));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::SignedBackupTransfer));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::RevealSecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopySecret));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::CopyTotp));
    assert!(!policy.allow_sensitive_operation(SensitiveOperation::ChangeSecuritySettings));

    assert!(policy.requires_short_autolock());
    assert!(policy.requires_strong_reauth_for_sensitive_ops());
}

/// The state-specific export helpers must remain aligned with the context-bound helpers
#[test]
fn state_specific_export_helpers_match_context_helpers() {
    let clean = policy(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let debugged = policy(UnlockOutcome::Primary, RuntimeInspectionState::Debugged);
    let unknown = policy(UnlockOutcome::Primary, RuntimeInspectionState::Unknown);
    let tamper = policy(
        UnlockOutcome::Primary,
        RuntimeInspectionState::TamperSuspected,
    );

    assert_eq!(
        clean.allow_secret_export_for_state(RuntimeInspectionState::NotDebugged),
        clean.allow_secret_export()
    );
    assert_eq!(
        debugged.allow_secret_export_for_state(RuntimeInspectionState::Debugged),
        debugged.allow_secret_export()
    );
    assert_eq!(
        unknown.allow_secret_export_for_state(RuntimeInspectionState::Unknown),
        unknown.allow_secret_export()
    );
    assert_eq!(
        tamper.allow_secret_export_for_state(RuntimeInspectionState::TamperSuspected),
        tamper.allow_secret_export()
    );
}

/// The state-specific plaintext import helpers must remain aligned with the context-bound helpers
#[test]
fn state_specific_plaintext_import_helpers_match_context_helpers() {
    let clean = policy(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let debugged = policy(UnlockOutcome::Primary, RuntimeInspectionState::Debugged);
    let unknown = policy(UnlockOutcome::Primary, RuntimeInspectionState::Unknown);
    let tamper = policy(
        UnlockOutcome::Primary,
        RuntimeInspectionState::TamperSuspected,
    );

    assert_eq!(
        clean.allow_plaintext_import_for_state(RuntimeInspectionState::NotDebugged),
        clean.allow_plaintext_import()
    );
    assert_eq!(
        debugged.allow_plaintext_import_for_state(RuntimeInspectionState::Debugged),
        debugged.allow_plaintext_import()
    );
    assert_eq!(
        unknown.allow_plaintext_import_for_state(RuntimeInspectionState::Unknown),
        unknown.allow_plaintext_import()
    );
    assert_eq!(
        tamper.allow_plaintext_import_for_state(RuntimeInspectionState::TamperSuspected),
        tamper.allow_plaintext_import()
    );
}

/// The state-specific biometric helpers must remain aligned with the context-bound helpers
#[test]
fn state_specific_biometric_helpers_match_context_helpers() {
    let clean = policy(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let debugged = policy(UnlockOutcome::Primary, RuntimeInspectionState::Debugged);
    let unknown = policy(UnlockOutcome::Primary, RuntimeInspectionState::Unknown);
    let tamper = policy(
        UnlockOutcome::Primary,
        RuntimeInspectionState::TamperSuspected,
    );

    assert_eq!(
        clean.allow_biometric_unlock_for_state(RuntimeInspectionState::NotDebugged),
        clean.allow_biometric_unlock()
    );
    assert_eq!(
        debugged.allow_biometric_unlock_for_state(RuntimeInspectionState::Debugged),
        debugged.allow_biometric_unlock()
    );
    assert_eq!(
        unknown.allow_biometric_unlock_for_state(RuntimeInspectionState::Unknown),
        unknown.allow_biometric_unlock()
    );
    assert_eq!(
        tamper.allow_biometric_unlock_for_state(RuntimeInspectionState::TamperSuspected),
        tamper.allow_biometric_unlock()
    );
}

/// The state-specific signed-backup helpers must remain aligned with the context-bound helpers
#[test]
fn state_specific_signed_backup_helpers_match_context_helpers() {
    let clean = policy(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let debugged = policy(UnlockOutcome::Primary, RuntimeInspectionState::Debugged);
    let unknown = policy(UnlockOutcome::Primary, RuntimeInspectionState::Unknown);
    let tamper = policy(
        UnlockOutcome::Primary,
        RuntimeInspectionState::TamperSuspected,
    );

    assert_eq!(
        clean.allow_signed_backup_transfer_for_state(RuntimeInspectionState::NotDebugged),
        clean.allow_signed_backup_transfer()
    );
    assert_eq!(
        debugged.allow_signed_backup_transfer_for_state(RuntimeInspectionState::Debugged),
        debugged.allow_signed_backup_transfer()
    );
    assert_eq!(
        unknown.allow_signed_backup_transfer_for_state(RuntimeInspectionState::Unknown),
        unknown.allow_signed_backup_transfer()
    );
    assert_eq!(
        tamper.allow_signed_backup_transfer_for_state(RuntimeInspectionState::TamperSuspected),
        tamper.allow_signed_backup_transfer()
    );
}

/// The state-specific OTPAuth helpers must remain aligned with the context-bound helpers
#[test]
fn state_specific_otpauth_helpers_match_context_helpers() {
    let clean = policy(UnlockOutcome::Primary, RuntimeInspectionState::NotDebugged);
    let debugged = policy(UnlockOutcome::Primary, RuntimeInspectionState::Debugged);
    let unknown = policy(UnlockOutcome::Primary, RuntimeInspectionState::Unknown);
    let tamper = policy(
        UnlockOutcome::Primary,
        RuntimeInspectionState::TamperSuspected,
    );

    assert_eq!(
        clean.allow_otpauth_import_for_state(RuntimeInspectionState::NotDebugged),
        clean.allow_otpauth_import()
    );
    assert_eq!(
        debugged.allow_otpauth_import_for_state(RuntimeInspectionState::Debugged),
        debugged.allow_otpauth_import()
    );
    assert_eq!(
        unknown.allow_otpauth_import_for_state(RuntimeInspectionState::Unknown),
        unknown.allow_otpauth_import()
    );
    assert_eq!(
        tamper.allow_otpauth_import_for_state(RuntimeInspectionState::TamperSuspected),
        tamper.allow_otpauth_import()
    );
}
