// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Anti-debug soft-policy tests
//!
//! # Scope
//! These tests validate the deterministic policy behavior driven by
//! [`DebugStatus`] without depending on the host operating system
//!
//! Covered:
//! - clipboard policy
//! - plaintext export policy
//! - auto-lock timeout clamping
//! - deterministic mapping from status to policy outcome
//!
//! # Security
//! The soft policy must deny sensitive capabilities only when active debugging
//! is detected, while preserving stable and predictable behavior for
//! `NotDebugged` and `Unknown`

use std::time::Duration;
use vipervault_core::core::{
    DEBUG_MAX_TIMEOUT_SECS, DebugStatus, allow_clipboard_for_status, allow_export_for_status,
    clamp_auto_lock_timeout_for_status,
};

/// Clipboard must remain allowed when no debugger is detected
#[test]
fn clipboard_is_allowed_when_not_debugged() {
    assert!(allow_clipboard_for_status(DebugStatus::NotDebugged));
}

/// Clipboard must be denied when a debugger is detected
#[test]
fn clipboard_is_denied_when_debugged() {
    assert!(!allow_clipboard_for_status(DebugStatus::Debugged));
}

/// Clipboard must remain allowed when debug status is unknown
#[test]
fn clipboard_is_allowed_when_debug_status_is_unknown() {
    assert!(allow_clipboard_for_status(DebugStatus::Unknown));
}

/// Plaintext export must remain allowed when no debugger is detected
#[test]
fn export_is_allowed_when_not_debugged() {
    assert!(allow_export_for_status(DebugStatus::NotDebugged));
}

/// Plaintext export must be denied when a debugger is detected
#[test]
fn export_is_denied_when_debugged() {
    assert!(!allow_export_for_status(DebugStatus::Debugged));
}

/// Plaintext export must remain allowed when debug status is unknown
#[test]
fn export_is_allowed_when_debug_status_is_unknown() {
    assert!(allow_export_for_status(DebugStatus::Unknown));
}

/// Auto-lock timeout must remain unchanged when no debugger is detected
#[test]
fn auto_lock_timeout_is_unchanged_when_not_debugged() {
    let requested = Duration::from_secs(120);

    let effective = clamp_auto_lock_timeout_for_status(DebugStatus::NotDebugged, requested);

    assert_eq!(effective, requested);
}

/// Auto-lock timeout must remain unchanged when debug status is unknown
#[test]
fn auto_lock_timeout_is_unchanged_when_debug_status_is_unknown() {
    let requested = Duration::from_secs(120);

    let effective = clamp_auto_lock_timeout_for_status(DebugStatus::Unknown, requested);

    assert_eq!(effective, requested);
}

/// Auto-lock timeout must be clamped when a debugger is detected and the
/// requested timeout exceeds the configured maximum
#[test]
fn auto_lock_timeout_is_clamped_when_debugged_and_requested_exceeds_limit() {
    let requested = Duration::from_secs(DEBUG_MAX_TIMEOUT_SECS + 120);

    let effective = clamp_auto_lock_timeout_for_status(DebugStatus::Debugged, requested);

    assert_eq!(effective, Duration::from_secs(DEBUG_MAX_TIMEOUT_SECS));
}

/// Auto-lock timeout must remain unchanged when a debugger is detected and the
/// requested timeout is already within the configured maximum
#[test]
fn auto_lock_timeout_is_preserved_when_debugged_and_requested_is_within_limit() {
    let requested = Duration::from_secs(DEBUG_MAX_TIMEOUT_SECS.saturating_sub(1));

    let effective = clamp_auto_lock_timeout_for_status(DebugStatus::Debugged, requested);

    assert_eq!(effective, requested);
}

/// Zero-duration auto-lock must remain stable under all debug states
#[test]
fn zero_timeout_is_stable_for_all_debug_states() {
    let requested = Duration::from_secs(0);

    let not_debugged = clamp_auto_lock_timeout_for_status(DebugStatus::NotDebugged, requested);
    let debugged = clamp_auto_lock_timeout_for_status(DebugStatus::Debugged, requested);
    let unknown = clamp_auto_lock_timeout_for_status(DebugStatus::Unknown, requested);

    assert_eq!(not_debugged, requested);
    assert_eq!(debugged, requested);
    assert_eq!(unknown, requested);
}

/// Policy decisions must be deterministic for repeated evaluations
#[test]
fn policy_decisions_are_deterministic_across_repeated_evaluations() {
    let statuses = [
        DebugStatus::NotDebugged,
        DebugStatus::Debugged,
        DebugStatus::Unknown,
    ];

    for status in statuses {
        let clipboard_first = allow_clipboard_for_status(status);
        let clipboard_second = allow_clipboard_for_status(status);

        let export_first = allow_export_for_status(status);
        let export_second = allow_export_for_status(status);

        let timeout_first = clamp_auto_lock_timeout_for_status(status, Duration::from_secs(300));
        let timeout_second = clamp_auto_lock_timeout_for_status(status, Duration::from_secs(300));

        assert_eq!(clipboard_first, clipboard_second);
        assert_eq!(export_first, export_second);
        assert_eq!(timeout_first, timeout_second);
    }
}

/// Clipboard policy and export policy must stay aligned for each debug state
#[test]
fn clipboard_and_export_policy_remain_aligned_per_status() {
    let statuses = [
        DebugStatus::NotDebugged,
        DebugStatus::Debugged,
        DebugStatus::Unknown,
    ];

    for status in statuses {
        assert_eq!(
            allow_clipboard_for_status(status),
            allow_export_for_status(status)
        );
    }
}
