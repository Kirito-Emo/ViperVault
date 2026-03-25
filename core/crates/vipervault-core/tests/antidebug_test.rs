// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Anti-debug runtime-state tests
//!
//! # Scope
//! These tests validate the deterministic helper behaviour of
//! [`RuntimeInspectionState`] without depending on the host operating system
//!
//! Covered:
//! - restrictive-state classification
//! - helper method consistency
//! - current runtime probe returns a valid known state
//!
//! # Security
//! The runtime inspection layer is a signal source for policy decisions \
//! Ambiguous states must remain conservative and deterministic

use vipervault_core::core::{current_runtime_inspection_state, RuntimeInspectionState};

/// A clean runtime state must not be restrictive
#[test]
fn not_debugged_is_not_restrictive() {
    assert!(!RuntimeInspectionState::NotDebugged.is_restrictive());
    assert!(!RuntimeInspectionState::NotDebugged.is_debugged());
    assert!(!RuntimeInspectionState::NotDebugged.is_unknown());
    assert!(!RuntimeInspectionState::NotDebugged.is_tamper_suspected());
}

/// A debugged runtime state must be restrictive and classified consistently
#[test]
fn debugged_is_restrictive() {
    assert!(RuntimeInspectionState::Debugged.is_restrictive());
    assert!(RuntimeInspectionState::Debugged.is_debugged());
    assert!(!RuntimeInspectionState::Debugged.is_unknown());
    assert!(!RuntimeInspectionState::Debugged.is_tamper_suspected());
}

/// An unknown runtime state must now be treated conservatively
#[test]
fn unknown_is_restrictive() {
    assert!(RuntimeInspectionState::Unknown.is_restrictive());
    assert!(!RuntimeInspectionState::Unknown.is_debugged());
    assert!(RuntimeInspectionState::Unknown.is_unknown());
    assert!(!RuntimeInspectionState::Unknown.is_tamper_suspected());
}

/// A tamper-suspected runtime state must be strongly restrictive
#[test]
fn tamper_suspected_is_restrictive() {
    assert!(RuntimeInspectionState::TamperSuspected.is_restrictive());
    assert!(!RuntimeInspectionState::TamperSuspected.is_debugged());
    assert!(!RuntimeInspectionState::TamperSuspected.is_unknown());
    assert!(RuntimeInspectionState::TamperSuspected.is_tamper_suspected());
}

/// The live runtime inspection probe must always return one of the supported known states
#[test]
fn current_runtime_state_is_a_supported_variant() {
    let state = current_runtime_inspection_state();

    assert!(matches!(
        state,
        RuntimeInspectionState::NotDebugged
            | RuntimeInspectionState::Debugged
            | RuntimeInspectionState::Unknown
            | RuntimeInspectionState::TamperSuspected
    ));
}
