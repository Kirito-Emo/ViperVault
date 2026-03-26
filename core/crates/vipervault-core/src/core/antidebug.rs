// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Best-effort runtime inspection and anti-debug signals
//!
//! # Security
//! This module does not provide a cryptographic or kernel-enforced security boundary \
//! Instead, it offers best-effort runtime signals that higher-level
//! policy code can use to degrade, deny or tighten sensitive operations
//!
//! # Design
//! - Keep platform probing isolated from product policy decisions
//! - Expose a conservative state model suitable for mobile-first hardening
//! - Avoid treating ambiguous runtime states as fully trusted
//!
//! # Important limitation
//! A determined attacker with device-level control may still bypass or tamper with these checks \
//! This module must therefore be treated as a signal source, not as a complete defence

/// Best-effort runtime inspection state
///
/// # Security
/// This state is conservative:
/// - [`Self::NotDebugged`] means no debugger/tamper signal was observed
/// - [`Self::Debugged`] means an active debugger signal was observed
/// - [`Self::Unknown`] means the runtime could not be classified confidently
/// - [`Self::TamperSuspected`] is reserved for stronger integrity concerns and
///   should be treated as the most restrictive state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeInspectionState {
    /// No debugger or tamper signal has been detected
    NotDebugged,

    /// A debugger has been detected
    Debugged,

    /// The runtime could not be classified with sufficient confidence
    Unknown,

    /// A stronger integrity anomaly or tamper signal was observed
    TamperSuspected,
}

impl RuntimeInspectionState {
    /// Return `true` when the runtime state should be treated as restrictive
    ///
    /// # Security
    /// This helper classifies both [`Self::Unknown`] and [`Self::TamperSuspected`] as restrictive
    pub fn is_restrictive(self) -> bool {
        !matches!(self, Self::NotDebugged)
    }

    /// Return `true` when a debugger was observed
    pub fn is_debugged(self) -> bool {
        matches!(self, Self::Debugged)
    }

    /// Return `true` when the runtime classification is ambiguous
    pub fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Return `true` when a stronger tamper signal was observed
    pub fn is_tamper_suspected(self) -> bool {
        matches!(self, Self::TamperSuspected)
    }
}

/// Detect the current runtime inspection state
///
/// # Security
/// This function is best-effort. It should be used only as an
/// input to higher-level policy, never as a standalone guarantee
///
/// # Platform behaviour
/// - On supported Unix-like targets, debugger presence is checked through
///   platform-specific probing
/// - Unsupported or ambiguous outcomes degrade to [`RuntimeInspectionState::Unknown`]
pub fn current_runtime_inspection_state() -> RuntimeInspectionState {
    detect_runtime_inspection_state()
}

/// Best-effort runtime inspection probe implementation
fn detect_runtime_inspection_state() -> RuntimeInspectionState {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        return detect_linux_like_runtime_state();
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        return detect_apple_runtime_state();
    }

    #[allow(unreachable_code)]
    RuntimeInspectionState::Unknown
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn detect_linux_like_runtime_state() -> RuntimeInspectionState {
    use std::fs;

    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return RuntimeInspectionState::Unknown;
    };

    let tracer_pid_line = status.lines().find(|line| line.starts_with("TracerPid:"));
    let Some(line) = tracer_pid_line else {
        return RuntimeInspectionState::Unknown;
    };

    let value = line
        .split_once(':')
        .map(|(_, rhs)| rhs.trim())
        .unwrap_or_default();

    match value.parse::<u32>() {
        Ok(0) => RuntimeInspectionState::NotDebugged,
        Ok(_) => RuntimeInspectionState::Debugged,
        Err(_) => RuntimeInspectionState::Unknown,
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn detect_apple_runtime_state() -> RuntimeInspectionState {
    use libc::{
        CTL_KERN, KERN_PROC, KERN_PROC_PID, P_TRACED, c_void, getpid, kinfo_proc, size_t, sysctl,
    };
    use std::mem::{MaybeUninit, size_of};
    use std::ptr;

    let mut info = MaybeUninit::<kinfo_proc>::zeroed();
    let mut size = size_of::<kinfo_proc>() as size_t;
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, unsafe { getpid() }];

    // SAFETY:
    // - `mib` points to a valid MIB array of length 4
    // - `info` points to writable memory of size `size`
    // - no output name buffer is requested
    let rc = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            info.as_mut_ptr().cast::<c_void>(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };

    if rc != 0 || size < size_of::<kinfo_proc>() as size_t {
        return RuntimeInspectionState::Unknown;
    }

    // SAFETY:
    // `sysctl` succeeded and wrote a full `kinfo_proc`
    let info = unsafe { info.assume_init() };

    if (info.kp_proc.p_flag & P_TRACED) != 0 {
        RuntimeInspectionState::Debugged
    } else {
        RuntimeInspectionState::NotDebugged
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeInspectionState;

    /// Restrictive-state classification must be conservative
    #[test]
    fn restrictive_state_classification_is_conservative() {
        assert!(!RuntimeInspectionState::NotDebugged.is_restrictive());
        assert!(RuntimeInspectionState::Debugged.is_restrictive());
        assert!(RuntimeInspectionState::Unknown.is_restrictive());
        assert!(RuntimeInspectionState::TamperSuspected.is_restrictive());
    }

    /// Convenience helpers must classify states correctly
    #[test]
    fn state_helper_methods_match_variants() {
        assert!(RuntimeInspectionState::Debugged.is_debugged());
        assert!(RuntimeInspectionState::Unknown.is_unknown());
        assert!(RuntimeInspectionState::TamperSuspected.is_tamper_suspected());
        assert!(!RuntimeInspectionState::NotDebugged.is_debugged());
    }
}
