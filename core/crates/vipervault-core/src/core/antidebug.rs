// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Anti-debugging detection (best-effort)
//!
//! # Security
//! This module provides mitigations, not guarantees \
//! Under debugging, sensitive features are degraded through a soft policy
//!
//! # Design
//! Platform-specific detection is intentionally separated from policy decisions \
//! This allows deterministic testing of policy behavior without depending on the
//! runtime host environment

use std::time::Duration;

/// Maximum auto-lock timeout allowed under active debugging
///
/// # Security
/// A shorter timeout reduces the exposure window of decrypted state when a
/// debugger is attached
pub const DEBUG_MAX_TIMEOUT_SECS: u64 = 30;

/// Debugging detection result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugStatus {
    /// No debugger has been detected
    NotDebugged,
    /// A debugger has been detected
    Debugged,
    /// The runtime could not determine whether debugging is active
    Unknown,
}

/// Detect whether a debugger is attached (best-effort)
pub fn detect_debugging() -> DebugStatus {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        detect_debugging_linux_proc()
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return detect_debugging_apple_sysctl();
    }

    #[cfg(windows)]
    {
        return detect_debugging_windows();
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        windows
    )))]
    {
        DebugStatus::Unknown
    }
}

/// Evaluate whether clipboard operations are allowed for a given debug status
///
/// # Parameters
/// - `status`: debug detection outcome used for policy evaluation
///
/// # Returns
/// `true` when clipboard operations remain allowed under the soft policy
///
/// # Security
/// Clipboard access is denied only when active debugging is detected \
/// The `Unknown` state remains permissive in order to avoid unnecessary
/// operational denial on unsupported or partially observable platforms
pub fn allow_clipboard_for_status(status: DebugStatus) -> bool {
    !matches!(status, DebugStatus::Debugged)
}

/// Whether clipboard operations are allowed under soft policy
pub fn allow_clipboard_under_soft_policy() -> bool {
    allow_clipboard_for_status(detect_debugging())
}

/// Evaluate whether plaintext export is allowed for a given debug status
///
/// # Parameters
/// - `status`: debug detection outcome used for policy evaluation
///
/// # Returns
/// `true` when plaintext export remains allowed under the soft policy
///
/// # Security
/// Plaintext export dramatically lowers the cost of data exfiltration \
/// Under active debugging, this operation is denied
pub fn allow_export_for_status(status: DebugStatus) -> bool {
    !matches!(status, DebugStatus::Debugged)
}

/// Whether plaintext export is allowed under soft policy
///
/// # Security
/// Plaintext export dramatically lowers the cost of data exfiltration \
/// Under debugging, this operation is denied
pub fn allow_export_under_soft_policy() -> bool {
    allow_export_for_status(detect_debugging())
}

/// Clamp an auto-lock timeout for a given debug status
///
/// # Parameters
/// - `status`: debug detection outcome used for policy evaluation
/// - `requested`: requested auto-lock timeout
///
/// # Returns
/// The original timeout when no debugger is detected, otherwise the minimum
/// between the requested timeout and [`DEBUG_MAX_TIMEOUT_SECS`]
///
/// # Security
/// A debugger materially increases the risk associated with long-lived decrypted state \
/// The timeout is therefore reduced under active debugging
pub fn clamp_auto_lock_timeout_for_status(status: DebugStatus, requested: Duration) -> Duration {
    if matches!(status, DebugStatus::Debugged) {
        requested.min(Duration::from_secs(DEBUG_MAX_TIMEOUT_SECS))
    } else {
        requested
    }
}

/// Clamp auto-lock timeout when debugging is detected
pub fn clamp_auto_lock_timeout_under_soft_policy(requested: Duration) -> Duration {
    clamp_auto_lock_timeout_for_status(detect_debugging(), requested)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn detect_debugging_linux_proc() -> DebugStatus {
    use std::fs;

    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return DebugStatus::Unknown,
    };

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return match rest.trim().parse::<u32>() {
                Ok(0) => DebugStatus::NotDebugged,
                Ok(_) => DebugStatus::Debugged,
                Err(_) => DebugStatus::Unknown,
            };
        }
    }

    DebugStatus::Unknown
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn detect_debugging_apple_sysctl() -> DebugStatus {
    use libc::{c_void, getpid, size_t};

    let pid = unsafe { getpid() };
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];

    let mut info: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::kinfo_proc>() as size_t;

    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            (&mut info as *mut _).cast::<c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if rc != 0 {
        return DebugStatus::Unknown;
    }

    if (unsafe { info.kp_proc.p_flag } & libc::P_TRACED) != 0 {
        DebugStatus::Debugged
    } else {
        DebugStatus::NotDebugged
    }
}

#[cfg(windows)]
fn detect_debugging_windows() -> DebugStatus {
    #[link(name = "kernel32")]
    extern "system" {
        fn IsDebuggerPresent() -> i32;
    }

    unsafe {
        if IsDebuggerPresent() != 0 {
            DebugStatus::Debugged
        } else {
            DebugStatus::NotDebugged
        }
    }
}
