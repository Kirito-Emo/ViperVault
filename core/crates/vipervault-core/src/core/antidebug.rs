// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Anti-debugging detection (best-effort)
//!
//! # Security
//! This module provides mitigations, not guarantees
//! Under debugging, sensitive features are degraded (soft policy)

use std::time::Duration;

/// Debugging detection result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugStatus {
    NotDebugged,
    Debugged,
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

/// Whether clipboard operations are allowed under soft policy
pub fn allow_clipboard_under_soft_policy() -> bool {
    !matches!(detect_debugging(), DebugStatus::Debugged)
}

/// Whether plaintext export is allowed under soft policy
///
/// # Security
/// Plaintext export dramatically lowers the cost of data exfiltration
/// Under debugging, this operation is denied
pub fn allow_export_under_soft_policy() -> bool {
    !matches!(detect_debugging(), DebugStatus::Debugged)
}

/// Clamp auto-lock timeout when debugging is detected
pub fn clamp_auto_lock_timeout_under_soft_policy(requested: Duration) -> Duration {
    const DEBUG_MAX_TIMEOUT_SECS: u64 = 30;

    if matches!(detect_debugging(), DebugStatus::Debugged) {
        requested.min(Duration::from_secs(DEBUG_MAX_TIMEOUT_SECS))
    } else {
        requested
    }
}

/* platform-specific detectors unchanged */
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
