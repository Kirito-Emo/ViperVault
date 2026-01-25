// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Clipboard FFI bindings (platform bridge)
//!
//! # Security
//! - Minimal `extern "C"` API for mobile/desktop bridges
//! - Clipboard is an untrusted sink
//! - Secret lifetime is minimized and wiped via `Zeroizing`
//! - Under anti-debug *soft policy*, clipboard operations are denied
//!
//! # ABI notes
//! - Platform provides a vtable of function pointers
//! - Strings are passed as UTF-8 `(ptr, len)`
//! - No panics are allowed to cross the FFI boundary

use crate::clipboard::guard::{ClipboardBackend, ClipboardGuard};
use crate::core::allow_clipboard_under_soft_policy;
use secrecy::SecretString;
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::time::Duration;

/// FFI error codes
pub const VV_OK: i32 = 0;
pub const VV_ERR_NULL: i32 = -1;
pub const VV_ERR_DENIED: i32 = -2;
pub const VV_ERR_UTF8: i32 = -3;
pub const VV_ERR_PANIC: i32 = -4;

/// Clipboard backend vtable provided by the host platform
///
/// # Safety contract (host side)
/// - All callbacks must be thread-safe
/// - Callbacks must not panic
/// - Returned buffers must be freed via `free_buf`
#[repr(C)]
pub struct VvClipboardVTable {
    pub set: Option<extern "C" fn(user_data: *mut c_void, value: *const u8, len: usize)>,
    pub get: Option<
        extern "C" fn(user_data: *mut c_void, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32,
    >,
    pub clear: Option<extern "C" fn(user_data: *mut c_void)>,
    pub free_buf: Option<extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize)>,
}

struct FfiClipboardBackend {
    vtable: VvClipboardVTable,
    user_data: *mut c_void,
}

unsafe impl Send for FfiClipboardBackend {}
unsafe impl Sync for FfiClipboardBackend {}

impl ClipboardBackend for FfiClipboardBackend {
    fn set(&self, value: &str) {
        if let Some(f) = self.vtable.set {
            f(self.user_data, value.as_ptr(), value.len());
        }
    }

    fn get(&self) -> Option<String> {
        let get = self.vtable.get?;
        let free = self.vtable.free_buf?;

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        if get(self.user_data, &mut out_ptr, &mut out_len) == 0 {
            return None;
        }

        if out_ptr.is_null() || out_len == 0 {
            return None;
        }

        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
        let result = std::str::from_utf8(bytes).ok().map(|s| s.to_owned());

        free(self.user_data, out_ptr, out_len);
        result
    }

    fn clear(&self) {
        if let Some(f) = self.vtable.clear {
            f(self.user_data);
        }
    }
}

/// Opaque FFI handle
#[repr(C)]
pub struct VvClipboardGuardHandle {
    inner: ClipboardGuard,
}

/// Create a new clipboard guard
#[unsafe(no_mangle)]
pub extern "C" fn vv_clipboard_guard_new(
    vtable: VvClipboardVTable,
    user_data: *mut c_void,
) -> *mut VvClipboardGuardHandle {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if vtable.set.is_none()
            || vtable.get.is_none()
            || vtable.clear.is_none()
            || vtable.free_buf.is_none()
        {
            return ptr::null_mut();
        }

        let backend = FfiClipboardBackend { vtable, user_data };
        let guard = ClipboardGuard::new(backend);

        Box::into_raw(Box::new(VvClipboardGuardHandle { inner: guard }))
    }));

    res.unwrap_or(ptr::null_mut())
}

/// Free a clipboard guard
#[unsafe(no_mangle)]
pub extern "C" fn vv_clipboard_guard_free(handle: *mut VvClipboardGuardHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            unsafe { drop(Box::from_raw(handle)) };
        }
    }));
}

/// Cancel any pending auto-clear task
#[unsafe(no_mangle)]
pub extern "C" fn vv_clipboard_guard_cancel(handle: *mut VvClipboardGuardHandle) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return VV_ERR_NULL;
        }

        unsafe { &mut *handle }.inner.cancel();
        VV_OK
    }));

    res.unwrap_or(VV_ERR_PANIC)
}

/// Copy a secret to clipboard with auto-clear
///
/// # Soft policy
/// If a debugger is detected, this operation is denied
#[unsafe(no_mangle)]
pub extern "C" fn vv_clipboard_guard_copy_with_timeout(
    handle: *mut VvClipboardGuardHandle,
    secret_ptr: *const u8,
    secret_len: usize,
    timeout_ms: u64,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || secret_ptr.is_null() {
            return VV_ERR_NULL;
        }

        if !allow_clipboard_under_soft_policy() {
            return VV_ERR_DENIED;
        }

        let bytes = unsafe { std::slice::from_raw_parts(secret_ptr, secret_len) };
        let s = match std::str::from_utf8(bytes) {
            Ok(v) => v,
            Err(_) => return VV_ERR_UTF8,
        };

        let secret = SecretString::new(s.to_owned().into());
        let timeout = Duration::from_millis(timeout_ms);

        unsafe { &mut *handle }
            .inner
            .copy_with_timeout(&secret, timeout);

        VV_OK
    }));

    res.unwrap_or(VV_ERR_PANIC)
}
