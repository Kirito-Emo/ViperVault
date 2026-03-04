// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Clipboard FFI bindings (platform bridge)
//!
//! # Security
//! - Minimal `extern "C"` API for mobile/desktop bridges
//! - Clipboard is an untrusted sink
//! - Secret lifetime is minimized
//! - Under anti-debug *soft policy*, clipboard operations are denied
//! - No panics are allowed to cross the FFI boundary
//! - Callbacks return `i32` error codes (`VV_OK == 0`)
//! - This allows the core to detect failures and enforce policy coherently

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
pub const VV_ERR_BACKEND: i32 = -5;
pub const VV_ERR_BOUNDS: i32 = -6;

/// Maximum clipboard bytes accepted from the host (anti-DoS bound)
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum secret length accepted via FFI (anti-DoS bound)
pub const MAX_SECRET_BYTES: usize = 64 * 1024; // 64 KiB

/// Clipboard backend vtable provided by the host platform
///
/// # Safety contract (host side)
/// - All callbacks must be thread-safe
/// - Callbacks must not panic
/// - Returned buffers must be freed via `free_buf`
/// - Return `VV_OK == 0` on success, non-zero on error
#[repr(C)]
pub struct VvClipboardVTable {
    pub set: Option<extern "C" fn(user_data: *mut c_void, value: *const u8, len: usize) -> i32>,
    pub get: Option<
        extern "C" fn(user_data: *mut c_void, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32,
    >,
    pub clear: Option<extern "C" fn(user_data: *mut c_void) -> i32>,
    pub free_buf: Option<extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize) -> i32>,
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
            let _ = f(self.user_data, value.as_ptr(), value.len());
        }
    }

    fn get(&self) -> Option<String> {
        let get = self.vtable.get?;
        let free = self.vtable.free_buf?;

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = get(self.user_data, &mut out_ptr, &mut out_len);
        if rc != VV_OK {
            return None;
        }

        struct HostBufGuard {
            user_data: *mut c_void,
            free: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize) -> i32,
            ptr: *mut u8,
            len: usize,
        }

        impl Drop for HostBufGuard {
            fn drop(&mut self) {
                if !self.ptr.is_null() {
                    let _ = (self.free)(self.user_data, self.ptr, self.len);
                }
            }
        }

        let _guard = HostBufGuard {
            user_data: self.user_data,
            free,
            ptr: out_ptr,
            len: out_len,
        };

        if out_ptr.is_null() || out_len == 0 || out_len > MAX_CLIPBOARD_BYTES {
            return None;
        }

        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
        std::str::from_utf8(bytes).ok().map(|s| s.to_owned())
    }

    fn clear(&self) {
        if let Some(f) = self.vtable.clear {
            let _ = f(self.user_data);
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
        if user_data.is_null() {
            return ptr::null_mut();
        }

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
///
/// # Safety
/// - `handle` must be either null or a pointer previously returned by `vv_clipboard_guard_new`
/// - `handle` must not be used after this call
/// - The caller must ensure no concurrent use of the same handle occurs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_clipboard_guard_free(handle: *mut VvClipboardGuardHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            // SAFETY: The caller guarantees `handle` was allocated by `Box::into_raw` and is not aliased for concurrent use
            unsafe { drop(Box::from_raw(handle)) };
        }
    }));
}

/// Cancel any pending auto-clear task
///
/// # Safety
/// - `handle` must be a non-null pointer previously returned by `vv_clipboard_guard_new`
/// - The caller must ensure no concurrent use of the same handle occurs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_clipboard_guard_cancel(handle: *mut VvClipboardGuardHandle) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return VV_ERR_NULL;
        }

        // SAFETY: The caller guarantees `handle` is valid and not concurrently used
        unsafe { &mut *handle }.inner.cancel();
        VV_OK
    }));

    res.unwrap_or(VV_ERR_PANIC)
}

/// Copy a secret to clipboard with auto-clear
///
/// # Soft policy
/// If a debugger is detected, this operation is denied
///
/// # Safety
/// - `handle` must be a non-null pointer previously returned by `vv_clipboard_guard_new`
/// - `secret_ptr` must be either null (treated as error) or point to a valid readable buffer of
///   `secret_len` bytes for the duration of this call
/// - The caller must ensure no concurrent use of the same handle occurs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_clipboard_guard_copy_with_timeout(
    handle: *mut VvClipboardGuardHandle,
    secret_ptr: *const u8,
    secret_len: usize,
    timeout_ms: u64,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || secret_ptr.is_null() {
            return VV_ERR_NULL;
        }

        if secret_len == 0 || secret_len > MAX_SECRET_BYTES {
            return VV_ERR_BOUNDS;
        }

        if !allow_clipboard_under_soft_policy() {
            return VV_ERR_DENIED;
        }

        // SAFETY: The caller guarantees `secret_ptr` is valid for `secret_len` bytes
        let bytes = unsafe { std::slice::from_raw_parts(secret_ptr, secret_len) };
        let s = match std::str::from_utf8(bytes) {
            Ok(v) => v,
            Err(_) => return VV_ERR_UTF8,
        };

        let secret = SecretString::new(s.to_owned().into());
        let timeout = Duration::from_millis(timeout_ms);

        // SAFETY: The caller guarantees `handle` is valid and not concurrently used
        unsafe { &mut *handle }
            .inner
            .copy_with_timeout(&secret, timeout);

        VV_OK
    }));

    res.unwrap_or(VV_ERR_PANIC)
}
