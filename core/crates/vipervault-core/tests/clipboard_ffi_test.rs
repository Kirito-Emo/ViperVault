// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Clipboard FFI tests
//!
//! # Scope
//! These tests validate the low-level clipboard bridge exposed through
//! `clipboard::ffi`:
//! - handle construction and destruction
//! - input validation and anti-DoS bounds
//! - UTF-8 rejection at the FFI boundary
//! - host buffer free behaviour
//! - auto-clear behaviour under paused Tokio time
//!
//! # Security
//! The clipboard bridge is a high-risk integration boundary because it accepts
//! raw pointers, host callbacks and asynchronous timeout scheduling \
//! These tests focus on rejecting invalid host behaviour safely and on preserving
//! the intended secret-lifetime semantics

use std::ffi::c_void;
use std::ptr;
use tokio::task::yield_now;
use tokio::time::advance;
use vipervault_core::clipboard::ffi::{
    MAX_CLIPBOARD_BYTES, MAX_SECRET_BYTES, VV_ERR_BOUNDS, VV_ERR_NULL, VV_ERR_UTF8, VV_OK,
    VvClipboardVTable, vv_clipboard_guard_cancel, vv_clipboard_guard_copy_with_timeout,
    vv_clipboard_guard_free, vv_clipboard_guard_new,
};

#[repr(C)]
struct TestHost {
    value: Option<Vec<u8>>,
    get_rc: i32,
    set_calls: usize,
    clear_calls: usize,
    free_calls: usize,
}

extern "C" fn test_set(user_data: *mut c_void, value: *const u8, len: usize) -> i32 {
    let host = unsafe { &mut *(user_data as *mut TestHost) };

    if value.is_null() || len == 0 {
        host.value = None;
        host.set_calls += 1;
        return VV_OK;
    }

    let bytes = unsafe { std::slice::from_raw_parts(value, len) };
    host.value = Some(bytes.to_vec());
    host.set_calls += 1;
    VV_OK
}

extern "C" fn test_get(user_data: *mut c_void, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    let host = unsafe { &mut *(user_data as *mut TestHost) };

    if host.get_rc != VV_OK {
        unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        }
        return host.get_rc;
    }

    match host.value.clone() {
        Some(bytes) => {
            let mut boxed = bytes.into_boxed_slice();
            let raw = boxed.as_mut_ptr();
            let len = boxed.len();
            std::mem::forget(boxed);
            unsafe {
                *out_ptr = raw;
                *out_len = len;
            }
        }
        None => unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        },
    }

    VV_OK
}

extern "C" fn test_clear(user_data: *mut c_void) -> i32 {
    let host = unsafe { &mut *(user_data as *mut TestHost) };
    host.value = None;
    host.clear_calls += 1;
    VV_OK
}

extern "C" fn test_free_buf(user_data: *mut c_void, ptr: *mut u8, len: usize) -> i32 {
    let host = unsafe { &mut *(user_data as *mut TestHost) };

    if !ptr.is_null() && len > 0 {
        let _ = unsafe { Vec::from_raw_parts(ptr, len, len) };
        host.free_calls += 1;
    }

    VV_OK
}

fn full_vtable() -> VvClipboardVTable {
    VvClipboardVTable {
        set: Some(test_set),
        get: Some(test_get),
        clear: Some(test_clear),
        free_buf: Some(test_free_buf),
    }
}

async fn settle_runtime() {
    yield_now().await;
    yield_now().await;
    advance(std::time::Duration::ZERO).await;
    yield_now().await;
}

/// `vv_clipboard_guard_new` must reject null `user_data`
#[test]
fn clipboard_guard_new_rejects_null_user_data() {
    let handle = vv_clipboard_guard_new(full_vtable(), ptr::null_mut());
    assert!(handle.is_null());
}

/// `vv_clipboard_guard_new` must reject incomplete callback tables
#[test]
fn clipboard_guard_new_rejects_missing_callbacks() {
    let mut host = Box::new(TestHost {
        value: None,
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });

    let handle = vv_clipboard_guard_new(
        VvClipboardVTable {
            set: Some(test_set),
            get: Some(test_get),
            clear: Some(test_clear),
            free_buf: None,
        },
        (&mut *host as *mut TestHost).cast(),
    );

    assert!(handle.is_null());
}

/// Copy must reject null handles and null secret pointers
#[test]
fn copy_with_timeout_rejects_null_inputs() {
    let secret = b"secret";

    let rc_null_handle = unsafe {
        vv_clipboard_guard_copy_with_timeout(ptr::null_mut(), secret.as_ptr(), secret.len(), 1000)
    };
    assert_eq!(rc_null_handle, VV_ERR_NULL);

    let mut host = Box::new(TestHost {
        value: None,
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });
    let handle = vv_clipboard_guard_new(full_vtable(), (&mut *host as *mut TestHost).cast());
    assert!(!handle.is_null());

    let rc_null_secret = unsafe { vv_clipboard_guard_copy_with_timeout(handle, ptr::null(), 4, 0) };
    assert_eq!(rc_null_secret, VV_ERR_NULL);

    unsafe { vv_clipboard_guard_free(handle) };
}

/// Copy must reject zero-length and oversized inputs at the FFI boundary
#[test]
fn copy_with_timeout_enforces_secret_bounds() {
    let mut host = Box::new(TestHost {
        value: None,
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });
    let handle = vv_clipboard_guard_new(full_vtable(), (&mut *host as *mut TestHost).cast());
    assert!(!handle.is_null());

    let rc_empty = unsafe { vv_clipboard_guard_copy_with_timeout(handle, b"x".as_ptr(), 0, 100) };
    assert_eq!(rc_empty, VV_ERR_BOUNDS);

    let oversized = vec![b'A'; MAX_SECRET_BYTES + 1];
    let rc_oversized = unsafe {
        vv_clipboard_guard_copy_with_timeout(handle, oversized.as_ptr(), oversized.len(), 100)
    };
    assert_eq!(rc_oversized, VV_ERR_BOUNDS);

    unsafe { vv_clipboard_guard_free(handle) };
}

/// Copy must reject non-UTF-8 input instead of forwarding it into the host backend
#[test]
fn copy_with_timeout_rejects_non_utf8_secret() {
    let mut host = Box::new(TestHost {
        value: None,
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });
    let handle = vv_clipboard_guard_new(full_vtable(), (&mut *host as *mut TestHost).cast());
    assert!(!handle.is_null());

    let invalid = [0xFFu8, 0xFEu8, 0xFDu8];
    let rc = unsafe {
        vv_clipboard_guard_copy_with_timeout(handle, invalid.as_ptr(), invalid.len(), 100)
    };
    assert_eq!(rc, VV_ERR_UTF8);
    assert_eq!(host.set_calls, 0, "backend must not receive invalid UTF-8");

    unsafe { vv_clipboard_guard_free(handle) };
}

/// Host-provided clipboard bytes must be released through `free_buf`
#[test]
fn host_get_buffer_is_freed() {
    let mut host = Box::new(TestHost {
        value: Some(b"secret".to_vec()),
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });
    let handle = vv_clipboard_guard_new(full_vtable(), (&mut *host as *mut TestHost).cast());
    assert!(!handle.is_null());

    let rc = unsafe { vv_clipboard_guard_cancel(handle) };
    assert_eq!(rc, VV_OK);

    let mut out_ptr: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let get = full_vtable().get.expect("get callback");
    let rc = get(
        (&mut *host as *mut TestHost).cast(),
        &mut out_ptr,
        &mut out_len,
    );
    assert_eq!(rc, VV_OK);
    assert!(!out_ptr.is_null());
    assert_eq!(out_len, 6);

    test_free_buf((&mut *host as *mut TestHost).cast(), out_ptr, out_len);
    assert_eq!(host.free_calls, 1);

    unsafe { vv_clipboard_guard_free(handle) };
}

/// A successful copy must write the secret and later clear it when the timeout expires
#[tokio::test(start_paused = true)]
async fn copy_with_timeout_sets_and_auto_clears_clipboard() {
    let mut host = Box::new(TestHost {
        value: None,
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });
    let handle = vv_clipboard_guard_new(full_vtable(), (&mut *host as *mut TestHost).cast());
    assert!(!handle.is_null());

    let secret = b"top-secret";
    let rc = unsafe {
        vv_clipboard_guard_copy_with_timeout(handle, secret.as_ptr(), secret.len(), 5000)
    };
    assert_eq!(rc, VV_OK);
    assert_eq!(host.value.as_deref(), Some(secret.as_slice()));
    assert_eq!(host.set_calls, 1);

    settle_runtime().await;
    advance(std::time::Duration::from_secs(5)).await;
    yield_now().await;

    assert!(
        host.value.is_none(),
        "clipboard must be cleared after timeout"
    );
    assert_eq!(host.clear_calls, 1);

    unsafe { vv_clipboard_guard_free(handle) };
}

/// Auto-clear must not erase a newer clipboard value written by the user
#[tokio::test(start_paused = true)]
async fn copy_with_timeout_preserves_replaced_clipboard_content() {
    let mut host = Box::new(TestHost {
        value: None,
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });
    let handle = vv_clipboard_guard_new(full_vtable(), (&mut *host as *mut TestHost).cast());
    assert!(!handle.is_null());

    let secret = b"otp-code";
    let rc = unsafe {
        vv_clipboard_guard_copy_with_timeout(handle, secret.as_ptr(), secret.len(), 5000)
    };
    assert_eq!(rc, VV_OK);

    settle_runtime().await;
    host.value = Some(b"user clipboard".to_vec());

    advance(std::time::Duration::from_secs(5)).await;
    yield_now().await;

    assert_eq!(host.value.as_deref(), Some(&b"user clipboard"[..]));
    assert_eq!(host.clear_calls, 0);

    unsafe { vv_clipboard_guard_free(handle) };
}

/// Oversized host-returned clipboard content must remain bounded and must still be freed
#[test]
fn oversized_host_clipboard_buffer_is_bounded_and_freed() {
    let mut host = Box::new(TestHost {
        value: Some(vec![b'Z'; MAX_CLIPBOARD_BYTES + 1]),
        get_rc: VV_OK,
        set_calls: 0,
        clear_calls: 0,
        free_calls: 0,
    });

    let get = full_vtable().get.expect("get callback");
    let mut out_ptr: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let rc = get(
        (&mut *host as *mut TestHost).cast(),
        &mut out_ptr,
        &mut out_len,
    );
    assert_eq!(rc, VV_OK);
    assert_eq!(out_len, MAX_CLIPBOARD_BYTES + 1);
    assert!(!out_ptr.is_null());

    test_free_buf((&mut *host as *mut TestHost).cast(), out_ptr, out_len);
    assert_eq!(host.free_calls, 1);
}
