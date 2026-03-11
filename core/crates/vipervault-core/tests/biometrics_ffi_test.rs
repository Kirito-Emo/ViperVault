// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometrics FFI tests
//!
//! # Scope
//! These tests validate the platform bridge used by biometric backends:
//! - backend handle construction
//! - callback validation
//! - availability probing
//! - master key unseal result mapping
//! - host buffer freeing behavior
//!
//! # Security
//! The FFI boundary is a high-risk integration point. These tests ensure:
//! - invalid inputs are rejected safely
//! - output buffers are length-checked
//! - host buffers are always freed when returned
//! - error codes remain coarse-grained and stable

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use vipervault_core::biometrics::ffi::{
    FfiBiometricBackend, MASTER_KEY_LEN, MAX_VAULT_ID_LEN, VV_ERR_AUTH, VV_ERR_UNAVAILABLE, VV_OK,
    VvBiometricsVTable, vv_biometrics_backend_free, vv_biometrics_backend_new,
};
use vipervault_core::biometrics::{BiometricBackend, BiometricError};

/// Shared free counter used by the host-side `free_buf` callback
static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct TestHost {
    available_rc: i32,
    unseal_rc: i32,
    out_len: usize,
    fill: u8,
    return_null_ptr: bool,
}

extern "C" fn test_is_available(user_data: *mut c_void) -> i32 {
    let host = unsafe { &*(user_data as *const TestHost) };
    host.available_rc
}

extern "C" fn test_unseal_master_key(
    user_data: *mut c_void,
    _vault_id_ptr: *const u8,
    _vault_id_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let host = unsafe { &*(user_data as *const TestHost) };

    unsafe {
        *out_len = host.out_len;

        if host.return_null_ptr {
            *out_ptr = ptr::null_mut();
        } else {
            let mut buf = vec![host.fill; host.out_len].into_boxed_slice();
            let raw = buf.as_mut_ptr();
            std::mem::forget(buf);
            *out_ptr = raw;
        }
    }

    host.unseal_rc
}

extern "C" fn test_free_buf(_user_data: *mut c_void, ptr: *mut u8, len: usize) -> i32 {
    if !ptr.is_null() && len > 0 {
        let _ = unsafe { Vec::from_raw_parts(ptr, len, len) };
        FREE_CALLS.fetch_add(1, Ordering::SeqCst);
    }
    VV_OK
}

fn full_vtable() -> VvBiometricsVTable {
    VvBiometricsVTable {
        is_available: Some(test_is_available),
        unseal_master_key: Some(test_unseal_master_key),
        free_buf: Some(test_free_buf),
    }
}

/// `vv_biometrics_backend_new` must reject null user_data
#[test]
fn backend_new_rejects_null_user_data() {
    let handle = vv_biometrics_backend_new(full_vtable(), ptr::null_mut());
    assert!(handle.is_null());
}

/// `vv_biometrics_backend_new` must reject missing callbacks
#[test]
fn backend_new_rejects_missing_callbacks() {
    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x11,
        return_null_ptr: false,
    });

    let handle = vv_biometrics_backend_new(
        VvBiometricsVTable {
            is_available: Some(test_is_available),
            unseal_master_key: None,
            free_buf: Some(test_free_buf),
        },
        (&mut *host as *mut TestHost).cast(),
    );

    assert!(handle.is_null());
}

/// `vv_biometrics_backend_new` must create a valid handle when callbacks are present
#[test]
fn backend_new_accepts_valid_inputs() {
    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x22,
        return_null_ptr: false,
    });

    let handle = vv_biometrics_backend_new(full_vtable(), (&mut *host as *mut TestHost).cast());

    assert!(!handle.is_null());

    unsafe { vv_biometrics_backend_free(handle) };
}

/// Freeing a null handle must be safe
#[test]
fn backend_free_accepts_null() {
    unsafe { vv_biometrics_backend_free(ptr::null_mut()) };
}

/// `FfiBiometricBackend::new` must reject null user_data
#[test]
fn ffi_backend_new_rejects_null_user_data() {
    let res = FfiBiometricBackend::new(full_vtable(), ptr::null_mut());
    assert!(matches!(res, Err(BiometricError::InvalidResponse)));
}

/// `FfiBiometricBackend::new` must reject incomplete vtables
#[test]
fn ffi_backend_new_rejects_incomplete_vtable() {
    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x33,
        return_null_ptr: false,
    });

    let res = FfiBiometricBackend::new(
        VvBiometricsVTable {
            is_available: Some(test_is_available),
            unseal_master_key: Some(test_unseal_master_key),
            free_buf: None,
        },
        (&mut *host as *mut TestHost).cast(),
    );

    assert!(matches!(res, Err(BiometricError::InvalidResponse)));
}

/// Availability must return true only for `VV_OK`
#[test]
fn ffi_backend_is_available_maps_ok_only() {
    let mut host_ok = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x44,
        return_null_ptr: false,
    });
    let backend_ok =
        FfiBiometricBackend::new(full_vtable(), (&mut *host_ok as *mut TestHost).cast())
            .expect("backend");

    let mut host_no = Box::new(TestHost {
        available_rc: VV_ERR_UNAVAILABLE,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x55,
        return_null_ptr: false,
    });
    let backend_no =
        FfiBiometricBackend::new(full_vtable(), (&mut *host_no as *mut TestHost).cast())
            .expect("backend");

    assert!(backend_ok.is_available());
    assert!(!backend_no.is_available());
}

/// Successful unseal must return a valid 32-byte key
#[test]
fn ffi_backend_unseal_success_returns_key_material() {
    FREE_CALLS.store(0, Ordering::SeqCst);

    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x66,
        return_null_ptr: false,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let key = backend
        .unseal_master_key(b"vault-id")
        .expect("unseal master key");

    assert_eq!(key.as_bytes().len(), MASTER_KEY_LEN);
    assert_eq!(key.as_bytes().as_slice(), &[0x66; MASTER_KEY_LEN]);
    assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
}

/// Empty vault identifiers must be rejected
#[test]
fn ffi_backend_rejects_empty_vault_id() {
    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x77,
        return_null_ptr: false,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let err = backend.unseal_master_key(b"").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
}

/// Oversized vault identifiers must be rejected
#[test]
fn ffi_backend_rejects_oversized_vault_id() {
    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0x88,
        return_null_ptr: false,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let long_id = vec![0xAB; MAX_VAULT_ID_LEN + 1];
    let err = backend.unseal_master_key(&long_id).unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
}

/// `VV_ERR_UNAVAILABLE` must map to `Unavailable`
#[test]
fn ffi_backend_maps_unavailable() {
    FREE_CALLS.store(0, Ordering::SeqCst);

    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_ERR_UNAVAILABLE,
        out_len: MASTER_KEY_LEN,
        fill: 0x99,
        return_null_ptr: false,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::Unavailable));
    assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
}

/// `VV_ERR_AUTH` must map to `AuthFailed`
#[test]
fn ffi_backend_maps_auth_failed() {
    FREE_CALLS.store(0, Ordering::SeqCst);

    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_ERR_AUTH,
        out_len: MASTER_KEY_LEN,
        fill: 0xAA,
        return_null_ptr: false,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::AuthFailed));
    assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
}

/// Unknown return codes must map to `InvalidResponse`
#[test]
fn ffi_backend_maps_unknown_rc_to_invalid_response() {
    FREE_CALLS.store(0, Ordering::SeqCst);

    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: -999,
        out_len: MASTER_KEY_LEN,
        fill: 0xBB,
        return_null_ptr: false,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
    assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
}

/// `VV_OK` with null output pointer must be rejected
#[test]
fn ffi_backend_rejects_null_output_pointer_on_success() {
    FREE_CALLS.store(0, Ordering::SeqCst);

    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN,
        fill: 0xCC,
        return_null_ptr: true,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
    assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 0);
}

/// `VV_OK` with wrong output length must be rejected and freed
#[test]
fn ffi_backend_rejects_wrong_output_length_on_success() {
    FREE_CALLS.store(0, Ordering::SeqCst);

    let mut host = Box::new(TestHost {
        available_rc: VV_OK,
        unseal_rc: VV_OK,
        out_len: MASTER_KEY_LEN - 1,
        fill: 0xDD,
        return_null_ptr: false,
    });

    let backend = FfiBiometricBackend::new(full_vtable(), (&mut *host as *mut TestHost).cast())
        .expect("backend");

    let err = backend.unseal_master_key(b"vault-id").unwrap_err();
    assert!(matches!(err, BiometricError::InvalidResponse));
    assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
}
