// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Biometrics FFI bindings (platform bridge)
//!
//! # Security
//! - No panics across FFI boundary
//! - Returned key material is bounded and validated
//! - All FFI buffers are freed by the host via `free_buf`
//!
//! # ABI
//! - Return codes follow `VV_OK == 0` convention
//! - Host allocates output buffers and must free them via `free_buf`

use super::{BiometricBackend, BiometricError};
use crate::memory::KeyMaterial;
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

pub const VV_OK: i32 = 0;
pub const VV_ERR_NULL: i32 = -1;
pub const VV_ERR_UNAVAILABLE: i32 = -2;
pub const VV_ERR_AUTH: i32 = -3;
pub const VV_ERR_BACKEND: i32 = -4;
pub const VV_ERR_BOUNDS: i32 = -5;
pub const VV_ERR_PANIC: i32 = -6;

/// Master key length in bytes
pub const MASTER_KEY_LEN: usize = 32;

/// Maximum accepted vault_id bytes (anti-DoS)
pub const MAX_VAULT_ID_LEN: usize = 128;

#[repr(C)]
pub struct VvBiometricsVTable {
    pub is_available: Option<extern "C" fn(user_data: *mut c_void) -> i32>,
    pub unseal_master_key: Option<
        extern "C" fn(
            user_data: *mut c_void,
            vault_id_ptr: *const u8,
            vault_id_len: usize,
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32,
    >,
    pub free_buf: Option<extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize) -> i32>,
}

pub struct FfiBiometricBackend {
    vtable: VvBiometricsVTable,
    user_data: *mut c_void,
}

unsafe impl Send for FfiBiometricBackend {}
unsafe impl Sync for FfiBiometricBackend {}

impl FfiBiometricBackend {
    pub fn new(vtable: VvBiometricsVTable, user_data: *mut c_void) -> Result<Self, BiometricError> {
        if user_data.is_null() {
            return Err(BiometricError::InvalidResponse);
        }

        if vtable.is_available.is_none()
            || vtable.unseal_master_key.is_none()
            || vtable.free_buf.is_none()
        {
            return Err(BiometricError::InvalidResponse);
        }

        Ok(Self { vtable, user_data })
    }
}

impl BiometricBackend for FfiBiometricBackend {
    fn is_available(&self) -> bool {
        let Some(f) = self.vtable.is_available else {
            return false;
        };
        f(self.user_data) == VV_OK
    }

    fn unseal_master_key(&self, vault_id: &[u8]) -> Result<KeyMaterial, BiometricError> {
        let unseal = self
            .vtable
            .unseal_master_key
            .ok_or(BiometricError::InvalidResponse)?;
        let free = self
            .vtable
            .free_buf
            .ok_or(BiometricError::InvalidResponse)?;

        if vault_id.is_empty() || vault_id.len() > MAX_VAULT_ID_LEN {
            return Err(BiometricError::InvalidResponse);
        }

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unseal(
            self.user_data,
            vault_id.as_ptr(),
            vault_id.len(),
            &mut out_ptr,
            &mut out_len,
        );

        // Always free if host returned a pointer
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

        match rc {
            VV_OK => {}
            VV_ERR_UNAVAILABLE => return Err(BiometricError::Unavailable),
            VV_ERR_AUTH => return Err(BiometricError::AuthFailed),
            _ => return Err(BiometricError::InvalidResponse),
        }

        if out_ptr.is_null() || out_len != MASTER_KEY_LEN {
            return Err(BiometricError::InvalidResponse);
        }

        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
        let mut arr = [0u8; MASTER_KEY_LEN];
        arr.copy_from_slice(bytes);

        Ok(KeyMaterial::new(arr))
    }
}

/// Opaque FFI handle
#[repr(C)]
pub struct VvBiometricBackendHandle {
    inner: FfiBiometricBackend,
}

#[unsafe(no_mangle)]
pub extern "C" fn vv_biometrics_backend_new(
    vtable: VvBiometricsVTable,
    user_data: *mut c_void,
) -> *mut VvBiometricBackendHandle {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let backend = FfiBiometricBackend::new(vtable, user_data).ok()?;
        Some(Box::into_raw(Box::new(VvBiometricBackendHandle {
            inner: backend,
        })))
    }));
    res.ok().flatten().unwrap_or(ptr::null_mut())
}

/// Free a biometrics backend handle
///
/// # Safety
/// - `handle` must be either null or a pointer previously returned by `vv_biometrics_backend_new`
/// - `handle` must not be used after this call
/// - The caller must ensure no concurrent use of the same handle occurs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vv_biometrics_backend_free(handle: *mut VvBiometricBackendHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            unsafe { drop(Box::from_raw(handle)) };
        }
    }));
}
