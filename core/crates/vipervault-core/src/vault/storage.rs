// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Transactional vault storage with file locking
//!
//! # Security & Reliability
//! - Uses an exclusive file lock for writes and a shared lock for reads
//! - Writes are performed to a temporary file in the same directory, then atomically renamed
//! - Calls `sync_all()` on the temporary file and best-effort sync on the parent directory
//! - Performs best-effort cleanup of temporary files on failure
//!
//! This prevents partial writes, reduces corruption risk under crashes and mitigates concurrent access issues

use crate::vault::error::VaultStorageError;
use fs2::FileExt;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// A locked vault file handle
///
/// This is an RAII guard: the lock is released when the value is dropped
pub struct LockedFile {
    file: File,
}

impl LockedFile {
    /// Acquire a shared lock (read lock)
    pub fn lock_shared(path: &Path) -> Result<Self, VaultStorageError> {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(VaultStorageError::Io)?;

        file.lock_shared().map_err(VaultStorageError::Lock)?;
        Ok(Self { file })
    }

    /// Acquire an exclusive lock (write lock)
    ///
    /// The file is created if it does not exist
    pub fn lock_exclusive(path: &Path) -> Result<Self, VaultStorageError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(VaultStorageError::Io)?;

        file.lock_exclusive().map_err(VaultStorageError::Lock)?;
        Ok(Self { file })
    }

    /// Read the entire file into memory
    pub fn read_all(&mut self) -> Result<Vec<u8>, VaultStorageError> {
        let mut buf = Vec::new();
        self.file
            .read_to_end(&mut buf)
            .map_err(VaultStorageError::Io)?;
        Ok(buf)
    }
}

/// Read a vault file under a shared lock
///
/// # Errors
/// Returns [`VaultStorageError`] if the file cannot be opened/locked/read
pub fn read_vault_locked(path: &Path) -> Result<Vec<u8>, VaultStorageError> {
    let mut locked = LockedFile::lock_shared(path)?;
    locked.read_all()
}

/// Write bytes to disk transactionally under an exclusive lock
///
/// # Atomicity
/// Data is written to a temporary file in the same directory, synced, then renamed
///
/// # Durability
/// - `sync_all()` is called on the temporary file
/// - best-effort `sync_all()` is called on the parent directory
///
/// # Cleanup
/// On failure, the temporary file is removed on a best-effort basis
///
/// # Security
/// The temporary file is created in the same directory as the target path in order to
/// preserve atomic rename semantics on the same filesystem
pub fn write_vault_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultStorageError> {
    let dir = path.parent().ok_or(VaultStorageError::InvalidPath)?;
    fs::create_dir_all(dir).map_err(VaultStorageError::Io)?;

    let _locked = LockedFile::lock_exclusive(path)?;
    let backend = RealStorageBackend;
    write_vault_atomic_with_backend(path, bytes, &backend)
}

/// Filesystem backend used by the transactional writer
///
/// # Design
/// This abstraction exists to make failure paths testable in a deterministic way
/// without changing the public API
trait StorageBackend {
    /// Temporary file type used by the backend
    type TempFile: Write;

    /// Build a temporary file path in `dir` for the provided base name
    fn temp_path_for(&self, dir: &Path, base_name: &OsStr) -> PathBuf;

    /// Create the temporary file
    fn create_temp_file(&self, path: &Path) -> Result<Self::TempFile, VaultStorageError>;

    /// Write all bytes to the temporary file
    fn write_all(&self, file: &mut Self::TempFile, bytes: &[u8]) -> Result<(), VaultStorageError>;

    /// Sync the temporary file to disk
    fn sync_temp_file(&self, file: &Self::TempFile) -> Result<(), VaultStorageError>;

    /// Atomically move the temporary file to the final target path
    fn rename(&self, from: &Path, to: &Path) -> Result<(), VaultStorageError>;

    /// Remove a temporary file on a best-effort basis
    fn remove_file(&self, path: &Path) -> Result<(), VaultStorageError>;

    /// Sync the parent directory metadata
    fn sync_parent_dir(&self, dir: &Path) -> Result<(), VaultStorageError>;
}

/// Production filesystem backend
struct RealStorageBackend;

impl StorageBackend for RealStorageBackend {
    type TempFile = File;

    fn temp_path_for(&self, dir: &Path, base_name: &OsStr) -> PathBuf {
        temp_path_for(dir, base_name)
    }

    fn create_temp_file(&self, path: &Path) -> Result<Self::TempFile, VaultStorageError> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(VaultStorageError::Io)
    }

    fn write_all(&self, file: &mut Self::TempFile, bytes: &[u8]) -> Result<(), VaultStorageError> {
        file.write_all(bytes).map_err(VaultStorageError::Io)
    }

    fn sync_temp_file(&self, file: &Self::TempFile) -> Result<(), VaultStorageError> {
        file.sync_all().map_err(VaultStorageError::Io)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), VaultStorageError> {
        fs::rename(from, to).map_err(VaultStorageError::Io)
    }

    fn remove_file(&self, path: &Path) -> Result<(), VaultStorageError> {
        fs::remove_file(path).map_err(VaultStorageError::Io)
    }

    fn sync_parent_dir(&self, dir: &Path) -> Result<(), VaultStorageError> {
        sync_parent_dir(dir)
    }
}

/// Internal atomic writer using an injectable storage backend
///
/// # Design
/// The caller is responsible for acquiring any required file lock before calling this function
///
/// # Cleanup
/// If any step fails, best-effort cleanup of the temporary file is attempted
///
/// # Security
/// The final rename step occurs only after all bytes have been successfully written
/// and synced to the temporary file
fn write_vault_atomic_with_backend<B: StorageBackend>(
    path: &Path,
    bytes: &[u8],
    backend: &B,
) -> Result<(), VaultStorageError> {
    let dir = path.parent().ok_or(VaultStorageError::InvalidPath)?;
    let base_name = path.file_name().ok_or(VaultStorageError::InvalidPath)?;
    let tmp_path = backend.temp_path_for(dir, base_name);

    let result = (|| -> Result<(), VaultStorageError> {
        let mut tmp = backend.create_temp_file(&tmp_path)?;
        backend.write_all(&mut tmp, bytes)?;
        backend.sync_temp_file(&tmp)?;
        drop(tmp);

        backend.rename(&tmp_path, path)?;
        backend.sync_parent_dir(dir)?;

        Ok(())
    })();

    if result.is_err() {
        let _ = backend.remove_file(&tmp_path);
    }

    result
}

/// Compute a temporary file path in `dir`
fn temp_path_for(dir: &Path, base_name: &OsStr) -> PathBuf {
    let suffix = uuid::Uuid::new_v4().to_string();
    dir.join(format!(".{}.tmp.{}", base_name.to_string_lossy(), suffix))
}

/// Best-effort fsync on the directory
fn sync_parent_dir(dir: &Path) -> Result<(), VaultStorageError> {
    #[cfg(unix)]
    {
        let d = File::open(dir).map_err(VaultStorageError::Io)?;
        d.sync_all().map_err(VaultStorageError::Io)?;
    }

    #[cfg(not(unix))]
    {
        let _ = dir;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tempfile::tempdir;

    /// Failure injection points for the internal storage backend tests
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailPoint {
        CreateTempFile,
        WriteAll,
        SyncTempFile,
        Rename,
        SyncParentDir,
        RemoveFile,
    }

    /// Temporary file wrapper used by the injected backend
    struct TestTempFile {
        inner: File,
    }

    impl Write for TestTempFile {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }

        fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
            self.inner.write_all(buf)
        }
    }

    /// Real-filesystem backend with deterministic failure injection
    struct InjectedFailureBackend {
        fail_at: Vec<FailPoint>,
        cleanup_attempted: Cell<bool>,
    }

    impl InjectedFailureBackend {
        /// Construct a backend with the provided injected failure points
        fn new(fail_at: &[FailPoint]) -> Self {
            Self {
                fail_at: fail_at.to_vec(),
                cleanup_attempted: Cell::new(false),
            }
        }

        /// Return the deterministic temporary path used by the backend
        fn expected_tmp_path(&self, dir: &Path, base_name: &OsStr) -> PathBuf {
            dir.join(format!(".{}.tmp.test", base_name.to_string_lossy()))
        }

        /// Return whether best-effort cleanup was attempted
        fn cleanup_attempted(&self) -> bool {
            self.cleanup_attempted.get()
        }

        /// Return a deterministic I/O error for the selected failure point
        fn fail(&self, point: FailPoint) -> Result<(), VaultStorageError> {
            if self.fail_at.contains(&point) {
                return Err(VaultStorageError::Io(std::io::Error::other(format!(
                    "injected failure at {point:?}"
                ))));
            }

            Ok(())
        }
    }

    impl StorageBackend for InjectedFailureBackend {
        type TempFile = TestTempFile;

        fn temp_path_for(&self, dir: &Path, base_name: &OsStr) -> PathBuf {
            self.expected_tmp_path(dir, base_name)
        }

        fn create_temp_file(&self, path: &Path) -> Result<Self::TempFile, VaultStorageError> {
            self.fail(FailPoint::CreateTempFile)?;
            let inner = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(VaultStorageError::Io)?;

            Ok(TestTempFile { inner })
        }

        fn write_all(
            &self,
            file: &mut Self::TempFile,
            bytes: &[u8],
        ) -> Result<(), VaultStorageError> {
            self.fail(FailPoint::WriteAll)?;
            file.write_all(bytes).map_err(VaultStorageError::Io)
        }

        fn sync_temp_file(&self, file: &Self::TempFile) -> Result<(), VaultStorageError> {
            self.fail(FailPoint::SyncTempFile)?;
            file.inner.sync_all().map_err(VaultStorageError::Io)
        }

        fn rename(&self, from: &Path, to: &Path) -> Result<(), VaultStorageError> {
            self.fail(FailPoint::Rename)?;
            fs::rename(from, to).map_err(VaultStorageError::Io)
        }

        fn remove_file(&self, path: &Path) -> Result<(), VaultStorageError> {
            self.cleanup_attempted.set(true);
            self.fail(FailPoint::RemoveFile)?;
            fs::remove_file(path).map_err(VaultStorageError::Io)
        }

        fn sync_parent_dir(&self, dir: &Path) -> Result<(), VaultStorageError> {
            self.fail(FailPoint::SyncParentDir)?;
            super::sync_parent_dir(dir)
        }
    }

    /// Temporary file creation failure must preserve the original target bytes
    #[test]
    fn create_temp_failure_preserves_original_target() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");
        fs::write(&path, b"original").expect("seed target");

        let backend = InjectedFailureBackend::new(&[FailPoint::CreateTempFile]);
        let err = write_vault_atomic_with_backend(&path, b"replacement", &backend).unwrap_err();

        assert!(matches!(err, VaultStorageError::Io(_)));
        assert_eq!(fs::read(&path).expect("read target"), b"original");
        assert!(backend.cleanup_attempted());

        let tmp = backend.expected_tmp_path(dir.path(), OsStr::new("vault.bin"));
        assert!(!tmp.exists());
    }

    /// Temporary file write failure must preserve the original target bytes and
    /// remove the temporary file
    #[test]
    fn write_failure_preserves_original_target_and_cleans_temp_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");
        fs::write(&path, b"original").expect("seed target");

        let backend = InjectedFailureBackend::new(&[FailPoint::WriteAll]);
        let err = write_vault_atomic_with_backend(&path, b"replacement", &backend).unwrap_err();

        assert!(matches!(err, VaultStorageError::Io(_)));
        assert_eq!(fs::read(&path).expect("read target"), b"original");
        assert!(backend.cleanup_attempted());

        let tmp = backend.expected_tmp_path(dir.path(), OsStr::new("vault.bin"));
        assert!(!tmp.exists());
    }

    /// Temporary file sync failure must preserve the original target bytes and
    /// remove the temporary file
    #[test]
    fn sync_temp_failure_preserves_original_target_and_cleans_temp_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");
        fs::write(&path, b"original").expect("seed target");

        let backend = InjectedFailureBackend::new(&[FailPoint::SyncTempFile]);
        let err = write_vault_atomic_with_backend(&path, b"replacement", &backend).unwrap_err();

        assert!(matches!(err, VaultStorageError::Io(_)));
        assert_eq!(fs::read(&path).expect("read target"), b"original");
        assert!(backend.cleanup_attempted());

        let tmp = backend.expected_tmp_path(dir.path(), OsStr::new("vault.bin"));
        assert!(!tmp.exists());
    }

    /// Rename failure must preserve the original target bytes and remove the
    /// temporary file
    #[test]
    fn rename_failure_preserves_original_target_and_cleans_temp_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");
        fs::write(&path, b"original").expect("seed target");

        let backend = InjectedFailureBackend::new(&[FailPoint::Rename]);
        let err = write_vault_atomic_with_backend(&path, b"replacement", &backend).unwrap_err();

        assert!(matches!(err, VaultStorageError::Io(_)));
        assert_eq!(fs::read(&path).expect("read target"), b"original");
        assert!(backend.cleanup_attempted());

        let tmp = backend.expected_tmp_path(dir.path(), OsStr::new("vault.bin"));
        assert!(!tmp.exists());
    }

    /// Parent directory sync failure occurs after the rename step, so the target
    /// bytes may already be committed even though the function returns an error
    #[test]
    fn parent_sync_failure_returns_error_after_target_replacement() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");

        let backend = InjectedFailureBackend::new(&[FailPoint::SyncParentDir]);
        let err = write_vault_atomic_with_backend(&path, b"replacement", &backend).unwrap_err();

        assert!(matches!(err, VaultStorageError::Io(_)));
        assert_eq!(fs::read(&path).expect("read target"), b"replacement");
        assert!(backend.cleanup_attempted());

        let tmp = backend.expected_tmp_path(dir.path(), OsStr::new("vault.bin"));
        assert!(!tmp.exists());
    }

    /// Cleanup failure must not override the original write-path failure
    #[test]
    fn cleanup_failure_does_not_override_original_error() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");
        fs::write(&path, b"original").expect("seed target");

        let backend = InjectedFailureBackend::new(&[FailPoint::WriteAll, FailPoint::RemoveFile]);
        let err = write_vault_atomic_with_backend(&path, b"replacement", &backend).unwrap_err();

        assert!(matches!(err, VaultStorageError::Io(_)));
        assert!(backend.cleanup_attempted());
        assert_eq!(fs::read(&path).expect("read target"), b"original");

        let tmp = backend.expected_tmp_path(dir.path(), OsStr::new("vault.bin"));
        assert!(tmp.exists());

        let _ = fs::remove_file(tmp);
    }
}
