// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Transactional vault storage with file locking
//!
//! # Security & Reliability
//! - Coordinates readers and writers through a dedicated lock file derived from the vault path
//! - Writes are performed to a temporary file in the same directory and then
//!   atomically renamed over the target path
//! - Calls `sync_all()` on the temporary file before commit and performs a
//!   best-effort parent directory sync after rename
//! - Performs best-effort clean-up of temporary files on failure
//! - Uses restrictive file permissions on Unix-like targets for lock and temporary files
//!
//! # Design Rationale
//! Locking the vault data file directly is fragile when the final commit is
//! performed through `rename()`, because advisory locks are attached to the file
//! descriptor / inode that was originally opened \
//! A dedicated lock file keeps the synchronization object stable across
//! atomic replacement of the vault data file

use crate::vault::error::VaultStorageError;
use fs2::FileExt;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Restrictive Unix permissions used for files created by this module
///
/// # Security
/// The vault payload is encrypted, but using private file permissions still
/// reduces accidental disclosure and is the most conservative default
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// A stable advisory file lock associated with a vault path
///
/// # Design
/// This guard never locks the vault data file itself \
/// Instead, it locks a sidecar file derived from the vault path, ensuring that reader/writer
/// coordination remains valid even when the vault file is atomically replaced
pub struct VaultFileLock {
    file: File,
}

impl VaultFileLock {
    /// Acquire a shared lock for the provided vault path
    ///
    /// # Errors
    /// Returns [`VaultStorageError`] if the lock file cannot be created/opened or
    /// if the shared lock cannot be acquired
    pub fn lock_shared(vault_path: &Path) -> Result<Self, VaultStorageError> {
        let lock_path = lock_path_for(vault_path)?;
        let file = open_lock_file(&lock_path)?;
        file.lock_shared().map_err(VaultStorageError::Lock)?;
        Ok(Self { file })
    }

    /// Acquire an exclusive lock for the provided vault path
    ///
    /// # Errors
    /// Returns [`VaultStorageError`] if the lock file cannot be created/opened or
    /// if the exclusive lock cannot be acquired
    pub fn lock_exclusive(vault_path: &Path) -> Result<Self, VaultStorageError> {
        let lock_path = lock_path_for(vault_path)?;
        let file = open_lock_file(&lock_path)?;
        file.lock_exclusive().map_err(VaultStorageError::Lock)?;
        Ok(Self { file })
    }

    /// Return a reference to the locked file handle
    ///
    /// # Design
    /// The handle is intentionally not exposed mutably to avoid weakening the role
    /// of this type as a synchronization guard
    #[allow(dead_code)]
    fn file(&self) -> &File {
        &self.file
    }
}

/// Read a vault file while holding a shared lock on its dedicated lock file
///
/// # Errors
/// Returns [`VaultStorageError`] if the lock file cannot be acquired or the vault
/// file cannot be opened/read
pub fn read_vault_locked(path: &Path) -> Result<Vec<u8>, VaultStorageError> {
    let _lock = VaultFileLock::lock_shared(path)?;
    read_vault_bytes(path)
}

/// Write bytes to disk transactionally while holding an exclusive lock on the
/// dedicated lock file
///
/// # Atomicity
/// Data is written to a temporary file in the same directory, synced and then
/// atomically renamed over the target vault path
///
/// # Durability
/// - `sync_all()` is called on the temporary file before rename
/// - best-effort `sync_all()` is called on the parent directory after rename
///
/// # Clean-up
/// On failure, the temporary file is removed on a best-effort basis
///
/// # Security
/// The dedicated lock file keeps synchronization stable across `rename()`,
/// avoiding the inode-replacement hazard of locking the target file itself
pub fn write_vault_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultStorageError> {
    let dir = path.parent().ok_or(VaultStorageError::InvalidPath)?;
    fs::create_dir_all(dir).map_err(VaultStorageError::Io)?;

    let _lock = VaultFileLock::lock_exclusive(path)?;
    let backend = RealStorageBackend;
    write_vault_atomic_with_backend(path, bytes, &backend)
}

/// Read the full contents of a vault file from the beginning
///
/// # Errors
/// Returns [`VaultStorageError`] if the target cannot be opened or read
fn read_vault_bytes(path: &Path) -> Result<Vec<u8>, VaultStorageError> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(VaultStorageError::Io)?;

    file.seek(SeekFrom::Start(0))
        .map_err(VaultStorageError::Io)?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(VaultStorageError::Io)?;
    Ok(buf)
}

/// Compute the lock-file path associated with a vault path
///
/// # Format
/// For a vault path `vault.bin`, the lock path is `vault.bin.lock`
///
/// # Errors
/// Returns [`VaultStorageError::InvalidPath`] when the provided path has no file
/// name or no parent directory
fn lock_path_for(vault_path: &Path) -> Result<PathBuf, VaultStorageError> {
    let dir = vault_path.parent().ok_or(VaultStorageError::InvalidPath)?;
    let base_name = vault_path
        .file_name()
        .ok_or(VaultStorageError::InvalidPath)?;

    Ok(dir.join(format!("{}.lock", base_name.to_string_lossy())))
}

/// Open or create the dedicated lock file with restrictive defaults
///
/// # Errors
/// Returns [`VaultStorageError`] if the file cannot be opened or created
fn open_lock_file(path: &Path) -> Result<File, VaultStorageError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);

    #[cfg(unix)]
    {
        options.mode(PRIVATE_FILE_MODE);
    }

    options.open(path).map_err(VaultStorageError::Io)
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
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            options.mode(PRIVATE_FILE_MODE);
        }

        options.open(path).map_err(VaultStorageError::Io)
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
/// The caller is responsible for acquiring the dedicated vault lock before calling this function
///
/// # Clean-up
/// If any step fails, best-effort clean-up of the temporary file is attempted
///
/// # Security
/// If `sync_parent_dir()` fails after `rename()`, the new vault bytes may
/// already be visible at the target path. In that case the returned error
/// indicates uncertain directory-entry durability, not a rollback
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
///
/// # Security
/// The temporary file is always placed in the same directory as the final target
/// in order to preserve same-filesystem atomic rename semantics
fn temp_path_for(dir: &Path, base_name: &OsStr) -> PathBuf {
    let suffix = uuid::Uuid::new_v4().to_string();
    dir.join(format!(".{}.tmp.{}", base_name.to_string_lossy(), suffix))
}

/// Perform a best-effort directory sync
///
/// # Platform Notes
/// On Unix-like platforms, the directory itself is opened and synced \
/// On other targets this function degrades to a no-op because directory fsync support is
/// not portable in the standard library
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

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);

            #[cfg(unix)]
            {
                options.mode(PRIVATE_FILE_MODE);
            }

            let inner = options.open(path).map_err(VaultStorageError::Io)?;
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

    /// The lock path must be derived deterministically from the vault path
    #[test]
    fn lock_path_is_derived_from_vault_path() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");
        let lock_path = lock_path_for(&path).expect("lock path");

        assert_eq!(lock_path, dir.path().join("vault.bin.lock"));
    }

    /// Invalid lock-path inputs must be rejected, while a plain relative
    /// file name remains a valid vault path
    #[test]
    fn lock_path_rejects_invalid_paths() {
        let relative = lock_path_for(Path::new("vault.bin")).expect("relative file name is valid");
        assert_eq!(relative, PathBuf::from("vault.bin.lock"));

        let err = lock_path_for(Path::new("")).unwrap_err();
        assert!(matches!(err, VaultStorageError::InvalidPath));

        let err = lock_path_for(Path::new(".")).unwrap_err();
        assert!(matches!(err, VaultStorageError::InvalidPath));

        #[cfg(unix)]
        {
            let err = lock_path_for(Path::new("/")).unwrap_err();
            assert!(matches!(err, VaultStorageError::InvalidPath));
        }
    }

    /// Shared lock acquisition must create the lock file on demand
    #[test]
    fn shared_lock_creates_lock_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");

        let _lock = VaultFileLock::lock_shared(&path).expect("shared lock");
        assert!(dir.path().join("vault.bin.lock").exists());
    }

    /// Exclusive lock acquisition must create the lock file on demand
    #[test]
    fn exclusive_lock_creates_lock_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");

        let _lock = VaultFileLock::lock_exclusive(&path).expect("exclusive lock");
        assert!(dir.path().join("vault.bin.lock").exists());
    }

    /// Reads must begin at offset zero even if the implementation later evolves
    /// toward handle reuse
    #[test]
    fn read_vault_locked_reads_full_file_from_start() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.bin");
        fs::write(&path, b"vault-bytes").expect("seed target");

        let bytes = read_vault_locked(&path).expect("read");
        assert_eq!(bytes, b"vault-bytes");
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
