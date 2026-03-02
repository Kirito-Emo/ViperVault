// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Transactional vault storage with file locking
//!
//! # Security & Reliability
//! - Uses an exclusive file lock for writes and a shared lock for reads
//! - Writes are performed to a temporary file in the same directory, then atomically renamed
//! - Calls `sync_all()` on the file and best-effort sync on the parent directory (where supported)
//! - Best-effort cleanup of temporary files on failure
//!
//! This prevents partial writes, reduces corruption risk under crashes and mitigates concurrent access issues

use crate::vault::error::VaultStorageError;
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// A locked vault file handle
///
/// This is an RAII guard: lock is released when dropped
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
/// Returns `VaultStorageError` if the file cannot be opened/locked/read
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
/// - `sync_all()` is called on the temp file
/// - best-effort `sync_all()` is called on the parent directory (on Unix)
///
/// # Cleanup
/// On failure, the temporary file is removed on a best-effort basis
pub fn write_vault_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultStorageError> {
    // Lock the target path exclusively to serialize writers
    let _locked = LockedFile::lock_exclusive(path)?;

    let dir = path.parent().ok_or(VaultStorageError::InvalidPath)?;
    fs::create_dir_all(dir).map_err(VaultStorageError::Io)?;

    // Create temp file in the same directory to guarantee rename atomicity
    let tmp_path = temp_path_for(dir, path.file_name().unwrap_or_default());

    let result = (|| -> Result<(), VaultStorageError> {
        // Write temp
        {
            let mut tmp = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .map_err(VaultStorageError::Io)?;

            tmp.write_all(bytes).map_err(VaultStorageError::Io)?;

            // Ensure bytes are flushed to disk.
            tmp.sync_all().map_err(VaultStorageError::Io)?;
        }

        // Rename temp -> final (atomic on same filesystem)
        fs::rename(&tmp_path, path).map_err(VaultStorageError::Io)?;

        // Best-effort sync directory metadata (improves crash consistency)
        sync_parent_dir(dir)?;

        Ok(())
    })();

    if result.is_err() {
        // Best-effort cleanup of temporary file if it still exists
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

/// Compute a temporary file path in `dir`
fn temp_path_for(dir: &Path, base_name: &std::ffi::OsStr) -> PathBuf {
    // Unique name prevents collisions and avoids overwriting existing files
    let suffix = uuid::Uuid::new_v4().to_string();
    dir.join(format!(".{}.tmp.{}", base_name.to_string_lossy(), suffix))
}

/// Best-effort fsync on the directory (Unix only)
fn sync_parent_dir(dir: &Path) -> Result<(), VaultStorageError> {
    #[cfg(unix)]
    {
        let d = File::open(dir).map_err(VaultStorageError::Io)?;
        d.sync_all().map_err(VaultStorageError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir; // no-op
    }
    Ok(())
}
