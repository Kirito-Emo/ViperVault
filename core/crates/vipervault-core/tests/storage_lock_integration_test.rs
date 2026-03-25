// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Multi-process storage lock integration tests
//!
//! # Purpose
//! These tests verify that vault reader/writer coordination is enforced through
//! the dedicated sidecar lock file across distinct OS processes rather than only
//! within a single process
//!
//! # Security
//! A lock design that appears correct in single-process tests can still fail
//! under real multi-process contention

#![cfg(unix)]

use fs2::FileExt;
use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use vipervault_core::vault::{read_vault_locked, write_vault_atomic};

/// Environment variable carrying the lock path for the helper child process
const ENV_LOCK_PATH: &str = "VIPERVAULT_TEST_LOCK_PATH";

/// Environment variable carrying the hold duration for the helper child process
const ENV_HOLD_MILLIS: &str = "VIPERVAULT_TEST_HOLD_MILLIS";

/// Hold time used by the helper child process
const CHILD_HOLD_MILLIS: u64 = 1_200;

/// Derive the lock-file path for a vault file
///
/// # Design
/// The storage subsystem coordinates through a stable sidecar file with the
/// `.lock` suffix appended to the vault file name
fn lock_path_for(vault_path: &Path) -> PathBuf {
    let dir = vault_path.parent().expect("vault parent");
    let base = vault_path.file_name().expect("vault file name");
    dir.join(format!("{}.lock", base.to_string_lossy()))
}

/// Acquire an exclusive lock and hold it for a fixed duration
///
/// # Parameters
/// - `lock_path`: lock-file path to open/create and lock
/// - `hold_millis`: duration for which the lock is retained
fn run_child_hold_lock(lock_path: &Path, hold_millis: u64) {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .expect("open lock file");

    file.lock_exclusive().expect("exclusive lock");
    thread::sleep(Duration::from_millis(hold_millis));
}

/// Spawn a helper child process that holds the vault lock for a fixed duration
///
/// # Design
/// The helper is implemented as an ignored test executed in a separate process
/// through the Rust test harness
fn spawn_lock_holder(lock_path: &Path, hold_millis: u64) -> Child {
    let exe = env::current_exe().expect("current test binary");

    Command::new(exe)
        .arg("--exact")
        .arg("child_hold_lock_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .env(ENV_LOCK_PATH, lock_path)
        .env(ENV_HOLD_MILLIS, hold_millis.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child lock holder")
}

/// Wait until the lock file exists
///
/// # Design
/// The child creates the lock file before taking the lock \
/// This helper avoids racy assertions in the parent process
fn wait_for_lock_file(lock_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);

    while Instant::now() < deadline {
        if lock_path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }

    panic!("lock file was not created in time");
}

/// Helper child test executed in a separate process
///
/// # Design
/// This test is marked as ignored so the normal test run does not execute it \
/// The parent integration test spawns the current test binary and instructs the
/// harness to run only this helper
#[test]
#[ignore]
fn child_hold_lock_helper() {
    let lock_path = PathBuf::from(env::var(ENV_LOCK_PATH).expect("lock path env var"));
    let hold_millis: u64 = env::var(ENV_HOLD_MILLIS)
        .expect("hold millis env var")
        .parse()
        .expect("valid hold millis");

    run_child_hold_lock(&lock_path, hold_millis);
}

/// Writing must block while another process holds the exclusive lock
#[test]
fn write_blocks_until_child_releases_exclusive_lock() {
    let dir = tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.bin");
    let lock_path = lock_path_for(&vault_path);

    fs::write(&vault_path, b"original").expect("seed vault");

    let mut child = spawn_lock_holder(&lock_path, CHILD_HOLD_MILLIS);
    wait_for_lock_file(&lock_path);

    let start = Instant::now();
    write_vault_atomic(&vault_path, b"replacement").expect("write after child release");
    let elapsed = start.elapsed();

    let status = child.wait().expect("wait child");
    assert!(status.success());

    assert!(
        elapsed >= Duration::from_millis(CHILD_HOLD_MILLIS.saturating_sub(150)),
        "write returned too early: {elapsed:?}"
    );
    assert_eq!(fs::read(&vault_path).expect("read vault"), b"replacement");
}

/// Reading must block while another process holds the exclusive lock
#[test]
fn read_blocks_until_child_releases_exclusive_lock() {
    let dir = tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.bin");
    let lock_path = lock_path_for(&vault_path);

    fs::write(&vault_path, b"vault-data").expect("seed vault");

    let mut child = spawn_lock_holder(&lock_path, CHILD_HOLD_MILLIS);
    wait_for_lock_file(&lock_path);

    let start = Instant::now();
    let bytes = read_vault_locked(&vault_path).expect("read after child release");
    let elapsed = start.elapsed();

    let status = child.wait().expect("wait child");
    assert!(status.success());

    assert!(
        elapsed >= Duration::from_millis(CHILD_HOLD_MILLIS.saturating_sub(150)),
        "read returned too early: {elapsed:?}"
    );
    assert_eq!(bytes, b"vault-data");
}
