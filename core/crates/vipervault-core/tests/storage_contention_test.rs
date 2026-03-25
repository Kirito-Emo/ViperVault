// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Intra-process storage contention tests
//!
//! # Security
//! The storage layer must serialize readers and writers through the sidecar lock file \
//! These tests verify that the public storage APIs block until the conflicting lock is released

#![cfg(unix)]

use fs2::FileExt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use vipervault_core::vault::{read_vault_locked, write_vault_atomic};

/// Minimum delay expected while a competing lock is held
///
/// # Design
/// A small tolerance is kept to reduce false negatives due to scheduler jitter
const EXPECTED_BLOCK_MILLIS: u64 = 600;

/// Hold duration used by the lock-holding thread
const HOLD_MILLIS: u64 = 750;

/// Derive the lock-file path associated with a vault file
fn lock_path_for(vault_path: &Path) -> PathBuf {
    let dir = vault_path.parent().expect("vault parent");
    let base = vault_path.file_name().expect("vault file name");
    dir.join(format!("{}.lock", base.to_string_lossy()))
}

/// Open or create the lock file used by the storage subsystem
fn open_lock_file(lock_path: &Path) -> std::fs::File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .expect("open lock file")
}

/// A writer must block while another thread holds a shared lock
///
/// # Security
/// Shared locks must prevent concurrent writers from committing a new vault
/// file while a reader is still inside its critical section
#[test]
fn writer_blocks_while_shared_lock_is_held() {
    let dir = tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.bin");
    let lock_path = lock_path_for(&vault_path);
    fs::write(&vault_path, b"original").expect("seed vault");

    let lock_file = open_lock_file(&lock_path);
    lock_file.lock_shared().expect("shared lock");

    let (started_tx, started_rx) = mpsc::channel();
    let path_for_thread = vault_path.clone();

    let handle = thread::spawn(move || {
        started_tx.send(()).expect("signal start");
        let start = Instant::now();
        write_vault_atomic(&path_for_thread, b"replacement").expect("write vault");
        start.elapsed()
    });

    started_rx.recv().expect("thread started");
    thread::sleep(Duration::from_millis(HOLD_MILLIS));
    lock_file.unlock().expect("unlock shared");

    let elapsed = handle.join().expect("join writer thread");
    assert!(
        elapsed >= Duration::from_millis(EXPECTED_BLOCK_MILLIS),
        "writer returned too early: {elapsed:?}"
    );
    assert_eq!(fs::read(&vault_path).expect("read vault"), b"replacement");
}

/// A reader must block while another thread holds an exclusive lock
///
/// # Security
/// Exclusive locks must prevent readers from observing the vault file before
/// the conflicting writer-critical section has completed
#[test]
fn reader_blocks_while_exclusive_lock_is_held() {
    let dir = tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.bin");
    let lock_path = lock_path_for(&vault_path);
    fs::write(&vault_path, b"vault-data").expect("seed vault");

    let lock_file = open_lock_file(&lock_path);
    lock_file.lock_exclusive().expect("exclusive lock");

    let (started_tx, started_rx) = mpsc::channel();
    let path_for_thread = vault_path.clone();

    let handle = thread::spawn(move || {
        started_tx.send(()).expect("signal start");
        let start = Instant::now();
        let bytes = read_vault_locked(&path_for_thread).expect("read vault");
        (start.elapsed(), bytes)
    });

    started_rx.recv().expect("thread started");
    thread::sleep(Duration::from_millis(HOLD_MILLIS));
    lock_file.unlock().expect("unlock exclusive");

    let (elapsed, bytes) = handle.join().expect("join reader thread");
    assert!(
        elapsed >= Duration::from_millis(EXPECTED_BLOCK_MILLIS),
        "reader returned too early: {elapsed:?}"
    );
    assert_eq!(bytes, b"vault-data");
}

/// Two writers must serialize rather than overlap
///
/// # Security
/// Competing writes must commit one after the other under the exclusive
/// sidecar lock, never concurrently
#[test]
fn writers_are_serialized() {
    let dir = tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.bin");
    let lock_path = lock_path_for(&vault_path);
    fs::write(&vault_path, b"initial").expect("seed vault");

    let lock_file = open_lock_file(&lock_path);
    lock_file.lock_exclusive().expect("exclusive lock");

    let (first_started_tx, first_started_rx) = mpsc::channel();
    let (second_started_tx, second_started_rx) = mpsc::channel();

    let first_path = vault_path.clone();
    let first = thread::spawn(move || {
        first_started_tx.send(()).expect("signal first start");
        let start = Instant::now();
        write_vault_atomic(&first_path, b"first").expect("first write");
        start.elapsed()
    });

    let second_path = vault_path.clone();
    let second = thread::spawn(move || {
        second_started_tx.send(()).expect("signal second start");
        let start = Instant::now();
        write_vault_atomic(&second_path, b"second").expect("second write");
        start.elapsed()
    });

    first_started_rx.recv().expect("first thread started");
    second_started_rx.recv().expect("second thread started");

    thread::sleep(Duration::from_millis(HOLD_MILLIS));
    lock_file.unlock().expect("unlock exclusive");

    let first_elapsed = first.join().expect("join first writer");
    let second_elapsed = second.join().expect("join second writer");

    assert!(
        first_elapsed >= Duration::from_millis(EXPECTED_BLOCK_MILLIS),
        "first writer returned too early: {first_elapsed:?}"
    );
    assert!(
        second_elapsed >= Duration::from_millis(EXPECTED_BLOCK_MILLIS),
        "second writer returned too early: {second_elapsed:?}"
    );

    let final_bytes = fs::read(&vault_path).expect("read final vault");
    assert!(
        final_bytes == b"first" || final_bytes == b"second",
        "unexpected final vault bytes: {final_bytes:?}"
    );
}
