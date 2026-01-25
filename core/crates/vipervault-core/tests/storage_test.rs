// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault storage tests
//!
//! # Scope
//! These tests validate the transactional and concurrency properties of the vault storage layer
//!
//! # Security & Reliability
//! - writes must be atomic
//! - concurrent writers must not corrupt data
//! - last write wins
//! - no partial or interleaved content

use std::fs;
use std::thread;
use tempfile::tempdir;
use vipervault_core::vault::{read_vault_locked, write_vault_atomic};

/// Writing then reading must roundtrip bytes exactly
#[test]
fn write_then_read_roundtrip_bytes() {
    let dir = tempdir().expect("tmp dir");
    let path = dir.path().join("vault.dat");

    let data = b"hello vault".to_vec();

    write_vault_atomic(&path, &data).expect("write");

    let read = read_vault_locked(&path).expect("read");

    assert_eq!(read, data);
}

/// Sequential writes must replace the entire file (no append)
#[test]
fn sequential_writes_replace_entire_file() {
    let dir = tempdir().expect("tmp dir");
    let path = dir.path().join("vault.dat");

    let first = b"first".to_vec();
    let second = b"second_longer".to_vec();

    write_vault_atomic(&path, &first).expect("write first");
    write_vault_atomic(&path, &second).expect("write second");

    let read = read_vault_locked(&path).expect("read");

    assert_eq!(read, second);
}

/// Concurrent writes must not corrupt the output
///
/// # Behavior
/// - writes are serialized via file locking
/// - final content must be one of the complete inputs
#[test]
fn concurrent_writes_do_not_corrupt_output() {
    let dir = tempdir().expect("tmp dir");
    let path = dir.path().join("vault.dat");

    let a = b"AAAAAA".to_vec();
    let b = b"BBBBBBBBBBBB".to_vec();

    // Clone buffers for thread ownership
    let a_thread = a.clone();
    let b_thread = b.clone();

    let path1 = path.clone();
    let path2 = path.clone();

    let t1 = thread::spawn(move || {
        write_vault_atomic(&path1, &a_thread).expect("write a");
    });

    let t2 = thread::spawn(move || {
        write_vault_atomic(&path2, &b_thread).expect("write b");
    });

    t1.join().expect("t1");
    t2.join().expect("t2");

    let final_data = fs::read(&path).expect("read final");

    assert!(
        final_data == a || final_data == b,
        "final content must be exactly one full write"
    );
}
