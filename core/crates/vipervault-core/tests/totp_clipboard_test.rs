// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! TOTP clipboard tests
//!
//! # Scope
//! These tests validate the secure TOTP clipboard integration:
//! - OTP generation and copy
//! - default timeout path
//! - custom timeout path
//! - auto-clear behavior when clipboard content is unchanged
//! - preservation of unrelated clipboard changes
//!
//! # Security
//! Clipboard is an untrusted sink. These tests ensure that:
//! - OTP is copied only as formatted decimal text
//! - auto-clear happens after timeout
//! - auto-clear does not erase unrelated user clipboard content
//! - timeout management remains deterministic under paused Tokio time

use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::yield_now;
use tokio::time::advance;
use vipervault_core::clipboard::guard::{ClipboardBackend, ClipboardGuard};
use vipervault_core::entries::types::{TotpAlgorithm, TotpSecret};
use vipervault_core::totp::clipboard::{
    DEFAULT_OTP_CLIPBOARD_TIMEOUT_SECS, totp_generate_and_copy_to_clipboard,
};

/// Simple in-memory clipboard backend for deterministic tests
#[derive(Clone, Default)]
struct TestClipboard {
    inner: Arc<Mutex<Option<String>>>,
}

impl TestClipboard {
    fn current(&self) -> Option<String> {
        self.inner.lock().expect("lock clipboard").clone()
    }

    fn overwrite(&self, value: &str) {
        *self.inner.lock().expect("lock clipboard") = Some(value.to_string());
    }
}

impl ClipboardBackend for TestClipboard {
    fn set(&self, value: &str) {
        *self.inner.lock().expect("lock clipboard") = Some(value.to_string());
    }

    fn get(&self) -> Option<String> {
        self.inner.lock().expect("lock clipboard").clone()
    }

    fn clear(&self) {
        *self.inner.lock().expect("lock clipboard") = None;
    }
}

fn valid_totp() -> TotpSecret {
    TotpSecret {
        issuer: Some(SecretString::new("GitHub".into())),
        account_name: Some(SecretString::new("octocat".into())),
        secret_b32: SecretString::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        digits: 6,
        period_secs: 30,
        algorithm: TotpAlgorithm::Sha1,
    }
}

/// Let spawned clipboard tasks arm their timers
async fn settle_runtime() {
    yield_now().await;
    yield_now().await;
    advance(Duration::ZERO).await;
    yield_now().await;
}

/// Copying a TOTP code must place a fixed-width decimal OTP on the clipboard
#[tokio::test(start_paused = true)]
async fn totp_copy_places_formatted_code_on_clipboard() {
    let backend = TestClipboard::default();
    let probe = backend.clone();
    let mut guard = ClipboardGuard::new(backend);

    let totp = valid_totp();

    totp_generate_and_copy_to_clipboard(
        &totp,
        1_700_000_000,
        &mut guard,
        Some(Duration::from_secs(5)),
    )
    .expect("copy totp");

    let copied = probe.current().expect("clipboard content");
    assert_eq!(copied.len(), 6);
    assert!(copied.chars().all(|c| c.is_ascii_digit()));
}

/// The custom timeout must auto-clear the clipboard if content is unchanged
#[tokio::test(start_paused = true)]
async fn totp_copy_custom_timeout_auto_clears() {
    let backend = TestClipboard::default();
    let probe = backend.clone();
    let mut guard = ClipboardGuard::new(backend);

    let totp = valid_totp();

    totp_generate_and_copy_to_clipboard(
        &totp,
        1_700_000_000,
        &mut guard,
        Some(Duration::from_secs(5)),
    )
    .expect("copy totp");

    settle_runtime().await;
    assert!(probe.current().is_some());

    advance(Duration::from_secs(5)).await;
    yield_now().await;

    assert!(probe.current().is_none());
}

/// The default timeout path must also schedule auto-clear
#[tokio::test(start_paused = true)]
async fn totp_copy_default_timeout_auto_clears() {
    let backend = TestClipboard::default();
    let probe = backend.clone();
    let mut guard = ClipboardGuard::new(backend);

    let totp = valid_totp();

    totp_generate_and_copy_to_clipboard(&totp, 1_700_000_000, &mut guard, None).expect("copy totp");

    settle_runtime().await;
    assert!(probe.current().is_some());

    advance(Duration::from_secs(DEFAULT_OTP_CLIPBOARD_TIMEOUT_SECS)).await;
    yield_now().await;

    assert!(probe.current().is_none());
}

/// Auto-clear must not erase unrelated clipboard content
///
/// # Security
/// If the user changes the clipboard before timeout, the guard must not clear that new value
#[tokio::test(start_paused = true)]
async fn totp_copy_does_not_clear_replaced_clipboard_content() {
    let backend = TestClipboard::default();
    let probe = backend.clone();
    let mut guard = ClipboardGuard::new(backend);

    let totp = valid_totp();

    totp_generate_and_copy_to_clipboard(
        &totp,
        1_700_000_000,
        &mut guard,
        Some(Duration::from_secs(5)),
    )
    .expect("copy totp");

    settle_runtime().await;
    assert!(probe.current().is_some());

    probe.overwrite("user clipboard content");

    advance(Duration::from_secs(5)).await;
    yield_now().await;

    assert_eq!(
        probe.current().expect("clipboard should remain set"),
        "user clipboard content"
    );
}

/// Re-copying before timeout must replace the old timer with a new one
///
/// # Security
/// This prevents stale timers from clearing a newer clipboard value too early
#[tokio::test(start_paused = true)]
async fn totp_copy_replaces_previous_timer() {
    let backend = TestClipboard::default();
    let probe = backend.clone();
    let mut guard = ClipboardGuard::new(backend);

    let totp = valid_totp();

    totp_generate_and_copy_to_clipboard(
        &totp,
        1_700_000_000,
        &mut guard,
        Some(Duration::from_secs(5)),
    )
    .expect("first copy");

    settle_runtime().await;
    let first = probe.current().expect("first clipboard value");

    advance(Duration::from_secs(2)).await;
    yield_now().await;

    totp_generate_and_copy_to_clipboard(
        &totp,
        1_700_000_030,
        &mut guard,
        Some(Duration::from_secs(5)),
    )
    .expect("second copy");

    settle_runtime().await;
    let second = probe.current().expect("second clipboard value");

    assert_ne!(first, second, "OTP should change across time steps");

    // Advance past the first timeout but not the second
    advance(Duration::from_secs(3)).await;
    yield_now().await;
    assert!(probe.current().is_some());

    // Advance past the second timeout
    advance(Duration::from_secs(3)).await;
    yield_now().await;
    assert!(probe.current().is_none());
}
