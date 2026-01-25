// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Clipboard auto-clear guard
//!
//! # Notes
//! - Clipboard is an untrusted sink
//! - Best to minimize exposure time and avoid leaving secrets in memory
//! - This module avoids keeping non-zeroized secret copies alive across async boundaries

use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use zeroize::Zeroizing;

/// Trait implemented by platform clipboard backends
///
/// # Security
/// - Implementations must avoid logging clipboard data
/// - Implementations should avoid additional internal caching when possible
pub trait ClipboardBackend: Send + Sync + 'static {
    /// Set clipboard contents
    fn set(&self, value: &str);

    /// Get clipboard contents
    ///
    /// # Security
    /// - Returned value is treated as untrusted and is used only for equality checks
    fn get(&self) -> Option<String>;

    /// Clear clipboard
    fn clear(&self);
}

/// RAII guard that clears the clipboard after a timeout
///
/// # Design
/// - Uses `Arc` to safely share the backend with async tasks
/// - Cancels previous clear task when a new copy occurs
/// - Clears clipboard only if content is unchanged
///
/// # Security
/// - The secret copy kept for comparison lives in a `Zeroizing<String>`
///   inside the async task and is wiped when the task ends (successfully or aborted)
pub struct ClipboardGuard {
    backend: Arc<dyn ClipboardBackend>,
    task: Option<JoinHandle<()>>,
}

impl ClipboardGuard {
    /// Create a new clipboard guard
    pub fn new<B>(backend: B) -> Self
    where
        B: ClipboardBackend,
    {
        Self {
            backend: Arc::new(backend),
            task: None,
        }
    }

    /// Copy a secret to clipboard and schedule auto-clear
    ///
    /// # Security
    /// - Secret is exposed only at the final boundary (clipboard write)
    /// - Clipboard is cleared after `timeout`
    /// - Clear happens only if clipboard still matches the secret
    /// - Any in-memory copy held for the timeout is wiped via `Zeroizing<String>`
    pub fn copy_with_timeout(&mut self, secret: &SecretString, timeout: Duration) {
        // A single owned copy used both for immediate set and later comparison and it is wiped once dropped
        let value: Zeroizing<String> = Zeroizing::new(secret.expose_secret().to_string());

        // Write to clipboard immediately
        self.backend.set(value.as_str());

        // Cancel previous task if any
        if let Some(task) = self.task.take() {
            task.abort();
        }

        let backend = Arc::clone(&self.backend);

        self.task = Some(tokio::spawn(async move {
            sleep(timeout).await;

            // Read current clipboard content only to verify it still matches
            // Wrap in Zeroizing so this temporary copy is wiped quickly
            let current: Option<Zeroizing<String>> = backend.get().map(Zeroizing::new);

            if let Some(cur) = current {
                if *cur == *value {
                    backend.clear();
                }
                // `cur` wiped here
            }
            // `value` wiped here
        }));
    }

    /// Cancel any pending auto-clear task
    ///
    /// # Security
    /// Aborting the task drops the future and wipes the secret copy held inside it
    pub fn cancel(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for ClipboardGuard {
    /// Ensure pending tasks are aborted on drop
    ///
    /// # Security
    /// We only abort the task: we do NOT clear the clipboard on drop to avoid
    /// overwriting user clipboard content unexpectedly
    fn drop(&mut self) {
        self.cancel();
    }
}
