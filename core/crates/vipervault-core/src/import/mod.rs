// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! High-level import API
//!
//! # Two import classes
//! Signed container import for ViperVault-owned vault containers
//! Interop import (plaintext exports) for migrating from other providers
//!
//! # Security notes
//! - Signed import is the only way to import a ViperVault `.vlt` container
//! - Interop import never accepts a "vault container" plaintext mode
//! - Interop import is quarantined and requires explicit user intent

pub mod e2e_interop;
pub mod e2e_signed;
pub mod error;
pub mod interop;
pub mod signed;

pub use e2e_interop::*;
pub use e2e_signed::*;
pub use error::ImportError;
pub use interop::*;
pub use signed::*;
