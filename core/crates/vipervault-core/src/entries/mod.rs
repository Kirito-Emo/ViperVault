// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault entry model and validation logic

pub mod error;
pub mod import;
pub mod types;
pub mod validate;

pub use error::*;
pub use types::*;
pub use validate::*;
