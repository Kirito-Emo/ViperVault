// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entry-related errors

use thiserror::Error;

/// Errors related to vault entry creation and CRUD operations
#[derive(Debug, Error)]
pub enum EntryError {
    #[error("field must not be empty")]
    EmptyField,

    #[error("field exceeds maximum allowed length")]
    FieldTooLarge,

    #[error("field contains forbidden characters")]
    ForbiddenChars,

    #[error("field contains potentially deceptive unicode (bidi/invisible controls)")]
    SuspiciousUnicode,

    #[error("vault is locked")]
    VaultLocked,

    #[error("entry not found")]
    EntryNotFound,

    #[error("duplicate entry id")]
    DuplicateEntry,

    #[error("reauthentication required")]
    ReauthRequired,

    #[error("operation denied by runtime policy")]
    PolicyDenied,

    #[error("invalid entry type")]
    InvalidType,

    #[error("entry contains invalid or inconsistent data")]
    InvalidData,
}
