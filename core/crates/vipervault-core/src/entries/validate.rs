// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Entry validation utilities
//!
//! # Security
//! - Enforces strict size limits to mitigate memory DoS
//! - Rejects control characters in most user-visible fields
//! - Detects potentially deceptive Unicode (bidi controls / invisible controls)
//!
//! Notes:
//! - Password fields are intentionally permissive (only bounded), to avoid weakening user password choices
//! - Titles/notes allow Unicode but reject dangerous controls used for spoofing

use crate::entries::error::EntryError;

/// Maximum lengths per field (bytes, UTF-8)
pub const MAX_TITLE_LEN: usize = 256;
pub const MAX_USERNAME_LEN: usize = 320; // typical email max is 254, allow margin
pub const MAX_NOTE_LEN: usize = 8 * 1024;
pub const MAX_PASSWORD_LEN: usize = 1024; // allow long passphrases / generated passwords

/// Validate a required title field
pub fn validate_title(title: &str) -> Result<(), EntryError> {
    validate_required_bounded(title, MAX_TITLE_LEN)?;
    reject_controls_and_bidi(title)?;
    Ok(())
}

/// Validate an optional note field
pub fn validate_note(note: &str) -> Result<(), EntryError> {
    validate_required_bounded(note, MAX_NOTE_LEN)?;
    reject_controls_and_bidi(note)?;
    Ok(())
}

/// Validate an optional username field
///
/// Usernames should not contain control characters and should be bounded
/// Unicode is allowed but bidi/invisible controls are rejected
pub fn validate_username(username: &str) -> Result<(), EntryError> {
    validate_required_bounded(username, MAX_USERNAME_LEN)?;
    reject_controls_and_bidi(username)?;
    Ok(())
}

/// Validate a password
///
/// Passwords are only bounded and must be non-empty
/// Deliberately do NOT reject characters to avoid blocking strong passwords
pub fn validate_password(password: &str) -> Result<(), EntryError> {
    validate_required_bounded(password, MAX_PASSWORD_LEN)?;
    Ok(())
}

/// Validate a required bounded string
fn validate_required_bounded(s: &str, max_len: usize) -> Result<(), EntryError> {
    if s.is_empty() {
        return Err(EntryError::EmptyField);
    }
    if s.len() > max_len {
        return Err(EntryError::FieldTooLarge);
    }
    Ok(())
}

/// Reject control characters and suspicious Unicode controls (bidi/invisible)
///
/// This mitigates display spoofing and copy/paste ambiguity in UIs
fn reject_controls_and_bidi(s: &str) -> Result<(), EntryError> {
    // Reject ASCII control chars (except common whitespace like '\n' and '\t' for notes)
    // For title/username, '\n'/'\t' are still rejected because they can break UI rendering
    for ch in s.chars() {
        if ch.is_control() {
            // Any Unicode control char is suspicious in user-visible identifiers
            return Err(EntryError::ForbiddenChars);
        }
    }

    // Reject bidi control characters and other invisible formatting characters frequently used for spoofing
    //
    // Minimal allow-/deny-list approach
    // Common bidi controls:
    // - U+202A..U+202E (LRE/RLE/PDF/LRO/RLO)
    // - U+2066..U+2069 (LRI/RLI/FSI/PDI)
    // - U+200E, U+200F (LRM/RLM)
    // - U+061C (ALM)
    //
    // Also reject zero-width joiners/spaces:
    // - U+200B..U+200D, U+FEFF
    for ch in s.chars() {
        let u = ch as u32;
        let bidi = (0x202A..=0x202E).contains(&u)
            || (0x2066..=0x2069).contains(&u)
            || u == 0x200E
            || u == 0x200F
            || u == 0x061C;

        let zero_width = (0x200B..=0x200D).contains(&u) || u == 0xFEFF;

        if bidi || zero_width {
            return Err(EntryError::SuspiciousUnicode);
        }
    }

    Ok(())
}
