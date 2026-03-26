// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Emanuele Relmi

//! Vault entry data model
//!
//! # Security design
//! - All user-visible fields (including title and notes) are encrypted at rest
//! - Sensitive fields are wrapped in `secrecy`/`zeroize` types in memory
//! - Manual serde via internal DTOs avoids deriving serde directly on secret wrappers
//! - Entry-type invariants are enforced after construction and after deserialization
//!
//! # Important note
//! The serde DTO boundary is still a plaintext materialization point because JSON
//! deserialization necessarily constructs temporary owned strings and byte buffers \
//! This file confines that behaviour to a narrow serialization boundary, but it
//! does not eliminate it entirely

use crate::entries::error::EntryError;
use crate::entries::validate::{
    validate_note, validate_password, validate_title, validate_username,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Supported entry types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryType {
    /// Username + password entry
    Password,

    /// Secure free-form note
    SecureNote,

    /// Payment card or similar
    Card,

    /// Time-based one-time password (TOTP) secret
    Totp,
}

/// TOTP HMAC algorithm
///
/// # Security
/// TOTP generation must use constant-time HMAC implementations
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (RFC 6238 baseline; still widely supported)
    Sha1,

    /// HMAC-SHA256
    Sha256,

    /// HMAC-SHA512
    Sha512,
}

/// TOTP parameters stored inside the encrypted vault
#[derive(Debug, Clone)]
pub struct TotpSecret {
    /// Optional issuer (e.g. `"GitHub"`)
    pub issuer: Option<SecretString>,

    /// Optional account name (e.g. email or username)
    pub account_name: Option<SecretString>,

    /// Base32-encoded secret (no spaces; uppercase recommended)
    ///
    /// # Security
    /// Kept as `SecretString` and never logged
    pub secret_b32: SecretString,

    /// Output digits (typically 6 or 8)
    pub digits: u8,

    /// Period in seconds (typically 30)
    pub period_secs: u32,

    /// HMAC algorithm
    pub algorithm: TotpAlgorithm,
}

impl TotpSecret {
    /// Validate the TOTP parameters
    ///
    /// # Security
    /// This rejects obviously unsafe or ambiguous parameter sets
    pub fn validate(&self) -> Result<(), EntryError> {
        if !(self.digits == 6 || self.digits == 7 || self.digits == 8) {
            return Err(EntryError::InvalidType);
        }

        if self.period_secs < 10 || self.period_secs > 120 {
            return Err(EntryError::InvalidType);
        }

        // Minimal sanity check for base32:
        // - bounded length to avoid pathological inputs
        // - ASCII-only to avoid invisible Unicode tricks
        let s = self.secret_b32.expose_secret();
        if s.is_empty() {
            return Err(EntryError::EmptyField);
        }

        if s.len() > 1024 {
            return Err(EntryError::FieldTooLarge);
        }

        if !s.is_ascii() {
            return Err(EntryError::SuspiciousUnicode);
        }

        // Allow only RFC4648 base32 alphabet + optional '=' padding
        // Strict decoding is performed in the MFA module with constant-time decoders
        if !s
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7' | b'='))
        {
            return Err(EntryError::ForbiddenChars);
        }

        Ok(())
    }
}

/// Non-sensitive metadata required for indexing
///
/// # Security
/// This struct must not contain user-identifying or user-visible data \
/// All such data is stored encrypted in [`EntrySecret`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Stable unique identifier
    pub id: Uuid,

    /// Entry category/type
    pub entry_type: EntryType,
}

/// A minimal UI-facing entry summary (still sensitive)
///
/// # Security
/// This value is produced only after unlocking the vault and still keeps the
/// title inside a secret wrapper to reduce accidental disclosure
#[derive(Debug, Clone)]
pub struct EntrySummary {
    /// Entry identifier
    pub id: Uuid,

    /// Entry category/type
    pub entry_type: EntryType,

    /// User-visible title (sensitive)
    pub title: SecretString,
}

impl EntrySummary {
    /// Expose the title for UI display
    ///
    /// # Security
    /// Use only within trusted UI boundaries and avoid logging
    pub fn expose_title(&self) -> &str {
        self.title.expose_secret()
    }
}

/// Full decrypted view of an entry for UI consumption
///
/// # Security
/// - This struct is created only after vault unlock
/// - All sensitive fields are wrapped in secrecy/zeroize types
/// - Dropping this value wipes secrets from memory
///
/// # Note on `extra`
/// `SecretBox<T>` is intentionally not `Clone` to prevent accidental secret copying \
/// For UI consumption it returns an owned `Zeroizing<Vec<u8>>` copy when needed
#[derive(Debug)]
pub struct EntryView {
    /// Entry identifier
    pub id: Uuid,

    /// Entry category/type
    pub entry_type: EntryType,

    /// User-visible title
    pub title: SecretString,

    /// Optional note
    pub note: Option<SecretString>,

    /// Optional username
    pub username: Option<SecretString>,

    /// Primary secret
    pub secret: SecretString,

    /// Optional binary attachment/secret blob
    pub extra: Option<Zeroizing<Vec<u8>>>,

    /// Optional TOTP parameters
    pub totp: Option<TotpSecret>,
}

impl EntryView {
    /// Expose the title for UI display
    pub fn expose_title(&self) -> &str {
        self.title.expose_secret()
    }

    /// Expose the primary secret
    ///
    /// # Security
    /// Use only at trusted boundaries (e.g. clipboard, autofill)
    pub fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }
}

/// Granular update operations for existing entries
///
/// # Security
/// Updates are validated at the boundary and applied only to an unlocked vault
#[derive(Debug)]
pub enum EntryUpdate {
    /// Change title
    SetTitle(String),

    /// Change note
    SetNote(Option<String>),

    /// Change username
    SetUsername(Option<String>),

    /// Replace primary secret
    SetSecret(String),

    /// Replace extra binary blob
    SetExtra(Option<Vec<u8>>),

    /// Replace TOTP parameters
    SetTotp(Option<TotpSecret>),

    /// Replace multiple fields at once
    Replace {
        /// Optional replacement title
        title: Option<String>,

        /// Optional replacement note
        note: Option<Option<String>>,

        /// Optional replacement username
        username: Option<Option<String>>,

        /// Optional replacement primary secret
        secret: Option<String>,

        /// Optional replacement extra blob
        extra: Option<Option<Vec<u8>>>,

        /// Optional replacement TOTP block
        totp: Option<Option<TotpSecret>>,
    },
}

/// Sensitive secret data for an entry
///
/// # Security
/// - All user data is encrypted at rest
/// - All in-memory secret fields are stored in secrecy-aware wrappers (wiped on drop)
#[derive(Debug)]
pub struct EntrySecret {
    /// User-visible title
    pub title: SecretString,

    /// Optional free-form note
    pub note: Option<SecretString>,

    /// Optional username / identifier
    pub username: Option<SecretString>,

    /// Primary secret (password, token, base32 secret, etc.)
    pub secret: SecretString,

    /// Optional additional binary secret material
    pub extra: Option<SecretBox<Zeroizing<Vec<u8>>>>,

    /// Optional TOTP parameters
    pub totp: Option<TotpSecret>,
}

/// A complete vault entry
#[derive(Debug)]
pub struct VaultEntry {
    /// Public metadata
    pub meta: EntryMetadata,

    /// Encrypted-at-rest secret fields
    pub secret: EntrySecret,
}

impl VaultEntry {
    /// Create a new password entry
    ///
    /// # Validation
    /// - `title` must be bounded and free of control/bidi/invisible chars
    /// - `username` (if present) must be bounded and safe
    /// - `password` must be non-empty and bounded
    /// - `note` (if present) must be bounded and safe
    pub fn new_password(
        title: String,
        username: Option<String>,
        password: String,
        note: Option<String>,
    ) -> Result<Self, EntryError> {
        validate_title(&title)?;
        if let Some(ref n) = note {
            validate_note(n)?;
        }
        if let Some(ref u) = username {
            validate_username(u)?;
        }
        validate_password(&password)?;

        let entry = Self {
            meta: EntryMetadata {
                id: Uuid::new_v4(),
                entry_type: EntryType::Password,
            },
            secret: EntrySecret {
                title: SecretString::new(title.into()),
                note: note.map(|n| SecretString::new(n.into())),
                username: username.map(|u| SecretString::new(u.into())),
                secret: SecretString::new(password.into()),
                extra: None,
                totp: None,
            },
        };

        entry.validate_invariants()?;
        Ok(entry)
    }

    /// Create a new secure note entry
    ///
    /// # Security
    /// The secure-note content is intentionally mirrored into both `note` and
    /// `secret` for compatibility with existing flows
    pub fn new_secure_note(title: String, note: String) -> Result<Self, EntryError> {
        validate_title(&title)?;
        validate_note(&note)?;

        let note_secret = SecretString::new(note.into());

        let entry = Self {
            meta: EntryMetadata {
                id: Uuid::new_v4(),
                entry_type: EntryType::SecureNote,
            },
            secret: EntrySecret {
                title: SecretString::new(title.into()),
                note: Some(note_secret.clone()),
                username: None,
                secret: note_secret,
                extra: None,
                totp: None,
            },
        };

        entry.validate_invariants()?;
        Ok(entry)
    }

    /// Create a new TOTP entry
    ///
    /// # Design
    /// The base32 secret is stored both in `secret.secret` and inside `totp.secret_b32`
    /// to remain compatible with existing UI flows that expect a primary secret string
    ///
    /// # Security
    /// The mirrored secret is duplicated by cloning the secret wrapper instead
    /// of re-materializing a plaintext `String`
    pub fn new_totp(
        title: String,
        totp: TotpSecret,
        note: Option<String>,
    ) -> Result<Self, EntryError> {
        validate_title(&title)?;
        if let Some(ref n) = note {
            validate_note(n)?;
        }
        totp.validate()?;

        let entry = Self {
            meta: EntryMetadata {
                id: Uuid::new_v4(),
                entry_type: EntryType::Totp,
            },
            secret: EntrySecret {
                title: SecretString::new(title.into()),
                note: note.map(|n| SecretString::new(n.into())),
                username: None,
                secret: totp.secret_b32.clone(),
                extra: None,
                totp: Some(totp),
            },
        };

        entry.validate_invariants()?;
        Ok(entry)
    }

    /// Convert this entry into a UI-facing summary
    pub fn to_summary(&self) -> EntrySummary {
        EntrySummary {
            id: self.meta.id,
            entry_type: self.meta.entry_type,
            title: self.secret.title.clone(),
        }
    }

    /// Convert this entry into a UI-facing decrypted view
    ///
    /// # Security
    /// - Clones `SecretString` fields intentionally so the UI owns its copy
    /// - `extra` is copied into `Zeroizing<Vec<u8>>` and wiped on drop
    pub fn to_view(&self) -> EntryView {
        let extra_copy: Option<Zeroizing<Vec<u8>>> = self
            .secret
            .extra
            .as_ref()
            .map(|b| Zeroizing::new(b.expose_secret().as_slice().to_vec()));

        EntryView {
            id: self.meta.id,
            entry_type: self.meta.entry_type,
            title: self.secret.title.clone(),
            note: self.secret.note.clone(),
            username: self.secret.username.clone(),
            secret: self.secret.secret.clone(),
            extra: extra_copy,
            totp: self.secret.totp.clone(),
        }
    }

    /// Apply a granular update to this entry
    ///
    /// # Security
    /// Validation is enforced before mutating secrets
    pub fn apply_update(&mut self, update: EntryUpdate) -> Result<(), EntryError> {
        match update {
            EntryUpdate::SetTitle(t) => {
                validate_title(&t)?;
                self.secret.title = SecretString::new(t.into());
            }

            EntryUpdate::SetNote(n) => {
                if let Some(ref s) = n {
                    validate_note(s)?;
                }
                self.secret.note = n.map(|x| SecretString::new(x.into()));
            }

            EntryUpdate::SetUsername(u) => {
                if let Some(ref s) = u {
                    validate_username(s)?;
                }
                self.secret.username = u.map(|x| SecretString::new(x.into()));
            }

            EntryUpdate::SetSecret(s) => {
                if self.meta.entry_type == EntryType::Password {
                    validate_password(&s)?;
                    self.secret.secret = SecretString::new(s.into());
                } else if self.meta.entry_type == EntryType::Totp {
                    // Keep both fields in sync for compatibility
                    let Some(ref mut t) = self.secret.totp else {
                        return Err(EntryError::InvalidType);
                    };

                    let secret_value = SecretString::new(s.into());
                    t.secret_b32 = secret_value.clone();
                    t.validate()?;
                    self.secret.secret = secret_value;
                } else {
                    self.secret.secret = SecretString::new(s.into());
                }
            }

            EntryUpdate::SetExtra(e) => {
                self.secret.extra = e.map(|v| SecretBox::new(Box::new(Zeroizing::new(v))));
            }

            EntryUpdate::SetTotp(t) => {
                if self.meta.entry_type != EntryType::Totp {
                    return Err(EntryError::InvalidType);
                }

                if let Some(ref tsec) = t {
                    tsec.validate()?;
                    self.secret.secret = tsec.secret_b32.clone();
                }

                self.secret.totp = t;
            }

            EntryUpdate::Replace {
                title,
                note,
                username,
                secret,
                extra,
                totp,
            } => {
                if let Some(t) = title {
                    validate_title(&t)?;
                    self.secret.title = SecretString::new(t.into());
                }

                if let Some(n) = note {
                    if let Some(ref s) = n {
                        validate_note(s)?;
                    }
                    self.secret.note = n.map(|x| SecretString::new(x.into()));
                }

                if let Some(u) = username {
                    if let Some(ref s) = u {
                        validate_username(s)?;
                    }
                    self.secret.username = u.map(|x| SecretString::new(x.into()));
                }

                if let Some(s) = secret {
                    self.apply_update(EntryUpdate::SetSecret(s))?;
                }

                if let Some(e) = extra {
                    self.secret.extra = e.map(|v| SecretBox::new(Box::new(Zeroizing::new(v))));
                }

                if let Some(t) = totp {
                    self.apply_update(EntryUpdate::SetTotp(t))?;
                }
            }
        }

        self.validate_invariants()?;
        Ok(())
    }

    /// Validate type-specific invariants
    fn validate_invariants(&self) -> Result<(), EntryError> {
        match self.meta.entry_type {
            EntryType::Totp => {
                let Some(ref t) = self.secret.totp else {
                    return Err(EntryError::InvalidType);
                };
                t.validate()?;
            }
            _ => {
                if self.secret.totp.is_some() {
                    return Err(EntryError::InvalidType);
                }
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Manual serde via internal DTOs
// -----------------------------------------------------------------------------

/// Serializable DTO for [`TotpSecret`]
///
/// # Security
/// This DTO necessarily materializes plaintext strings while crossing the serde boundary \
/// The exposure is confined to serialization and deserialization only
#[derive(Debug, Serialize, Deserialize)]
struct TotpSecretDto {
    /// Optional issuer
    issuer: Option<String>,

    /// Optional account name
    account_name: Option<String>,

    /// Base32-encoded secret
    secret_b32: String,

    /// Output digits
    digits: u8,

    /// Period in seconds
    period_secs: u32,

    /// HMAC algorithm
    algorithm: TotpAlgorithm,
}

impl From<&TotpSecret> for TotpSecretDto {
    fn from(t: &TotpSecret) -> Self {
        Self {
            issuer: t.issuer.as_ref().map(|s| s.expose_secret().to_string()),
            account_name: t
                .account_name
                .as_ref()
                .map(|s| s.expose_secret().to_string()),
            secret_b32: t.secret_b32.expose_secret().to_string(),
            digits: t.digits,
            period_secs: t.period_secs,
            algorithm: t.algorithm,
        }
    }
}

impl From<TotpSecretDto> for TotpSecret {
    fn from(dto: TotpSecretDto) -> Self {
        Self {
            issuer: dto.issuer.map(|s| SecretString::new(s.into())),
            account_name: dto.account_name.map(|s| SecretString::new(s.into())),
            secret_b32: SecretString::new(dto.secret_b32.into()),
            digits: dto.digits,
            period_secs: dto.period_secs,
            algorithm: dto.algorithm,
        }
    }
}

/// Serializable DTO for [`EntrySecret`]
///
/// # Security
/// This DTO necessarily materializes plaintext strings and bytes
/// while crossing the serde boundary \
/// The copies are deliberate and confined to serialization and deserialization boundaries
#[derive(Debug, Serialize, Deserialize)]
struct EntrySecretDto {
    /// Title
    title: String,

    /// Optional note
    note: Option<String>,

    /// Optional username
    username: Option<String>,

    /// Primary secret
    secret: String,

    /// Optional binary blob
    extra: Option<Vec<u8>>,

    /// Optional TOTP block
    totp: Option<TotpSecretDto>,
}

/// Serializable DTO for [`VaultEntry`]
#[derive(Debug, Serialize, Deserialize)]
struct VaultEntryDto {
    /// Public metadata
    meta: EntryMetadata,

    /// Secret fields
    secret: EntrySecretDto,
}

impl From<&EntrySecret> for EntrySecretDto {
    fn from(s: &EntrySecret) -> Self {
        Self {
            title: s.title.expose_secret().to_string(),
            note: s.note.as_ref().map(|n| n.expose_secret().to_string()),
            username: s.username.as_ref().map(|u| u.expose_secret().to_string()),
            secret: s.secret.expose_secret().to_string(),
            extra: s
                .extra
                .as_ref()
                .map(|b| b.expose_secret().as_slice().to_vec()),
            totp: s.totp.as_ref().map(TotpSecretDto::from),
        }
    }
}

impl From<EntrySecretDto> for EntrySecret {
    fn from(dto: EntrySecretDto) -> Self {
        Self {
            title: SecretString::new(dto.title.into()),
            note: dto.note.map(|n| SecretString::new(n.into())),
            username: dto.username.map(|u| SecretString::new(u.into())),
            secret: SecretString::new(dto.secret.into()),
            extra: dto
                .extra
                .map(|v| SecretBox::new(Box::new(Zeroizing::new(v)))),
            totp: dto.totp.map(TotpSecret::from),
        }
    }
}

impl From<&VaultEntry> for VaultEntryDto {
    fn from(e: &VaultEntry) -> Self {
        Self {
            meta: e.meta.clone(),
            secret: EntrySecretDto::from(&e.secret),
        }
    }
}

impl Serialize for VaultEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        VaultEntryDto::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VaultEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let dto = VaultEntryDto::deserialize(deserializer)?;

        let entry = VaultEntry {
            meta: dto.meta,
            secret: EntrySecret::from(dto.secret),
        };

        entry
            .validate_invariants()
            .map_err(|_| serde::de::Error::custom("invalid entry invariants"))?;

        Ok(entry)
    }
}
