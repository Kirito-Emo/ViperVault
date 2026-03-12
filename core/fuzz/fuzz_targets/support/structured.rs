// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Emanuele Relmi

//! Shared helpers for structure-aware fuzz targets
//!
//! # Design goals
//! - Keep generated values bounded
//! - Prefer stable ASCII-oriented inputs
//! - Generate mostly meaningful protocol-level values
//! - Preserve determinism for a fixed libFuzzer input stream

use arbitrary::{Arbitrary, Result, Unstructured};
use vipervault_core::entries::types::TotpAlgorithm;

/// Bounded ASCII display string suitable for titles and issuers
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SafeDisplay(pub String);

impl<'a> Arbitrary<'a> for SafeDisplay {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let len = u.int_in_range::<usize>(1..=24)?;
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
        let mut out = String::with_capacity(len);

        for _ in 0..len {
            let idx = u.int_in_range::<usize>(0..=alphabet.len() - 1)?;
            out.push(alphabet[idx] as char);
        }

        Ok(Self(out))
    }
}

/// Bounded ASCII account-like string
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SafeAccount(pub String);

impl<'a> Arbitrary<'a> for SafeAccount {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let len = u.int_in_range::<usize>(1..=32)?;
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@+";
        let mut out = String::with_capacity(len);

        for _ in 0..len {
            let idx = u.int_in_range::<usize>(0..=alphabet.len() - 1)?;
            out.push(alphabet[idx] as char);
        }

        Ok(Self(out))
    }
}

/// Mostly valid Base32 secret material
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Base32Secret(pub String);

impl<'a> Arbitrary<'a> for Base32Secret {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let len = u.int_in_range::<usize>(16..=64)?;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::with_capacity(len);

        for _ in 0..len {
            let idx = u.int_in_range::<usize>(0..=alphabet.len() - 1)?;
            out.push(alphabet[idx] as char);
        }

        Ok(Self(out))
    }
}

/// Small opaque byte buffer for payload material
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SmallBytes(pub Vec<u8>);

impl<'a> Arbitrary<'a> for SmallBytes {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let len = u.int_in_range::<usize>(0..=256)?;
        let bytes = u.bytes(len)?.to_vec();
        Ok(Self(bytes))
    }
}

/// Supported TOTP algorithm selector
#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum StructuredAlgorithm {
    /// SHA-1
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
}

impl StructuredAlgorithm {
    /// Convert the fuzz-side selector into the production enum
    #[allow(dead_code)]
    pub fn into_totp(self) -> TotpAlgorithm {
        match self {
            Self::Sha1 => TotpAlgorithm::Sha1,
            Self::Sha256 => TotpAlgorithm::Sha256,
            Self::Sha512 => TotpAlgorithm::Sha512,
        }
    }
}

/// Convert an arbitrary selector into a project-valid digit count
#[allow(dead_code)]
pub fn digits_from_selector(selector: u8) -> u8 {
    match selector % 3 {
        0 => 6,
        1 => 7,
        _ => 8,
    }
}

/// Convert an arbitrary selector into a project-valid TOTP period
#[allow(dead_code)]
pub fn period_from_selector(selector: u8) -> u32 {
    match selector % 7 {
        0 => 10,
        1 => 15,
        2 => 30,
        3 => 45,
        4 => 60,
        5 => 90,
        _ => 120,
    }
}

/// Fill a fixed-size array from a variable-size byte slice \
/// Missing bytes are zero-filled
#[allow(dead_code)]
pub fn fill_fixed<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];

    for (idx, byte) in src.iter().copied().enumerate().take(N) {
        out[idx] = byte;
    }

    out
}
