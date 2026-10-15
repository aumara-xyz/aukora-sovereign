// SPDX-License-Identifier: AGPL-3.0-or-later
//! Nostr identities and authenticated messages. No transport or secret export.

pub mod event;
pub mod keys;
pub mod nip44;
pub mod nip59;
pub mod schnorr;

pub use keys::{npub_decode, npub_encode, SecretKey};
pub use schnorr::verify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);

impl Error {
    pub const fn code(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

pub fn hex_decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2 {
        return Err(Error("nostr:hex-length"));
    }
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |value| match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(Error("nostr:hex-invalid")),
        };
        *byte = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
