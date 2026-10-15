// SPDX-License-Identifier: AGPL-3.0-or-later
//! Origin labels assigned by trusted ingress, never upgraded by content claims.

use crate::{alg::AlgorithmId, ids::AppId, Result};

/// A bounded Nostr public-key address, carrying its algorithm as key formats do.
/// Decoding verifies the `npub` representation; it does not approve a contact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Npub {
    algorithm: AlgorithmId,
    encoded: String,
}

impl Npub {
    /// Encode 32 public-key bytes as canonical lowercase NIP-19 Bech32, tagged
    /// `Secp256k1Schnorr`. This checks representation by construction, not curve
    /// membership, contact approval or owner authority.
    pub fn from_key_bytes(bytes: [u8; 32]) -> Self {
        const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let mut encoded = String::with_capacity(63);
        encoded.push_str("npub1");
        let mut checksum = 1;
        for part in b"npub"
            .iter()
            .map(|byte| byte >> 5)
            .chain([0])
            .chain(b"npub".iter().map(|byte| byte & 31))
        {
            checksum = npub_checksum_step(checksum, part);
        }
        let mut pending = 0_u16;
        let mut bits = 0_u8;
        for byte in bytes {
            pending = (pending << 8) | u16::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let part = ((pending >> bits) & 31) as u8;
                encoded.push(char::from(CHARSET[usize::from(part)]));
                checksum = npub_checksum_step(checksum, part);
            }
            pending &= (1_u16 << bits) - 1;
        }
        if bits != 0 {
            let part = (pending << (5 - bits)) as u8;
            encoded.push(char::from(CHARSET[usize::from(part)]));
            checksum = npub_checksum_step(checksum, part);
        }
        for _ in 0..6 {
            checksum = npub_checksum_step(checksum, 0);
        }
        checksum ^= 1;
        for digit in (0..6).rev() {
            let part = ((checksum >> (digit * 5)) & 31) as usize;
            encoded.push(char::from(CHARSET[part]));
        }
        Self {
            algorithm: AlgorithmId::Secp256k1Schnorr,
            encoded,
        }
    }

    /// Checks a canonical `npub` address of at most 128 UTF-8 bytes and requires
    /// `Secp256k1Schnorr`. Unknown algorithms or address encodings refuse.
    pub fn parse(algorithm: AlgorithmId, encoded: &str) -> Result<Self> {
        use bech32::{primitives::decode::CheckedHrpstring, Bech32};
        if algorithm != AlgorithmId::Secp256k1Schnorr {
            return Err(crate::codes::ALG_UNSUPPORTED);
        }
        if encoded.len() > 128 || !encoded.starts_with("npub1") {
            return Err(crate::codes::ID_INVALID);
        }
        let checked =
            CheckedHrpstring::new::<Bech32>(encoded).map_err(|_| crate::codes::ID_INVALID)?;
        let bytes: Vec<u8> = checked.byte_iter().collect();
        if checked.hrp().as_str() != "npub"
            || bytes.len() != 32
            || bech32::encode::<Bech32>(checked.hrp(), &bytes)
                .map_err(|_| crate::codes::ID_INVALID)?
                != encoded
        {
            return Err(crate::codes::ID_INVALID);
        }
        Ok(Self {
            algorithm,
            encoded: encoded.to_owned(),
        })
    }

    /// Returns the algorithm declared by this public-key address.
    pub const fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// Borrows the canonical address without exposing private key material.
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

fn npub_checksum_step(checksum: u32, part: u8) -> u32 {
    let upper = checksum >> 25;
    let mut next = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(part);
    for (bit, generator) in [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ]
    .into_iter()
    .enumerate()
    {
        if upper & (1 << bit) != 0 {
            next ^= generator;
        }
    }
    next
}

/// The trusted ingress classification of incoming data. Only `Owner` can ever
/// supply an instruction; every other source remains data regardless of wording,
/// signatures, model confidence, embedded role labels or relayed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source {
    /// An owner command attributed only by the signed-in owner session.
    Owner,
    /// Auma's generated data, including proposals and tool-call suggestions.
    Auma,
    /// Data from a contact; the label alone establishes no approval or trust.
    Contact(Npub),
    /// Output from an installed application, still untrusted data.
    App(AppId),
    /// Document content, including text that resembles instructions.
    Document,
    /// Recalled memory; cited evidence does not become an instruction.
    Memory,
    /// Unattributed or unapproved remote content; counted in Aura, never delivered to Auma.
    Stranger,
}

/// A frame's source stamped by the supervisor from its ingress channel. Only
/// `Owner`, obtained solely from the signed-in session, can ever be an instruction;
/// even an owner instruction authorizes no effect without the owner's passkey
/// over exact bytes or a policy already signed by the owner. A guest frame claiming
/// any provenance other than `Auma` is refused. `Stranger` is counted in Aura and
/// never delivered to Auma; content claims never promote a source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    /// The source established by ingress, rather than asserted by frame content.
    pub source: Source,
}

impl Npub {
    /// Decode one lowercase Bech32 `npub` with a 32-byte payload, checksum 1,
    /// and zero unused padding bits. The address alone does not approve a contact.
    pub fn from_memory_address(encoded: &str) -> Result<Self> {
        const SYMBOLS: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        const GENERATORS: [u32; 5] = [
            0x3b6a_57b2,
            0x2650_8e6d,
            0x1ea1_19fa,
            0x3d42_33dd,
            0x2a14_62b3,
        ];
        let invalid = crate::codes::ID_INVALID;
        if encoded.len() != 63 || !encoded.starts_with("npub1") {
            return Err(invalid);
        }
        let mut symbols = [0u8; 58];
        for (slot, character) in symbols.iter_mut().zip(encoded.as_bytes()[5..].iter()) {
            *slot = SYMBOLS
                .iter()
                .position(|candidate| candidate == character)
                .ok_or(invalid)? as u8;
        }
        let expanded_hrp = b"npub"
            .iter()
            .map(|byte| byte >> 5)
            .chain(core::iter::once(0))
            .chain(b"npub".iter().map(|byte| byte & 31));
        let mut checksum = 1u32;
        for symbol in expanded_hrp.chain(symbols.iter().copied()) {
            let high = checksum >> 25;
            checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(symbol);
            for (bit, generator) in GENERATORS.iter().enumerate() {
                if high & (1 << bit) != 0 {
                    checksum ^= generator;
                }
            }
        }
        if checksum != 1 {
            return Err(invalid);
        }
        let mut raw = [0u8; 32];
        let (mut buffered, mut bits, mut written) = (0u32, 0u32, 0usize);
        for symbol in &symbols[..52] {
            buffered = (buffered << 5) | u32::from(*symbol);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                *raw.get_mut(written).ok_or(invalid)? = (buffered >> bits) as u8;
                written += 1;
            }
            buffered &= (1 << bits) - 1;
        }
        if written != raw.len() || bits != 4 || buffered != 0 {
            return Err(invalid);
        }
        Ok(Self {
            algorithm: AlgorithmId::Secp256k1Schnorr,
            encoded: encoded.to_owned(),
        })
    }
}
