// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 118: the relationship bloom, the shared Pentora of a pairing.
//!
//! Two identities give one digest, `sha256("pentora.bloom.v1" || 0x00 || low || high)`, where
//! `low` and `high` are the two 32-byte identities in bytewise order, so either argument order
//! draws the same picture. Trit `i` is `floor(N / 3^i) mod 3` for `i` in `0..110`, `N` being the
//! big-endian integer of that digest, drawn on the `i`-th non-centre cell as the fingerprint's
//! trits are. `vectors/bloom-v1.json` lists the inputs, digest and trits of each case.
//!
//! The bloom is a picture. It proves no meeting, carries no consent and grants nothing.

use crate::fingerprint::{Expansion, FingerprintTrit, TRIT_COUNT};
use crate::CellIndex;
use canon::{digest::Digest32, ids::SessionId, Result};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

pub const BLOOM_FORMAT_VERSION: u16 = 1;
pub const BLOOM_LABEL: &str = "Relationship bloom — display only";
/// The pairing derivation's own domain tag. The fingerprint keeps `pentora.display.v1`.
pub const BLOOM_DOMAIN: &str = "pentora.bloom.v1";
/// An identity is exactly this many raw bytes; the derivation reads no other width.
pub const IDENTITY_BYTES: usize = 32;

/// A transcript commitment is display input, never proof of co-presence or consent.
///
/// `shared_commitment` is drawn as it is: the `pairing_digest` of two identities, or a digest
/// both screens computed from one exchange. `session` labels the display and enters no digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingDisplayContext {
    pub session: SessionId,
    pub shared_commitment: Digest32,
}

impl PairingDisplayContext {
    /// The context whose commitment is `pairing_digest(first, second)`, the same in either order.
    pub fn from_identities(session: SessionId, first: &[u8], second: &[u8]) -> Result<Self> {
        Ok(Self {
            session,
            shared_commitment: pairing_digest(first, second)?,
        })
    }
}

/// Kept distinct from both the node fingerprint's source snapshot and health cells.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationshipBloom {
    context: PairingDisplayContext,
    expansion: Expansion,
}

impl RelationshipBloom {
    /// Draws the context's commitment as it is. An all-zero commitment is a missing one and refuses.
    pub fn from_pairing(context: PairingDisplayContext) -> Result<Self> {
        let expansion = expand(context.shared_commitment)?;
        Ok(Self { context, expansion })
    }

    /// Each screen of a pairing holds both identities, so each builds this bloom in its own order.
    pub fn from_identities(session: SessionId, first: &[u8], second: &[u8]) -> Result<Self> {
        Self::from_pairing(PairingDisplayContext::from_identities(
            session, first, second,
        )?)
    }

    pub const fn context(&self) -> PairingDisplayContext {
        self.context
    }
    pub const fn expansion(&self) -> &Expansion {
        &self.expansion
    }
    pub const fn label(&self) -> &'static str {
        BLOOM_LABEL
    }

    /// The trit drawn on a cell. `CellIndex` never names the centre, which has no trit.
    pub const fn trit(&self, cell: CellIndex) -> FingerprintTrit {
        self.expansion.trits()[cell.digit()]
    }
}

/// The pairing digest of two identities. Each must be exactly `IDENTITY_BYTES` long and the two
/// must differ; the lower one, bytewise, is hashed first, so the order given never matters.
pub fn pairing_digest(first: &[u8], second: &[u8]) -> Result<Digest32> {
    let first: &[u8; IDENTITY_BYTES] = first
        .try_into()
        .map_err(|_| crate::refusal("identity-invalid"))?;
    let second: &[u8; IDENTITY_BYTES] = second
        .try_into()
        .map_err(|_| crate::refusal("identity-invalid"))?;
    let (low, high) = match first.cmp(second) {
        Ordering::Less => (first, second),
        Ordering::Greater => (second, first),
        Ordering::Equal => return Err(crate::refusal("identities-equal")),
    };
    let digest: [u8; 32] = Sha256::new()
        .chain_update(BLOOM_DOMAIN.as_bytes())
        .chain_update([0])
        .chain_update(low)
        .chain_update(high)
        .finalize()
        .into();
    Ok(Digest32::from_bytes(digest))
}

/// The pairing digest of two identities with its 110 trits, for a caller that has no session.
pub fn pairing_expansion(first: &[u8], second: &[u8]) -> Result<Expansion> {
    expand(pairing_digest(first, second)?)
}

fn expand(commitment: Digest32) -> Result<Expansion> {
    let bytes = commitment.as_bytes();
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(crate::refusal("commitment-empty"));
    }
    Ok(Expansion::from_parts(commitment, read_trits(bytes)))
}

/// The digest as a big-endian integer, divided by three 110 times: least significant digit first.
fn read_trits(digest: &[u8; 32]) -> [FingerprintTrit; TRIT_COUNT] {
    // Four big-endian limbs keep the quotient whole while the low digits come off.
    let mut limbs = [0_u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(digest.chunks_exact(8)) {
        *limb = bytes
            .iter()
            .fold(0, |acc, byte| (acc << 8) | u64::from(*byte));
    }
    let mut trits = [FingerprintTrit::Zero; TRIT_COUNT];
    for trit in &mut trits {
        let mut remainder = 0_u128;
        for limb in &mut limbs {
            let dividend = (remainder << 64) | u128::from(*limb);
            *limb = (dividend / 3) as u64;
            remainder = dividend % 3;
        }
        *trit = match remainder {
            0 => FingerprintTrit::Zero,
            1 => FingerprintTrit::One,
            _ => FingerprintTrit::Two,
        };
    }
    trits
}
