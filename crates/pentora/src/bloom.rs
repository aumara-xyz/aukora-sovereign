// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 118: the relationship bloom, the shared Pentora of a pairing.
//!
//! Two person Nostr x-only public keys give a head commitment under `pentora.bloom.v1`.
//! The sorted raw keys enter that hash; `pentora_expand` expands its result. Version two
//! uses the shared display derivation and refuses contexts carrying only a commitment.
//!
//! The bloom is a picture. It proves no meeting, carries no consent and grants nothing.

use crate::fingerprint::{pentora_expand, Expansion, FingerprintTrit};
use crate::CellIndex;
use canon::{digest::Digest32, ids::SessionId, Result};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

pub const BLOOM_FORMAT_VERSION: u16 = 2;
pub const BLOOM_LABEL: &str = "Relationship bloom — display only";
/// The pairing derivation's own domain tag. The fingerprint keeps `pentora.display.v1`.
pub const BLOOM_DOMAIN: &str = canon::domain::PENTORA_BLOOM_DOMAIN;
/// A person Nostr x-only public key contains exactly this many raw bytes.
pub const IDENTITY_BYTES: usize = 32;

/// Display metadata retained for callers of the original context API.
/// A commitment alone cannot construct a relationship bloom. `session` enters no digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingDisplayContext {
    pub session: SessionId,
    pub shared_commitment: Digest32,
}

impl PairingDisplayContext {
    /// Metadata for two person public keys, with the same commitment in either order.
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
    /// The legacy context contains no person keys, so it cannot supply a relationship picture.
    pub fn from_pairing(_context: PairingDisplayContext) -> Result<Self> {
        Err(crate::refusal("person-keys-required"))
    }

    /// The caller supplies the two people's person Nostr keys, never node or device identities.
    pub fn from_identities(session: SessionId, first: &[u8], second: &[u8]) -> Result<Self> {
        let context = PairingDisplayContext::from_identities(session, first, second)?;
        let expansion = pentora_expand(context.shared_commitment.as_bytes())?;
        Ok(Self { context, expansion })
    }

    /// Missing person keys leave the relationship absent; no other identity is substituted.
    pub fn from_person_keys(
        session: SessionId,
        first: Option<&[u8]>,
        second: Option<&[u8]>,
    ) -> Result<Option<Self>> {
        match (first, second) {
            (Some(first), Some(second)) => Self::from_identities(session, first, second).map(Some),
            _ => Ok(None),
        }
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

/// Hash two person Nostr x-only public keys, sorted bytewise, under the relationship domain.
/// Both widths are checked before equality. This display input grants no identity authority.
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

/// Apply the shared Rust display expansion to the two person keys' head commitment.
pub fn pairing_expansion(first: &[u8], second: &[u8]) -> Result<Expansion> {
    pentora_expand(pairing_digest(first, second)?.as_bytes())
}
