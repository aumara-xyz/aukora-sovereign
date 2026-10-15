// SPDX-License-Identifier: AGPL-3.0-or-later
//! Contact records and pairing labels carry evidence without owner authority.

use canon::{authority::AuthorityVersion, digest::Digest32, ids::ProposalId};
use nostr::PublicKey;

pub const MAX_CONTACT_LABEL_BYTES: usize = 160;

/// A channel established by the pairing verifier, never by message content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingMethod {
    ScreenToScreen,
    Remote,
    Relayed,
    Unknown,
}

/// Public data retained from a verified receipt; this does not add a contact.
/// Messaging has no dependency on the verifier and accepts this only through the
/// supervisor's checked adapter, with both endpoint keys matched to the receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingEvidence {
    pub receipt_digest: Digest32,
    pub local_key: PublicKey,
    pub remote_key: PublicKey,
    pub method: PairingMethod,
    pub verified_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactDraft {
    pub key: PublicKey,
    pub label: String,
    pub pairing: Option<PairingEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactChange {
    Add(ContactDraft),
    Remove { key: PublicKey },
}

/// Private fields prevent an incoming claimed contact record from granting access.
/// Wave 1 creates this only from current, consumed owner-card state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedContact {
    key: PublicKey,
    label: String,
    authority: AuthorityVersion,
    proposal: ProposalId,
    consumed_card: Digest32,
    pairing: Option<PairingEvidence>,
}

impl ApprovedContact {
    pub const fn key(&self) -> PublicKey {
        self.key
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn authority(&self) -> AuthorityVersion {
        self.authority
    }

    pub const fn proposal(&self) -> ProposalId {
        self.proposal
    }

    pub const fn consumed_card(&self) -> Digest32 {
        self.consumed_card
    }

    pub fn pairing(&self) -> Option<&PairingEvidence> {
        self.pairing.as_ref()
    }
}
