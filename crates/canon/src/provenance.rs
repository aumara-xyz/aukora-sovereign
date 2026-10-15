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
    /// Checks a canonical `npub` address of at most 128 UTF-8 bytes and requires
    /// `Secp256k1Schnorr`. Unknown algorithms or address encodings refuse.
    pub fn parse(_algorithm: AlgorithmId, _encoded: &str) -> Result<Self> {
        todo!("row 32")
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
