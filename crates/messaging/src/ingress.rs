// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 135 cannot append a network refusal through canon's closed FactKind yet.

use canon::{authority::AuthorityTxn, digest::Digest32, Result};
use nostr::{EventId, PublicKey, TransportEnvelope, TransportKind};

use crate::Messaging;

/// Refusal classes have fixed cardinality; attacker identities cannot add buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    Envelope,
    Signature,
    Recipient,
    Stranger,
    Replay,
    Payload,
    StaleContact,
}

impl RefusalReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Envelope => "messaging:envelope",
            Self::Signature => "messaging:signature",
            Self::Recipient => "messaging:recipient",
            Self::Stranger => "messaging:stranger",
            Self::Replay => "messaging:replay",
            Self::Payload => "messaging:payload",
            Self::StaleContact => "messaging:stale-contact",
        }
    }
}

/// No attacker text or unbounded sender map is present in refusal observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusalObservation {
    pub ingress_digest: Digest32,
    pub envelope_id: Option<EventId>,
    pub transport: TransportKind,
    pub reason: RefusalReason,
    pub observed_at_ms: u64,
}

/// Monotonic totals are data for the Network health collector, never permission.
/// Saturation must refuse admission rather than silently dropping an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusalCounts {
    pub envelope: u64,
    pub signature: u64,
    pub recipient: u64,
    pub stranger: u64,
    pub replay: u64,
    pub payload: u64,
    pub stale_contact: u64,
    pub total: u64,
    pub last_aura_sequence: u64,
}

/// A counted refusal is not constructible until its Aura append is durable.
#[derive(Debug)]
pub struct CountedRefusal {
    observation: RefusalObservation,
    sequence: u64,
}

impl CountedRefusal {
    pub const fn observation(&self) -> &RefusalObservation {
        &self.observation
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// There is no Owner variant. The supervisor maps this to canon Source::Contact,
/// and the guest receives only its text and evidence, never an instruction.
#[derive(Debug)]
pub struct ContactData {
    sender: PublicKey,
    event: EventId,
    text: String,
    transport: TransportKind,
    contact_receipt: Digest32,
}

impl ContactData {
    pub const fn sender(&self) -> PublicKey {
        self.sender
    }

    pub const fn event(&self) -> EventId {
        self.event
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    pub const fn contact_receipt(&self) -> Digest32 {
        self.contact_receipt
    }
}

#[derive(Debug)]
pub enum IngressOutcome {
    Data(ContactData),
    Refused(CountedRefusal),
}

/// An explicit unavailable integration, not a counterfeit gate or boot fact.
/// Canon must add a nonauthorizing network-refusal fact and append path before
/// row 135 can report durable counts. No observation is recorded by this body.
pub fn append_refusal<T: AuthorityTxn + ?Sized>(
    _txn: &mut T,
    _observation: RefusalObservation,
) -> Result<CountedRefusal> {
    Err(canon::Refusal {
        organ: "messaging",
        reason: "aura-refusal-kind-unavailable",
    })
}

impl Messaging {
    /// The receiver must verify the wrapper and inner sender, consult current
    /// consumed-card contacts, reject replay and persist refusal counts before
    /// any guest delivery. With the Aura append gap, row 135 remains unavailable.
    pub fn receive<T: AuthorityTxn + ?Sized>(
        &mut self,
        _txn: &mut T,
        _envelope: &TransportEnvelope,
        _recipient_key: &nostr::SecretKey,
        _transport: TransportKind,
        _received_at_ms: u64,
    ) -> Result<IngressOutcome> {
        Err(canon::Refusal {
            organ: "messaging",
            reason: "aura-refusal-kind-unavailable",
        })
    }

    pub fn refusal_counts(&self) -> Result<RefusalCounts> {
        Err(canon::Refusal {
            organ: "messaging",
            reason: "aura-refusal-kind-unavailable",
        })
    }
}
