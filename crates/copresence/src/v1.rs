// SPDX-License-Identifier: AGPL-3.0-or-later
//! New exchange contracts; none changes the pinned `copresence.v0` core.
//!
//! Wire envelope is `{schema, body}`. Schema and signing domains distinguish it
//! from old portal frames. Each encoder and verifier currently refuses.

use crate::{PublicKeyBytes, Refusal, Result, SignatureBytes, UNIMPLEMENTED};
use canon::{digest::Digest32, ids::NodeId};

pub const RECEIPT_SCHEMA: &str = "aukora.copresence.hardened.v1";
pub const FRAME_SCHEMA: &str = "aukora.copresence.frame.v1";
pub const CORE_DOMAIN: &str = "copresence.v1";
pub const FRAME_DOMAIN: &str = "copresence.frame.v1";
pub const NONCE_DOMAIN: &str = "copresence.nonce-commitment.v1";
pub const CONTEXT_DOMAIN: &str = "copresence.context.v1";
pub const TRANSCRIPT_DOMAIN: &str = "copresence.transcript.v1";
pub const INTENT_ACK_DOMAIN: &str = "copresence.intent-ack.v2";
pub const FRAME_ROTATION_MS: u64 = 1_000;
pub const FRAME_FRESHNESS_SECONDS: u64 = 5;
pub const MAX_WINDOW_SECONDS: u64 = 10;

/// Method is carried in the first signed frame and in the final core context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    ScreenToScreen,
    Remote,
    Relayed,
}

/// Requested layers are fixed with the method before any exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredLayers {
    pub sound: bool,
    pub motion: bool,
    pub intent_ack: bool,
}

/// Session id is public correlation data; nonce material has a separate field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Participant {
    pub node: NodeId,
    pub device_key: PublicKeyBytes,
    pub device_epoch: u64,
    pub session_id: [u8; 16],
    pub attempt_sequence: u64,
}

/// Full context includes both identities, epochs, sessions and attempt counters.
/// Purpose is inert text. Intent is the digest of the exact acknowledged text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    pub a: Participant,
    pub b: Participant,
    pub method: Method,
    pub required_layers: RequiredLayers,
    pub purpose: String,
    pub intent: Option<Digest32>,
}

/// The first frame has a commitment, but has no nonce or nonce disclosure field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Face {
    pub participant: Participant,
    pub method: Method,
    pub required_layers: RequiredLayers,
    pub nonce_commitment: Digest32,
    pub t_seconds: u64,
    pub frame_index: u64,
}

/// A targeted reveal follows both FACE frames; it commits to their exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeenYou {
    pub context: Context,
    pub sender: crate::Side,
    pub face_a: Digest32,
    pub face_b: Digest32,
    pub nonce: [u8; 32],
    pub t_seconds: u64,
    pub frame_index: u64,
}

/// Optional channel observations are commitments to bounded receipt data.
/// A missing required channel is a refusal, not an automatic method downgrade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelCommitments {
    pub sound: Option<Digest32>,
    pub motion: Option<Digest32>,
}

/// Both timestamps, context and channel observations enter the signed core.
/// Transcript covers FACE and SEENYOU only, avoiding a signature/hash cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreInput {
    pub context: Context,
    pub nonce_a: [u8; 32],
    pub nonce_b: [u8; 32],
    pub t_a_seconds: u64,
    pub t_b_seconds: u64,
    pub transcript: Digest32,
    pub channels: ChannelCommitments,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Handshake {
    pub core: CoreInput,
    pub sig_b: SignatureBytes,
    pub t_seconds: u64,
    pub frame_index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bloom {
    pub context: Digest32,
    pub core: Digest32,
    pub sig_a: SignatureBytes,
    pub t_seconds: u64,
    pub frame_index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameBody {
    Face(Face),
    SeenYou(SeenYou),
    Handshake(Handshake),
    Bloom(Bloom),
}

/// Signature is P-256/SHA-256 over a domain-separated frame digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedFrame {
    pub body: FrameBody,
    pub signature: SignatureBytes,
}

/// Ack commits to the core, context and exact intent; it is device evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentAcknowledgement {
    pub by: crate::Side,
    pub intent: Digest32,
    pub core: Digest32,
    pub context: Digest32,
    pub signature: SignatureBytes,
}

/// Claimed receipt data, never a successful verification result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBody {
    pub core: CoreInput,
    pub sig_a: SignatureBytes,
    pub sig_b: SignatureBytes,
    pub intent_ack: Option<IntentAcknowledgement>,
}

/// Local sequence comes from the attempt journal, not from remote JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptTicket {
    pub sequence: u64,
    pub local_session: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptOutcome {
    Accepted { receipt: Digest32 },
    Refused(Refusal),
    Abandoned,
}

/// Durable attempt accounting contract for the supervisor's storage adapter.
/// `begin` counts before decoding, including malformed/replayed input. `finish`
/// consumes one ticket; accepted receipt digests cannot be accepted twice.
/// Storage failure refuses the exchange; interrupted tickets remain counted.
pub trait AttemptJournal {
    fn begin(&mut self, local_session: [u8; 16]) -> Result<AttemptTicket>;
    fn finish(&mut self, ticket: AttemptTicket, outcome: AttemptOutcome) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Face,
    SeenYou,
    Handshake,
    Bloom,
    Refused,
}

/// No public constructor or transition can mint a verified receipt in wave 0.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    body: ReceiptBody,
    digest: Digest32,
    counted_attempt: AttemptTicket,
}

impl VerifiedReceipt {
    pub const fn body(&self) -> &ReceiptBody {
        &self.body
    }

    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    pub const fn counted_attempt(&self) -> &AttemptTicket {
        &self.counted_attempt
    }
}

/// Private state keeps the selected method out of post-start mutation APIs.
pub struct Exchange {
    method: Method,
    stage: Stage,
}

impl Exchange {
    pub const fn method(&self) -> Method {
        self.method
    }

    pub const fn stage(&self) -> Stage {
        self.stage
    }

    /// Counts before starting an exchange; wave 0 cannot start one.
    pub fn begin(_face: Face, _journal: &mut dyn AttemptJournal) -> Result<Self> {
        Err(UNIMPLEMENTED)
    }

    /// Each input is a new counted attempt, including invalid frame bytes.
    /// Unknown frames, changed methods, wrong peers and replays refuse.
    pub fn observe(
        &mut self,
        _frame_bytes: &[u8],
        _now_seconds: u64,
        _journal: &mut dyn AttemptJournal,
    ) -> Result<Stage> {
        Err(UNIMPLEMENTED)
    }
}

/// Binary preimage layout is declared in vectors/hardened-v1.json.
pub fn core_digest(_input: &CoreInput) -> Result<Digest32> {
    Err(UNIMPLEMENTED)
}

/// Encodes only the new outer envelope; no v0 frame receives additional keys.
pub fn encode_frame(_frame: &SignedFrame) -> Result<Vec<u8>> {
    Err(UNIMPLEMENTED)
}

/// Verifies both device signatures and exact expected context after counting.
/// A single-use success requires durable journal completion, even offline.
pub fn verify_receipt(
    _bytes: &[u8],
    _expected: &Context,
    _now_seconds: u64,
    _journal: &mut dyn AttemptJournal,
) -> Result<VerifiedReceipt> {
    Err(UNIMPLEMENTED)
}
