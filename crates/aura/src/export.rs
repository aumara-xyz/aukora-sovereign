// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen cold-proof-v1 data; no field grants authority or independent trust.

use canon::{
    authority::{Kind, Phase},
    digest::Digest32,
    ids::OperationId,
    json::Value,
    Result,
};

pub const COLD_PROOF_SCHEMA: &str = "aukora-aura-cold-proof-v1";
pub const RETAINED_HEAD_SCHEMA: &str = "aukora-aura-retained-head-v1";
pub const PRESENTED_HEAD_SCHEMA: &str = "aukora-aura-presented-head-v1";
pub const LEAF_CONVENTION: &str = canon::domain::RFC6962_LEAF_CONVENTION;

/// The ten C3 wire keys are seq,prev,hash,sig,at,kind,actor,op,phase,body.
/// Previous None represents the domain sentinel; absent operation represents "".
/// The signature remains one standard padded-base64 Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowV1 {
    pub sequence: u64,
    pub previous: Option<Digest32>,
    pub hash: Digest32,
    pub signature: [u8; 64],
    pub at: i64,
    pub kind: Kind,
    pub actor: String,
    pub operation: Option<OperationId>,
    pub phase: Phase,
    pub body: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedHeadV1 {
    pub sequence: u64,
    pub hash: Digest32,
    pub tree_size: u64,
    pub root: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedHeadV1 {
    pub tree_size: u64,
    pub root: Digest32,
    pub retained_tree_size: u64,
    pub proof_from_previous: Vec<Digest32>,
}

/// Wire keys are exactly head,publicKey,rows,schema. The embedded key is untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdProofV1 {
    pub head: RetainedHeadV1,
    pub public_key: [u8; 32],
    pub rows: Vec<RowV1>,
}

/// Explicit caller limits bound parsing and output before allocating row bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportLimits {
    pub max_bytes: usize,
    pub max_rows: usize,
}

impl ColdProofV1 {
    /// Wave-1 contract: strict C1 parse, exact closed keys and pinned v1 encodings.
    pub fn parse(_bytes: &[u8], _limits: ExportLimits) -> Result<Self> {
        crate::unavailable()
    }

    /// Wave-1 contract: verify both arms and all signatures before emitting C1 bytes.
    pub fn canonical_bytes(&self, _limits: ExportLimits) -> Result<Vec<u8>> {
        crate::unavailable()
    }
}

impl RetainedHeadV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        crate::unavailable()
    }
}

impl PresentedHeadV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        crate::unavailable()
    }
}
