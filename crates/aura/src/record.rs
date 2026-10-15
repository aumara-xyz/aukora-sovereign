// SPDX-License-Identifier: AGPL-3.0-or-later
//! Epoch and algorithm wrappers live inside new bodies; frozen v1 rows stay unchanged.

use canon::{
    alg::{AlgorithmId, PublicKey, Signatures},
    authority::{AuthorityRecord, AuthorityVersion, Kind},
    digest::Digest32,
    json::Value,
    Result,
};

pub const AUTHORITY_BODY_SCHEMA: &str = "aukora-aura-authority-body-v1";
pub const MEMBERSHIP_SCHEMA: &str = "aukora-aura-membership-v1";
pub const MEMBERSHIP_DOMAIN: &str = "aukora:aura-membership:v1";

/// New authority bodies bind this context into C2's hash through the body member.
/// Wire keys are schema,algorithm,epoch,sequence,previous_hash,payload. Historical
/// v1 bodies are preserved exactly and never gain inferred authority metadata.
/// previous_hash is C2's domain sentinel at sequence one, otherwise lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityBodyV1 {
    pub algorithm: AlgorithmId,
    pub authority: AuthorityVersion,
    pub payload: Value,
}

impl AuthorityBodyV1 {
    pub fn canonical_value(&self) -> Result<Value> {
        crate::unavailable()
    }

    pub fn parse(_body: &Value) -> Result<Self> {
        crate::unavailable()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipSet {
    pub epoch: u64,
    pub members: Vec<PublicKey>,
    pub required_signers: u32,
}

/// Joint approval signs the same old/new membership transition bytes. These are
/// unverified inputs, not a substitute for a VerifiedProof or an owner binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipTransition {
    pub old: MembershipSet,
    pub new: MembershipSet,
    pub predecessor: AuthorityVersion,
    pub old_signatures: Vec<(PublicKey, Signatures)>,
    pub new_signatures: Vec<(PublicKey, Signatures)>,
}

impl MembershipTransition {
    /// The domain plus NUL prefixes the canonical schema,old,new,predecessor object;
    /// signatures are excluded. Both sets attest to these same exact bytes.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        crate::unavailable()
    }

    /// Wave-1 contract: old equals locked membership, new epoch is old epoch plus
    /// one, sets contain unique keys, thresholds are in 1..=member count, and each
    /// set independently reaches its threshold over signing_bytes. Duplicate keys,
    /// duplicate signatures, unsupported algorithms and incomplete hybrids refuse.
    pub fn verify_joint(&self, _expected_old: &MembershipSet) -> Result<()> {
        crate::unavailable()
    }
}

/// This is the C3 closed registry; unknown spellings produce an Aura refusal.
pub fn kind_from_wire(name: &str) -> Result<Kind> {
    use Kind::*;
    let kinds = [
        BootFacts,
        GatePropose,
        GateReview,
        GateConsume,
        GateApply,
        GateRetire,
        GateRefuse,
        GateExpire,
        GateRecover,
        FloorAdvance,
        AumlokEnrol,
        AumlokBind,
        AumlokSignin,
        BrokerGrant,
        BrokerReserve,
        BrokerSettle,
        BrokerRevoke,
        KiraSave,
        KiraDemote,
        KiraPermission,
        SandboxStart,
        SandboxExit,
        NostrBind,
    ];
    kinds
        .into_iter()
        .find(|kind| kind.wire_name() == name)
        .ok_or(canon::codes::AURA_UNVERIFIED)
}

/// Hash only sequence,at,kind,actor,op,phase,body,prev,domain as C2/C3 specify.
/// Hash and signature are excluded; op and phase are included even when op is "".
pub fn entry_hash_v1(_row: &crate::export::RowV1) -> Result<Digest32> {
    crate::unavailable()
}

/// Require all stored components and body epoch context; no algorithm fallback.
pub fn verify_record(_record: &AuthorityRecord, _keys: &[PublicKey]) -> Result<()> {
    crate::unavailable()
}
