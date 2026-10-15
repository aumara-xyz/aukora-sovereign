// SPDX-License-Identifier: AGPL-3.0-or-later
use aumlok::webauthn::{self, AssertionMaterial, Config, Credential};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::Value;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Refusal, Result};

const AUTH_DOMAIN: &[u8] = b"aukora:owner-authorization:v1\0";
const OPERATION_DOMAIN: &[u8] = b"aukora:operation-content:v1\0";
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerBinding {
    pub node_id: String,
    pub rp_id: String,
    pub origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub v: u8,
    pub auth_bytes: String,
    pub assertion: AssertionMaterial,
    pub credential: Credential,
    pub rp_id: String,
    pub origin: String,
    pub rows: Vec<EvidenceRow>,
    pub node_public_key: String,
    pub release: ReleaseRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Components {
    pub node: String,
    pub harness: String,
    pub guest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    pub v: u8,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<Components>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRow {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    pub sig: String,
    pub at: i64,
    pub kind: String,
    pub actor: String,
    pub op: String,
    pub phase: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedOwner {
    pub node: String,
    pub subject: String,
    pub rp_id: String,
    pub origin: String,
    pub node_public_key: String,
    pub credential: Credential,
}

#[derive(Clone, Debug)]
pub struct VerifiedApproval {
    pub(crate) release: String,
    pub(crate) record_sha256: String,
    pub(crate) signer_epoch: u64,
    pub(crate) ledger_seq: u64,
    pub(crate) signer_key_sha256: String,
    pub(crate) ledger_hash: String,
    pub(crate) operation: String,
    pub(crate) proposal: String,
    pub(crate) auth_sha256: String,
    pub(crate) owner: PinnedOwner,
    pub(crate) sign_count: u32,
}

impl VerifiedApproval {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.signer_epoch == 0
            || self.signer_epoch > MAX_SAFE
            || self.ledger_seq == 0
            || self.ledger_seq > MAX_SAFE
            || !hex_value(&self.release, 64)
            || !hex_value(&self.record_sha256, 64)
            || !hex_value(&self.signer_key_sha256, 64)
            || !hex_value(&self.ledger_hash, 64)
            || !hex_value(&self.operation, 64)
            || !hex_value(&self.proposal, 32)
            || !hex_value(&self.auth_sha256, 64)
        {
            return Err(Refusal("floor:ordering-evidence"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    v: u8,
    node: String,
    subject: String,
    op: String,
    proposal: String,
    target: String,
    base_sha256: String,
    new_sha256: String,
    cell: serde_json::Value,
    display_sha256: String,
    challenge: String,
    expires_at: u64,
    epoch: u64,
    operation: String,
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| Refusal("floor:evidence-format"))?;
    let value = canon::parse(&bytes).map_err(|_| Refusal("floor:evidence-format"))?;
    canon::canonical_json(&value).map_err(|_| Refusal("floor:evidence-format"))
}

fn hex_value(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> String {
    hash(&[domain, bytes].concat())
}

fn canonical_input(bytes: &[u8], reason: &'static str) -> Result<Value> {
    let parsed = canon::parse(bytes).map_err(|_| Refusal(reason))?;
    if canon::canonical_json(&parsed).map_err(|_| Refusal(reason))? != bytes {
        return Err(Refusal(reason));
    }
    Ok(parsed)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(Refusal("floor:aura-binding"))
}

fn string(value: &Value) -> Option<&str> {
    if let Value::String(value) = value {
        Some(value)
    } else {
        None
    }
}

fn equal_string(value: &Value, name: &str, expected: &str) -> bool {
    value.get(name).and_then(string) == Some(expected)
}

fn equal_integer(value: &Value, name: &str, expected: u64) -> bool {
    value.get(name) == Some(&Value::Integer(expected as i64))
}

impl EvidenceRow {
    fn entry(&self) -> Result<aura::Entry> {
        Ok(aura::Entry {
            sequence: self.seq,
            prev: self.prev.clone(),
            hash: self.hash.clone(),
            sig: self.sig.clone(),
            at: self.at,
            kind: self.kind.clone(),
            actor: self.actor.clone(),
            op: self.op.clone(),
            phase: self.phase.clone(),
            body: canonical_input(self.body.as_bytes(), "floor:aura-body")?,
        })
    }
}

fn selected<'a>(mut rows: impl Iterator<Item = &'a aura::Entry>) -> Result<&'a aura::Entry> {
    let row = rows.next().ok_or(Refusal("floor:aura-binding"))?;
    if rows.next().is_some() {
        return Err(Refusal("floor:aura-binding"));
    }
    Ok(row)
}

fn owner_state(value: &Value, auth: &Authorization) -> bool {
    equal_string(value, "subject", &auth.subject) && equal_integer(value, "epoch", auth.epoch)
}

fn row_reference(value: &Value, row: &aura::Entry) -> bool {
    equal_integer(value, "seq", row.sequence) && equal_string(value, "hash", &row.hash)
}

fn verify_rows(
    evidence: &Evidence,
    auth: &Authorization,
    auth_value: &Value,
    auth_sha: &str,
    key: &VerifyingKey,
    signer_key_sha: &str,
) -> Result<(u64, String)> {
    let entries = evidence
        .rows
        .iter()
        .map(EvidenceRow::entry)
        .collect::<Result<Vec<_>>>()?;
    aura::walk(&entries, key, None).map_err(|_| Refusal("floor:aura-invalid"))?;
    let terminal = entries.last().ok_or(Refusal("floor:aura-binding"))?;
    if terminal.kind != "gate.apply"
        || terminal.phase != "terminal"
        || terminal.op != auth.proposal
        || terminal.actor != auth.subject
    {
        return Err(Refusal("floor:aura-terminal"));
    }
    let proposal = selected(entries.iter().filter(|row| {
        row.kind == "gate.propose"
            && row.op == auth.proposal
            && row.phase == "intent"
            && row.actor == "supervisor"
    }))?;
    let consume = selected(
        entries
            .iter()
            .filter(|row| row.kind == "gate.consume" && row.op == auth.proposal),
    )?;
    let review_ref = field(&consume.body, "review_issue")?;
    let review = entries
        .iter()
        .find(|row| row_reference(review_ref, row))
        .ok_or(Refusal("floor:aura-binding"))?;
    if proposal.phase != "intent"
        || proposal.actor != "supervisor"
        || review.kind != "gate.review"
        || review.phase != "fact"
        || review.op != auth.proposal
        || consume.phase != "settle"
        || consume.actor != auth.subject
        || !(proposal.sequence < review.sequence
            && review.sequence < consume.sequence
            && consume.sequence < terminal.sequence)
    {
        return Err(Refusal("floor:aura-order"));
    }
    if !equal_string(&proposal.body, "target", &auth.target)
        || !equal_string(&proposal.body, "base_sha256", &auth.base_sha256)
        || !equal_string(&proposal.body, "new_sha256", &auth.new_sha256)
        || !equal_string(&proposal.body, "digest", &auth.operation)
        || field(&review.body, "authorization")? != auth_value
        || field(&consume.body, "authorization")? != auth_value
        || !equal_string(&consume.body, "authorization_sha256", auth_sha)
        || field(&consume.body, "spent")? != &Value::Bool(true)
        || !owner_state(field(&review.body, "owner_state")?, auth)
        || field(&review.body, "owner_state")? != field(&consume.body, "owner_state")?
    {
        return Err(Refusal("floor:aura-binding"));
    }
    let card = canon::canonical_json(field(&review.body, "card")?)
        .map_err(|_| Refusal("floor:aura-binding"))?;
    if hash(&card) != auth.display_sha256 {
        return Err(Refusal("floor:aura-card"));
    }
    let proof_hex = field(&consume.body, "proof_hex")?
        .as_string()
        .ok_or(Refusal("floor:aura-proof"))?;
    if proof_hex.len() > 131_072 || !hex_value(proof_hex, proof_hex.len()) {
        return Err(Refusal("floor:aura-proof"));
    }
    let proof = hex::decode(proof_hex).map_err(|_| Refusal("floor:aura-proof"))?;
    let proof_value = canon::parse(&proof).map_err(|_| Refusal("floor:aura-proof"))?;
    let encoded = canon::canonical_json(&proof_value).map_err(|_| Refusal("floor:aura-proof"))?;
    // The retained proof may have whitespace; its exact bytes still define its hash.
    let retained: AssertionMaterial =
        serde_json::from_slice(&encoded).map_err(|_| Refusal("floor:aura-proof"))?;
    if canonical(&retained)? != canonical(&evidence.assertion)?
        || !equal_string(&consume.body, "proof_sha256", &hash(&proof))
    {
        return Err(Refusal("floor:aura-proof"));
    }
    let receipt = field(&terminal.body, "receipt")?;
    let authorization = field(receipt, "owner_authorization")?;
    let consumption = field(receipt, "owner_consumption")?;
    if !equal_integer(receipt, "v", 3)
        || !equal_string(receipt, "kind", "change")
        || !equal_string(receipt, "proposal", &auth.proposal)
        || !equal_string(receipt, "node", &auth.node)
        || !equal_string(receipt, "approver", &auth.subject)
        || !equal_string(receipt, "target", &auth.target)
        || !equal_string(receipt, "base_sha256", &auth.base_sha256)
        || !equal_string(receipt, "new_sha256", &auth.new_sha256)
        || !equal_string(receipt, "gate_pubkey_sha256", signer_key_sha)
        || !equal_integer(authorization, "version", 1)
        || !equal_string(authorization, "kind", "aukora-owner-authorization-ref/v1")
        || !equal_string(authorization, "authorization_id", auth_sha)
        || !equal_string(authorization, "authorization_sha256", auth_sha)
        || !equal_string(authorization, "proof_sha256", &hash(&proof))
        || !row_reference(consumption, consume)
        || !row_reference(field(consumption, "review_issue")?, review)
    {
        return Err(Refusal("floor:aura-receipt"));
    }
    Ok((terminal.sequence, terminal.hash.clone()))
}

trait ValueString {
    fn as_string(&self) -> Option<&str>;
}
impl ValueString for Value {
    fn as_string(&self) -> Option<&str> {
        string(self)
    }
}

/// Historical check verifies the signature while advance also enforces the protected counter.
pub fn verify(
    evidence: &Evidence,
    binding: &OwnerBinding,
    pinned: Option<&PinnedOwner>,
    enforce_counter: bool,
) -> Result<VerifiedApproval> {
    if evidence.v != 1 && evidence.v != 2 {
        return Err(Refusal("floor:evidence-version"));
    }
    let auth_bytes = webauthn::decode_base64url(&evidence.auth_bytes, 65_536)
        .map_err(|_| Refusal("floor:authorization-format"))?;
    let auth_value = canonical_input(&auth_bytes, "floor:authorization-format")?;
    if auth_value.as_object().is_some_and(|fields| {
        fields.len() == 21
            && fields.iter().all(|(name, _)| {
                matches!(
                    name.as_str(),
                    "v" | "node"
                        | "subject"
                        | "op"
                        | "proposal"
                        | "target"
                        | "epoch"
                        | "operation"
                        | "owner_epoch"
                        | "owner_root_id"
                        | "binding_sha256"
                        | "issued_at"
                        | "issued_at_ms"
                        | "gate"
                        | "pubkey_fp"
                        | "base_sha256"
                        | "new_sha256"
                        | "cell"
                        | "display_sha256"
                        | "challenge"
                        | "expires_at"
                )
            })
    }) && equal_string(&auth_value, "op", "release")
        && equal_string(&auth_value, "target", "release")
    {
        return Err(Refusal("floor:pre-a3-release-reapprove"));
    }
    if auth_value
        .as_object()
        .is_none_or(|fields| fields.len() != 14)
    {
        return Err(Refusal("floor:authorization-format"));
    }
    let auth: Authorization =
        serde_json::from_slice(&auth_bytes).map_err(|_| Refusal("floor:authorization-format"))?;
    if auth.v != 1
        || !hex_value(&auth.node, 32)
        || !auth.subject.starts_with("aukora:1:")
        || !hex_value(&auth.subject[9..], 64)
        || !hex_value(&auth.proposal, 32)
        || !hex_value(&auth.operation, 64)
        || (auth.base_sha256 != "absent" && !hex_value(&auth.base_sha256, 64))
        || !hex_value(&auth.new_sha256, 64)
        || !hex_value(&auth.display_sha256, 64)
        || !hex_value(&auth.challenge, 64)
        || auth.epoch == 0
        || auth.epoch > MAX_SAFE
        || auth.expires_at > MAX_SAFE
        || !auth.cell.is_null()
    {
        return Err(Refusal("floor:authorization-format"));
    }
    if auth.op != "release" || auth.target != "release" {
        return Err(Refusal("floor:authorization-op"));
    }
    if evidence.release.v != 1
        || !hex_value(&evidence.release.digest, 64)
        || evidence
            .release
            .components
            .as_ref()
            .is_some_and(|components| {
                !hex_value(&components.node, 64)
                    || !hex_value(&components.harness, 64)
                    || !hex_value(&components.guest, 64)
            })
    {
        return Err(Refusal("floor:release-format"));
    }
    let record_sha256 = hash(&canonical(&evidence.release)?);
    if record_sha256 != auth.new_sha256 {
        return Err(Refusal("floor:release-digest"));
    }
    let content = canonical(&serde_json::json!({
        "v":1,"node":auth.node,"target":auth.target,"base_sha256":auth.base_sha256,
        "new_sha256":auth.new_sha256,"cell":null
    }))?;
    if domain_hash(OPERATION_DOMAIN, &content) != auth.operation {
        return Err(Refusal("floor:operation-digest"));
    }
    let expected_owner = if evidence.v == 1 {
        auth.subject.clone()
    } else {
        format!("owner:{}", auth.node)
    };
    if auth.node != binding.node_id
        || evidence.rp_id != binding.rp_id
        || evidence.origin != binding.origin
        || evidence.credential.owner_id != expected_owner
        || !hex_value(&evidence.node_public_key, 64)
    {
        return Err(Refusal("floor:owner-binding"));
    }
    let key_bytes: [u8; 32] = hex::decode(&evidence.node_public_key)
        .map_err(|_| Refusal("floor:node-key"))?
        .try_into()
        .map_err(|_| Refusal("floor:node-key"))?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| Refusal("floor:node-key"))?;
    if key.is_weak() {
        return Err(Refusal("floor:node-key"));
    }
    let mut owner = PinnedOwner {
        node: auth.node.clone(),
        subject: auth.subject.clone(),
        rp_id: evidence.rp_id.clone(),
        origin: evidence.origin.clone(),
        node_public_key: evidence.node_public_key.clone(),
        credential: evidence.credential.clone(),
    };
    if let Some(pinned) = pinned {
        owner.credential.sign_count = pinned.credential.sign_count;
        let mut prior = pinned.clone();
        prior.node_public_key.clone_from(&owner.node_public_key);
        if owner != prior {
            return Err(Refusal("floor:credential-not-pinned"));
        }
    }
    let auth_sha256 = domain_hash(AUTH_DOMAIN, &auth_bytes);
    let challenge = URL_SAFE_NO_PAD
        .encode(hex::decode(&auth_sha256).map_err(|_| Refusal("floor:authorization-format"))?);
    let config = Config {
        rp_id: owner.rp_id.clone(),
        origin: owner.origin.clone(),
        credential: owner.credential.clone(),
    };
    let assertion = webauthn::verify_assertion(
        &evidence.assertion,
        &config,
        &owner.credential.owner_id,
        &challenge,
        (!enforce_counter).then_some(0),
    )
    .map_err(|error| {
        if error.0 == "aumlok:counter-replayed" {
            Refusal("floor:counter-replayed")
        } else {
            Refusal("floor:assertion-invalid")
        }
    })?;
    let signer_key_sha256 = hash(&key_bytes);
    let (ledger_seq, ledger_hash) = verify_rows(
        evidence,
        &auth,
        &auth_value,
        &auth_sha256,
        &key,
        &signer_key_sha256,
    )?;
    Ok(VerifiedApproval {
        release: evidence.release.digest.clone(),
        record_sha256,
        signer_epoch: auth.epoch,
        ledger_seq,
        signer_key_sha256,
        ledger_hash,
        operation: auth.operation,
        proposal: auth.proposal,
        auth_sha256,
        owner,
        sign_count: assertion.sign_count,
    })
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
pub(crate) mod tests;
