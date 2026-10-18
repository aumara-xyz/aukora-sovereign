// SPDX-License-Identifier: AGPL-3.0-or-later
//! One durable slider view for owner contacts, Settings and the door.
//!
//! Passkey-approved policy bytes come from retained gate receipts. An owner-session
//! fact can only tighten their setting; it never changes class rules or grants.
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactKind, FactRecord, Kind, Phase},
    digest::Digest32,
    ids::ProposalId,
    json::{Value, ValueView},
    Result,
};
use gate::proposal::EvidenceReference;
use laya::{SliderPolicy, SliderSetting};

pub const TIGHTEN_SCHEMA: &str = "aukora-slider-tighten-v1";
const BASELINE_SCHEMA: &str = "aukora-slider-baseline-v1";

pub(crate) struct PolicyState {
    pub policy: SliderPolicy,
    pub applied: Option<Vec<u8>>,
    pub tightening: Option<EvidenceReference>,
    initialized: bool,
}

impl super::HostLedger {
    /// Preserve the installed door's policy once, before either owner or engine
    /// ingress starts. Later configuration edits cannot reset an owner's slider.
    pub fn initialize_slider(&self, policy: SliderPolicy) -> Result<()> {
        let bytes = policy.canonical_bytes()?;
        self.transaction(|txn| {
            if current_state(txn)?.initialized {
                return Ok(());
            }
            let context = txn.observation_context()?;
            txn.append_fact(FactRecord {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                authority: context.authority,
                at: context.at,
                kind: FactKind::BootFacts,
                actor: "supervisor".into(),
                body: Value::object(vec![
                    ("schema".into(), Value::text(BASELINE_SCHEMA.into())?),
                    ("policy".into(), Value::text(hex::encode(&bytes))?),
                    (
                        "policy_sha256".into(),
                        Value::text(Digest32::sha256(&bytes).to_string())?,
                    ),
                ])?,
            })?;
            Ok(())
        })
    }
}

pub(crate) fn current_policy(txn: &mut aura::LedgerTxn<'_>) -> Result<SliderPolicy> {
    Ok(current_state(txn)?.policy)
}

pub(crate) fn current_state(txn: &mut aura::LedgerTxn<'_>) -> Result<PolicyState> {
    let mut state = PolicyState {
        policy: laya::slider::starter()?,
        applied: None,
        tightening: None,
        initialized: false,
    };
    let end = txn.current_version()?.sequence;
    for sequence in 1..end {
        let row = txn
            .floor_record_at_sequence(sequence)?
            .ok_or(refuse("slider-history-gap"))?;
        let body = aura::record::AuthorityBodyV1::parse(&row.body)?.payload;
        if row.kind == Kind::GateApply
            && row.phase == Phase::Terminal
            && string(&body, "target").ok() == Some(laya::slider::POLICY_TARGET)
            && string(&body, "state").ok() == Some("applied")
        {
            let id = ProposalId::from_hex(string(&body, "proposal")?)?;
            let receipt = Digest32::from_hex(string(&body, "consumed_approval")?)?;
            let stored = txn.proposal(&id)?;
            let consumed = txn.check_target_consumption(id, receipt)?;
            if stored.status != aura::storage::ProposalStatus::Applied
                || stored.target != laya::slider::POLICY_TARGET
                || row.operation != Some(stored.operation)
                || row.authority.epoch != stored.authority.epoch
                || row.authority.sequence <= consumed.authority.sequence
                || string(&body, "new_sha256")? != Digest32::sha256(&stored.new_bytes).to_string()
                || !policy_evidence_matches(txn, &stored, state.tightening.as_ref())?
            {
                return Err(refuse("slider-projection-invalid"));
            }
            state.policy = SliderPolicy::parse(&stored.new_bytes)?;
            state.applied = Some(stored.new_bytes);
            state.tightening = None;
            state.initialized = true;
        } else if row.kind == Kind::BootFacts
            && row.phase == Phase::Fact
            && row.operation.is_none()
            && row.actor == "supervisor"
            && string(&body, "schema").ok() == Some(BASELINE_SCHEMA)
        {
            exact(&body, &["schema", "policy", "policy_sha256"])?;
            let bytes = hex::decode(string(&body, "policy")?)
                .map_err(|_| refuse("slider-record-invalid"))?;
            if state.initialized
                || string(&body, "policy_sha256")? != Digest32::sha256(&bytes).to_string()
            {
                return Err(refuse("slider-projection-invalid"));
            }
            state.policy = SliderPolicy::parse(&bytes)?;
            state.initialized = true;
        } else if row.kind == Kind::BootFacts
            && row.phase == Phase::Fact
            && row.operation.is_none()
            && row.actor == "owner"
            && string(&body, "schema").ok() == Some(TIGHTEN_SCHEMA)
        {
            exact(&body, &["schema", "setting", "previous_sha256"])?;
            if string(&body, "previous_sha256")?
                != Digest32::sha256(&state.policy.canonical_bytes()?).to_string()
            {
                return Err(refuse("slider-projection-invalid"));
            }
            let setting = SliderSetting::from_policy_wire(string(&body, "setting")?)?;
            let mut candidate = state.policy.clone();
            candidate.setting = setting;
            if candidate.loosens(state.policy.setting) || candidate.setting == state.policy.setting
            {
                return Err(refuse("slider-projection-invalid"));
            }
            state.policy = candidate;
            state.tightening = Some(EvidenceReference {
                digest: row.hash,
                source_record: row.authority,
            });
            state.initialized = true;
        }
    }
    Ok(state)
}

/// An explicit retry may wrap the original evidence in existing owner-again
/// facts. Each link retains the policy bytes and names the current tightening.
fn policy_evidence_matches(
    txn: &mut aura::LedgerTxn<'_>,
    stored: &aura::storage::ProposalState,
    tightening: Option<&EvidenceReference>,
) -> Result<bool> {
    let mut proposal = stored.clone();
    loop {
        if proposal.evidence_source == tightening.map(|evidence| evidence.source_record) {
            return Ok(
                tightening.is_none_or(|evidence| proposal.evidence_digest == evidence.digest)
            );
        }
        let Some(source) = proposal.evidence_source else {
            return Ok(false);
        };
        let row = txn
            .floor_record_at_sequence(source.sequence)?
            .ok_or(refuse("slider-history-gap"))?;
        if row.authority != source || row.hash != proposal.evidence_digest {
            return Ok(false);
        }
        let body = aura::record::AuthorityBodyV1::parse(&row.body)?.payload;
        let Ok(id) = string(&body, "declined").and_then(ProposalId::from_hex) else {
            return Ok(false);
        };
        let previous = txn.proposal(&id)?;
        if previous.target != laya::slider::POLICY_TARGET
            || previous.new_bytes != proposal.new_bytes
            || previous.authority.sequence >= source.sequence
            || source.sequence >= proposal.authority.sequence
            || !gate::proposal::is_owner_again(&row, id, previous.operation_digest)?
        {
            return Ok(false);
        }
        proposal = previous;
    }
}

pub(crate) fn tighten(
    txn: &mut aura::LedgerTxn<'_>,
    state: &PolicyState,
    setting: SliderSetting,
) -> Result<()> {
    let mut candidate = state.policy.clone();
    candidate.setting = setting;
    if candidate.loosens(state.policy.setting) || setting == state.policy.setting {
        return Err(refuse("slider-tightening-required"));
    }
    let context = txn.observation_context()?;
    txn.append_fact(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: context.authority,
        at: context.at,
        kind: FactKind::BootFacts,
        actor: "owner".into(),
        body: Value::object(vec![
            ("schema".into(), Value::text(TIGHTEN_SCHEMA.into())?),
            ("setting".into(), Value::text(setting.wire_name().into())?),
            (
                "previous_sha256".into(),
                Value::text(Digest32::sha256(&state.policy.canonical_bytes()?).to_string())?,
            ),
        ])?,
    })?;
    Ok(())
}

fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == keys.len()
                && fields.iter().all(|(key, _)| keys.contains(&key.as_str())) =>
        {
            Ok(())
        }
        _ => Err(refuse("slider-record-invalid")),
    }
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(value)) => Ok(value),
        _ => Err(refuse("slider-record-invalid")),
    }
}
fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "supervisor",
        reason,
    }
}
