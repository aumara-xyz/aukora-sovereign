// SPDX-License-Identifier: AGPL-3.0-or-later
//! Protected persistence contracts. A path or a successful order check is not authority.

mod store;

use crate::{
    advance_floor, refuse, state::CredentialHighWater, ProtectedState, ReleaseOrder, Result,
    SpentApproval,
};
use canon::{
    alg::AlgorithmId,
    authority::{
        AuthorityRecord, AuthorityTxn, Kind, OwnerOperation, PendingAuthorityRecord, Phase,
        VerifiedProof,
    },
    digest::Digest32,
    json::{self, Value, ValueView},
};
use std::path::Path;

const STATE_FILE: &str = "floor-state.json";
const PENDING_FILE: &str = "floor-stage.json";
const STAGE_SCHEMA: &str = "aukora-floor-stage-v1";
const ADVANCE_SCHEMA: &str = "aukora-floor-advance-v1";
const STAGE_MAX: usize = crate::state::STATE_MAX_BYTES + 1024;

pub struct FloorService {
    store: store::Store,
}

impl FloorService {
    /// Row 65: open through safe no-follow directory descriptors, lock, validate owner,
    /// permissions and bounded bytes. Missing protected state refuses; do not bootstrap.
    pub fn open(directory: &Path) -> Result<Self> {
        let service = Self {
            store: store::Store::open(directory)?,
        };
        service.read_state()?;
        if let Some(bytes) = service.store.read(PENDING_FILE, STAGE_MAX)? {
            Stage::parse(&bytes)?;
        }
        Ok(service)
    }

    pub fn snapshot(&self) -> Result<ProtectedState> {
        if self.store.read(PENDING_FILE, STAGE_MAX)?.is_some() {
            return Err(refuse("recovery-ledger-required"));
        }
        self.read_state()
    }

    /// Read-only source for the registered `floor.release-guard` health check.
    /// Success reports consistency with authenticated Aura rows; it grants no authority.
    pub fn probe_release_guard(&self, transaction: &aura::LedgerTxn<'_>) -> Result<()> {
        let state = self.snapshot()?;
        if transaction.floor_state()?.as_deref() != Some(state.canonical_bytes()?.as_slice()) {
            return Err(refuse("ledger-state-mismatch"));
        }
        check_receipt(&transaction.record_at(state.authority)?, &state)?;
        for spent in &state.high_water.spent {
            let row = transaction.record_at(spent.authority)?;
            let body = payload(&row.body)?;
            if row.kind != Kind::FloorAdvance
                || row.phase != Phase::Terminal
                || row.operation != Some(spent.operation)
                || field_text(body, "schema") != Some(ADVANCE_SCHEMA)
                || field_text(body, "proposal") != Some(spent.proposal.to_string().as_str())
                || field_text(body, "authorization_sha256")
                    != Some(spent.authorization_sha256.to_string().as_str())
            {
                return Err(refuse("receipt-mismatch"));
            }
        }
        Ok(())
    }

    /// Row 65/110: verify exact Release action and matching authority transaction,
    /// reject any spent proposal or authorization, then stage floor and high-water
    /// persistence with the signed floor.advance record. No filesystem effect is
    /// authorized by the unsigned `ReleaseOrder`; a failure rolls back the stage.
    pub fn advance(
        &mut self,
        transaction: &mut aura::LedgerTxn<'_>,
        proof: VerifiedProof,
        proposed: &ReleaseOrder,
    ) -> Result<AuthorityRecord> {
        let current = self.snapshot()?;
        let old_bytes = current.canonical_bytes()?;
        if transaction.floor_state()?.as_deref() != Some(old_bytes.as_slice()) {
            return Err(refuse("ledger-state-mismatch"));
        }
        if transaction.transaction_id() != proof.transaction_id() {
            return Err(refuse("proof-transaction"));
        }
        proposed.validate()?;
        let auth = proof.authorization();
        let proposal = transaction.proposal(&auth.proposal)?;
        if auth.op != OwnerOperation::Release
            || auth.target != "release"
            || auth.cell.is_some()
            || auth.algorithm != AlgorithmId::Sha256
            || auth.new_sha256 != proposed.record
            || auth.epoch != proposed.signer_epoch
            || auth.epoch < current.high_water.highest_epoch
            || proposal.target != auth.target
            || proposal.cell.is_some()
            || proposal.base_sha256 != auth.base_sha256
            || proposal.operation_digest != auth.operation
            || proposal.status != aura::storage::ProposalStatus::Pending
            || Digest32::sha256(&proposal.new_bytes) != proposed.record
        {
            return Err(refuse("release-binding"));
        }
        release_pointer(&proposal.new_bytes, proposed.digest)?;
        let approval = Digest32::sha256(proof.authorization_bytes());
        if auth.canonical_bytes()?.as_slice() != proof.authorization_bytes()
            || current.high_water.spent.iter().any(|spent| {
                spent.operation == proposal.operation
                    || spent.proposal == auth.proposal
                    || spent.authorization_sha256 == approval
            })
        {
            return Err(refuse("approval-spent"));
        }
        // Ordering evidence must be a retained terminal, never a caller's claimed hash.
        let source = transaction
            .floor_record_at_sequence(proposed.ledger_seq)?
            .ok_or_else(|| refuse("ordering-evidence"))?;
        let source_body = payload(&source.body)?;
        if source.authority.epoch != proposed.signer_epoch
            || source.authority.sequence != proposed.ledger_seq
            || source.hash != proposed.ledger_hash
            || !matches!(source.kind, Kind::GateApply | Kind::GateRecover)
            || source.phase != Phase::Terminal
            || field_text(source_body, "target") != Some("release")
            || field_text(source_body, "state") != Some("applied")
            || field_text(source_body, "new_sha256") != Some(proposed.record.to_string().as_str())
        {
            return Err(refuse("ordering-evidence"));
        }
        let signing_keys = transaction.floor_signing_keys()?;
        let ed25519: Vec<_> = signing_keys
            .iter()
            .filter(|key| key.algorithm == AlgorithmId::Ed25519)
            .collect();
        if ed25519.len() != 1
            || !ed25519.iter().any(|key| {
                key.v == 1
                    && key.algorithm == AlgorithmId::Ed25519
                    && key.bytes.len() == 32
                    && Digest32::sha256(&key.bytes) == proposed.signer_key_sha256
            })
        {
            return Err(refuse("signer-epoch-mismatch"));
        }
        aura::record::verify_record(&source, &signing_keys)?;
        let prior = transaction.record_at(current.authority)?;
        check_receipt(&prior, &current)?;
        let floor = advance_floor(Some(&current.floor), proposed)?;
        let context = transaction.floor_append_context(&proof)?;
        if context.operation_id != proposal.operation
            || context.authority.epoch != auth.epoch
            || context.authority.sequence <= current.high_water.highest_sequence
            || source.authority.sequence >= context.authority.sequence
            || !(0..=json::MAX_SAFE_INTEGER).contains(&context.at)
        {
            return Err(refuse("high-water-predecessor"));
        }
        let mut high_water = current.high_water.clone();
        pin_credential(&mut high_water, &proof)?;
        high_water.highest_epoch = context.authority.epoch;
        high_water.highest_sequence = context.authority.sequence;
        high_water.spent.push(SpentApproval {
            algorithm: proof.algorithm(),
            authority: context.authority,
            operation: proposal.operation,
            proposal: auth.proposal,
            authorization_sha256: approval,
        });
        let record = PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: Kind::FloorAdvance,
            actor: auth.subject.to_string(),
            operation: Some(proposal.operation),
            phase: Phase::Terminal,
            body: aura::record::AuthorityBodyV1 {
                algorithm: AlgorithmId::Sha256,
                authority: context.authority,
                payload: object(vec![
                    ("schema", text(ADVANCE_SCHEMA)?),
                    ("floor", json::parse_strict(&floor.canonical_bytes()?)?),
                    ("proposal", text(auth.proposal)?),
                    ("authorization_sha256", text(approval)?),
                ])?,
            }
            .canonical_value()?,
        };
        high_water.head = expected_hash(&record)?;
        let next = ProtectedState {
            schema: crate::state::STATE_SCHEMA.into(),
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            floor,
            high_water,
        };
        current.high_water.validate_successor(&next.high_water)?;
        let next_bytes = next.canonical_bytes()?;
        let stage = Stage {
            transaction: transaction.transaction_id(),
            previous: Digest32::sha256(&old_bytes),
            state: next,
        };
        // The stage is durable before Aura can commit; it cannot be read as installed state.
        self.store.write_new(PENDING_FILE, &stage.bytes()?)?;
        transaction.persist_counter(&proof)?;
        transaction.consume(&proof)?;
        transaction.stage_floor(&proof, Some(stage.previous), &next_bytes)?;
        let appended = transaction.append(proof, record)?;
        check_receipt(&appended, &stage.state)?;
        Ok(appended)
    }

    /// Row 65: interrupted release recovery can reconcile an already-consumed exact
    /// release only. It cannot reset high-water state or revive spent authority.
    pub fn reconcile(&mut self) -> Result<ProtectedState> {
        self.snapshot()
    }

    /// Finish only from a fresh transaction after the caller committed `advance`.
    /// A rolled-back stage can be discarded only at its unchanged append predecessor.
    pub fn reconcile_committed(
        &mut self,
        transaction: &mut aura::LedgerTxn<'_>,
    ) -> Result<ProtectedState> {
        let current = self.read_state()?;
        let Some(bytes) = self.store.read(PENDING_FILE, STAGE_MAX)? else {
            let stored = current.canonical_bytes()?;
            if transaction.floor_state()?.as_deref() != Some(stored.as_slice()) {
                return Err(refuse("ledger-state-mismatch"));
            }
            check_receipt(&transaction.record_at(current.authority)?, &current)?;
            return Ok(current);
        };
        let stage = Stage::parse(&bytes)?;
        if stage.transaction == transaction.transaction_id() {
            return Err(refuse("uncommitted-stage"));
        }
        let old_bytes = current.canonical_bytes()?;
        let next_bytes = stage.state.canonical_bytes()?;
        let current_hash = Digest32::sha256(&old_bytes);
        if current_hash != stage.previous && old_bytes != next_bytes {
            return Err(refuse("stage-conflict"));
        }
        let committed = transaction.floor_state()?.ok_or_else(|| refuse("absent"))?;
        if committed != next_bytes {
            if committed == old_bytes && current_hash == stage.previous {
                let next = transaction.current_version()?;
                let occupant =
                    transaction.floor_record_at_sequence(stage.state.authority.sequence)?;
                let not_appended = match occupant {
                    Some(row) => row.hash != stage.state.high_water.head,
                    None => next.sequence <= stage.state.authority.sequence,
                };
                if not_appended {
                    self.store.remove(PENDING_FILE)?;
                    return Ok(current);
                }
            }
            return Err(refuse("recovery-ledger-mismatch"));
        }
        if old_bytes != next_bytes {
            current
                .high_water
                .validate_successor(&stage.state.high_water)?;
        }
        check_receipt(&transaction.record_at(stage.state.authority)?, &stage.state)?;
        if old_bytes != next_bytes {
            self.store.replace(STATE_FILE, &next_bytes)?;
        }
        self.store.remove(PENDING_FILE)?;
        Ok(stage.state)
    }

    fn read_state(&self) -> Result<ProtectedState> {
        let bytes = self
            .store
            .read(STATE_FILE, crate::state::STATE_MAX_BYTES)?
            .ok_or_else(|| refuse("absent"))?;
        ProtectedState::parse(&bytes)
    }
}

fn pin_credential(high_water: &mut crate::HighWater, proof: &VerifiedProof) -> Result<()> {
    let key_sha256 = Digest32::sha256(&proof.public_key().bytes);
    let epoch = proof.authorization().epoch;
    if let Some(pin) = high_water
        .credentials
        .iter_mut()
        .find(|pin| &pin.credential == proof.credential_id())
    {
        if pin.key_sha256 != key_sha256 || pin.algorithm != proof.algorithm() || epoch < pin.epoch {
            return Err(refuse("credential-not-pinned"));
        }
        if pin.counter != 0 && proof.sign_counter() <= pin.counter {
            return Err(refuse("counter-replayed"));
        }
        pin.epoch = epoch;
        pin.counter = proof.sign_counter();
    } else {
        high_water.credentials.push(CredentialHighWater {
            credential: proof.credential_id().clone(),
            algorithm: proof.algorithm(),
            key_sha256,
            epoch,
            counter: proof.sign_counter(),
        });
    }
    Ok(())
}

fn expected_hash(record: &PendingAuthorityRecord) -> Result<Digest32> {
    aura::record::entry_hash_v1(&aura::export::RowV1 {
        sequence: record.authority.sequence,
        previous: record.authority.previous_hash,
        hash: Digest32::from_bytes([0; 32]),
        signature: [0; 64],
        at: record.at,
        kind: record.kind,
        actor: record.actor.clone(),
        operation: record.operation,
        phase: record.phase,
        body: record.body.clone(),
    })
}

fn check_receipt(record: &AuthorityRecord, state: &ProtectedState) -> Result<()> {
    let body = payload(&record.body)?;
    let spent = state
        .high_water
        .spent
        .iter()
        .find(|spent| spent.authority == state.authority)
        .ok_or_else(|| refuse("receipt-mismatch"))?;
    if record.v != 1
        || record.algorithm != AlgorithmId::Sha256
        || record.authority != state.authority
        || record.hash != state.high_water.head
        || record.kind != Kind::FloorAdvance
        || record.phase != Phase::Terminal
        || record.operation != Some(spent.operation)
        || field_text(body, "schema") != Some(ADVANCE_SCHEMA)
        || field_text(body, "proposal") != Some(spent.proposal.to_string().as_str())
        || field_text(body, "authorization_sha256")
            != Some(spent.authorization_sha256.to_string().as_str())
        || body.get("floor").map(json::to_canonical) != Some(state.floor.canonical_bytes()?)
    {
        return Err(refuse("receipt-mismatch"));
    }
    Ok(())
}

fn release_pointer(bytes: &[u8], digest: Digest32) -> Result<()> {
    let pointer = json::parse_strict(bytes).map_err(|_| refuse("release-record"))?;
    let ValueView::Object(fields) = pointer.view() else {
        return Err(refuse("release-record"));
    };
    if json::to_canonical(&pointer) != bytes
        || !(2..=3).contains(&fields.len())
        || fields
            .iter()
            .any(|(key, _)| !["v", "digest", "components"].contains(&key.as_str()))
        || !matches!(pointer.get("v").map(Value::view), Some(ValueView::Integer(v)) if v.get() == 1)
        || field_text(&pointer, "digest") != Some(digest.to_string().as_str())
    {
        return Err(refuse("release-record"));
    }
    if let Some(components) = pointer.get("components") {
        let ValueView::Object(fields) = components.view() else {
            return Err(refuse("release-record"));
        };
        if fields.len() != 3 || fields.iter().any(|(key, value)| {
            !["node", "harness", "guest"].contains(&key.as_str())
                || !matches!(value.view(), ValueView::Text(text) if Digest32::from_hex(text).is_ok())
        }) {
            return Err(refuse("release-record"));
        }
    }
    Ok(())
}

struct Stage {
    transaction: Digest32,
    previous: Digest32,
    state: ProtectedState,
}

impl Stage {
    fn bytes(&self) -> Result<Vec<u8>> {
        let value = object(vec![
            ("schema", text(STAGE_SCHEMA)?),
            ("transaction", text(self.transaction)?),
            ("previous", text(self.previous)?),
            ("state", json::parse_strict(&self.state.canonical_bytes()?)?),
        ])?;
        let bytes = json::to_canonical(&value);
        if bytes.len() > STAGE_MAX {
            return Err(refuse("high-water-full"));
        }
        Ok(bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let value = json::parse_strict(bytes).map_err(|_| refuse("stage-malformed"))?;
        let ValueView::Object(fields) = value.view() else {
            return Err(refuse("stage-malformed"));
        };
        if bytes.len() > STAGE_MAX
            || json::to_canonical(&value) != bytes
            || fields.len() != 4
            || field_text(&value, "schema") != Some(STAGE_SCHEMA)
        {
            return Err(refuse("stage-malformed"));
        }
        let hash = |name| {
            field_text(&value, name)
                .ok_or_else(|| refuse("stage-malformed"))
                .and_then(|value| Digest32::from_hex(value).map_err(|_| refuse("stage-malformed")))
        };
        let state = value
            .get("state")
            .ok_or_else(|| refuse("stage-malformed"))?;
        Ok(Self {
            transaction: hash("transaction")?,
            previous: hash("previous")?,
            state: ProtectedState::parse(&json::to_canonical(state))?,
        })
    }
}

fn payload(value: &Value) -> Result<&Value> {
    let wrapper = aura::record::AuthorityBodyV1::parse(value)?;
    if wrapper.algorithm != AlgorithmId::Sha256 {
        return Err(refuse("receipt-mismatch"));
    }
    value
        .get("payload")
        .ok_or_else(|| refuse("receipt-mismatch"))
}

fn field_text<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    match value.get(name)?.view() {
        ValueView::Text(value) => Some(value),
        _ => None,
    }
}

fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}
fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
