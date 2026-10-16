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
const GENESIS_STAGE_SCHEMA: &str = "aukora-floor-stage-v2";
const ADVANCE_SCHEMA: &str = "aukora-floor-advance-v1";
const STAGE_MAX: usize = crate::state::STATE_MAX_BYTES + 1024;

pub struct FloorService {
    store: store::Store,
}

impl FloorService {
    /// Row 65: open through safe no-follow directory descriptors, lock, validate owner,
    /// permissions and bounded bytes. An empty store awaits an authorized transition.
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
        self.unstaged_state()?.ok_or_else(|| refuse("absent"))
    }

    fn unstaged_state(&self) -> Result<Option<ProtectedState>> {
        if self.store.read(PENDING_FILE, STAGE_MAX)?.is_some() {
            return Err(refuse("recovery-ledger-required"));
        }
        self.read_state()
    }

    /// Read-only source for the registered `floor.release-guard` health check.
    /// Success reports consistency with authenticated Aura rows; it grants no authority.
    pub fn probe_release_guard(&self, transaction: &aura::LedgerTxn<'_>) -> Result<()> {
        let state = self.snapshot()?;
        if transaction.floor_recovery_state()?.as_deref()
            != Some(state.canonical_bytes()?.as_slice())
        {
            return Err(refuse("ledger-state-mismatch"));
        }
        check_history(transaction, &state)
    }

    /// Record the verified install before claim. The supervisor holds the claim-store
    /// lock; Aura independently refuses any owner or earlier floor in its transaction.
    pub fn initialize_from_install(
        &mut self,
        transaction: &mut aura::LedgerTxn<'_>,
        digest: Digest32,
    ) -> Result<AuthorityRecord> {
        if self.unstaged_state()?.is_some() || transaction.floor_recovery_state()?.is_some() {
            return Err(refuse("install-floor-exists"));
        }
        let (authority, at, signer_key_sha256) = transaction.floor_install_context()?;
        let record = PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority,
            at,
            kind: Kind::BootFacts,
            actor: "supervisor".into(),
            operation: None,
            phase: Phase::Fact,
            body: aura::record::AuthorityBodyV1 {
                algorithm: AlgorithmId::Sha256,
                authority,
                payload: object(vec![
                    ("schema", text("aukora-floor-install-v1")?),
                    ("origin", text("install")?),
                    ("owner", Value::null()),
                    ("digest", text(digest)?),
                ])?,
            }
            .canonical_value()?,
        };
        let head = expected_hash(&record)?;
        let state = ProtectedState {
            schema: crate::state::INSTALL_STATE_SCHEMA.into(),
            algorithm: AlgorithmId::Sha256,
            authority,
            floor: crate::Floor {
                digest,
                record: digest,
                signer_epoch: 0,
                ledger_seq: authority.sequence,
                signer_key_sha256,
                ledger_hash: head,
                history: Vec::new(),
            },
            high_water: crate::HighWater {
                highest_epoch: 0,
                highest_sequence: authority.sequence,
                head,
                credentials: Vec::new(),
                spent: Vec::new(),
            },
        };
        let next_bytes = state.canonical_bytes()?;
        let stage = Stage {
            transaction: transaction.transaction_id(),
            previous: None,
            state,
        };
        let stage_bytes = stage.bytes()?;
        let outcome = (|| {
            self.store.write_new(PENDING_FILE, &stage_bytes)?;
            let appended = transaction.stage_install_floor(&next_bytes, record)?;
            check_receipt(&appended, &stage.state)?;
            self.publish_state(None, &next_bytes)?;
            Ok(appended)
        })();
        if outcome.is_err() {
            transaction.abort_floor_transition()?;
            self.restore_state(None, &next_bytes)?;
            self.store.discard_stage(&stage_bytes)?;
        }
        outcome
    }

    /// Row 65/110: verify exact Release action in a transaction with no prior append,
    /// reject any spent proposal or authorization, then stage floor and high-water
    /// persistence with the signed floor.advance record. No filesystem effect is
    /// authorized by the unsigned `ReleaseOrder`. Publication follows append; the
    /// caller must commit Aura and reconcile through a fresh transaction before
    /// snapshots are available. The recovery stage remains until then.
    pub fn advance(
        &mut self,
        transaction: &mut aura::LedgerTxn<'_>,
        proof: VerifiedProof,
        proposed: &ReleaseOrder,
    ) -> Result<AuthorityRecord> {
        let current = self.unstaged_state()?;
        let old_bytes = current
            .as_ref()
            .map(ProtectedState::canonical_bytes)
            .transpose()?;
        if transaction.floor_recovery_state()? != old_bytes {
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
            || current
                .as_ref()
                .is_some_and(|state| auth.epoch < state.high_water.highest_epoch)
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
            || current.as_ref().is_some_and(|state| {
                state.high_water.spent.iter().any(|spent| {
                    spent.operation == proposal.operation
                        || spent.proposal == auth.proposal
                        || spent.authorization_sha256 == approval
                })
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
        if let Some(current) = &current {
            let prior = transaction.record_at(current.authority)?;
            check_receipt(&prior, current)?;
        }
        let floor = successor_floor(current.as_ref(), proposed)?;
        let context = transaction.authority_append_context(&proof)?;
        if context.operation_id != proposal.operation
            || context.authority.epoch != auth.epoch
            || current.as_ref().is_some_and(|state| {
                context.authority.sequence <= state.high_water.highest_sequence
            })
            || source.authority.sequence >= context.authority.sequence
            || !(0..=json::MAX_SAFE_INTEGER).contains(&context.at)
        {
            return Err(refuse("high-water-predecessor"));
        }
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
        let mut high_water = crate::HighWater {
            highest_epoch: context.authority.epoch,
            highest_sequence: context.authority.sequence,
            head: expected_hash(&record)?,
            credentials: current
                .as_ref()
                .map_or_else(Vec::new, |state| state.high_water.credentials.clone()),
            spent: current
                .as_ref()
                .map_or_else(Vec::new, |state| state.high_water.spent.clone()),
        };
        pin_credential(&mut high_water, &proof)?;
        high_water.spent.push(SpentApproval {
            algorithm: proof.algorithm(),
            authority: context.authority,
            operation: proposal.operation,
            proposal: auth.proposal,
            authorization_sha256: approval,
        });
        let next = ProtectedState {
            schema: crate::state::STATE_SCHEMA.into(),
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            floor,
            high_water,
        };
        if let Some(current) = &current {
            current.high_water.validate_successor(&next.high_water)?;
        }
        let next_bytes = next.canonical_bytes()?;
        let stage = Stage {
            transaction: transaction.transaction_id(),
            previous: old_bytes.as_deref().map(Digest32::sha256),
            state: next,
        };
        let stage_bytes = stage.bytes()?;
        // Publication can fail after rename, so it shares Aura's rollback path.
        let outcome = (|| {
            self.store.write_new(PENDING_FILE, &stage_bytes)?;
            transaction.persist_counter(&proof)?;
            transaction.consume(&proof)?;
            transaction.stage_floor(&proof, stage.previous, &next_bytes)?;
            let appended = transaction.append(proof, record)?;
            check_receipt(&appended, &stage.state)?;
            self.publish_state(current.as_ref(), &next_bytes)?;
            Ok(appended)
        })();
        if outcome.is_err() {
            transaction.abort_floor_transition()?;
            self.restore_state(old_bytes.as_deref(), &next_bytes)?;
            self.store.discard_stage(&stage_bytes)?;
        }
        outcome
    }

    /// Finish an exact consumed release using a fresh, unchanged Aura transaction.
    /// Discard an aborted stage only with its retained predecessor and no spent identity.
    pub fn reconcile(&mut self, transaction: &mut aura::LedgerTxn<'_>) -> Result<ProtectedState> {
        let current = self.read_state()?;
        let old_bytes = current
            .as_ref()
            .map(ProtectedState::canonical_bytes)
            .transpose()?;
        let committed = transaction.floor_recovery_state()?;
        let Some(bytes) = self.store.read(PENDING_FILE, STAGE_MAX)? else {
            if committed != old_bytes {
                return Err(refuse("ledger-state-mismatch"));
            }
            let current = current.ok_or_else(|| refuse("absent"))?;
            check_history(transaction, &current)?;
            return Ok(current);
        };
        let stage = Stage::parse(&bytes)?;
        if stage.transaction == transaction.transaction_id() {
            return Err(refuse("uncommitted-stage"));
        }
        let next_bytes = stage.state.canonical_bytes()?;
        if committed.as_deref() == Some(next_bytes.as_slice()) {
            if old_bytes.as_deref() != Some(next_bytes.as_slice()) {
                if old_bytes.as_deref().map(Digest32::sha256) != stage.previous {
                    return Err(refuse("stage-conflict"));
                }
                check_successor(current.as_ref(), &stage.state)?;
            } else if stage.previous.is_none() {
                check_successor(None, &stage.state)?;
            }
            check_history(transaction, &stage.state)?;
            if old_bytes.as_deref() != Some(next_bytes.as_slice()) {
                self.publish_state(current.as_ref(), &next_bytes)?;
            }
            self.store.remove(PENDING_FILE)?;
            return Ok(stage.state);
        }
        if committed.as_deref().map(Digest32::sha256) != stage.previous {
            return Err(refuse("recovery-ledger-mismatch"));
        }
        if old_bytes != committed && old_bytes.as_deref() != Some(next_bytes.as_slice()) {
            return Err(refuse("stage-conflict"));
        }
        let predecessor = committed
            .as_deref()
            .map(ProtectedState::parse)
            .transpose()?;
        if let Some(predecessor) = &predecessor {
            check_history(transaction, predecessor)?;
        }
        check_successor(predecessor.as_ref(), &stage.state)?;
        check_aborted(transaction, &stage)?;
        self.restore_state(committed.as_deref(), &next_bytes)?;
        self.store.discard_stage(&bytes)?;
        predecessor.ok_or_else(|| refuse("absent"))
    }

    /// Compatibility entry point for callers finishing a committed advance.
    pub fn reconcile_committed(
        &mut self,
        transaction: &mut aura::LedgerTxn<'_>,
    ) -> Result<ProtectedState> {
        self.reconcile(transaction)
    }

    fn read_state(&self) -> Result<Option<ProtectedState>> {
        self.store
            .read(STATE_FILE, crate::state::STATE_MAX_BYTES)?
            .as_deref()
            .map(ProtectedState::parse)
            .transpose()
    }

    fn publish_state(&self, current: Option<&ProtectedState>, next: &[u8]) -> Result<()> {
        match current {
            Some(_) => self.store.replace(STATE_FILE, next),
            None => self.store.write_new(STATE_FILE, next),
        }
    }

    fn restore_state(&self, previous: Option<&[u8]>, next: &[u8]) -> Result<()> {
        let stored = self.store.read(STATE_FILE, crate::state::STATE_MAX_BYTES)?;
        if stored.as_deref() == previous {
            return Ok(());
        }
        if stored.as_deref() != Some(next) {
            return Err(refuse("stage-conflict"));
        }
        match previous {
            Some(bytes) => self.store.replace(STATE_FILE, bytes),
            None => self.store.remove(STATE_FILE),
        }
    }
}

fn check_successor(current: Option<&ProtectedState>, next: &ProtectedState) -> Result<()> {
    next.validate()?;
    if next.is_install_genesis() {
        return if current.is_none() {
            Ok(())
        } else {
            Err(refuse("stage-conflict"))
        };
    }
    let retained = match current {
        Some(current) => {
            current.high_water.validate_successor(&next.high_water)?;
            current.high_water.spent.len()
        }
        None => {
            if next.high_water.credentials.len() != 1 {
                return Err(refuse("stage-conflict"));
            }
            0
        }
    };
    if successor_floor(current, &release_order(next))? != next.floor
        || next.high_water.spent.len() != retained + 1
    {
        return Err(refuse("stage-conflict"));
    }
    Ok(())
}

fn successor_floor(
    current: Option<&ProtectedState>,
    proposed: &ReleaseOrder,
) -> Result<crate::Floor> {
    if let Some(install) = current.filter(|state| state.is_install_genesis()) {
        install.validate()?;
        if proposed.ledger_seq <= install.floor.ledger_seq {
            return Err(refuse("high-water-predecessor"));
        }
        let mut next = advance_floor(None, proposed)?;
        if next.digest != install.floor.digest {
            next.history.push(install.floor.digest);
        }
        return Ok(next);
    }
    advance_floor(current.map(|state| &state.floor), proposed)
}

fn check_history(transaction: &aura::LedgerTxn<'_>, state: &ProtectedState) -> Result<()> {
    check_receipt(&transaction.record_at(state.authority)?, state)?;
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
            || transaction.floor_consumption(
                spent.authorization_sha256,
                spent.proposal,
                spent.operation,
            )? != Some(spent.authority)
        {
            return Err(refuse("receipt-mismatch"));
        }
    }
    Ok(())
}

fn check_aborted(transaction: &aura::LedgerTxn<'_>, stage: &Stage) -> Result<()> {
    let authority = stage.state.authority;
    if stage.state.is_install_genesis() {
        let next = transaction.current_version()?;
        let predecessor = if authority.sequence == 1 {
            None
        } else {
            Some(
                transaction
                    .floor_record_at_sequence(authority.sequence - 1)?
                    .ok_or_else(|| refuse("recovery-ledger-mismatch"))?
                    .hash,
            )
        };
        if stage.previous.is_some()
            || next.sequence < authority.sequence
            || predecessor != authority.previous_hash
            || transaction
                .floor_record_at_sequence(authority.sequence)?
                .is_some_and(|row| row.hash == stage.state.high_water.head)
        {
            return Err(refuse("recovery-ledger-mismatch"));
        }
        return Ok(());
    }
    let spent = stage
        .state
        .high_water
        .spent
        .iter()
        .find(|spent| spent.authority == authority)
        .ok_or_else(|| refuse("stage-conflict"))?;
    let next = transaction.current_version()?;
    let prior = transaction
        .floor_record_at_sequence(authority.sequence.saturating_sub(1))?
        .ok_or_else(|| refuse("recovery-ledger-mismatch"))?;
    let occupant = transaction.floor_record_at_sequence(authority.sequence)?;
    if let Some(terminal) = transaction.gate_terminal(&spent.operation)? {
        let body = payload(&terminal.body)?;
        let expected = match terminal.kind {
            Kind::GateExpire => "expired",
            Kind::GateRefuse => "refused",
            _ => return Err(refuse("recovery-ledger-mismatch")),
        };
        if field_text(body, "proposal") != Some(spent.proposal.to_string().as_str())
            || field_text(body, "state") != Some(expected)
        {
            return Err(refuse("recovery-ledger-mismatch"));
        }
    }
    if next.epoch < authority.epoch
        || next.sequence < authority.sequence
        || Some(prior.hash) != authority.previous_hash
        || prior.authority.epoch > authority.epoch
        || occupant.is_some_and(|row| row.hash == stage.state.high_water.head)
        || transaction
            .floor_consumption(spent.authorization_sha256, spent.proposal, spent.operation)?
            .is_some()
    {
        return Err(refuse("recovery-ledger-mismatch"));
    }
    Ok(())
}

fn release_order(state: &ProtectedState) -> ReleaseOrder {
    ReleaseOrder {
        digest: state.floor.digest,
        record: state.floor.record,
        signer_epoch: state.floor.signer_epoch,
        ledger_seq: state.floor.ledger_seq,
        signer_key_sha256: state.floor.signer_key_sha256,
        ledger_hash: state.floor.ledger_hash,
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
    if state.is_install_genesis() {
        state.validate()?;
        let expected = object(vec![
            ("schema", text("aukora-floor-install-v1")?),
            ("origin", text("install")?),
            ("owner", Value::null()),
            ("digest", text(state.floor.digest)?),
        ])?;
        if record.v != 1
            || record.algorithm != AlgorithmId::Sha256
            || record.authority != state.authority
            || record.hash != state.high_water.head
            || record.kind != Kind::BootFacts
            || record.phase != Phase::Fact
            || record.operation.is_some()
            || record.actor != "supervisor"
            || body != &expected
        {
            return Err(refuse("receipt-mismatch"));
        }
        return Ok(());
    }
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
    previous: Option<Digest32>,
    state: ProtectedState,
}

impl Stage {
    fn bytes(&self) -> Result<Vec<u8>> {
        let (schema, previous) = match self.previous {
            Some(previous) => (STAGE_SCHEMA, text(previous)?),
            None => (GENESIS_STAGE_SCHEMA, Value::null()),
        };
        let value = object(vec![
            ("schema", text(schema)?),
            ("transaction", text(self.transaction)?),
            ("previous", previous),
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
        if bytes.len() > STAGE_MAX || json::to_canonical(&value) != bytes || fields.len() != 4 {
            return Err(refuse("stage-malformed"));
        }
        let hash = |name| {
            field_text(&value, name)
                .ok_or_else(|| refuse("stage-malformed"))
                .and_then(|value| Digest32::from_hex(value).map_err(|_| refuse("stage-malformed")))
        };
        let previous = match field_text(&value, "schema") {
            Some(STAGE_SCHEMA) => Some(hash("previous")?),
            Some(GENESIS_STAGE_SCHEMA)
                if matches!(
                    value.get("previous").map(Value::view),
                    Some(ValueView::Null)
                ) =>
            {
                None
            }
            _ => return Err(refuse("stage-malformed")),
        };
        let state = value
            .get("state")
            .ok_or_else(|| refuse("stage-malformed"))?;
        Ok(Self {
            transaction: hash("transaction")?,
            previous,
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
