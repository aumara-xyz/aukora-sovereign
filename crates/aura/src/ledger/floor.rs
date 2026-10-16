// SPDX-License-Identifier: AGPL-3.0-or-later
//! Install genesis and owner-approved releases share signed transactional storage.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    alg::AlgorithmId,
    authority::{Kind, OwnerOperation, PendingAuthorityRecord, Phase},
    ids::ProposalId,
    json::{self, Value, ValueView},
};
use rusqlite::{params, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet};
mod genesis;

const INSTALL_STATE: &str = "aukora-floor-install-state-v1";
const INSTALL_RECORD: &str = "aukora-floor-install-v1";

impl LedgerTxn<'_> {
    /// An install context exists only before any owner or previous release floor.
    pub fn floor_install_context(&self) -> Result<(AuthorityVersion, i64, Digest32)> {
        self.active()?;
        if self.state.epoch != 0
            || self.state.next()? != self.retained.next()?
            || self.transaction.total_changes() != self.observation_start_changes
            || !self.counters.is_empty()
            || !self.consumptions.is_empty()
            || self.floor_obligation.is_some()
            || self.target_observation.is_some()
            || self.floor_state()?.is_some()
        {
            return Err(refusal("floor-install-context"));
        }
        let occupied: bool = self.transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_bindings) OR EXISTS(SELECT 1 FROM aura WHERE kind IN ('aumlok.enrol','aumlok.bind','floor.advance'))",
            [], |row| row.get(0),
        ).map_err(sql)?;
        if occupied {
            return Err(refusal("floor-install-owner"));
        }
        let mut statement = self
            .transaction
            .prepare("SELECT seq FROM aura WHERE kind='boot.facts' ORDER BY seq")
            .map_err(sql)?;
        let sequences = statement
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(sql)?;
        for sequence in sequences {
            let sequence = u64::try_from(sequence.map_err(sql)?)
                .map_err(|_| refusal("floor-install-history"))?;
            let record = io::record_at(&self.transaction, sequence)?;
            if super::gate_payload(&record.body)
                .get("schema")
                .is_some_and(|value| matches!(value.view(), ValueView::Text(INSTALL_RECORD)))
            {
                return Err(refusal("floor-install-repeated"));
            }
        }
        let keys = self.services.signer.public_keys()?;
        let keys = keys
            .iter()
            .filter(|key| key.algorithm == AlgorithmId::Ed25519)
            .collect::<Vec<_>>();
        if keys.len() != 1 {
            return Err(refusal("floor-signer"));
        }
        Ok((
            self.current_version()?,
            self.services.clock.now_ms()?,
            Digest32::sha256(&keys[0].bytes),
        ))
    }

    /// Persist the first install floor and its signed receipt in this transaction.
    pub fn stage_install_floor(
        &mut self,
        next_state_bytes: &[u8],
        pending: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.mutate(|this| {
            let (context, _, signer) = this.floor_install_context()?;
            let next = state(next_state_bytes)?;
            let floor = member(&next, "floor")?;
            if field_text(&next, "schema")? != INSTALL_STATE
                || authority(member(&next, "authority")?)? != context
                || hash(floor, "signer_key_sha256")? != signer
                || pending.authority != context
                || pending.kind != Kind::BootFacts
                || pending.phase != Phase::Fact
                || pending.operation.is_some()
                || pending.actor != "supervisor"
            {
                return Err(refusal("floor-install-context"));
            }
            check_install_payload(super::gate_payload(&pending.body), hash(floor, "digest")?)?;
            let record = this.write_record(pending)?;
            check_install_record(&record, &next, signer)?;
            this.transaction
                .execute(
                    "INSERT INTO authority_floor(id,state) VALUES(1,?1)",
                    [next_state_bytes],
                )
                .map_err(sql)?;
            Ok(record)
        })
    }

    pub fn floor_state(&self) -> Result<Option<Vec<u8>>> {
        self.active()?;
        self.transaction
            .query_row("SELECT state FROM authority_floor WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sql)
    }

    pub fn stage_floor(
        &mut self,
        proof: &VerifiedProof,
        expected_state_digest: Option<Digest32>,
        next_state_bytes: &[u8],
    ) -> Result<()> {
        self.mutate(|this| {
            let auth = proof.authorization();
            let approval = Digest32::sha256(proof.authorization_bytes());
            if proof.transaction_id() != this.identity || auth.op != OwnerOperation::Release
                || auth.target != "release" || auth.cell.is_some() || auth.epoch != this.state.epoch
                || this.floor_obligation.is_some() || !this.consumptions.contains(&approval.to_string()) {
                return Err(refusal("floor-proof"));
            }
            let proposal = this.proposal(&auth.proposal)?;
            if proposal.status != crate::storage::ProposalStatus::Consumed
                || proposal.operation_digest != auth.operation || Digest32::sha256(&proposal.new_bytes) != auth.new_sha256 {
                return Err(refusal("floor-proposal"));
            }
            let consumed: i64 = this.transaction.query_row("SELECT count(*) FROM authority_consumptions WHERE approval=?1 AND proposal=?2 AND operation=?3 AND credential=?4 AND counter=?5 AND action='release' AND appended=0",
                params![approval.to_string(),auth.proposal.to_string(),proposal.operation.to_string(),URL_SAFE_NO_PAD.encode(proof.credential_id().as_bytes()),proof.sign_counter()],|row|row.get(0)).map_err(sql)?;
            if consumed != 1 { return Err(refusal("floor-consumption")); }
            let next = state(next_state_bytes)?;
            let next_context = authority(member(&next,"authority")?)?;
            if next_context != this.current_version()? { return Err(refusal("floor-context")); }
            let current_bytes = this.floor_state()?;
            if current_bytes.as_deref().map(Digest32::sha256) != expected_state_digest {
                return Err(refusal("floor-base"));
            }
            let current = current_bytes.as_deref().map(state).transpose()?;
            if let Some(current) = &current { this.verify_floor_history(current)?; }
            check_successor(current.as_ref(), &next, proof, proposal.operation)?;
            let floor = member(&next,"floor")?;
            if hash(floor,"record")? != auth.new_sha256 || positive(floor,"signer_epoch")? != auth.epoch {
                return Err(refusal("floor-release"));
            }
            release_pointer(&proposal.new_bytes,hash(floor,"digest")?)?;
            let source = this.record_at(authority_for_sequence(this,positive(floor,"ledger_seq")?)?)?;
            let payload = super::gate_payload(&source.body);
            if !genesis::release_proposal_source(current.as_ref(), &next, &source, &proposal)? {
            if source.hash != hash(floor,"ledger_hash")? || source.authority.epoch != positive(floor,"signer_epoch")?
                || !matches!(source.kind,Kind::GateApply|Kind::GateRecover) || source.phase != Phase::Terminal
                || field_text(payload,"target")? != "release" || field_text(payload,"state")? != "applied"
                || hash(payload,"new_sha256")? != auth.new_sha256 || source.authority.sequence >= next_context.sequence {
                return Err(refusal("floor-ordering"));
            }
            }
            let keys = this.services.signer.public_keys()?;
            let ed_keys = keys.iter().filter(|key|key.algorithm==AlgorithmId::Ed25519).collect::<Vec<_>>();
            if ed_keys.len()!=1 || Digest32::sha256(&ed_keys[0].bytes)!=hash(floor,"signer_key_sha256")? {
                return Err(refusal("floor-signer"));
            }
            this.transaction.execute("INSERT INTO authority_floor(id,state) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET state=excluded.state",[next_state_bytes]).map_err(sql)?;
            this.floor_obligation = Some(approval);
            Ok(())
        })
    }

    pub(super) fn check_floor_append(&self, proof: &VerifiedProof, body: &Value) -> Result<()> {
        let approval = Digest32::sha256(proof.authorization_bytes());
        if self.floor_obligation != Some(approval) {
            return Err(refusal("floor-not-staged"));
        }
        let bytes = self.floor_state()?.ok_or(refusal("floor-not-staged"))?;
        let staged = state(&bytes)?;
        exact(
            body,
            &["schema", "floor", "proposal", "authorization_sha256"],
        )?;
        if field_text(body, "schema")? != "aukora-floor-advance-v1"
            || field_text(body, "proposal")? != proof.authorization().proposal.to_string()
            || hash(body, "authorization_sha256")? != approval
            || member(body, "floor")? != member(&staged, "floor")?
        {
            return Err(refusal("floor-append"));
        }
        Ok(())
    }

    pub(super) fn check_floor_record(&mut self, record: &AuthorityRecord) -> Result<()> {
        let approval = self.floor_obligation.ok_or(refusal("floor-not-staged"))?;
        let bytes = self.floor_state()?.ok_or(refusal("floor-not-staged"))?;
        let staged = state(&bytes)?;
        let payload = super::gate_payload(&record.body);
        if record.kind != Kind::FloorAdvance
            || record.phase != Phase::Terminal
            || record.authority != authority(member(&staged, "authority")?)?
            || record.hash != hash(member(&staged, "high_water")?, "head")?
            || hash(payload, "authorization_sha256")? != approval
            || member(payload, "floor")? != member(&staged, "floor")?
        {
            return Err(refusal("floor-receipt"));
        }
        self.floor_obligation = None;
        Ok(())
    }

    fn verify_floor_history(&self, value: &Value) -> Result<()> {
        let high = member(value, "high_water")?;
        let context = authority(member(value, "authority")?)?;
        let head = self.record_at(context)?;
        if field_text(value, "schema")? == INSTALL_STATE {
            let prior_owner: bool = self.transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM aura WHERE seq<?1 AND kind IN ('aumlok.enrol','aumlok.bind')) OR EXISTS(SELECT 1 FROM aura WHERE kind='floor.advance')",
                [i64::try_from(context.sequence).map_err(|_| refusal("floor-context"))?],
                |row| row.get(0),
            ).map_err(sql)?;
            if prior_owner {
                return Err(refusal("floor-install-history"));
            }
            let mut statement = self
                .transaction
                .prepare("SELECT seq FROM aura WHERE seq!=?1 AND kind='boot.facts' ORDER BY seq")
                .map_err(sql)?;
            let sequences = statement
                .query_map(
                    [i64::try_from(context.sequence).map_err(|_| refusal("floor-context"))?],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(sql)?;
            for sequence in sequences {
                let sequence = u64::try_from(sequence.map_err(sql)?)
                    .map_err(|_| refusal("floor-install-history"))?;
                let record = io::record_at(&self.transaction, sequence)?;
                if super::gate_payload(&record.body)
                    .get("schema")
                    .is_some_and(|value| matches!(value.view(), ValueView::Text(INSTALL_RECORD)))
                {
                    return Err(refusal("floor-install-history"));
                }
            }
            let keys = self.services.signer.public_keys()?;
            let keys = keys
                .iter()
                .filter(|key| key.algorithm == AlgorithmId::Ed25519)
                .collect::<Vec<_>>();
            if keys.len() != 1 {
                return Err(refusal("floor-signer"));
            }
            return check_install_record(&head, value, Digest32::sha256(&keys[0].bytes));
        }
        if head.hash != hash(high, "head")?
            || member(super::gate_payload(&head.body), "floor")? != member(value, "floor")?
        {
            return Err(refusal("floor-retained-head"));
        }
        for spent in array(high, "spent")? {
            let record = self.record_at(authority(member(spent, "authority")?)?)?;
            let payload = super::gate_payload(&record.body);
            if record.kind != Kind::FloorAdvance
                || record.phase != Phase::Terminal
                || record.operation != Some(OperationId::from_hex(field_text(spent, "operation")?)?)
                || field_text(payload, "schema")? != "aukora-floor-advance-v1"
                || field_text(payload, "proposal")? != field_text(spent, "proposal")?
                || hash(payload, "authorization_sha256")? != hash(spent, "authorization_sha256")?
            {
                return Err(refusal("floor-retained-spent"));
            }
        }
        Ok(())
    }
}

fn authority_for_sequence(transaction: &LedgerTxn<'_>, sequence: u64) -> Result<AuthorityVersion> {
    Ok(io::record_at(&transaction.transaction, sequence)?.authority)
}

fn check_install_payload(payload: &Value, digest: Digest32) -> Result<()> {
    exact(payload, &["schema", "origin", "owner", "digest"])?;
    if field_text(payload, "schema")? != INSTALL_RECORD
        || field_text(payload, "origin")? != "install"
        || !matches!(member(payload, "owner")?.view(), ValueView::Null)
        || hash(payload, "digest")? != digest
    {
        return Err(refusal("floor-install-record"));
    }
    Ok(())
}

fn check_install_record(record: &AuthorityRecord, state: &Value, signer: Digest32) -> Result<()> {
    let context = authority(member(state, "authority")?)?;
    let floor = member(state, "floor")?;
    if record.kind != Kind::BootFacts
        || record.phase != Phase::Fact
        || record.actor != "supervisor"
        || record.operation.is_some()
        || record.authority != context
        || context.epoch != 0
        || record.hash != hash(floor, "ledger_hash")?
        || record.hash != hash(member(state, "high_water")?, "head")?
        || hash(floor, "signer_key_sha256")? != signer
    {
        return Err(refusal("floor-install-record"));
    }
    check_install_payload(super::gate_payload(&record.body), hash(floor, "digest")?)
}

fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(refusal("floor-format"))
}
fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(value) => Ok(value),
        _ => Err(refusal("floor-format")),
    }
}
fn field_text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    text(member(value, key)?)
}
fn number(value: &Value, key: &str) -> Result<u64> {
    match member(value, key)?.view() {
        ValueView::Integer(value) if value.get() >= 0 => Ok(value.get() as u64),
        _ => Err(refusal("floor-format")),
    }
}
fn positive(value: &Value, key: &str) -> Result<u64> {
    let number = number(value, key)?;
    if number == 0 {
        Err(refusal("floor-format"))
    } else {
        Ok(number)
    }
}
fn hash(value: &Value, key: &str) -> Result<Digest32> {
    Digest32::from_hex(field_text(value, key)?)
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    match member(value, key)?.view() {
        ValueView::Array(value) => Ok(value),
        _ => Err(refusal("floor-format")),
    }
}
fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == keys.len()
                && members.iter().all(|(key, _)| keys.contains(&key.as_str())) =>
        {
            Ok(())
        }
        _ => Err(refusal("floor-format")),
    }
}
fn authority(value: &Value) -> Result<AuthorityVersion> {
    exact(value, &["epoch", "sequence", "previous_hash"])?;
    let context = AuthorityVersion {
        epoch: number(value, "epoch")?,
        sequence: positive(value, "sequence")?,
        previous_hash: match member(value, "previous_hash")?.view() {
            ValueView::Null => None,
            _ => Some(hash(value, "previous_hash")?),
        },
    };
    if (context.sequence == 1) != context.previous_hash.is_none() {
        return Err(refusal("floor-context"));
    }
    Ok(context)
}
fn signature_algorithm(value: &Value) -> Result<AlgorithmId> {
    match AlgorithmId::from_wire(field_text(value, "algorithm")?)? {
        algorithm @ (AlgorithmId::Ed25519 | AlgorithmId::EcdsaP256Sha256) => Ok(algorithm),
        _ => Err(refusal("floor-algorithm")),
    }
}

fn state(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        return Err(refusal("floor-size"));
    }
    let value = json::parse_strict(bytes)?;
    if value.canonical_bytes() != bytes {
        return Err(refusal("floor-canonical"));
    }
    exact(
        &value,
        &["schema", "algorithm", "authority", "floor", "high_water"],
    )?;
    let install = field_text(&value, "schema")? == INSTALL_STATE;
    if (!install && field_text(&value, "schema")? != "aukora-floor-state-v2")
        || field_text(&value, "algorithm")? != "sha256"
    {
        return Err(refusal("floor-schema"));
    }
    let context = authority(member(&value, "authority")?)?;
    if (context.epoch == 0) != install {
        return Err(refusal("floor-context"));
    }
    let floor = member(&value, "floor")?;
    exact(
        floor,
        &[
            "digest",
            "record",
            "signer_epoch",
            "ledger_seq",
            "signer_key_sha256",
            "ledger_hash",
            "history",
        ],
    )?;
    let digest = hash(floor, "digest")?;
    for key in ["record", "signer_key_sha256", "ledger_hash"] {
        hash(floor, key)?;
    }
    if number(floor, "signer_epoch")? > context.epoch
        || (!install && number(floor, "signer_epoch")? == 0)
        || positive(floor, "ledger_seq")? > context.sequence
    {
        return Err(refusal("floor-context"));
    }
    let history = array(floor, "history")?;
    let mut digests = BTreeSet::new();
    if history.len() > 64 {
        return Err(refusal("floor-history"));
    }
    for item in history {
        let item = Digest32::from_hex(text(item)?)?;
        if item == digest || !digests.insert(item.to_string()) {
            return Err(refusal("floor-history"));
        }
    }
    let high = member(&value, "high_water")?;
    exact(
        high,
        &[
            "highest_epoch",
            "highest_sequence",
            "head",
            "credentials",
            "spent",
        ],
    )?;
    if number(high, "highest_epoch")? != context.epoch
        || positive(high, "highest_sequence")? != context.sequence
    {
        return Err(refusal("floor-context"));
    }
    hash(high, "head")?;
    if install {
        if positive(floor, "ledger_seq")? != context.sequence
            || hash(floor, "ledger_hash")? != hash(high, "head")?
            || hash(floor, "record")? != digest
            || !history.is_empty()
            || !array(high, "credentials")?.is_empty()
            || !array(high, "spent")?.is_empty()
        {
            return Err(refusal("floor-install-state"));
        }
        return Ok(value);
    }
    let mut identities = BTreeSet::new();
    let mut current = false;
    for credential in array(high, "credentials")? {
        exact(
            credential,
            &["credential", "algorithm", "key_sha256", "epoch", "counter"],
        )?;
        signature_algorithm(credential)?;
        let id = field_text(credential, "credential")?;
        let raw = URL_SAFE_NO_PAD
            .decode(id)
            .map_err(|_| refusal("floor-credential"))?;
        if raw.is_empty()
            || raw.len() > 1024
            || URL_SAFE_NO_PAD.encode(&raw) != id
            || !identities.insert(id)
        {
            return Err(refusal("floor-credential"));
        }
        hash(credential, "key_sha256")?;
        let epoch = positive(credential, "epoch")?;
        if epoch > context.epoch || number(credential, "counter")? > u32::MAX as u64 {
            return Err(refusal("floor-credential"));
        }
        current |= epoch == context.epoch;
    }
    if !current {
        return Err(refusal("floor-credential"));
    }
    let (mut operations, mut proposals, mut approvals, mut ordered) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeMap::new(),
    );
    let mut current = false;
    for spent in array(high, "spent")? {
        exact(
            spent,
            &[
                "algorithm",
                "authority",
                "operation",
                "proposal",
                "authorization_sha256",
            ],
        )?;
        signature_algorithm(spent)?;
        let at = authority(member(spent, "authority")?)?;
        let op = OperationId::from_hex(field_text(spent, "operation")?)?;
        let proposal = ProposalId::from_hex(field_text(spent, "proposal")?)?;
        let approval = hash(spent, "authorization_sha256")?;
        if at.epoch == 0
            || at.epoch > context.epoch
            || at.sequence > context.sequence
            || !operations.insert(op)
            || !proposals.insert(proposal)
            || !approvals.insert(approval.to_string())
            || ordered.insert(at.sequence, at.epoch).is_some()
        {
            return Err(refusal("floor-spent"));
        }
        current |= at == context;
    }
    let mut epoch = 0;
    for next in ordered.into_values() {
        if next < epoch {
            return Err(refusal("floor-epoch"));
        }
        epoch = next;
    }
    if !current {
        return Err(refusal("floor-spent"));
    }
    Ok(value)
}

fn check_successor(
    current: Option<&Value>,
    next: &Value,
    proof: &VerifiedProof,
    operation: OperationId,
) -> Result<()> {
    let context = authority(member(next, "authority")?)?;
    let high = member(next, "high_water")?;
    let new_spent = array(high, "spent")?;
    let old_high = current
        .map(|value| member(value, "high_water"))
        .transpose()?;
    let old_spent = old_high
        .map(|value| array(value, "spent"))
        .transpose()?
        .unwrap_or(&[]);
    if new_spent.len() != old_spent.len() + 1 {
        return Err(refusal("floor-unspent"));
    }
    for spent in old_spent {
        if !new_spent.contains(spent) {
            return Err(refusal("floor-unspent"));
        }
    }
    let approval = Digest32::sha256(proof.authorization_bytes());
    let fresh = new_spent
        .iter()
        .filter(|spent| !old_spent.contains(spent))
        .collect::<Vec<_>>();
    if fresh.len() != 1
        || authority(member(fresh[0], "authority")?)? != context
        || field_text(fresh[0], "operation")? != operation.to_string()
        || field_text(fresh[0], "proposal")? != proof.authorization().proposal.to_string()
        || hash(fresh[0], "authorization_sha256")? != approval
        || signature_algorithm(fresh[0])? != proof.algorithm()
    {
        return Err(refusal("floor-spent"));
    }
    let credentials = array(high, "credentials")?;
    let old_credentials = old_high
        .map(|value| array(value, "credentials"))
        .transpose()?
        .unwrap_or(&[]);
    let id = URL_SAFE_NO_PAD.encode(proof.credential_id().as_bytes());
    let mut known = false;
    for old in old_credentials {
        let old_id = field_text(old, "credential")?;
        let matching = credentials
            .iter()
            .find(|pin| field_text(pin, "credential").ok() == Some(old_id))
            .ok_or(refusal("floor-credential-lost"))?;
        if old_id == id {
            known = true;
            if hash(old, "key_sha256")? != hash(matching, "key_sha256")?
                || signature_algorithm(old)? != signature_algorithm(matching)?
                || positive(old, "epoch")? > positive(matching, "epoch")?
                || (number(old, "counter")? != 0
                    && number(matching, "counter")? <= number(old, "counter")?)
            {
                return Err(refusal("floor-counter"));
            }
        } else if old != matching {
            return Err(refusal("floor-credential-changed"));
        }
    }
    if credentials.len() != old_credentials.len() + usize::from(!known) {
        return Err(refusal("floor-credential-added"));
    }
    let pin = credentials
        .iter()
        .find(|pin| field_text(pin, "credential").ok() == Some(id.as_str()))
        .ok_or(refusal("floor-credential-missing"))?;
    if signature_algorithm(pin)? != proof.algorithm()
        || hash(pin, "key_sha256")? != Digest32::sha256(&proof.public_key().bytes)
        || positive(pin, "epoch")? != proof.authorization().epoch
        || number(pin, "counter")? != u64::from(proof.sign_counter())
    {
        return Err(refusal("floor-credential-proof"));
    }
    if let Some(old) = old_high {
        if context.epoch < number(old, "highest_epoch")?
            || context.sequence <= positive(old, "highest_sequence")?
            || hash(high, "head")? == hash(old, "head")?
        {
            return Err(refusal("floor-rollback"));
        }
        if context.sequence == positive(old, "highest_sequence")? + 1
            && context.previous_hash != Some(hash(old, "head")?)
        {
            return Err(refusal("floor-predecessor"));
        }
    }
    let floor = member(next, "floor")?;
    let mut history = Vec::new();
    if let Some(current) = current {
        let old = member(current, "floor")?;
        let old_order = (number(old, "signer_epoch")?, positive(old, "ledger_seq")?);
        let new_order = (
            positive(floor, "signer_epoch")?,
            positive(floor, "ledger_seq")?,
        );
        if new_order <= old_order
            || (new_order.0 == old_order.0
                && hash(floor, "signer_key_sha256")? != hash(old, "signer_key_sha256")?)
        {
            return Err(refusal("floor-order"));
        }
        let new_digest = member(floor, "digest")?;
        history = array(old, "history")?
            .iter()
            .filter(|entry| *entry != new_digest)
            .cloned()
            .collect();
        if member(old, "digest")? != new_digest {
            history.push(member(old, "digest")?.clone());
        }
        let discard = history.len().saturating_sub(64);
        history.drain(..discard);
    }
    if array(floor, "history")? != history {
        return Err(refusal("floor-history"));
    }
    Ok(())
}

fn release_pointer(bytes: &[u8], digest: Digest32) -> Result<()> {
    let pointer = json::parse_strict(bytes)?;
    if pointer.canonical_bytes() != bytes {
        return Err(refusal("floor-release-pointer"));
    }
    if pointer.get("components").is_some() {
        exact(&pointer, &["v", "digest", "components"])?;
    } else {
        exact(&pointer, &["v", "digest"])?;
    }
    if number(&pointer, "v")? != 1 || hash(&pointer, "digest")? != digest {
        return Err(refusal("floor-release-pointer"));
    }
    if let Some(components) = pointer.get("components") {
        exact(components, &["node", "harness", "guest"])?;
        for key in ["node", "harness", "guest"] {
            hash(components, key)?;
        }
    }
    Ok(())
}

impl LedgerTxn<'_> {
    /// Roll back an active floor transition, including a poisoned transaction.
    pub fn abort_floor_transition(&mut self) -> Result<()> {
        if self.transaction.is_autocommit() {
            return Err(refusal("transaction"));
        }
        self.poisoned = true;
        self.transaction.execute_batch("ROLLBACK").map_err(sql)
    }

    /// Read retained floor bytes before any append or pending authority mutation.
    pub fn floor_recovery_state(&self) -> Result<Option<Vec<u8>>> {
        self.active()?;
        if self.state.next()? != self.retained.next()?
            || !self.counters.is_empty()
            || !self.consumptions.is_empty()
            || self.floor_obligation.is_some()
        {
            return Err(refusal("floor-recovery-transaction"));
        }
        let bytes = self.floor_state()?;
        if let Some(bytes) = &bytes {
            self.verify_floor_history(&state(bytes)?)?;
        }
        Ok(bytes)
    }

    /// Resolve an exact release consumption; colliding spent identities refuse.
    pub fn floor_consumption(
        &self,
        approval: Digest32,
        proposal: ProposalId,
        operation: OperationId,
    ) -> Result<Option<canon::authority::AuthorityVersion>> {
        self.active()?;
        let mut statement = self.transaction.prepare(
            "SELECT approval,proposal,operation,epoch,sequence,previous_hash,action,appended,proof,credential FROM authority_consumptions WHERE approval=?1 OR proposal=?2 OR operation=?3",
        ).map_err(sql)?;
        let mut rows = statement
            .query(params![
                approval.to_string(),
                proposal.to_string(),
                operation.to_string()
            ])
            .map_err(sql)?;
        let Some(row) = rows.next().map_err(sql)? else {
            let spent: i64 = self
                .transaction
                .query_row(
                    "SELECT count(*) FROM authority_challenges WHERE proposal=?1 AND spent=1",
                    [proposal.to_string()],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            if spent != 0 {
                return Err(refusal("floor-consumption"));
            }
            return Ok(None);
        };
        let previous: Option<String> = row.get(5).map_err(sql)?;
        let context = canon::authority::AuthorityVersion {
            epoch: u64::try_from(row.get::<_, i64>(3).map_err(sql)?)
                .map_err(|_| refusal("floor-consumption"))?,
            sequence: u64::try_from(row.get::<_, i64>(4).map_err(sql)?)
                .map_err(|_| refusal("floor-consumption"))?,
            previous_hash: previous
                .map(|value| Digest32::from_hex(&value))
                .transpose()?,
        };
        let proof_bytes: Vec<u8> = row.get(8).map_err(sql)?;
        let credential: String = row.get(9).map_err(sql)?;
        if row.get::<_, String>(0).map_err(sql)? != approval.to_string()
            || row.get::<_, String>(1).map_err(sql)? != proposal.to_string()
            || row.get::<_, String>(2).map_err(sql)? != operation.to_string()
            || row.get::<_, String>(6).map_err(sql)? != "release"
            || row.get::<_, i64>(7).map_err(sql)? != 1
            || context.epoch == 0
            || context.sequence == 0
            || context.epoch > json::MAX_SAFE_INTEGER as u64
            || context.sequence > json::MAX_SAFE_INTEGER as u64
            || rows.next().map_err(sql)?.is_some()
        {
            return Err(refusal("floor-consumption"));
        }
        let proof = json::parse_strict(&proof_bytes)?;
        let authorization = member(&proof, "authorization")?.canonical_bytes();
        let auth = crate::storage::decode_authorization(&authorization)?;
        let stored = self.proposal(&proposal)?;
        if proof.canonical_bytes() != proof_bytes
            || field_text(&proof, "credential")? != credential
            || Digest32::sha256(&authorization) != approval
            || auth.proposal != proposal
            || auth.epoch != context.epoch
            || auth.op != OwnerOperation::Release
            || auth.target != "release"
            || auth.cell.is_some()
            || stored.operation != operation
            || stored.status != crate::storage::ProposalStatus::Applied
            || stored.target != auth.target
            || stored.cell != auth.cell
            || stored.operation_digest != auth.operation
            || stored.base_sha256 != auth.base_sha256
            || Digest32::sha256(&stored.new_bytes) != auth.new_sha256
        {
            return Err(refusal("floor-consumption"));
        }
        let matches: i64 = self.transaction.query_row(
            "SELECT count(*) FROM authority_challenges WHERE proposal=?1 AND action='release' AND challenge=?2 AND body=?3 AND spent=1",
            params![proposal.to_string(), auth.challenge.to_string(), authorization],
            |row| row.get(0),
        ).map_err(sql)?;
        if matches != 1 {
            return Err(refusal("floor-consumption"));
        }
        Ok(Some(context))
    }

    /// Recheck the exact assertion retained by an authenticated release receipt.
    pub fn check_floor_assertion(
        &self,
        proposal: ProposalId,
        approval: Digest32,
        assertion: canon::authority::OwnerAssertion,
    ) -> Result<canon::authority::OwnerAuthorization> {
        use base64::engine::general_purpose::STANDARD;

        let stored = self.proposal(&proposal)?;
        let context = self
            .floor_consumption(approval, proposal, stored.operation)?
            .ok_or(refusal("floor-consumption"))?;
        let receipt = self.record_at(context)?;
        let payload = super::gate_payload(&receipt.body);
        exact(
            payload,
            &["schema", "floor", "proposal", "authorization_sha256"],
        )?;
        if receipt.kind != Kind::FloorAdvance
            || receipt.phase != Phase::Terminal
            || receipt.operation != Some(stored.operation)
            || field_text(payload, "schema")? != "aukora-floor-advance-v1"
            || field_text(payload, "proposal")? != proposal.to_string()
            || hash(payload, "authorization_sha256")? != approval
            || hash(member(payload, "floor")?, "record")? != Digest32::sha256(&stored.new_bytes)
        {
            return Err(refusal("floor-consumption"));
        }
        let (proof_bytes, counter): (Vec<u8>, u32) = self
            .transaction
            .query_row(
                "SELECT proof,counter FROM authority_consumptions WHERE approval=?1",
                [approval.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sql)?;
        if proof_bytes.len() > 65_536 {
            return Err(refusal("floor-consumption"));
        }
        let proof = json::parse_strict(&proof_bytes)?;
        exact(
            &proof,
            &[
                "authorization",
                "credential",
                "authenticator_data",
                "client_data_json",
                "signed_bytes",
                "public_keys",
                "signatures",
            ],
        )?;
        let authorization_bytes = member(&proof, "authorization")?.canonical_bytes();
        let authorization = crate::storage::decode_authorization(&authorization_bytes)?;
        let binding = super::epochs::immune_binding_before(
            &self.transaction,
            &assertion.credential_id,
            context.epoch,
            context.sequence,
            &self.state.keys,
        )?;
        let keys = crate::storage::decode_keys(&member(&proof, "public_keys")?.canonical_bytes())?;
        let signatures =
            crate::storage::decode_signatures(&member(&proof, "signatures")?.canonical_bytes())?;
        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(Digest32::sha256(&assertion.client_data_json).as_bytes());
        if proof.canonical_bytes() != proof_bytes
            || authorization.canonical_bytes()? != authorization_bytes
            || Digest32::sha256(&authorization_bytes) != approval
            || authorization.proposal != proposal
            || authorization.op != OwnerOperation::Release
            || authorization.epoch != context.epoch
            || authorization.expires_at <= receipt.at
            || receipt.actor != authorization.subject.to_string()
            || field_text(&proof, "credential")?
                != URL_SAFE_NO_PAD.encode(assertion.credential_id.as_bytes())
            || field_text(&proof, "authenticator_data")?
                != STANDARD.encode(&assertion.authenticator_data)
            || field_text(&proof, "client_data_json")?
                != STANDARD.encode(&assertion.client_data_json)
            || field_text(&proof, "signed_bytes")? != STANDARD.encode(&signed)
            || assertion.authenticator_data.len() != 37
            || assertion.authenticator_data[33..37] != counter.to_be_bytes()
            || keys.as_slice() != std::slice::from_ref(&binding.public_key)
            || signatures.components() != std::slice::from_ref(&assertion.signature)
        {
            return Err(refusal("floor-consumption"));
        }
        let card_bytes: Vec<u8> = self.transaction.query_row(
            "SELECT card FROM authority_challenges WHERE proposal=?1 AND action='release'",
            [proposal.to_string()], |row| row.get(0),
        ).map_err(sql)?;
        let card = crate::storage::decode_card(&card_bytes)?;
        if Digest32::sha256(&card_bytes) != authorization.display_sha256
            || card.risk != stored.risk
            || card.model_note != stored.model_note
        {
            return Err(refusal("floor-consumption"));
        }
        canon::authority::verify_retained_owner_assertion(
            binding,
            authorization.clone(),
            assertion,
            crate::record::verify_signature,
        )?;
        Ok(authorization)
    }
}
