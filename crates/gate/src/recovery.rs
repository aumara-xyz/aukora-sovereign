// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery observes consumed work. It cannot construct an effect permit.

use crate::{proposal::ProposalState, target::TargetObservation, Result};
use canon::{
    authority::{AuthorityVersion, BaseDigest},
    digest::Digest32,
    ids::ProposalId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    BeforeProposal,
    AfterProposal,
    BeforeReview,
    AfterReview,
    AfterProof,
    AfterCounter,
    AfterConsumption,
    AfterAppend,
    BeforeCommit,
    AfterCommit,
    BeforeEffect,
    AfterEffect,
    BeforeTerminal,
    AfterTerminal,
    BeforeRetire,
    AfterRetire,
    BeforeRecovery,
    AfterRecovery,
    BeforeReconcile,
    AfterReconcile,
    BeforeExpire,
    AfterExpire,
    BeforeDecline,
    AfterDecline,
    BeforeRevoke,
    AfterRevoke,
}

pub const CRASH_POINTS: [CrashPoint; 26] = [
    CrashPoint::BeforeProposal,
    CrashPoint::AfterProposal,
    CrashPoint::BeforeReview,
    CrashPoint::AfterReview,
    CrashPoint::AfterProof,
    CrashPoint::AfterCounter,
    CrashPoint::AfterConsumption,
    CrashPoint::AfterAppend,
    CrashPoint::BeforeCommit,
    CrashPoint::AfterCommit,
    CrashPoint::BeforeEffect,
    CrashPoint::AfterEffect,
    CrashPoint::BeforeTerminal,
    CrashPoint::AfterTerminal,
    CrashPoint::BeforeRetire,
    CrashPoint::AfterRetire,
    CrashPoint::BeforeRecovery,
    CrashPoint::AfterRecovery,
    CrashPoint::BeforeReconcile,
    CrashPoint::AfterReconcile,
    CrashPoint::BeforeExpire,
    CrashPoint::AfterExpire,
    CrashPoint::BeforeDecline,
    CrashPoint::AfterDecline,
    CrashPoint::BeforeRevoke,
    CrashPoint::AfterRevoke,
];

pub trait CrashInjector {
    fn at(&mut self, point: CrashPoint) -> Result<()>;
}

#[derive(Default)]
pub struct NoInjection;

impl CrashInjector for NoInjection {
    fn at(&mut self, _point: CrashPoint) -> Result<()> {
        Ok(())
    }
}

pub struct RefuseAt(pub CrashPoint);

impl CrashInjector for RefuseAt {
    fn at(&mut self, point: CrashPoint) -> Result<()> {
        if point == self.0 {
            Err(crate::refuse("crash-injected"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryItem {
    pub proposal: ProposalId,
    pub consumed_approval: Digest32,
    pub consumption: AuthorityVersion,
    pub expected_base: BaseDigest,
    pub expected_new_digest: Digest32,
    pub observed: TargetObservation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryResult {
    pub proposal: ProposalId,
    pub state: ProposalState,
    pub terminal: AuthorityVersion,
    pub target_released: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoverySweep {
    pub settled: Vec<RecoveryResult>,
    pub blocked: Vec<(ProposalId, crate::Refusal)>,
}

pub fn classify_observation(item: &RecoveryItem) -> Result<ProposalState> {
    if item.consumption.sequence == 0
        || item.consumption.sequence > canon::json::MAX_SAFE_INTEGER as u64
        || (item.consumption.sequence == 1) != item.consumption.previous_hash.is_none()
    {
        return Err(crate::refuse("recovery-context"));
    }
    if crate::observation::validate(&item.observed).is_err() {
        return Ok(ProposalState::Unknown);
    }
    if item.observed.digest == BaseDigest::Present(item.expected_new_digest) {
        Ok(ProposalState::Incomplete)
    } else if item.observed.digest == item.expected_base {
        Ok(ProposalState::Failed)
    } else {
        Ok(ProposalState::Conflict)
    }
}

impl<'a, S: crate::target::TargetStore> crate::service::Gate<'a, S> {
    pub fn open_store(
        ledger: aura::Ledger,
        targets: S,
        config: crate::service::GateConfig,
        services: aura::TransactionServices<'a>,
    ) -> Result<Self> {
        let mut names = std::collections::BTreeSet::new();
        if config.proposal_lifetime_ms == 0
            || config.proposal_lifetime_ms > canon::json::MAX_SAFE_INTEGER as u64
            || config.ceremony_lifetime_ms == 0
            || config.ceremony_lifetime_ms > 300_000
            || config.targets.iter().any(|spec| {
                spec.class != crate::target::TargetClass::Install
                    || spec.risk != crate::RiskTier::Critical
                    || spec.max_bytes == 0
                    || spec.max_bytes > crate::install::MAX_INSTALL_BYTES
                    || !names.insert(spec.id.clone())
            })
        {
            return Err(crate::refuse("install-configuration"));
        }
        let mut gate = Self::install_construct(ledger, targets, config, services);
        if !gate.recover_store(&mut NoInjection)?.blocked.is_empty() {
            return Err(crate::refuse("recovery-blocked"));
        }
        Ok(gate)
    }

    /// Reconcile this store's consumed work without constructing an effect permit.
    pub fn recover_store(&mut self, crash: &mut dyn CrashInjector) -> Result<RecoverySweep> {
        crash.at(CrashPoint::BeforeRecovery)?;
        let (ledger, _, config, services) = self.install_parts();
        crate::install::transition_now(services)?;
        let transaction = ledger.begin(services)?;
        let pending = transaction.pending_proposals(10_001)?;
        let consumed = transaction.recovery_work(10_001)?;
        if pending.len() > 10_000 || consumed.len() > 10_000 {
            return Err(crate::refuse("recovery-limit"));
        }
        let owned = |target: &str| config.targets.iter().any(|spec| spec.id.as_str() == target);
        let mut ids = std::collections::BTreeSet::new();
        ids.extend(
            pending
                .iter()
                .filter(|stored| owned(&stored.target))
                .map(|stored| stored.proposal),
        );
        ids.extend(
            consumed
                .iter()
                .filter(|work| owned(&work.target))
                .map(|work| work.proposal),
        );
        transaction.rollback()?;
        let mut sweep = RecoverySweep::default();
        for id in ids {
            match self.reconcile_store(id, crash) {
                Ok(Some(item)) => sweep.settled.push(item),
                Ok(None) => (),
                Err(error) => sweep.blocked.push((id, error)),
            }
        }
        crash.at(CrashPoint::AfterRecovery)?;
        Ok(sweep)
    }

    fn reconcile_store(
        &mut self,
        id: ProposalId,
        crash: &mut dyn CrashInjector,
    ) -> Result<Option<RecoveryResult>> {
        use crate::install;
        use canon::authority::{AuthorityTxn, Kind, LifecycleKind, LifecycleRecord, Phase};
        use canon::json::{Value, ValueView};
        crash.at(CrashPoint::BeforeReconcile)?;
        let (ledger, targets, config, services) = self.install_parts();
        let now = install::transition_now(services)?;
        let mut transaction = ledger.begin(services)?;
        let proposal = install::transition_load(&transaction, id)?;
        install::transition_target(
            config,
            &proposal.request.target,
            proposal.request.new_bytes.len(),
        )?;
        install::validate_proposal(&proposal)?;
        if proposal.risk != crate::RiskTier::Critical
            || proposal.new_digest != Digest32::sha256(&proposal.request.new_bytes)
            || proposal.operation_digest
                != crate::proposal::content_digest(config.node, &proposal.request)?
        {
            return Err(crate::refuse("operation-mismatch"));
        }
        if proposal.state == ProposalState::Pending
            && proposal.authority.epoch == transaction.current_version()?.epoch
            && now < proposal.expires_at_ms
        {
            transaction.rollback()?;
            crash.at(CrashPoint::AfterReconcile)?;
            return Ok(None);
        }
        let (state, receipt) = if proposal.state.is_terminal() {
            let receipt = transaction
                .gate_terminal(&proposal.operation_id)?
                .ok_or(crate::refuse("missing-terminal"))?;
            let payload = receipt.body.get("payload").unwrap_or(&receipt.body);
            let field = |name| match payload.get(name).map(Value::view) {
                Some(ValueView::Text(s)) => Some(s),
                _ => None,
            };
            let expected_state = match proposal.state {
                ProposalState::Applied => "applied",
                ProposalState::Refused => "refused",
                ProposalState::Expired => "expired",
                ProposalState::Retired => "retired",
                ProposalState::Incomplete => "incomplete",
                ProposalState::Failed => "failed",
                ProposalState::Conflict => "conflict",
                ProposalState::Unknown => "unknown",
                _ => return Err(crate::refuse("terminal-mismatch")),
            };
            if field("proposal") != Some(id.to_string().as_str())
                || field("target") != Some(proposal.request.target.as_str())
                || field("operation") != Some(proposal.operation_digest.to_string().as_str())
                || field("new_sha256") != Some(proposal.new_digest.to_string().as_str())
                || field("state") != Some(expected_state)
            {
                return Err(crate::refuse("terminal-mismatch"));
            }
            (proposal.state, receipt)
        } else if proposal.state == ProposalState::Pending
            && proposal.authority.epoch != transaction.current_version()?.epoch
        {
            crash.at(CrashPoint::BeforeTerminal)?;
            let receipt = transaction.refuse_stale_pending(id)?;
            crash.at(CrashPoint::AfterTerminal)?;
            (ProposalState::Refused, receipt)
        } else if proposal.state == ProposalState::Pending {
            let text = |s: String| Value::text(s);
            crash.at(CrashPoint::BeforeTerminal)?;
            let record = LifecycleRecord {
                v: 1,
                algorithm: canon::alg::AlgorithmId::Sha256,
                authority: transaction.current_version()?,
                at: now,
                kind: LifecycleKind::GateExpire,
                actor: "gate".into(),
                operation: proposal.operation_id,
                phase: Phase::Terminal,
                body: Value::object(vec![
                    ("proposal".into(), text(id.to_string())?),
                    (
                        "target".into(),
                        text(proposal.request.target.as_str().into())?,
                    ),
                    (
                        "operation".into(),
                        text(proposal.operation_digest.to_string())?,
                    ),
                    ("base_sha256".into(), text("absent".into())?),
                    ("new_sha256".into(), text(proposal.new_digest.to_string())?),
                    ("state".into(), text("expired".into())?),
                    ("retry".into(), Value::boolean(false)),
                ])?,
            };
            let receipt = transaction.append_lifecycle(record)?;
            crash.at(CrashPoint::AfterTerminal)?;
            (ProposalState::Expired, receipt)
        } else if proposal.state == ProposalState::Consumed {
            let work = transaction.recovery_work(10_001)?;
            if work.len() > 10_000 {
                return Err(crate::refuse("recovery-limit"));
            }
            let mut matching = work.into_iter().filter(|work| work.proposal == id);
            let work = matching
                .next()
                .ok_or(crate::refuse("missing-consumption"))?;
            if matching.next().is_some()
                || work.operation != proposal.operation_id
                || work.target != proposal.request.target.as_str()
                || work.base_sha256 != proposal.request.base
                || work.new_sha256 != proposal.new_digest
            {
                return Err(crate::refuse("consumption-mismatch"));
            }
            settle_interrupted(
                &mut transaction,
                targets,
                &proposal,
                work.consumed_approval,
                crash,
            )?
        } else {
            return Err(crate::refuse("install-state"));
        };
        if receipt.operation != Some(proposal.operation_id)
            || receipt.phase != Phase::Terminal
            || !matches!(
                receipt.kind,
                Kind::GateApply
                    | Kind::GateRecover
                    | Kind::GateExpire
                    | Kind::GateRefuse
                    | Kind::GateRetire
            )
        {
            return Err(crate::refuse("terminal-mismatch"));
        }
        transaction.release_reservation(&id)?;
        install::transition_commit(transaction, crash)?;
        crash.at(CrashPoint::AfterReconcile)?;
        Ok(Some(RecoveryResult {
            proposal: id,
            state,
            terminal: receipt.authority,
            target_released: true,
        }))
    }
}

impl<S: crate::target::TargetStore> crate::service::Gate<'_, S> {
    pub(crate) fn site_proposal(&mut self, id: ProposalId) -> Result<bool> {
        let (ledger, _, _, services) = self.install_parts();
        let transaction = ledger.begin(services)?;
        let proposal = crate::install::transition_load(&transaction, id)?;
        let site = proposal.request.target.as_str().starts_with("sites/");
        transaction.rollback()?;
        Ok(site)
    }

    pub(crate) fn recover_site_into(
        &mut self,
        id: ProposalId,
        crash: &mut dyn CrashInjector,
        sweep: &mut RecoverySweep,
    ) -> Result<()> {
        match self.reconcile_site(id, crash) {
            Ok(Some(outcome)) => {
                let (ledger, _, _, services) = self.install_parts();
                let transaction = ledger.begin(services)?;
                let stored = transaction.proposal(&id)?;
                let terminal = transaction
                    .gate_terminal(&stored.operation)?
                    .ok_or(crate::refuse("missing-terminal"))?;
                sweep.settled.push(RecoveryResult {
                    proposal: id,
                    state: outcome.state,
                    terminal: terminal.authority,
                    target_released: true,
                });
                transaction.rollback()?;
            }
            Ok(None) => (),
            Err(error) => sweep.blocked.push((id, error)),
        }
        Ok(())
    }

    /// Observe an interrupted site transition; recovery never constructs a permit.
    pub(crate) fn reconcile_site(
        &mut self,
        id: ProposalId,
        crash: &mut dyn CrashInjector,
    ) -> Result<Option<crate::service::Outcome>> {
        use canon::{
            alg::AlgorithmId,
            authority::{AuthorityTxn, LifecycleKind, LifecycleRecord, Phase},
            json::{Value, ValueView},
        };
        crash.at(CrashPoint::BeforeReconcile)?;
        let (ledger, targets, config, services) = self.install_parts();
        let now = crate::install::transition_now(services)?;
        let mut transaction = ledger.begin(services)?;
        let proposal = crate::install::transition_load(&transaction, id)?;
        crate::target::sites::validate(config, &proposal)?;
        if proposal.state == ProposalState::Pending
            && proposal.authority.epoch == transaction.current_version()?.epoch
            && now < proposal.expires_at_ms
        {
            transaction.rollback()?;
            crash.at(CrashPoint::AfterReconcile)?;
            return Ok(None);
        }
        let text = |value: String| Value::text(value);
        let base = match proposal.request.base {
            BaseDigest::Absent => "absent".into(),
            BaseDigest::Present(digest) => digest.to_string(),
        };
        let (state, receipt) = if proposal.state.is_terminal() {
            let terminal = transaction
                .gate_terminal(&proposal.operation_id)?
                .ok_or(crate::refuse("missing-terminal"))?;
            let wrapped = aura::record::AuthorityBodyV1::parse(&terminal.body)?;
            let payload = &wrapped.payload;
            let state = match proposal.state {
                ProposalState::Applied => "applied",
                ProposalState::Refused => "refused",
                ProposalState::Expired => "expired",
                ProposalState::Retired => "retired",
                ProposalState::Incomplete => "incomplete",
                ProposalState::Failed => "failed",
                ProposalState::Conflict => "conflict",
                ProposalState::Unknown => "unknown",
                _ => return Err(crate::refuse("terminal-mismatch")),
            };
            let matches = |key: &str, expected: String| {
                payload.get(key).is_some_and(
                    |value| matches!(value.view(), ValueView::Text(actual) if actual == expected),
                )
            };
            if !matches("proposal", id.to_string())
                || !matches("target", proposal.request.target.as_str().into())
                || !matches("operation", proposal.operation_digest.to_string())
                || !matches("base_sha256", base)
                || !matches("new_sha256", proposal.new_digest.to_string())
                || !matches("state", state.into())
            {
                return Err(crate::refuse("terminal-mismatch"));
            }
            (proposal.state, terminal)
        } else if proposal.state == ProposalState::Pending
            && proposal.authority.epoch != transaction.current_version()?.epoch
        {
            crash.at(CrashPoint::BeforeTerminal)?;
            let terminal = transaction.refuse_stale_pending(id)?;
            crash.at(CrashPoint::AfterTerminal)?;
            (ProposalState::Refused, terminal)
        } else if proposal.state == ProposalState::Pending {
            crash.at(CrashPoint::BeforeTerminal)?;
            let authority = transaction.current_version()?;
            let terminal = transaction.append_lifecycle(LifecycleRecord {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                authority,
                at: now,
                kind: LifecycleKind::GateExpire,
                actor: "gate".into(),
                operation: proposal.operation_id,
                phase: Phase::Terminal,
                body: Value::object(vec![
                    ("proposal".into(), text(id.to_string())?),
                    (
                        "target".into(),
                        text(proposal.request.target.as_str().into())?,
                    ),
                    (
                        "operation".into(),
                        text(proposal.operation_digest.to_string())?,
                    ),
                    ("base_sha256".into(), text(base)?),
                    ("new_sha256".into(), text(proposal.new_digest.to_string())?),
                    ("state".into(), text("expired".into())?),
                    ("retry".into(), Value::boolean(false)),
                ])?,
            })?;
            crash.at(CrashPoint::AfterTerminal)?;
            (ProposalState::Expired, terminal)
        } else if proposal.state == ProposalState::Consumed {
            let work = transaction.recovery_work(10_001)?;
            if work.len() > 10_000 {
                return Err(crate::refuse("recovery-limit"));
            }
            let mut matches = work.into_iter().filter(|work| work.proposal == id);
            let work = matches.next().ok_or(crate::refuse("missing-consumption"))?;
            if matches.next().is_some()
                || work.operation != proposal.operation_id
                || work.target != proposal.request.target.as_str()
                || work.base_sha256 != proposal.request.base
                || work.new_sha256 != proposal.new_digest
            {
                return Err(crate::refuse("consumption-mismatch"));
            }
            settle_interrupted(
                &mut transaction,
                targets,
                &proposal,
                work.consumed_approval,
                crash,
            )?
        } else {
            return Err(crate::refuse("not-consumed"));
        };
        transaction.release_reservation(&id)?;
        crate::install::transition_commit(transaction, crash)?;
        crash.at(CrashPoint::AfterReconcile)?;
        Ok(Some(crate::service::Outcome {
            proposal: id,
            state,
            receipt_hash: receipt.hash,
        }))
    }
}

fn settle_interrupted<S: crate::target::TargetStore>(
    transaction: &mut aura::LedgerTxn<'_>,
    targets: &mut S,
    proposal: &crate::Proposal,
    approval: Digest32,
    crash: &mut dyn CrashInjector,
) -> Result<(ProposalState, canon::authority::AuthorityRecord)> {
    let read = crate::observation::read_for_settlement(
        transaction,
        targets,
        proposal.id,
        &proposal.request.target,
    )?;
    let (status, observed) =
        transaction.observe_recoverable_target(proposal.id, approval, |_: &str| read)?;
    let state = match status {
        aura::storage::ProposalStatus::Incomplete => ProposalState::Incomplete,
        aura::storage::ProposalStatus::Failed => ProposalState::Failed,
        aura::storage::ProposalStatus::Conflict => ProposalState::Conflict,
        aura::storage::ProposalStatus::Unknown => ProposalState::Unknown,
        _ => return Err(crate::refuse("settlement-state")),
    };
    crash.at(CrashPoint::BeforeTerminal)?;
    let receipt = transaction.settle_recovered_target(proposal.id, approval, status, observed)?;
    crash.at(CrashPoint::AfterTerminal)?;
    Ok((state, receipt))
}
