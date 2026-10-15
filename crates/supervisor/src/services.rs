// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed in-process organ ports. No organ receives the guest descriptor.

use crate::ingress::{BindingState, PrincipalScope};
use canon::{
    authority::{OwnerAssertion, OwnerAuthorization, OwnerOperation},
    fd3_payloads::{
        Accepted, MemoryList, MemoryListReply, MemoryPut, MemoryRecall, ModelCall, ModelReply,
        OrgansReply, Outcome, Propose, Read, ReadReply, Recall, StatusReply,
    },
    frame::FrameId,
    ids::{ProposalId, RequestId, ReservationId},
    session::{ModelCancel, ModelDelta, ModelEnd, ModelError, ModelStart, ModelStarted},
    Result,
};
use std::{future::Future, pin::Pin};

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// A gate-owned view; bytes are displayed literally by the owner origin.
/// Receipt of this data does not consume an approval or authorize an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerReview {
    pub proposal_id: ProposalId,
    pub authorization: OwnerAuthorization,
    pub authorization_bytes: Vec<u8>,
    pub card_bytes: Vec<u8>,
}

/// Gate policy, target allowlists, approval consumption and application remain in gate.
pub trait GateService: Send + Sync {
    /// Versioned site proposals include an explicit absent base for first publication.
    /// The gate adapter must validate its configured host and retain pending bytes.
    fn propose_site<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        proposal: canon::fd3_payloads::sites::SiteProposal,
    ) -> ServiceFuture<'a, Accepted>;

    fn propose<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        proposal: Propose,
    ) -> ServiceFuture<'a, Accepted>;

    fn read(&self, scope: PrincipalScope, request: Read) -> ServiceFuture<'_, ReadReply>;

    fn outcome(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
    ) -> ServiceFuture<'_, Option<Outcome>>;

    /// Loads the exact card and authorization from gate state by id. Browser-supplied
    /// card bytes, target bytes and authorization objects are not method arguments.
    fn review(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
    ) -> ServiceFuture<'_, OwnerReview>;

    /// Gate and AUMLOK perform the shared Aura transaction. The supervisor forwards
    /// the retained assertion; it does not mint VerifiedProof or update counters.
    fn owner_assertion(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
        assertion: OwnerAssertion,
    ) -> ServiceFuture<'_, Outcome>;
}

/// Broker admission owns grants, exactly one reservation, model identity and settlement.
/// Dropping a client or cancelling a stream never fabricates a receipt.
/// Admission and call futures may be dropped on revocation. The adapter retains
/// every in-flight request key until broker settlement, including failed starts.
pub trait BrokerService: Send + Sync {
    /// Confirm that nonblocking polling and post-write acknowledgements are installed.
    fn streaming_ready(&self) -> Result<()> {
        Err(canon::codes::SUPERVISOR_NOT_READY)
    }

    fn call<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        call: ModelCall,
    ) -> ServiceFuture<'a, ModelReply>;

    /// A refusal leaves no unsettled reservation; admitted work is retained even
    /// if this future is dropped before its acknowledgement reaches the router.
    fn start(&self, scope: PrincipalScope, request: ModelStart) -> ServiceFuture<'_, ModelStarted>;

    /// Observes the identified stream without requesting cancellation.
    fn next(&self, scope: PrincipalScope, stream: StreamHandle) -> ServiceFuture<'_, BrokerEvent>;

    /// Observe currently available output without cancelling or waiting for provider I/O.
    /// Adapters must implement this port before the router admits streaming work.
    fn poll(
        &self,
        _scope: PrincipalScope,
        _stream: StreamHandle,
    ) -> ServiceFuture<'_, Option<BrokerEvent>> {
        Box::pin(async { Err(canon::codes::SUPERVISOR_NOT_READY) })
    }

    /// Release one provider queue slot only after the corresponding FD 3 write.
    fn delivered(
        &self,
        _scope: PrincipalScope,
        _stream: StreamHandle,
        _index: u64,
    ) -> ServiceFuture<'_, ()> {
        Box::pin(async { Err(canon::codes::SUPERVISOR_NOT_READY) })
    }

    /// Settle all channel-owned work after disconnect, including dropped call/start
    /// futures whose admission reply never reached the router. No new work is admitted.
    /// Repeating cleanup returns existing durable settlements without charging again.
    fn disconnect(&self, _scope: PrincipalScope) -> ServiceFuture<'_, ()> {
        Box::pin(async { Err(canon::codes::SUPERVISOR_NOT_READY) })
    }

    /// Repeated cancellation of an admitted handle returns its existing settlement.
    fn cancel(&self, scope: PrincipalScope, request: ModelCancel) -> ServiceFuture<'_, ModelEnd>;
}

/// Correlation data for polling and delivery acknowledgement; never a cancel command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamHandle {
    pub request_id: RequestId,
    pub reservation_id: ReservationId,
}

/// Only broker-originated records can be forwarded as usage or final settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerEvent {
    Delta(ModelDelta),
    End(ModelEnd),
    Error(ModelError),
}

/// Kira owns note policy, permitted recall, citations and any pending note outcome.
pub trait KiraService: Send + Sync {
    fn put<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        request: MemoryPut,
    ) -> ServiceFuture<'a, Accepted>;

    fn recall(&self, scope: PrincipalScope, request: MemoryRecall) -> ServiceFuture<'_, Recall>;

    fn list(
        &self,
        scope: PrincipalScope,
        request: MemoryList,
    ) -> ServiceFuture<'_, MemoryListReply>;

    fn outcome(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
    ) -> ServiceFuture<'_, Option<Outcome>>;
}

/// Re-executes the approved WASM cell and compares exact effect bytes and all digests.
/// A successful comparison is evidence only; gate or Kira still owns the operation.
pub trait CellService: Send + Sync {
    fn proposal(&self, proposal: &Propose) -> Result<()>;
    fn memory(&self, request: &MemoryPut) -> Result<()>;
}

/// The live AUMLOK binding is consulted again at dispatch, including after revocation.
pub trait BindingService: Send + Sync {
    fn current(&self) -> ServiceFuture<'_, BindingState>;
}

/// Read-only frozen C4 snapshots, including approvals_pending in organs.reply.
/// No health map or fingerprint influences either return value or guest admission.
pub trait SnapshotService: Send + Sync {
    fn status(&self) -> ServiceFuture<'_, StatusReply>;
    fn organs(&self) -> ServiceFuture<'_, OrgansReply>;
}

/// Runs the pinned cell for the theme target selected by trusted boot configuration.
/// Other target policy and all owner authorization remain with the gate.
pub struct PinnedCellService {
    runner: wasmcell::Runner,
    theme_target: String,
}

impl PinnedCellService {
    pub fn new(runner: wasmcell::Runner, theme_target: String) -> Result<Self> {
        wasmcell::ThemeInput::new(
            wasmcell::theme::THEME_ADAPTER_VERSION,
            theme_target.clone(),
            b"{}",
        )?;
        Ok(Self {
            runner,
            theme_target,
        })
    }

    fn inspect_theme_proposal(&self, proposal: &Propose) -> Result<wasmcell::ThemeProposal> {
        if proposal.target != self.theme_target {
            return Err(canon::codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        let claimed = proposal
            .cell
            .ok_or(canon::codes::WASMCELL_EVIDENCE_MISMATCH)?;
        self.runner.inspect_theme(
            wasmcell::theme::THEME_ADAPTER_VERSION,
            proposal.target.clone(),
            &proposal.replacement_bytes()?,
            claimed,
        )
    }

    /// Recomputes the configured theme effect against this transaction's owner proof.
    pub fn rerun_theme_before_apply(
        &self,
        proposal: &Propose,
        proof: &canon::authority::VerifiedProof,
    ) -> Result<wasmcell::ThemeRerun> {
        let inspected = self.inspect_theme_proposal(proposal)?;
        self.runner.rerun_theme_before_apply(&inspected, proof)
    }
}

impl CellService for PinnedCellService {
    fn proposal(&self, proposal: &Propose) -> Result<()> {
        if proposal.target == self.theme_target {
            self.inspect_theme_proposal(proposal).map(|_| ())
        } else if proposal.cell.is_some() {
            Err(canon::codes::WASMCELL_EVIDENCE_MISMATCH)
        } else {
            Ok(())
        }
    }

    fn memory(&self, request: &MemoryPut) -> Result<()> {
        use canon::{digest::Digest32, json::Value};

        let mut fields = vec![
            ("category".into(), Value::text(request.category.clone())?),
            ("statement".into(), Value::text(request.statement.clone())?),
        ];
        if let Some(quote) = &request.quote {
            fields.push(("quote".into(), Value::text(quote.clone())?));
        }
        let value = Value::object(fields)?;
        let key = wasmcell::CellKey::new(format!(
            "memory:{}",
            Digest32::sha256(&canon::json::to_canonical(&value))
        ))?;
        let input = wasmcell::CellInput::new(key, value)?;
        let output = self.runner.run(&input)?;
        if output.commitments() != request.cell {
            return Err(canon::codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        Ok(())
    }
}

/// Host observations of the candidate guest used for both attack phases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelIntakeState {
    pub candidate: canon::digest::Digest32,
    pub challenge: canon::digest::Digest32,
    pub parent_cgroup: u64,
    pub attack_cgroup: u64,
    pub guest_grants: u32,
}

/// The host binds these two immune drivers to the same candidate guest.
/// These methods observe host state; guest-produced reports cannot implement this port.
pub trait ModelIntakeDriver: immune::hostile::CageDriver + immune::ratchet::Replay {
    fn begin_candidate(&mut self, challenge: &broker::intake::IntakeChallenge) -> Result<()>;
    fn candidate_state(&mut self) -> Result<ModelIntakeState>;
}

type IntakeHerdReplay<D> = fn(
    &immune::herd::HerdStore,
    immune::hostile::Limits,
    &mut D,
) -> Result<immune::herd::ReplayFacts>;

/// Wires immune's cage attack and full ratchet to broker's slot admission.
pub struct ModelIntakeRunner<'a, D: ModelIntakeDriver> {
    driver: &'a mut D,
    registry: &'a immune::registry::Registry,
    corpus: &'a immune::ratchet::Corpus,
    heldout: &'a immune::heldout::HeldOut,
    cage_limits: immune::hostile::Limits,
    replay_limits: immune::hostile::Limits,
    herd: Option<(
        &'a immune::herd::HerdStore,
        immune::hostile::Limits,
        IntakeHerdReplay<D>,
    )>,
}

impl<'a, D: ModelIntakeDriver> ModelIntakeRunner<'a, D> {
    pub fn new(
        driver: &'a mut D,
        registry: &'a immune::registry::Registry,
        corpus: &'a immune::ratchet::Corpus,
        heldout: &'a immune::heldout::HeldOut,
        cage_limits: immune::hostile::Limits,
        replay_limits: immune::hostile::Limits,
    ) -> Self {
        Self {
            driver,
            registry,
            corpus,
            heldout,
            cage_limits,
            replay_limits,
            herd: None,
        }
    }

    pub fn with_herd(
        mut self,
        store: &'a immune::herd::HerdStore,
        limits: immune::hostile::Limits,
    ) -> Self
    where
        D: immune::herd::HerdReplay,
    {
        self.herd = Some((store, limits, |store, limits, driver| {
            store.replay(limits, driver)
        }));
        self
    }
}

impl<D: ModelIntakeDriver> broker::intake::IntakeRunner for ModelIntakeRunner<'_, D> {
    fn attack_cage(
        &mut self,
        challenge: &broker::intake::IntakeChallenge,
    ) -> Result<broker::intake::CageAttackReport> {
        use canon::digest::Digest32;
        let unavailable = canon::codes::BROKER_PROVIDER_UNAVAILABLE;
        self.cage_limits.validate()?;
        self.replay_limits.validate()?;
        let inventory_active =
            u32::try_from(self.registry.active_count()).map_err(|_| unavailable)?;
        let (policy_root, imported) = match self.herd {
            Some((store, limits, _)) => {
                limits.validate()?;
                let count =
                    u32::try_from(store.imported_cases().count()).map_err(|_| unavailable)?;
                let floor = immune::ratchet::Corpus::from_files(store.fixed_files())?;
                if count > limits.cases || floor.root() != self.corpus.root() {
                    return Err(unavailable);
                }
                (store.root(), count)
            }
            None => (self.corpus.root(), 0),
        };
        let active = inventory_active.checked_add(imported).ok_or(unavailable)?;
        let heldout = u32::try_from(self.heldout.vectors().len()).map_err(|_| unavailable)?;
        let fixed = u32::try_from(self.corpus.vectors().len()).map_err(|_| unavailable)?;
        let replay_count = inventory_active.checked_add(fixed).ok_or(unavailable)?;
        let total = replay_count.checked_add(heldout).ok_or(unavailable)?;
        if challenge.policy.corpus_root != policy_root
            || challenge.policy.required_active != active
            || challenge.policy.required_heldout != heldout
            || self.heldout.release() != challenge.candidate.release_digest
            || active == 0
            || heldout == 0
            || total > self.replay_limits.cases
        {
            return Err(unavailable);
        }
        let candidate = challenge.candidate.commitment()?;
        let challenge_digest = challenge.commitment()?;
        self.driver.begin_candidate(challenge)?;
        let initial = self.driver.candidate_state()?;
        if initial.candidate != candidate
            || initial.challenge != challenge_digest
            || initial.guest_grants != 0
            || initial.parent_cgroup == 0
            || initial.attack_cgroup == 0
            || initial.parent_cgroup == initial.attack_cgroup
        {
            return Err(unavailable);
        }
        let request = immune::boot_attack::Request {
            run_id: challenge_digest,
            candidate,
            release: challenge.candidate.release_digest,
            cage: challenge.candidate.cage_digest,
            challenge: challenge_digest,
            corpus_root: policy_root,
            limits: self.cage_limits,
        };
        let evidence = immune::boot_attack::attack(self.driver, &request)?;
        let run = evidence.run();
        if run.parent_cgroup != initial.parent_cgroup
            || run.attack_cgroup != initial.attack_cgroup
            || self.driver.candidate_state()? != initial
        {
            return Err(unavailable);
        }
        let facts = immune::ratchet::release(
            self.registry,
            self.corpus,
            self.heldout,
            self.replay_limits,
            self.driver,
        )?;
        if self.driver.candidate_state()? != initial {
            return Err(unavailable);
        }
        let herd_facts = match self.herd {
            Some((store, limits, replay)) => {
                let observed = replay(store, limits, self.driver)?;
                if observed.corpus_root != policy_root
                    || observed.attempted != imported
                    || observed.passed != imported
                    || !observed.failures.is_empty()
                {
                    return Err(unavailable);
                }
                Some(observed)
            }
            None => None,
        };
        let final_state = self.driver.candidate_state()?;
        if final_state != initial
            || facts.release != challenge.candidate.release_digest
            || facts.corpus_root != self.corpus.root()
            || facts.active != inventory_active
            || facts.replayed != replay_count
            || facts.heldout_count != heldout
            || facts.heldout_passed != heldout
            || facts.budget_exhausted
            || !facts.failures.is_empty()
        {
            return Err(unavailable);
        }
        let commitment = intake_evidence_body(&evidence, &facts, herd_facts.as_ref())?;
        Ok(broker::intake::CageAttackReport {
            challenge: challenge.clone(),
            completed_active: active,
            completed_heldout: heldout,
            failures: 0,
            guest_grants_at_start: initial.guest_grants,
            guest_grants_at_end: final_state.guest_grants,
            guest_was_driven_by_candidate: run.candidate_drove_guest,
            isolated_cgroup: run.parent_cgroup != run.attack_cgroup,
            report_commitment: Digest32::sha256(&commitment.canonical_bytes()),
        })
    }
}

fn intake_evidence_body(
    evidence: &immune::boot_attack::AttackEvidence,
    facts: &immune::ratchet::ReleaseFacts,
    herd: Option<&immune::herd::ReplayFacts>,
) -> Result<canon::json::Value> {
    use canon::json::{SafeInteger, Value};
    let number = |value: u64| -> Result<Value> {
        let value = i64::try_from(value).map_err(|_| canon::codes::BROKER_STATE)?;
        Ok(Value::integer(SafeInteger::new(value)?))
    };
    let usage = evidence.usage();
    let run = evidence.run();
    let cage = Value::object(vec![
        (
            "request_commitment".into(),
            Value::text(evidence.request_commitment().to_string())?,
        ),
        ("parent_cgroup".into(), number(run.parent_cgroup)?),
        ("attack_cgroup".into(), number(run.attack_cgroup)?),
        ("wall_ms".into(), number(usage.wall_ms)?),
        ("cpu_us".into(), number(usage.cpu_us)?),
        ("memory_bytes".into(), number(usage.memory_bytes)?),
        ("io_bytes".into(), number(usage.io_bytes)?),
        (
            "output_bytes".into(),
            number(u64::from(usage.output_bytes))?,
        ),
        ("cases".into(), number(u64::from(usage.cases))?),
    ])?;
    let mut body = vec![
        ("cage_attack".into(), cage),
        ("ratchet".into(), facts.to_body()?),
    ];
    if let Some(herd) = herd {
        let failures = herd
            .failures
            .iter()
            .map(|digest| Value::text(digest.to_string()))
            .collect::<Result<Vec<_>>>()?;
        body.push((
            "herd".into(),
            Value::object(vec![
                (
                    "corpus_root".into(),
                    Value::text(herd.corpus_root.to_string())?,
                ),
                ("attempted".into(), number(u64::from(herd.attempted))?),
                ("passed".into(), number(u64::from(herd.passed))?),
                ("failures".into(), Value::array(failures)?),
            ])?,
        ));
    }
    Value::object(body)
}

/// Bridges authenticated Nostr data to immune's append-only corpus. No relay
/// operation or authority transaction is available through this port.
pub struct HerdAntibodyStore<R: nostr::antibody::AntibodyRegistry> {
    corpus: immune::herd::HerdStore,
    registry: R,
}

impl<R: nostr::antibody::AntibodyRegistry> HerdAntibodyStore<R> {
    pub fn pinned(registry: R) -> Result<Self> {
        Ok(Self {
            corpus: immune::herd::HerdStore::pinned()?,
            registry,
        })
    }

    pub fn corpus(&self) -> &immune::herd::HerdStore {
        &self.corpus
    }
}

struct HerdRegistry<'a, R>(&'a R);

impl<R: nostr::antibody::AntibodyRegistry> immune::herd::EngineRegistry for HerdRegistry<'_, R> {
    fn supports(&self, engine: &str, format_version: u16) -> bool {
        self.0.supports(engine, format_version)
    }

    fn accepts_refusal(&self, refusal: &str) -> bool {
        self.0.accepts_refusal(refusal)
    }
}

struct HerdAnnouncement<'a>(&'a nostr::antibody::VerifiedAntibodies);

impl immune::herd::AuthenticatedAntibodies for HerdAnnouncement<'_> {
    fn source_event(&self) -> canon::digest::Digest32 {
        self.0.event_id().digest()
    }

    fn author(&self) -> [u8; 32] {
        *self.0.author().as_bytes()
    }

    fn canonical_cases(&self) -> Result<Vec<Vec<u8>>> {
        self.0
            .announcement()
            .cases
            .iter()
            .map(nostr::antibody::AntibodyCase::canonical_bytes)
            .collect()
    }
}

impl<R: nostr::antibody::AntibodyRegistry> nostr::antibody::AdditiveAntibodyStore
    for HerdAntibodyStore<R>
{
    fn append_verified(
        &mut self,
        addition: &nostr::antibody::VerifiedAntibodies,
    ) -> Result<nostr::antibody::ImportOutcome> {
        let outcome = self
            .corpus
            .append_verified(&HerdAnnouncement(addition), &HerdRegistry(&self.registry))?;
        Ok(nostr::antibody::ImportOutcome {
            source_event: addition.event_id(),
            previous_root: outcome.previous_root,
            retained_root: outcome.retained_root,
            inserted: outcome.inserted,
            already_present: outcome.already_present,
        })
    }
}
