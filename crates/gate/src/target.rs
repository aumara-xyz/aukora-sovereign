// SPDX-License-Identifier: AGPL-3.0-or-later
//! Confinement and compare-and-replace contracts for trusted target adapters.

use crate::{Result, RiskTier};
use canon::{authority::BaseDigest, digest::Digest32, ids::OperationId};
use rustix::fs::{self, FlockOperation, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

const TEMP_PREFIX: &str = ".aukora-gate-";

impl<S: TargetStore> crate::service::Gate<'_, S> {
    pub(crate) fn install_effect(
        &mut self,
        id: canon::ids::ProposalId,
        approval: Digest32,
        crash: &mut dyn crate::recovery::CrashInjector,
    ) -> Result<crate::service::Outcome> {
        use crate::{install, recovery::CrashPoint, ProposalState};
        let (ledger, targets, config, services) = self.install_parts();
        let mut transaction = ledger.begin(services)?;
        let proposal = install::transition_load(&transaction, id)?;
        install::transition_target(
            config,
            &proposal.request.target,
            proposal.request.new_bytes.len(),
        )?;
        install::validate_proposal(&proposal)?;
        if proposal.state != ProposalState::Consumed
            || proposal.risk != crate::RiskTier::Critical
            || proposal.authority.epoch != transaction.current_version()?.epoch
            || proposal.new_digest != Digest32::sha256(&proposal.request.new_bytes)
            || proposal.operation_digest
                != crate::proposal::content_digest(config.node, &proposal.request)?
        {
            return Err(crate::refuse("install-consumption"));
        }
        transaction.check_target_consumption(id, approval)?;
        let before = targets.observe(&proposal.request.target).ok();
        if let Some(observed) = &before {
            crate::observation::validate(observed)?;
        }
        let mut acknowledged = false;
        if before
            .as_ref()
            .is_some_and(|seen| seen.digest == proposal.request.base)
        {
            crash.at(CrashPoint::BeforeEffect)?;
            let result = targets.replace_once(EffectPermit::new(
                proposal.operation_id,
                proposal.request.target.clone(),
                proposal.request.base,
                proposal.new_digest,
                proposal.request.new_bytes.clone(),
            ));
            crash.at(CrashPoint::AfterEffect)?;
            if let Ok(seen) = result {
                crate::observation::validate(&seen)?;
                acknowledged = seen.digest == BaseDigest::Present(proposal.new_digest)
                    && seen.bytes.as_ref() == Some(&proposal.request.new_bytes);
            }
        }
        crash.at(CrashPoint::BeforeTerminal)?;
        let (state, status, observed) =
            observe_effect(&mut transaction, targets, id, approval, acknowledged)?;
        let receipt = transaction.settle_consumed_target(id, approval, status, observed)?;
        transaction.release_reservation(&id)?;
        crash.at(CrashPoint::AfterTerminal)?;
        install::transition_commit(transaction, crash)?;
        Ok(crate::service::Outcome {
            proposal: id,
            state,
            receipt_hash: receipt.hash,
        })
    }
}

fn observe_effect<S: TargetStore>(
    transaction: &mut aura::LedgerTxn<'_>,
    targets: &S,
    id: canon::ids::ProposalId,
    approval: Digest32,
    acknowledged: bool,
) -> Result<(
    crate::ProposalState,
    aura::storage::ProposalStatus,
    Option<BaseDigest>,
)> {
    let proposal = crate::install::transition_load(transaction, id)?;
    let read = crate::observation::read_for_settlement(
        transaction,
        targets,
        id,
        &proposal.request.target,
    )?;
    let reader = |_: &str| read;
    let (status, observed) = if acknowledged {
        transaction.observe_consumed_target(id, approval, reader)?
    } else {
        transaction.observe_interrupted_target(id, approval, reader)?
    };
    let state = match status {
        aura::storage::ProposalStatus::Applied => crate::ProposalState::Applied,
        aura::storage::ProposalStatus::Incomplete => crate::ProposalState::Incomplete,
        aura::storage::ProposalStatus::Failed => crate::ProposalState::Failed,
        aura::storage::ProposalStatus::Conflict => crate::ProposalState::Conflict,
        aura::storage::ProposalStatus::Unknown => crate::ProposalState::Unknown,
        _ => return Err(crate::refuse("settlement-state")),
    };
    Ok((state, status, observed))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetId(String);

impl TargetId {
    pub fn new(name: String) -> Result<Self> {
        if name.is_empty()
            || name.len() > 256
            || name.starts_with('/')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(crate::refuse("target-invalid"));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetClass {
    Content,
    Release,
    OwnerBinding,
    Permission,
    SpendGrant,
    Install,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSpec {
    pub id: TargetId,
    pub class: TargetClass,
    pub risk: RiskTier,
    pub max_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetObservation {
    pub digest: BaseDigest,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct EffectPermit {
    operation: OperationId,
    target: TargetId,
    base: BaseDigest,
    new_digest: Digest32,
    bytes: Vec<u8>,
}

impl EffectPermit {
    pub(crate) fn new(
        operation: OperationId,
        target: TargetId,
        base: BaseDigest,
        new_digest: Digest32,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            operation,
            target,
            base,
            new_digest,
            bytes,
        }
    }

    pub fn operation(&self) -> OperationId {
        self.operation
    }
    pub fn target(&self) -> &TargetId {
        &self.target
    }
    pub fn base(&self) -> BaseDigest {
        self.base
    }
    pub fn new_digest(&self) -> Digest32 {
        self.new_digest
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub trait TargetStore {
    fn observe(&self, target: &TargetId) -> Result<TargetObservation>;

    /// Consumes a permit. Implementations compare the base, replace once and sync
    /// bytes and directory; an error is ambiguous and must not be retried.
    fn replace_once(&mut self, permit: EffectPermit) -> Result<TargetObservation>;
}

#[derive(Debug)]
pub struct ConfinedStore {
    directory: std::fs::File,
    targets: BTreeMap<TargetId, TargetSpec>,
    attempted: BTreeSet<OperationId>,
}

impl ConfinedStore {
    pub fn open(directory: std::fs::File, targets: Vec<TargetSpec>) -> Result<Self> {
        if !directory
            .metadata()
            .map_err(|_| crate::refuse("store-root"))?
            .is_dir()
        {
            return Err(crate::refuse("store-root"));
        }
        let directory = open_directory(&directory, ".")?;
        fs::flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| crate::refuse("writer-locked"))?;
        let mut configured = BTreeMap::new();
        for target in targets {
            if target
                .id
                .as_str()
                .split('/')
                .any(|part| part.starts_with(TEMP_PREFIX) || part.len() > 255)
                || target.max_bytes == usize::MAX
            {
                return Err(crate::refuse("target-invalid"));
            }
            if configured.insert(target.id.clone(), target).is_some() {
                return Err(crate::refuse("duplicate-target"));
            }
        }
        for name in configured.keys() {
            for (index, _) in name.as_str().match_indices('/') {
                if configured
                    .keys()
                    .any(|other| other.as_str() == &name.as_str()[..index])
                {
                    return Err(crate::refuse("duplicate-target"));
                }
            }
        }
        Ok(Self {
            directory,
            targets: configured,
            attempted: BTreeSet::new(),
        })
    }

    pub fn directory(&self) -> &std::fs::File {
        &self.directory
    }

    fn specification(&self, target: &TargetId) -> Result<&TargetSpec> {
        self.targets
            .get(target)
            .ok_or(crate::refuse("target-not-allowed"))
    }

    fn parent(&self, target: &TargetId, create: bool) -> Result<Option<(File, String)>> {
        let mut parts = target.as_str().split('/').peekable();
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|_| crate::refuse("io"))?;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                return Ok(Some((directory, part.to_owned())));
            }
            match fs::openat(&directory, part, directory_flags(), Mode::empty()) {
                Ok(next) => directory = File::from(next),
                Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
                Err(rustix::io::Errno::NOENT) => {
                    match fs::mkdirat(&directory, part, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                        Ok(()) => directory.sync_all().map_err(|_| crate::refuse("io"))?,
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(_) => return Err(crate::refuse("io")),
                    }
                    directory = open_directory(&directory, part)?;
                }
                Err(_) => return Err(crate::refuse("store-root")),
            }
        }
        Err(crate::refuse("target-invalid"))
    }

    fn read_at(directory: &File, name: &str, max_bytes: usize) -> Result<TargetObservation> {
        let descriptor = match fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => return Ok(absent()),
            Err(_) => return Err(crate::refuse("io")),
        };
        let file = File::from(descriptor);
        let before = file.metadata().map_err(|_| crate::refuse("io"))?;
        if !before.is_file() || before.nlink() != 1 {
            return Err(crate::refuse("store-not-regular"));
        }
        if before.len() > max_bytes as u64 {
            return Err(crate::refuse("target-limit"));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| crate::refuse("io"))?;
        if bytes.len() > max_bytes {
            return Err(crate::refuse("target-limit"));
        }
        let after = file.metadata().map_err(|_| crate::refuse("io"))?;
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(crate::refuse("stale-base"));
        }
        Ok(TargetObservation {
            digest: BaseDigest::Present(hash(&bytes)),
            bytes: Some(bytes),
        })
    }
}

impl TargetStore for ConfinedStore {
    fn observe(&self, target: &TargetId) -> Result<TargetObservation> {
        let specification = self.specification(target)?;
        match self.parent(target, false)? {
            Some((directory, name)) => Self::read_at(&directory, &name, specification.max_bytes),
            None => Ok(absent()),
        }
    }

    fn replace_once(&mut self, permit: EffectPermit) -> Result<TargetObservation> {
        if !self.attempted.insert(permit.operation) {
            return Err(crate::refuse("write-already-claimed"));
        }
        let max_bytes = self.specification(&permit.target)?.max_bytes;
        if permit.bytes.len() > max_bytes {
            return Err(crate::refuse("target-limit"));
        }
        if hash(&permit.bytes) != permit.new_digest {
            return Err(crate::refuse("post-write-hash"));
        }
        if permit.base == BaseDigest::Present(permit.new_digest) {
            return Err(crate::refuse("identical"));
        }
        if self.observe(&permit.target)?.digest != permit.base {
            return Err(crate::refuse("stale-base"));
        }
        let (directory, name) = self
            .parent(&permit.target, true)?
            .ok_or(crate::refuse("store-root"))?;
        let temporary = format!("{TEMP_PREFIX}{}", permit.operation);
        let descriptor = fs::openat(
            &directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                crate::refuse("write-already-claimed")
            } else {
                crate::refuse("io")
            }
        })?;
        let mut file = File::from(descriptor);
        // Retained temporary names fence attempts that fail before replacement.
        directory.sync_all().map_err(|_| crate::refuse("io"))?;
        file.write_all(&permit.bytes)
            .map_err(|_| crate::refuse("io"))?;
        file.sync_all().map_err(|_| crate::refuse("io"))?;
        if Self::read_at(&directory, &name, max_bytes)?.digest != permit.base {
            return Err(crate::refuse("stale-base"));
        }
        let retained = fs::statat(
            &directory,
            temporary.as_str(),
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| crate::refuse("io"))?;
        let written = file.metadata().map_err(|_| crate::refuse("io"))?;
        if retained.st_dev as u64 != written.dev()
            || retained.st_ino as u64 != written.ino()
            || written.nlink() != 1
            || written.len() != permit.bytes.len() as u64
        {
            return Err(crate::refuse("store-not-regular"));
        }
        if permit.base == BaseDigest::Absent {
            fs::renameat_with(
                &directory,
                temporary.as_str(),
                &directory,
                name.as_str(),
                fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| crate::refuse("io"))?;
        } else {
            fs::renameat(&directory, temporary.as_str(), &directory, name.as_str())
                .map_err(|_| crate::refuse("io"))?;
        }
        directory.sync_all().map_err(|_| crate::refuse("io"))?;
        let observed = Self::read_at(&directory, &name, max_bytes)?;
        if observed.digest != BaseDigest::Present(permit.new_digest)
            || observed.bytes.as_deref() != Some(permit.bytes.as_slice())
        {
            return Err(crate::refuse("post-write-hash"));
        }
        Ok(observed)
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory(parent: &File, name: &str) -> Result<File> {
    fs::openat(parent, name, directory_flags(), Mode::empty())
        .map(File::from)
        .map_err(|_| crate::refuse("store-root"))
}

fn absent() -> TargetObservation {
    TargetObservation {
        digest: BaseDigest::Absent,
        bytes: None,
    }
}

/// Owner-approved static site bundles use the same consume-once target boundary.
pub mod sites {
    use super::{EffectPermit, TargetClass, TargetId, TargetObservation, TargetSpec, TargetStore};
    use crate::{
        proposal::{Proposal, ProposalRequest, ProposalState, SuggestionOrder},
        recovery::{CrashInjector, CrashPoint},
        service::{Gate, Outcome, OwnerReview},
        Result, RiskTier,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use canon::{
        alg::AlgorithmId,
        authority::{
            AuthorityTxn, AuthorizationChallenge, BaseDigest, Kind, LifecycleKind, LifecycleRecord,
            OwnerAssertion, OwnerAuthorization, OwnerOperation, PendingAuthorityRecord, Phase,
        },
        digest::Digest32,
        fd3_payloads::sites::{SiteBundle, SiteProposal},
        ids::ProposalId,
        json::{Value, ValueView, MAX_SAFE_INTEGER},
    };

    /// Created only after the signed consumption, terminal row and current bytes agree.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PublishedSite {
        bundle: SiteBundle,
        proposal: ProposalId,
        receipt_sequence: u64,
    }

    impl PublishedSite {
        pub fn bundle(&self) -> &SiteBundle {
            &self.bundle
        }
        pub fn proposal(&self) -> ProposalId {
            self.proposal
        }
        pub fn receipt_sequence(&self) -> u64 {
            self.receipt_sequence
        }
        pub fn bundle_digest(&self) -> Digest32 {
            self.bundle.digest()
        }
    }

    pub fn target_spec(host: &str) -> Result<TargetSpec> {
        canon::fd3_payloads::sites::validate_host(host)?;
        Ok(TargetSpec {
            id: TargetId::new(format!("sites/{host}.json"))?,
            class: TargetClass::Content,
            risk: RiskTier::Critical,
            max_bytes: 32_768,
        })
    }

    pub fn proposal_request(request: &SiteProposal) -> Result<ProposalRequest> {
        let bundle = SiteBundle::decode(request.bundle.canonical_bytes())?;
        if request.note.len() > 8_192 {
            return Err(crate::refuse("proposal-too-large"));
        }
        Ok(ProposalRequest {
            target: TargetId::new(bundle.target().into())?,
            base: request.base,
            new_bytes: bundle.canonical_bytes().to_vec(),
            model_note: request.note.clone(),
            cell: None,
            new_evidence: None,
            suggestion: SuggestionOrder::Single,
        })
    }

    impl<S: TargetStore> Gate<'_, S> {
        /// Read proposal data for host admission without staging a ceremony or effect.
        pub fn site_bundle(&mut self, id: ProposalId) -> Result<SiteBundle> {
            let (ledger, _, config, services) = self.install_parts();
            let transaction = ledger.begin(services)?;
            let proposal = crate::install::transition_load(&transaction, id)?;
            let bundle = validate(config, &proposal)?;
            transaction.rollback()?;
            Ok(bundle)
        }

        pub fn propose_site(
            &mut self,
            request: SiteProposal,
            crash: &mut dyn CrashInjector,
        ) -> Result<Proposal> {
            let proposal = proposal_request(&request)?;
            configured(self.config(), &proposal)?;
            self.propose(proposal, crash)
        }

        pub fn review_site(
            &mut self,
            id: ProposalId,
            crash: &mut dyn CrashInjector,
        ) -> Result<OwnerReview> {
            crash.at(CrashPoint::BeforeReview)?;
            let (ledger, targets, config, services) = self.install_parts();
            let now = crate::install::transition_now(services)?;
            let mut transaction = ledger.begin(services)?;
            let proposal = crate::install::transition_load(&transaction, id)?;
            let bundle = validate(config, &proposal)?;
            pending(&proposal, now)?;
            current_epoch(&transaction, &proposal)?;
            same_base(targets, &proposal)?;
            let displayed = crate::card::build_card(
                &proposal,
                OwnerOperation::Apply,
                crate::card::ReviewFacts {
                    says: "Publish this exact website bundle at the displayed address.".into(),
                    facts: vec![
                        (
                            "address".into(),
                            text(format!("https://{}/", bundle.host()))?,
                        ),
                        ("target".into(), text(proposal.request.target.as_str())?),
                        ("bundle_sha256".into(), text(bundle.digest())?),
                        (
                            "isolation".into(),
                            text("Separate host; no cookies or WebAuthn; framing refused.")?,
                        ),
                    ],
                    from_to: vec![
                        (
                            "base_sha256".into(),
                            text(base_name(proposal.request.base))?,
                        ),
                        (
                            "new_bytes_b64".into(),
                            text(STANDARD.encode(&proposal.request.new_bytes))?,
                        ),
                    ],
                },
            )?;
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).map_err(|_| crate::refuse("randomness"))?;
            let expires_at = now
                .checked_add(
                    i64::try_from(config.ceremony_lifetime_ms)
                        .map_err(|_| crate::refuse("clock"))?,
                )
                .filter(|value| *value <= MAX_SAFE_INTEGER)
                .ok_or(crate::refuse("clock"))?
                .min(proposal.expires_at_ms);
            let authorization = OwnerAuthorization {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                node: config.node,
                subject: transaction.gate_owner_subject()?,
                op: OwnerOperation::Apply,
                proposal: id,
                target: proposal.request.target.as_str().into(),
                base_sha256: proposal.request.base,
                new_sha256: proposal.new_digest,
                cell: None,
                display_sha256: displayed.digest(),
                challenge: AuthorizationChallenge::from_bytes(nonce),
                expires_at,
                epoch: transaction.current_version()?.epoch,
                operation: proposal.operation_digest,
            };
            let authorization_bytes = authorization.canonical_bytes()?;
            let passkey_challenge = crate::install::passkey_challenge(&authorization)?;
            transaction.stage_authorization(aura::storage::StagedAuthorization {
                authorization,
                card: displayed.card().clone(),
            })?;
            let authority = transaction.current_version()?;
            transaction.append_lifecycle(LifecycleRecord {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                authority,
                at: now,
                kind: LifecycleKind::GateReview,
                actor: "gate".into(),
                operation: proposal.operation_id,
                phase: Phase::Settle,
                body: object(vec![
                    ("proposal", text(id)?),
                    ("action", text("apply")?),
                    ("display_sha256", text(displayed.digest())?),
                    (
                        "authorization_sha256",
                        text(Digest32::sha256(&authorization_bytes))?,
                    ),
                ])?,
            })?;
            crate::install::transition_commit(transaction, crash)?;
            crash.at(CrashPoint::AfterReview)?;
            Ok(OwnerReview {
                proposal: id,
                action: OwnerOperation::Apply,
                card: displayed,
                authorization_bytes,
                passkey_challenge,
            })
        }

        pub fn apply_site(
            &mut self,
            id: ProposalId,
            assertion: OwnerAssertion,
            crash: &mut dyn CrashInjector,
        ) -> Result<Outcome> {
            crate::coverage::lookup(
                crate::coverage::EntryPoint::Apply,
                crate::coverage::EffectRoute::TargetReplace,
            )?;
            let (ledger, targets, config, services) = self.install_parts();
            let now = crate::install::transition_now(services)?;
            let mut transaction = ledger.begin(services)?;
            let proposal = crate::install::transition_load(&transaction, id)?;
            validate(config, &proposal)?;
            pending(&proposal, now)?;
            current_epoch(&transaction, &proposal)?;
            same_base(targets, &proposal)?;
            let proof = canon::authority::VerifiedProof::verify(
                &mut transaction,
                &id,
                OwnerOperation::Apply,
                assertion,
            )?;
            crash.at(CrashPoint::AfterProof)?;
            let approval = Digest32::sha256(proof.authorization_bytes());
            transaction.persist_counter(&proof)?;
            crash.at(CrashPoint::AfterCounter)?;
            transaction.consume(&proof)?;
            crash.at(CrashPoint::AfterConsumption)?;
            let authority = transaction.current_version()?;
            transaction.append(
                proof,
                PendingAuthorityRecord {
                    v: 1,
                    algorithm: AlgorithmId::Sha256,
                    authority,
                    at: now,
                    kind: Kind::GateConsume,
                    actor: "owner".into(),
                    operation: Some(proposal.operation_id),
                    phase: Phase::Settle,
                    body: object(vec![
                        ("proposal", text(id)?),
                        ("target", text(proposal.request.target.as_str())?),
                        ("operation", text(proposal.operation_digest)?),
                        ("base_sha256", text(base_name(proposal.request.base))?),
                        ("new_sha256", text(proposal.new_digest)?),
                        ("state", text("consumed")?),
                        ("retry", Value::boolean(false)),
                        ("consumed_approval", text(approval)?),
                    ])?,
                },
            )?;
            crash.at(CrashPoint::AfterAppend)?;
            crate::install::transition_commit(transaction, crash)?;
            self.site_effect(id, approval, crash)
        }

        fn site_effect(
            &mut self,
            id: ProposalId,
            approval: Digest32,
            crash: &mut dyn CrashInjector,
        ) -> Result<Outcome> {
            let (ledger, targets, config, services) = self.install_parts();
            let mut transaction = ledger.begin(services)?;
            let proposal = crate::install::transition_load(&transaction, id)?;
            validate(config, &proposal)?;
            if proposal.state != ProposalState::Consumed {
                return Err(crate::refuse("not-consumed"));
            }
            current_epoch(&transaction, &proposal)?;
            transaction.check_target_consumption(id, approval)?;
            let before = targets.observe(&proposal.request.target).ok();
            if let Some(observed) = &before {
                crate::observation::validate(observed)?;
            }
            let mut acknowledged = false;
            if before
                .as_ref()
                .is_some_and(|value| value.digest == proposal.request.base)
            {
                crash.at(CrashPoint::BeforeEffect)?;
                let replacement = targets.replace_once(EffectPermit::new(
                    proposal.operation_id,
                    proposal.request.target.clone(),
                    proposal.request.base,
                    proposal.new_digest,
                    proposal.request.new_bytes.clone(),
                ));
                crash.at(CrashPoint::AfterEffect)?;
                if let Ok(seen) = replacement {
                    crate::observation::validate(&seen)?;
                    acknowledged = seen.digest == BaseDigest::Present(proposal.new_digest)
                        && seen.bytes.as_ref() == Some(&proposal.request.new_bytes);
                }
            }
            crash.at(CrashPoint::BeforeTerminal)?;
            let (state, status, observed) =
                super::observe_effect(&mut transaction, targets, id, approval, acknowledged)?;
            let terminal = transaction.settle_consumed_target(id, approval, status, observed)?;
            transaction.release_reservation(&id)?;
            crash.at(CrashPoint::AfterTerminal)?;
            crate::install::transition_commit(transaction, crash)?;
            Ok(Outcome {
                proposal: id,
                state,
                receipt_hash: terminal.hash,
            })
        }

        pub fn published_site(&mut self, id: ProposalId) -> Result<PublishedSite> {
            let (ledger, targets, config, services) = self.install_parts();
            let transaction = ledger.begin(services)?;
            let proposal = crate::install::transition_load(&transaction, id)?;
            let bundle = validate(config, &proposal)?;
            if proposal.state != ProposalState::Applied {
                return Err(crate::refuse("not-applied"));
            }
            let terminal = transaction
                .gate_terminal(&proposal.operation_id)?
                .ok_or(crate::refuse("missing-terminal"))?;
            let wrapped = aura::record::AuthorityBodyV1::parse(&terminal.body)?;
            let body = &wrapped.payload;
            let matches = |key: &str, value: String| {
                body.get(key).is_some_and(
                    |field| matches!(field.view(), ValueView::Text(text) if text == value),
                )
            };
            if terminal.kind != Kind::GateApply
                || terminal.phase != Phase::Terminal
                || terminal.actor != "gate"
                || terminal.operation != Some(proposal.operation_id)
                || !matches("proposal", id.to_string())
                || !matches("target", proposal.request.target.as_str().into())
                || !matches("operation", proposal.operation_digest.to_string())
                || !matches("base_sha256", base_name(proposal.request.base))
                || !matches("new_sha256", proposal.new_digest.to_string())
                || !matches("observed_sha256", proposal.new_digest.to_string())
                || !matches("state", "applied".into())
                || !body
                    .get("retry")
                    .is_some_and(|field| matches!(field.view(), ValueView::Boolean(false)))
            {
                return Err(crate::refuse("terminal-mismatch"));
            }
            let approval = match body.get("consumed_approval").map(Value::view) {
                Some(ValueView::Text(value)) => Digest32::from_hex(value)?,
                _ => return Err(crate::refuse("consumption-mismatch")),
            };
            let consumed = transaction.check_target_consumption(id, approval)?;
            if consumed.authority.sequence >= terminal.authority.sequence
                || consumed.authority.epoch != terminal.authority.epoch
            {
                return Err(crate::refuse("consumption-mismatch"));
            }
            let observed = targets.observe(&proposal.request.target)?;
            if !observation_valid(&observed)
                || observed.digest != BaseDigest::Present(proposal.new_digest)
                || observed.bytes.as_ref() != Some(&proposal.request.new_bytes)
            {
                return Err(crate::refuse("target-observation"));
            }
            transaction.rollback()?;
            Ok(PublishedSite {
                bundle,
                proposal: id,
                receipt_sequence: terminal.authority.sequence,
            })
        }
    }

    pub(crate) fn validate_request(
        config: &crate::service::GateConfig,
        request: &ProposalRequest,
    ) -> Result<()> {
        configured(config, request)?;
        let bundle = SiteBundle::decode(&request.new_bytes)?;
        if request.target.as_str() != bundle.target()
            || request.cell.is_some()
            || request.new_evidence.is_some()
            || request.suggestion != SuggestionOrder::Single
        {
            return Err(crate::refuse("operation-mismatch"));
        }
        Ok(())
    }

    fn configured(config: &crate::service::GateConfig, request: &ProposalRequest) -> Result<()> {
        let spec = config
            .targets
            .iter()
            .find(|value| value.id == request.target)
            .ok_or(crate::refuse("unknown-target"))?;
        if spec.class != TargetClass::Content || spec.risk != RiskTier::Critical {
            return Err(crate::refuse("unsupported-operation"));
        }
        if request.new_bytes.len() > spec.max_bytes {
            return Err(crate::refuse("proposal-too-large"));
        }
        Ok(())
    }

    pub(crate) fn validate(
        config: &crate::service::GateConfig,
        proposal: &Proposal,
    ) -> Result<SiteBundle> {
        configured(config, &proposal.request)?;
        let bundle = SiteBundle::decode(&proposal.request.new_bytes)?;
        if proposal.request.target.as_str() != bundle.target()
            || proposal.risk != RiskTier::Critical
            || proposal.request.cell.is_some()
            || proposal.request.new_evidence.is_some()
            || proposal.request.suggestion != SuggestionOrder::Single
            || proposal.new_digest != bundle.digest()
            || proposal.operation_digest
                != crate::proposal::content_digest(config.node, &proposal.request)?
        {
            return Err(crate::refuse("operation-mismatch"));
        }
        Ok(bundle)
    }

    fn pending(proposal: &Proposal, now: i64) -> Result<()> {
        if proposal.state != ProposalState::Pending {
            return Err(crate::refuse("not-pending"));
        }
        if now >= proposal.expires_at_ms {
            return Err(crate::refuse("expired"));
        }
        Ok(())
    }

    fn current_epoch(transaction: &aura::LedgerTxn<'_>, proposal: &Proposal) -> Result<()> {
        if proposal.authority.epoch != transaction.current_version()?.epoch {
            return Err(crate::refuse("operation-mismatch"));
        }
        Ok(())
    }

    fn same_base(store: &impl TargetStore, proposal: &Proposal) -> Result<()> {
        let seen = store.observe(&proposal.request.target)?;
        if !observation_valid(&seen) {
            return Err(crate::refuse("target-observation"));
        }
        if seen.digest != proposal.request.base {
            return Err(crate::refuse("stale-base"));
        }
        Ok(())
    }

    fn observation_valid(value: &TargetObservation) -> bool {
        match (&value.digest, &value.bytes) {
            (BaseDigest::Absent, None) => true,
            (BaseDigest::Present(digest), Some(bytes)) => *digest == Digest32::sha256(bytes),
            _ => false,
        }
    }

    fn base_name(base: BaseDigest) -> String {
        match base {
            BaseDigest::Absent => "absent".into(),
            BaseDigest::Present(digest) => digest.to_string(),
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
}

fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}
