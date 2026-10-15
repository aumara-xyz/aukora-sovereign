// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed app bytes and closed app-local grants. Proposals never authorize launch.

use crate::{
    card::{CeremonyContext, DisplayedCard, ReviewFacts},
    proposal::SuggestionOrder,
    target::{TargetClass, TargetId, TargetSpec},
    Proposal, ProposalRequest, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    authority::{BaseDigest, Card, CardRisk, OwnerAuthorization, OwnerOperation},
    digest::Digest32,
    ids::AppId,
    json::{self, Value, ValueView},
};
use sha2::{Digest, Sha256};

pub const MANIFEST_SCHEMA: &str = "aukora-app-manifest-v1";
pub const INSTALL_SCHEMA: &str = "aukora-app-install-v1";
pub const MANIFEST_DOMAIN: &str = "aukora:app-manifest:v1";
pub const MAX_MANIFEST_BYTES: usize = 16_384;
pub const MAX_PACKAGE_BYTES: usize = 8_388_608;
pub const MAX_INSTALL_BYTES: usize = 24_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallRequest {
    pub app: AppId,
    pub package_digest: Digest32,
    pub manifest_bytes: Vec<u8>,
}

/// Authority, network, model calls and global storage are never grant variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppGrant {
    Clock,
    Random,
    StorageRead,
    StorageWrite,
}

impl AppGrant {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Clock => "app.clock",
            Self::Random => "app.random",
            Self::StorageRead => "app.storage.read",
            Self::StorageWrite => "app.storage.write",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "app.clock" => Ok(Self::Clock),
            "app.random" => Ok(Self::Random),
            "app.storage.read" => Ok(Self::StorageRead),
            "app.storage.write" => Ok(Self::StorageWrite),
            _ => Err(crate::refuse("install-grant")),
        }
    }
}

/// Valid author evidence. Its private fields cannot supply an owner proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallManifest {
    app: AppId,
    name: String,
    version: String,
    package_digest: Digest32,
    author: [u8; 32],
    grants: Vec<AppGrant>,
    runtime_entry: String,
    face_entry: String,
    bytes: Vec<u8>,
}

impl InstallManifest {
    pub const fn app(&self) -> AppId {
        self.app
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub const fn package_digest(&self) -> Digest32 {
        self.package_digest
    }
    pub const fn author(&self) -> &[u8; 32] {
        &self.author
    }
    pub fn grants(&self) -> &[AppGrant] {
        &self.grants
    }
    pub fn runtime_entry(&self) -> &str {
        &self.runtime_entry
    }
    pub fn face_entry(&self) -> &str {
        &self.face_entry
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact package verification does not authorize installation or execution.
    pub fn verify_package(&self, package: &[u8]) -> Result<()> {
        if package.is_empty() || package.len() > MAX_PACKAGE_BYTES {
            return Err(crate::refuse("install-package-size"));
        }
        if hash(package) != self.package_digest {
            return Err(crate::refuse("install-package-digest"));
        }
        Ok(())
    }
}

pub fn decode_manifest(bytes: &[u8]) -> Result<InstallManifest> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(crate::refuse("install-manifest-size"));
    }
    let outer = canonical(bytes)?;
    keys(&outer, &["schema", "body", "signature"])?;
    if text(field(&outer, "schema")?)? != MANIFEST_SCHEMA {
        return Err(crate::refuse("install-version"));
    }
    let body = field(&outer, "body")?;
    keys(
        body,
        &[
            "id",
            "name",
            "version",
            "package_sha256",
            "grants",
            "runtime",
            "face",
        ],
    )?;
    let app = AppId::from_hex(text(field(body, "id")?)?)?;
    let name = text(field(body, "name")?)?;
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(crate::refuse("install-name"));
    }
    let version = text(field(body, "version")?)?;
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(crate::refuse("install-version"));
    }
    let package_digest = Digest32::from_hex(text(field(body, "package_sha256")?)?)?;
    let ValueView::Array(values) = field(body, "grants")?.view() else {
        return Err(crate::refuse("install-grant"));
    };
    if values.len() > 4 {
        return Err(crate::refuse("install-grant"));
    }
    let mut grants = Vec::with_capacity(values.len());
    for value in values {
        let grant = AppGrant::parse(text(value)?)?;
        if grants.last().is_some_and(|previous| *previous >= grant) {
            return Err(crate::refuse("install-grant-order"));
        }
        grants.push(grant);
    }
    let runtime = field(body, "runtime")?;
    keys(runtime, &["kind", "entry", "network", "exec", "wasi"])?;
    if text(field(runtime, "kind")?)? != "user-app" {
        return Err(crate::refuse("install-runtime"));
    }
    for key in ["network", "exec", "wasi"] {
        if !matches!(field(runtime, key)?.view(), ValueView::Boolean(false)) {
            return Err(crate::refuse("install-runtime"));
        }
    }
    let runtime_entry = path(field(runtime, "entry")?, ".wasm")?;
    let face = field(body, "face")?;
    keys(face, &["entry"])?;
    let face_entry = path(field(face, "entry")?, ".html")?;
    let signature = field(&outer, "signature")?;
    keys(signature, &["v", "algorithm", "public_key", "signature"])?;
    if !matches!(field(signature, "v")?.view(), ValueView::Integer(n) if n.get() == 1)
        || text(field(signature, "algorithm")?)? != "secp256k1-schnorr"
    {
        return Err(crate::refuse("install-signature-algorithm"));
    }
    let author: [u8; 32] = decode_hex(text(field(signature, "public_key")?)?)?;
    let signature: [u8; 64] = decode_hex(text(field(signature, "signature")?)?)?;
    let mut message = Vec::from(MANIFEST_DOMAIN.as_bytes());
    message.push(0);
    message.extend(json::to_canonical(body));
    aumlok::keys::verify_app_manifest_signature(&author, &message, &signature)
        .map_err(|_| crate::refuse("install-signature"))?;
    Ok(InstallManifest {
        app,
        name: name.into(),
        version: version.into(),
        package_digest,
        author,
        grants,
        runtime_entry,
        face_entry,
        bytes: bytes.to_vec(),
    })
}

pub fn install_target(app: AppId) -> Result<TargetId> {
    TargetId::new(format!("apps/{app}/installed"))
}

pub fn target_spec(app: AppId) -> Result<TargetSpec> {
    Ok(TargetSpec {
        id: install_target(app)?,
        class: TargetClass::Install,
        risk: CardRisk::Critical,
        max_bytes: MAX_INSTALL_BYTES,
    })
}

/// C5 commits to these exact signed manifest bytes, package digest and grants.
pub fn propose_install(request: InstallRequest) -> Result<ProposalRequest> {
    let manifest = decode_manifest(&request.manifest_bytes)?;
    if manifest.app != request.app || manifest.package_digest != request.package_digest {
        return Err(crate::refuse("install-manifest-binding"));
    }
    let body = object(vec![
        ("app", string(request.app)?),
        ("package_sha256", string(request.package_digest)?),
        (
            "manifest_b64",
            string(STANDARD.encode(&request.manifest_bytes))?,
        ),
    ])?;
    let new_bytes =
        object(vec![("schema", string(INSTALL_SCHEMA)?), ("body", body)])?.canonical_bytes();
    Ok(ProposalRequest {
        target: install_target(request.app)?,
        base: BaseDigest::Absent,
        new_bytes,
        model_note: String::new(),
        cell: None,
        new_evidence: None,
        suggestion: SuggestionOrder::Single,
    })
}

pub fn propose_package(request: InstallRequest, package: &[u8]) -> Result<ProposalRequest> {
    decode_manifest(&request.manifest_bytes)?.verify_package(package)?;
    propose_install(request)
}

pub fn validate_proposal(proposal: &Proposal) -> Result<InstallManifest> {
    validate_request(&proposal.request)
}

pub fn validate_request(request: &ProposalRequest) -> Result<InstallManifest> {
    if request.new_bytes.len() > MAX_INSTALL_BYTES
        || request.cell.is_some()
        || request.base != BaseDigest::Absent
        || !matches!(request.suggestion, SuggestionOrder::Single)
        || request.new_evidence.is_some()
        || !request.model_note.is_empty()
    {
        return Err(crate::refuse("install-proposal"));
    }
    let outer = canonical(&request.new_bytes)?;
    keys(&outer, &["schema", "body"])?;
    if text(field(&outer, "schema")?)? != INSTALL_SCHEMA {
        return Err(crate::refuse("install-version"));
    }
    let body = field(&outer, "body")?;
    keys(body, &["app", "package_sha256", "manifest_b64"])?;
    let encoded = text(field(body, "manifest_b64")?)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| crate::refuse("install-manifest-encoding"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(crate::refuse("install-manifest-encoding"));
    }
    let manifest = decode_manifest(&bytes)?;
    if text(field(body, "app")?)? != manifest.app.to_string()
        || text(field(body, "package_sha256")?)? != manifest.package_digest.to_string()
        || request.target != install_target(manifest.app)?
    {
        return Err(crate::refuse("install-manifest-binding"));
    }
    Ok(manifest)
}

pub fn review_facts(proposal: &Proposal) -> Result<ReviewFacts> {
    let manifest = validate_proposal(proposal)?;
    let grants = manifest
        .grants
        .iter()
        .map(|g| string(g.wire_name()))
        .collect::<Result<Vec<_>>>()?;
    Ok(ReviewFacts {
        says: "Install these exact signed app bytes with only the displayed app-local grants."
            .into(),
        facts: vec![
            ("app".into(), string(manifest.app)?),
            ("name".into(), string(&manifest.name)?),
            ("version".into(), string(&manifest.version)?),
            ("author".into(), string(hex::encode(manifest.author))?),
            ("package_sha256".into(), string(manifest.package_digest)?),
            ("manifest_sha256".into(), string(hash(&manifest.bytes))?),
            ("grants".into(), Value::array(grants)?),
            (
                "runtime".into(),
                string(
                    "Required: separate user-app cage; no network, exec or WASI; never Auma or wasmcell.",
                )?,
            ),
        ],
        from_to: vec![
            ("base_sha256".into(), string("absent")?),
            (
                "new_bytes_b64".into(),
                string(STANDARD.encode(&proposal.request.new_bytes))?,
            ),
        ],
    })
}

pub fn build_displayed_card(proposal: &Proposal, action: OwnerOperation) -> Result<DisplayedCard> {
    if action != OwnerOperation::Apply {
        return Err(crate::refuse("install-operation"));
    }
    let facts = review_facts(proposal)?;
    let card = Card {
        v: 1,
        risk: CardRisk::Critical,
        says: facts.says,
        facts: facts.facts,
        from_to: facts.from_to,
        model_note: String::new(),
    };
    DisplayedCard::from_install_card(card)
}

pub fn owner_authorization(
    proposal: &Proposal,
    card: &DisplayedCard,
    context: CeremonyContext,
) -> Result<OwnerAuthorization> {
    validate_proposal(proposal)?;
    if proposal.risk != CardRisk::Critical || context.epoch != proposal.authority.epoch {
        return Err(crate::refuse("install-authority"));
    }
    Ok(OwnerAuthorization {
        v: 1,
        algorithm: canon::alg::AlgorithmId::Sha256,
        node: context.node,
        subject: context.subject,
        op: OwnerOperation::Apply,
        proposal: proposal.id,
        target: proposal.request.target.as_str().into(),
        base_sha256: proposal.request.base,
        new_sha256: hash(&proposal.request.new_bytes),
        cell: None,
        display_sha256: card.digest(),
        challenge: context.challenge,
        expires_at: context.expires_at_ms,
        epoch: context.epoch,
        operation: crate::proposal::content_digest(context.node, &proposal.request)?,
    })
}

pub fn passkey_challenge(authorization: &OwnerAuthorization) -> Result<Digest32> {
    let mut digest = Sha256::new();
    digest.update(canon::domain::OWNER_AUTHORIZATION_DOMAIN.as_bytes());
    digest.update([0]);
    digest.update(authorization.canonical_bytes()?);
    Ok(Digest32::from_bytes(digest.finalize().into()))
}

fn canonical(bytes: &[u8]) -> Result<Value> {
    let value = json::parse_strict(bytes)?;
    if json::to_canonical(&value) != bytes {
        return Err(crate::refuse("install-noncanonical"));
    }
    Ok(value)
}
fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let ValueView::Object(members) = value.view() else {
        return Err(crate::refuse("install-shape"));
    };
    if members.len() != expected.len()
        || members
            .iter()
            .any(|(key, _)| !expected.contains(&key.as_str()))
    {
        return Err(crate::refuse("install-shape"));
    }
    Ok(())
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(crate::refuse("install-shape"))
}
fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(s) => Ok(s),
        _ => Err(crate::refuse("install-shape")),
    }
}
fn path(value: &Value, suffix: &str) -> Result<String> {
    let s = text(value)?;
    if s.is_empty()
        || s.len() > 128
        || !s.ends_with(suffix)
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || s.split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(crate::refuse("install-path"));
    }
    Ok(s.into())
}
fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(crate::refuse("install-signature-encoding"));
    }
    let bytes = hex::decode(s).map_err(|_| crate::refuse("install-signature-encoding"))?;
    bytes
        .try_into()
        .map_err(|_| crate::refuse("install-signature-encoding"))
}
fn string(s: impl ToString) -> Result<Value> {
    Value::text(s.to_string())
}
fn object(entries: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

// Installation transitions.

use canon::authority::AuthorityTxn as _;

impl<'a, S: crate::target::TargetStore> crate::service::Gate<'a, S> {
    pub fn propose_install(
        &mut self,
        request: InstallRequest,
        crash: &mut dyn crate::recovery::CrashInjector,
    ) -> Result<Proposal> {
        let request = propose_install(request)?;
        let (_, _, config, _) = self.install_parts();
        transition_target(config, &request.target, request.new_bytes.len())?;
        self.propose(request, crash)
    }

    pub fn review_install(
        &mut self,
        id: canon::ids::ProposalId,
        crash: &mut dyn crate::recovery::CrashInjector,
    ) -> Result<crate::service::OwnerReview> {
        use crate::recovery::CrashPoint;
        use canon::authority::{AuthorizationChallenge, LifecycleKind, LifecycleRecord, Phase};

        crash.at(CrashPoint::BeforeReview)?;
        let (ledger, targets, config, services) = self.install_parts();
        let now = transition_now(services)?;
        let mut transaction = ledger.begin(services)?;
        let proposal = transition_load(&transaction, id)?;
        transition_validate(config, &proposal, now)?;
        transition_observe(targets, &proposal)?;
        let displayed = build_displayed_card(&proposal, OwnerOperation::Apply)?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| crate::refuse("randomness"))?;
        let expires_at_ms = now
            .checked_add(
                i64::try_from(config.ceremony_lifetime_ms).map_err(|_| crate::refuse("clock"))?,
            )
            .filter(|expires| *expires <= canon::json::MAX_SAFE_INTEGER)
            .ok_or(crate::refuse("clock"))?
            .min(proposal.expires_at_ms);
        let authorization = owner_authorization(
            &proposal,
            &displayed,
            CeremonyContext {
                node: config.node,
                subject: transaction.gate_owner_subject()?,
                epoch: transaction.current_version()?.epoch,
                challenge: AuthorizationChallenge::from_bytes(nonce),
                expires_at_ms,
            },
        )?;
        let authorization_bytes = authorization.canonical_bytes()?;
        let passkey_challenge = passkey_challenge(&authorization)?;
        transaction.stage_authorization(aura::storage::StagedAuthorization {
            authorization,
            card: displayed.card().clone(),
        })?;
        let record = LifecycleRecord {
            v: 1,
            algorithm: canon::alg::AlgorithmId::Sha256,
            authority: transaction.current_version()?,
            at: now,
            kind: LifecycleKind::GateReview,
            actor: "gate".into(),
            operation: proposal.operation_id,
            phase: Phase::Settle,
            body: object(vec![
                ("proposal", string(id)?),
                ("action", string(OwnerOperation::Apply.wire_name())?),
                ("display_sha256", string(displayed.digest())?),
                ("authorization_sha256", string(hash(&authorization_bytes))?),
            ])?,
        };
        transaction.append_lifecycle(record)?;
        transition_commit(transaction, crash)?;
        crash.at(CrashPoint::AfterReview)?;
        Ok(crate::service::OwnerReview {
            proposal: id,
            action: OwnerOperation::Apply,
            card: displayed,
            authorization_bytes,
            passkey_challenge,
        })
    }

    pub fn apply_install(
        &mut self,
        id: canon::ids::ProposalId,
        assertion: canon::authority::OwnerAssertion,
        crash: &mut dyn crate::recovery::CrashInjector,
    ) -> Result<crate::service::Outcome> {
        use crate::{
            coverage::{self, EffectRoute, EntryPoint},
            recovery::CrashPoint,
        };
        use canon::authority::{Kind, PendingAuthorityRecord, Phase};

        coverage::lookup(EntryPoint::Apply, EffectRoute::TargetReplace)?;
        let (ledger, targets, config, services) = self.install_parts();
        let now = transition_now(services)?;
        let mut transaction = ledger.begin(services)?;
        let proposal = transition_load(&transaction, id)?;
        transition_validate(config, &proposal, now)?;
        transition_observe(targets, &proposal)?;
        let proof = canon::authority::VerifiedProof::verify(
            &mut transaction,
            &id,
            OwnerOperation::Apply,
            assertion,
        )?;
        crash.at(CrashPoint::AfterProof)?;
        let approval = hash(proof.authorization_bytes());
        transaction.persist_counter(&proof)?;
        crash.at(CrashPoint::AfterCounter)?;
        transaction.consume(&proof)?;
        crash.at(CrashPoint::AfterConsumption)?;
        let record = PendingAuthorityRecord {
            v: 1,
            algorithm: canon::alg::AlgorithmId::Sha256,
            authority: transaction.current_version()?,
            at: now,
            kind: Kind::GateConsume,
            actor: "owner".into(),
            operation: Some(proposal.operation_id),
            phase: Phase::Settle,
            body: object(vec![
                ("proposal", string(proposal.id)?),
                ("target", string(proposal.request.target.as_str())?),
                ("operation", string(proposal.operation_digest)?),
                ("base_sha256", string("absent")?),
                ("new_sha256", string(proposal.new_digest)?),
                ("state", string("consumed")?),
                ("retry", Value::boolean(false)),
                ("consumed_approval", string(approval)?),
            ])?,
        };
        transaction.append(proof, record)?;
        crash.at(CrashPoint::AfterAppend)?;
        transition_commit(transaction, crash)?;
        self.install_effect(id, approval, crash)
    }
}

pub(crate) fn transition_target(
    config: &crate::service::GateConfig,
    target: &TargetId,
    length: usize,
) -> Result<()> {
    let spec = config
        .targets
        .iter()
        .find(|spec| spec.id == *target)
        .ok_or(crate::refuse("unknown-target"))?;
    if spec.class != TargetClass::Install || spec.risk != CardRisk::Critical {
        return Err(crate::refuse("install-target-class"));
    }
    if length > spec.max_bytes || length > MAX_INSTALL_BYTES {
        return Err(crate::refuse("proposal-too-large"));
    }
    Ok(())
}

pub(crate) fn transition_load(
    transaction: &aura::LedgerTxn<'_>,
    id: canon::ids::ProposalId,
) -> Result<Proposal> {
    let stored = transaction.proposal(&id)?;
    let record = transaction.record_at(stored.authority)?;
    crate::proposal::from_stored(stored, &record)
}

fn transition_validate(
    config: &crate::service::GateConfig,
    proposal: &Proposal,
    now: i64,
) -> Result<()> {
    transition_target(
        config,
        &proposal.request.target,
        proposal.request.new_bytes.len(),
    )?;
    if proposal.state != crate::ProposalState::Pending {
        return Err(crate::refuse("not-pending"));
    }
    if now >= proposal.expires_at_ms {
        return Err(crate::refuse("expired"));
    }
    if proposal.risk != CardRisk::Critical
        || proposal.new_digest != hash(&proposal.request.new_bytes)
        || proposal.operation_digest
            != crate::proposal::content_digest(config.node, &proposal.request)?
    {
        return Err(crate::refuse("operation-mismatch"));
    }
    validate_proposal(proposal)?;
    Ok(())
}

fn transition_observe<S: crate::target::TargetStore>(
    targets: &S,
    proposal: &Proposal,
) -> Result<()> {
    let observed = targets.observe(&proposal.request.target)?;
    match (&observed.digest, &observed.bytes) {
        (BaseDigest::Absent, None) => (),
        (BaseDigest::Present(expected), Some(bytes)) if *expected == hash(bytes) => (),
        _ => return Err(crate::refuse("target-observation")),
    }
    if observed.digest != proposal.request.base {
        return Err(crate::refuse("stale-base"));
    }
    Ok(())
}

pub(crate) fn transition_now(services: aura::TransactionServices<'_>) -> Result<i64> {
    let now = services.clock.now_ms()?;
    if !(0..=canon::json::MAX_SAFE_INTEGER).contains(&now) {
        return Err(crate::refuse("clock"));
    }
    Ok(now)
}

pub(crate) fn observe_settlement<S: crate::target::TargetStore>(
    transaction: &mut aura::LedgerTxn<'_>,
    targets: &S,
    proposal: &Proposal,
    approval: Digest32,
    status: aura::storage::ProposalStatus,
    observed: Option<&crate::target::TargetObservation>,
) -> Result<()> {
    let stored = transaction.proposal(&proposal.id)?;
    if stored.target != proposal.request.target.as_str() {
        return Err(crate::refuse("install-target-mismatch"));
    }
    let seen = targets.observe(&proposal.request.target)?;
    match (&seen.digest, &seen.bytes) {
        (BaseDigest::Absent, None) => (),
        (BaseDigest::Present(digest), Some(bytes)) if *digest == hash(bytes) => (),
        _ => return Err(crate::refuse("target-observation")),
    }
    // Validate the read before Aura can classify a reader error as Unknown.
    let (read_status, read_digest) = transaction.observe_consumed_target(
        proposal.id,
        approval,
        |_| Ok(seen.bytes),
    )?;
    if read_status != status || read_digest != observed.map(|seen| seen.digest) {
        return Err(crate::refuse("install-observation-changed"));
    }
    Ok(())
}

pub(crate) fn transition_commit(
    transaction: aura::LedgerTxn<'_>,
    crash: &mut dyn crate::recovery::CrashInjector,
) -> Result<()> {
    crash.at(crate::recovery::CrashPoint::BeforeCommit)?;
    transaction.commit()?;
    crash.at(crate::recovery::CrashPoint::AfterCommit)
}

/// Minted only from a verified applied owner receipt and the matching stored bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledApp {
    manifest: InstallManifest,
    receipt_sequence: u64,
}

impl InstalledApp {
    pub const fn app(&self) -> AppId {
        self.manifest.app()
    }
    pub fn manifest(&self) -> &InstallManifest {
        &self.manifest
    }
    pub const fn receipt_sequence(&self) -> u64 {
        self.receipt_sequence
    }
    pub fn service_grant(&self, operation: &str) -> Result<AppGrant> {
        let required = match operation {
            "storage.read" => AppGrant::StorageRead,
            "storage.write" => AppGrant::StorageWrite,
            "clock.now" => AppGrant::Clock,
            "random.bytes" => AppGrant::Random,
            _ => return Err(crate::refuse("install-service-operation")),
        };
        if !self.manifest.grants.contains(&required) {
            return Err(crate::refuse("install-service-denied"));
        }
        Ok(required)
    }
}

impl<S: crate::target::TargetStore> crate::service::Gate<'_, S> {
    pub fn installed_app(&mut self, id: canon::ids::ProposalId) -> Result<InstalledApp> {
        use canon::authority::{Kind, Phase};
        let (ledger, targets, config, services) = self.install_parts();
        let transaction = ledger.begin(services)?;
        let proposal = transition_load(&transaction, id)?;
        transition_target(
            config,
            &proposal.request.target,
            proposal.request.new_bytes.len(),
        )?;
        let manifest = validate_proposal(&proposal)?;
        if proposal.state != crate::ProposalState::Applied
            || proposal.risk != CardRisk::Critical
            || proposal.new_digest != hash(&proposal.request.new_bytes)
            || proposal.operation_digest
                != crate::proposal::content_digest(config.node, &proposal.request)?
        {
            return Err(crate::refuse("install-not-applied"));
        }
        let receipt = transaction
            .gate_terminal(&proposal.operation_id)?
            .ok_or(crate::refuse("missing-terminal"))?;
        let wrapped = aura::record::AuthorityBodyV1::parse(&receipt.body)?;
        let payload = &wrapped.payload;
        if receipt.kind != Kind::GateApply
            || receipt.phase != Phase::Terminal
            || receipt.actor != "gate"
            || receipt.operation != Some(proposal.operation_id)
            || text(field(payload, "proposal")?)? != id.to_string()
            || text(field(payload, "target")?)? != proposal.request.target.as_str()
            || text(field(payload, "operation")?)? != proposal.operation_digest.to_string()
            || text(field(payload, "base_sha256")?)? != "absent"
            || text(field(payload, "new_sha256")?)? != proposal.new_digest.to_string()
            || text(field(payload, "observed_sha256")?)? != proposal.new_digest.to_string()
            || text(field(payload, "state")?)? != "applied"
            || !matches!(field(payload, "retry")?.view(), ValueView::Boolean(false))
        {
            return Err(crate::refuse("install-receipt"));
        }
        let approval = Digest32::from_hex(text(field(payload, "consumed_approval")?)?)?;
        let consumed = transaction.check_target_consumption(id, approval)?;
        if consumed.authority.sequence >= receipt.authority.sequence
            || consumed.authority.epoch != receipt.authority.epoch
        {
            return Err(crate::refuse("install-receipt"));
        }
        let observed = targets.observe(&proposal.request.target)?;
        if observed.digest != BaseDigest::Present(proposal.new_digest)
            || observed.bytes.as_ref() != Some(&proposal.request.new_bytes)
        {
            return Err(crate::refuse("install-target-mismatch"));
        }
        transaction.rollback()?;
        Ok(InstalledApp {
            manifest,
            receipt_sequence: receipt.authority.sequence,
        })
    }
}
