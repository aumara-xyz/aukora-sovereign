// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host composition for the deployed supervisor entry point.

mod door_routes;
mod engine_routes;
pub use engine_routes::ReleaseStanding;
mod owner_gate;
mod pairing_routes;

use crate::{
    adapters::{HostClock, HostLedger},
    config::NodeConfig,
    release::ReleaseFiles,
    state::HostState,
};
use canon::{codes, json::Value, Result};
use frontdoor::{
    assets::{ApprovedRelease, AssetSurface},
    documents::DocumentRoot,
    ingress::{AdmittedRequest, HostRole, HttpAdmission, Method},
    owner_origin::OwnerRoute,
    session::DurableSessions,
};
use std::{
    fs::File,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use supervisor::{
    ingress::{BindingState, PrincipalScope},
    runtime::{GuestState, RuntimeMeasurement, SupervisorRuntime},
};

impl supervisor::claim::ClaimAuthority for HostLedger {
    fn transaction(
        &self,
        operation: &mut dyn FnMut(
            &mut aura::LedgerTxn<'_>,
        ) -> Result<frontdoor::session::SessionRecord>,
    ) -> Result<frontdoor::session::SessionRecord> {
        HostLedger::transaction(self, |authority| operation(authority))
    }
}

pub struct Host {
    pub config: NodeConfig,
    pub state: HostState,
    pub ledger: Arc<HostLedger>,
    pub documents: DocumentRoot,
    sessions: File,
    claim_service: Mutex<Option<supervisor::claim::HostClaimService>>,
    identity: Arc<Mutex<crate::identity::Identity>>,
    assets: Arc<Mutex<Assets>>,
    pub runtime: Arc<crate::adapters::runtime::RuntimeAdapter>,
    pub health: Arc<crate::health::HealthCollector>,
    data: Arc<crate::data::HostData>,
    live_data: crate::data::live::RuntimeData,
    broker: Arc<crate::adapters::BrokerAdapter>,
    faces: crate::faces::host::HostFaces,
    approvals: crate::approvals::ApprovalFeed,
    gate: Arc<crate::adapters::GateAdapter>,
    runtime_refusal: Mutex<Option<canon::Refusal>>,
    handoffs: Mutex<frontdoor::fd4::ShellHandoffs>,
    engine: Option<Arc<crate::engine::Engine>>,
    model_broker: Option<Arc<crate::model_broker::ModelBroker>>,
    pairing: Option<Arc<crate::pairing::Pairing>>,
}
struct Assets {
    source: ReleaseFiles,
    release: Option<ApprovedRelease>,
    measured: RuntimeMeasurement,
}

impl crate::adapters::runtime::ReleaseAdmission for Mutex<Assets> {
    fn measure(&self) -> Result<RuntimeMeasurement> {
        Ok(self.lock().map_err(|_| codes::SUPERVISOR_STATE)?.measured)
    }
    fn require_release(&self, measured: RuntimeMeasurement) -> Result<()> {
        let assets = self.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        if assets.measured != measured {
            return Err(codes::SUPERVISOR_STATE);
        }
        assets.source.approval()
    }
}

pub async fn serve(config: NodeConfig) -> Result<()> {
    let _egress = config.load_egress()?;
    let boundary = config.boundary()?;
    let state = HostState::open(&config.state_root, &config.node)?;
    let ledger = HostLedger::open(
        &config.state_root.join("aura.sqlite3"),
        state.signer.clone(),
        Arc::new(HostClock),
    )?;
    let ledger = Arc::new(ledger);
    let sessions = state.subdirectory("browser-sessions")?;
    let descriptor = sessions.try_clone().map_err(|_| codes::SUPERVISOR_STATE)?;
    match rustix::fs::statat(
        &sessions,
        "sessions-v1.json",
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(rustix::io::Errno::NOENT) => {
            ledger.transaction(|transaction| {
                require_initial_sessions(transaction, &sessions)?;
                DurableSessions::initialize(
                    descriptor,
                    state.node,
                    boundary.shell,
                    boundary.owner,
                )?;
                Ok(())
            })?;
        }
        Ok(_) => {
            DurableSessions::open(descriptor, state.node, boundary.shell, boundary.owner)?;
        }
        Err(_) => return Err(codes::SUPERVISOR_STATE),
    }
    let documents = DocumentRoot::open(state.subdirectory("documents")?)?;
    state.subdirectory("floor")?;
    let source = ReleaseFiles::open(
        &config.approved_release_root,
        config.state_root.join("floor"),
        ledger.clone(),
    )?;
    source.initialize_floor(
        &sessions,
        state.node,
        &config.shell_origin,
        &config.owner_origin,
    )?;
    source.configure_owner_approval(state.node, &config.approved_release_root)?;
    let measured = RuntimeMeasurement {
        binary_sha256: source.binary_digest,
        shell_manifest_sha256: source.manifest_digest(),
        antibody_root: immune::ratchet::Corpus::pinned()?.root(),
    };
    let assets = Arc::new(Mutex::new(Assets {
        source,
        release: None,
        measured,
    }));
    // No target is writable until an owning-organ target configuration is supplied.
    let gate = Arc::new(crate::adapters::GateAdapter::start(
        config.state_root.join("aura.sqlite3"),
        state.subdirectory("targets")?,
        gate::service::GateConfig {
            node: state.node,
            targets: Vec::new(),
            proposal_lifetime_ms: 300_000,
            ceremony_lifetime_ms: 300_000,
        },
        ledger.clone(),
    )?);
    gate.configure_targets(config.gate_targets()?)?;
    // The door for the engine's crossings, when this node has a policy for it: its asks become gate proposals.
    crate::door::start_in_node(&config, ledger.clone(), gate.clone());
    if let BindingState::Bound(scope) = ledger.binding()? {
        // A floor that differs from the installed release is a refused shell, never a crash loop (SCOUT 6c4046c).
        // Raising the release proposal is best effort at start-up: a refused or stale proposal leaves the shell
        // refused, never a crash loop (SCOUT ad03d28 #4). The approvals poll retries it.
        if let Err(refusal) = ledger.ensure_release_proposal(scope) {
            eprintln!("supervisor: release proposal not raised at start-up: {}:{}", refusal.organ, refusal.reason);
        }
    }
    // One key inbox: the key the owner enters for the engine's model path is the broker's key.
    let keys = Arc::new(broker::keystore::KeyInbox::new());
    let broker = Arc::new(crate::adapters::BrokerAdapter::new(
        ledger.clone(),
        keys.clone(),
        Arc::new(broker::intake::ModelSlot::new()),
    ));
    // The engine's model path (deploy/engine/NODE.md section 7), when this node has `model-broker-v1.json`.
    state.subdirectory("model-broker")?;
    // The owner-approved provider key at rest (broker::keyfile): a private folder of the supervisor's own state.
    state.subdirectory("model-key")?;
    let model_broker = crate::model_broker::start_in_node(
        &config,
        config.state_root.join("model-broker"),
        ledger.clone(),
        gate.clone(),
        keys,
        config.state_root.join("model-key"),
    );
    // Recovery refusal remains in the broker adapter and cannot take down owner ingress.
    let _recovery = broker.recover();
    let health = Arc::new(crate::health::HealthCollector::new(
        ledger.clone(),
        gate.clone(),
        config.clone(),
    ));
    state.subdirectory("transcripts")?;
    let transcripts = Arc::new(supervisor::session::DurableSessions::open(
        supervisor::session::SessionStoreConfig {
            root: config.state_root.join("transcripts"),
            limits: supervisor::session::SessionLimits {
                max_sessions_per_principal: 4096,
                max_entries_per_session: 1_000_000,
                max_bytes_per_principal: 1024 * 1024 * 1024,
            },
        },
    )?);
    let runner = wasmcell::Runner::new()?;
    let kira = Arc::new(crate::adapters::kira::KiraAdapter::new(ledger.clone())?);
    let snapshots = Arc::new(crate::adapters::snapshot::SnapshotAdapter::new(
        ledger.clone(),
        Arc::new(crate::adapters::snapshot::UnavailablePublicSnapshots),
        runner.module_digest(),
        config.owner_origin.clone(),
    )?);
    state.subdirectory("messaging")?;
    let messaging = messaging::Messaging::open(&config.state_root.join("messaging"), state.node)?;
    let network = Arc::new(crate::faces::live_network::LiveNetwork::new(
        ledger.clone(),
        messaging,
    ));
    let identity = Arc::new(Mutex::new(crate::identity::Identity::open(
        ledger.clone(),
        frontdoor::owner_origin::CeremonyContext::from_boundary(&config.boundary()?)?,
        state.node,
        &config.state_root.join("aura.sqlite3"),
    )?));
    let faces = crate::faces::host::HostFaces::new(
        ledger.clone(),
        transcripts.clone(),
        health.clone(),
        broker.clone(),
    )
    .with_network(network)
    .with_kira(kira.clone())
    .with_identity(identity.clone());
    let owner_gate = gate.clone();
    let runtime = Arc::new(crate::adapters::runtime::RuntimeAdapter::new(
        crate::adapters::runtime::RuntimeOrgans {
            ledger: ledger.clone(),
            gate,
            broker: broker.clone(),
            kira,
            cell: Arc::new(supervisor::services::PinnedCellService::new(
                runner,
                "theme".into(),
            )?),
            sessions: transcripts.clone(),
            snapshots,
        },
        assets.clone(),
        Arc::new(crate::adapters::runtime::UnavailableGuestPlan),
    ));
    let data = Arc::new(crate::data::HostData::new(
        transcripts,
        health.clone(),
        ledger.clone(),
        state.node,
    )?);
    let live_data = crate::data::live::RuntimeData::new(data.clone());
    // The engine (deploy/engine/NODE.md), when this node has `engine-v1.json`. A bad file is logged; the node serves on.
    let engine = crate::engine::Engine::load(&config).unwrap_or_else(|refusal| {
        eprintln!("engine: not configured: {}:{}", refusal.organ, refusal.reason);
        None
    });
    // Co-presence pairing (COPRESENCE-NODE.md); a store that cannot open refuses only pairing.
    state.subdirectory("copresence")?;
    let pairing = crate::pairing::Pairing::open(
        &config.state_root.join("copresence").join("pairing-v1.sqlite3"),
        state.node,
        &config.owner_origin,
    )
    .map_err(|refusal| eprintln!("copresence: pairing unavailable: {}:{}", refusal.organ, refusal.reason))
    .ok()
    .map(Arc::new);
    if let Some(pairing) = &pairing {
        pairing_routes::sweep_at_boot(pairing, &ledger);
    }
    let host = Arc::new(Host {
        pairing,
        identity,
        approvals: crate::approvals::ApprovalFeed::new(ledger.clone()),
        gate: owner_gate,
        config,
        state,
        ledger,
        documents,
        sessions,
        claim_service: Mutex::new(None),
        assets,
        runtime,
        health,
        data,
        live_data,
        broker,
        faces,
        runtime_refusal: Mutex::new(None),
        handoffs: Mutex::new(frontdoor::fd4::ShellHandoffs::default()),
        engine: engine.clone(),
        model_broker,
    });
    if let Some(engine) = engine {
        crate::engine::run(host.clone(), engine);
    }
    crate::web::serve_handoff(host).await
}

fn require_initial_sessions(transaction: &aura::LedgerTxn<'_>, sessions: &File) -> Result<()> {
    let missing = canon::Refusal {
        organ: "supervisor",
        reason: "sessions-missing",
    };
    // Claims are served only after genesis commits. An empty install context also
    // permits restarting a first boot interrupted after node identity creation.
    let (context, _, _) = transaction.floor_install_context().map_err(|_| missing)?;
    if context.sequence != 1 || context.previous_hash.is_some() {
        return Err(missing);
    }
    let mut entries = rustix::fs::Dir::read_from(sessions).map_err(|_| missing)?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|_| missing)?;
        match entry.file_name().to_bytes() {
            b"." | b".." | b"sessions.lock" => {}
            // Retain claim databases, their sidecars and incomplete session writes.
            _ => return Err(missing),
        }
    }
    Ok(())
}

impl Host {
    pub fn dispatch_handoff(
        &self,
        admitted: &frontdoor::ingress::HandoffAdmission,
    ) -> Result<http::Response<Vec<u8>>> {
        let request = admitted.admission.request();
        if request.path() == frontdoor::fd4::HANDOFF_PREPARE_PATH {
            self.with_release(|_| Ok(()))?;
            let prepared = self
                .handoffs
                .lock()
                .map_err(|_| codes::SUPERVISOR_STATE)?
                .prepare(request, &self.config.boundary()?, &admitted.pending, now()?)?;
            let mut response = handoff_response(&prepared.cookies)?;
            *response.body_mut() = Value::object(vec![(
                "reference".into(),
                Value::text(prepared.reference.to_string())?,
            )])?
            .canonical_bytes();
            return Ok(response);
        }
        if request.path() == frontdoor::fd4::HANDOFF_COMPLETE_PATH {
            self.with_release(|_| Ok(()))?;
            let mut sessions = self.sessions()?;
            let cookies = self
                .handoffs
                .lock()
                .map_err(|_| codes::SUPERVISOR_STATE)?
                .complete(
                    request,
                    &admitted.pending,
                    &admitted.correlation,
                    &mut sessions,
                    now()?,
                )?;
            return handoff_response(&cookies);
        }
        if request.role() == HostRole::Owner && request.path() == "/api/signin/finish" {
            let route = OwnerRoute::resolve(request.role(), request.method(), request.path())?;
            let handoff = if admitted.correlation.is_empty() || admitted.owner_pending.is_empty() {
                None
            } else {
                Some((
                    admitted.correlation.as_slice(),
                    admitted.owner_pending.as_slice(),
                ))
            };
            return self.signin(request, route, handoff);
        }
        if let Some(reference) = admitted.navigation {
            let mut response = self.dispatch(&admitted.admission)?;
            let cookie = self
                .handoffs
                .lock()
                .map_err(|_| codes::SUPERVISOR_STATE)?
                .owner_navigation(
                    reference,
                    &admitted.correlation,
                    admitted
                        .admission
                        .owner_navigation()
                        .ok_or(codes::FRONTDOOR_ORIGIN_REFUSED)?,
                    now()?,
                )?;
            response.headers_mut().append(
                http::header::SET_COOKIE,
                cookie
                    .parse()
                    .map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?,
            );
            return Ok(response);
        }
        self.dispatch(&admitted.admission)
    }
    fn data_request(
        &self,
        session: &frontdoor::session::BoundSession<'_>,
        endpoint: frontdoor::fd4::DataEndpoint,
        body: &Value,
    ) -> Result<http::Response<Vec<u8>>> {
        let at = now()?;
        self.with_release(|_| Ok(()))?;
        if endpoint == frontdoor::fd4::DataEndpoint::Event {
            self.live_data.pump(at, &self.runtime)?;
            return self
                .data
                .dispatch(session, endpoint, &body.canonical_bytes(), at);
        }
        canon::frame::decode(&body.canonical_bytes())?;
        let version = body.get("v").map(Value::view);
        if matches!(version, Some(canon::json::ValueView::Integer(value)) if value.get() == 3) {
            return self.service_read(session, body, at);
        }
        self.with_release(|_| Ok(()))?;
        self.live_data.submit(
            session,
            &body.canonical_bytes(),
            at,
            &self.runtime,
            self.broker.slot.admitted().is_none(),
        )
    }

    fn service_read(
        &self,
        session: &frontdoor::session::BoundSession<'_>,
        frame: &Value,
        at: u64,
    ) -> Result<http::Response<Vec<u8>>> {
        let canon::json::ValueView::Object(fields) = frame.view() else {
            return Err(codes::FRAME_INVALID_FIELD);
        };
        let names = ["v", "id", "kind", "provenance", "body"];
        if fields.len() != names.len()
            || fields.iter().any(|(key, _)| !names.contains(&key.as_str()))
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        let field = |name| frame.get(name).ok_or(codes::FRAME_INVALID_FIELD);
        let canon::json::ValueView::Text(id) = field("id")?.view() else {
            return Err(codes::FRAME_INVALID_ID);
        };
        let id = canon::frame::FrameId::new(id.into())?;
        if !matches!(
            field("kind")?.view(),
            canon::json::ValueView::Text("service.read")
        ) {
            return Err(codes::FRAME_UNKNOWN_KIND);
        }
        let provenance = canon::provenance::Provenance {
            source: canon::provenance::Source::Owner,
        };
        let probe = canon::fd4::encode_command(&canon::frame::Frame {
            v: canon::fd4::VERSION,
            id: id.clone(),
            provenance: provenance.clone(),
            body: canon::fd4::ChatCommand::HealthSnapshot,
        })?;
        let probe = canon::frame::decode(&probe)?;
        if field("provenance")? != probe.get("provenance").ok_or(codes::FRAME_PROVENANCE)? {
            return Err(codes::FRAME_PROVENANCE);
        }
        let read = self.with_release(|release| {
            frontdoor::api::service_reads::authorize_data(release, field("body")?)
        })?;
        self.data.submit_generated(session, at, |_| {
            let value = self
                .faces
                .dispatch_extended(session, &read, &self.documents)?;
            self.with_release(|_| Ok(()))?;
            let reply = Value::object(vec![
                (
                    "v".into(),
                    Value::integer(canon::json::SafeInteger::new(3)?),
                ),
                ("id".into(), Value::text(id.as_str().into())?),
                ("kind".into(), Value::text("service.reply".into())?),
                ("provenance".into(), field("provenance")?.clone()),
                (
                    "body".into(),
                    Value::object(vec![
                        (
                            "schema".into(),
                            Value::text("aukora:face-service:v3".into())?,
                        ),
                        ("value".into(), value),
                    ])?,
                ),
            ])?;
            Ok(reply.canonical_bytes())
        })
    }

    fn consume_host_claim(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        if OwnerRoute::resolve(request.role(), request.method(), request.path())?
            != OwnerRoute::Claim
        {
            return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
        }
        let mut service = self
            .claim_service
            .lock()
            .map_err(|_| codes::AUMLOK_CLAIM_UNKNOWN)?;
        if service.is_none() {
            *service = Some(supervisor::claim::HostClaimService::from_host(
                &self.config.config_directory()?,
                self.sessions()?,
                self.ledger.clone(),
            )?);
        }
        frontdoor::session::consume_recoverable_claim(
            service.as_mut().ok_or(codes::AUMLOK_CLAIM_UNKNOWN)?,
            request,
            self.state.node,
            now()?,
        )
    }

    pub fn listener_started(self: &Arc<Self>) {
        self.runtime.host_listener_bound();
        tokio::spawn(self.health.clone().run());
        let host = self.clone();
        tokio::spawn(async move {
            let mut runtime = SupervisorRuntime::new(host.config.runtime_config());
            loop {
                let result = runtime.run(host.runtime.as_ref()).await;
                if let Ok(mut refusal) = host.runtime_refusal.lock() {
                    *refusal = result.err();
                }
                if !matches!(
                    runtime.state(),
                    GuestState::AwaitingBinding | GuestState::AwaitingRelease
                ) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }
    fn sessions(&self) -> Result<DurableSessions> {
        let boundary = self.config.boundary()?;
        DurableSessions::open(
            self.sessions
                .try_clone()
                .map_err(|_| codes::SUPERVISOR_STATE)?,
            self.state.node,
            boundary.shell,
            boundary.owner,
        )
    }

    /// Called from `web`'s blocking worker with a Tokio runtime entered. Data and
    /// face reads synchronously wait for async organ ports and cannot run on a
    /// Tokio runtime worker thread.
    pub fn dispatch(&self, admission: &HttpAdmission) -> Result<http::Response<Vec<u8>>> {
        let request = admission.request();
        if let Some(response) = self.engine_route(request) {
            return response;
        }
        if !request.path().starts_with("/api/") {
            return self.asset(request, admission.owner_navigation());
        }
        if request.role() == HostRole::Shell && request.path() == "/api/approvals" {
            if request.method() != frontdoor::ingress::Method::Get {
                return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
            }
            self.with_release(|_| Ok(()))?;
            let mut sessions = self.sessions()?;
            return frontdoor::session::with_bound_session(
                &mut sessions,
                request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
                self.state.node,
                request.origin(),
                now()?,
                |session| {
                    if session.record().scope != frontdoor::session::SessionScope::Shell {
                        return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
                    }
                    let snapshot = self.approvals.snapshot(&session, now()?)?;
                    self.with_release(|_| Ok(()))?;
                    json_response(snapshot)
                },
            );
        }
        if request.role() == HostRole::Owner && request.path() == "/api/claim" {
            return self.consume_host_claim(request);
        }
        if request.role() == HostRole::Owner {
            let route = OwnerRoute::resolve(request.role(), request.method(), request.path())?;
            if matches!(route, OwnerRoute::SigninStart | OwnerRoute::SigninFinish) {
                return self.signin(request, route, None);
            }
            if frontdoor::owner_origin::is_phone_pairing_route(route) {
                return self.pairing_phone(request, route);
            }
            let mut sessions = self.sessions()?;
            let mut identity = self.identity.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
            let result = frontdoor::session::with_owner_session(
                &mut sessions,
                request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
                self.state.node,
                request.origin(),
                route,
                now()?,
                |session| {
                    if frontdoor::owner_origin::is_gate_route(route) {
                        let frontdoor::session::OwnerSession::Bound(session) = session else {
                            return Err(codes::AUMLOK_BINDING_REQUIRED);
                        };
                        return self.owner_gate_request(&session, route, request.body());
                    }
                    if frontdoor::owner_origin::is_owner_pairing_route(route) {
                        let frontdoor::session::OwnerSession::Bound(session) = session else {
                            return Err(codes::AUMLOK_BINDING_REQUIRED);
                        };
                        let body = self.pairing_owner(&session, route, request.body())?;
                        return Ok(crate::identity::Reply { body, transition: None });
                    }
                    if route == OwnerRoute::Approvals {
                        let frontdoor::session::OwnerSession::Bound(session) = session else {
                            return Err(codes::AUMLOK_BINDING_REQUIRED);
                        };
                        return Ok(crate::identity::Reply {
                            body: self.approvals.snapshot(&session, now()?)?,
                            transition: None,
                        });
                    }
                    let record = match &session {
                        frontdoor::session::OwnerSession::Binding(session) => session.record(),
                        frontdoor::session::OwnerSession::Bound(session) => session.record(),
                    };
                    if route == OwnerRoute::ApprovalRetireChallenge {
                        return Err(codes::SUPERVISOR_GATE_SCOPE_UNAVAILABLE);
                    }
                    identity.authenticated(route, record, request.body(), now()?)
                },
            )?;
            let mut rotated_cookie = None;
            if let Some((epoch, binding, subject)) = result.transition {
                let advanced_at = now()?;
                rotated_cookie = sessions
                    .advance_after_ceremony(
                        frontdoor::session::session_digest(
                            request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
                        )?,
                        epoch,
                        binding,
                        subject,
                        advanced_at,
                    )?
                    .map(|(bearer, expiry)| {
                        bearer.cookie_header(
                            frontdoor::session::SessionScope::BindingOnly,
                            expiry,
                            advanced_at,
                        )
                    })
                    .transpose()?;
                if binding == frontdoor::session::BindingState::Bound {
                    // The binding has committed; a release proposal that cannot be raised now must not turn it
                    // into a failure the owner retries into already-bound (SCOUT ad03d28 #3). The poll retries it.
                    if let Err(refusal) = self.ledger.ensure_release_proposal(PrincipalScope {
                        subject: subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
                        epoch,
                    }) {
                        eprintln!("supervisor: release proposal not raised after binding: {}:{}", refusal.organ, refusal.reason);
                    }
                }
            }
            if frontdoor::owner_origin::is_gate_route(route) {
                return owner_gate::owner_gate_response(result.body);
            }
            let mut response = json_response(result.body)?;
            if let Some(cookie) = rotated_cookie {
                response.headers_mut().insert(
                    http::header::SET_COOKIE,
                    cookie
                        .parse()
                        .map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?,
                );
            }
            return Ok(response);
        }
        if request.path() == frontdoor::api::service_reads::PATH {
            let read = self.with_release(|release| {
                frontdoor::api::service_reads::authorize(release, request)
            })?;
            let mut sessions = self.sessions()?;
            return frontdoor::session::with_bound_session(
                &mut sessions,
                request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
                self.state.node,
                request.origin(),
                now()?,
                |session| {
                    let value = self.faces.dispatch(&session, &read, &self.documents)?;
                    self.with_release(|_| Ok(()))?;
                    json_response(value)
                },
            );
        }
        if request.path() == frontdoor::fd4::DATA_PATH {
            let endpoint = frontdoor::fd4::DataEndpoint::resolve(
                request.role(),
                request.method(),
                request.path(),
            )?;
            let mut sessions = self.sessions()?;
            return frontdoor::session::with_bound_session(
                &mut sessions,
                request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
                self.state.node,
                request.origin(),
                now()?,
                |session| self.data_request(&session, endpoint, request.body()),
            );
        }
        let endpoint = frontdoor::api::FaceEndpoint::resolve(
            request.role(),
            request.method(),
            request.path(),
        )?;
        self.with_release(|release| {
            frontdoor::api::FaceAccess::register(
                release,
                canon::session::Text::new("documents".into())?,
            )
        })?;
        let decoded = frontdoor::api::decode(endpoint, &request.body().canonical_bytes())?;
        let mut sessions = self.sessions()?;
        frontdoor::session::with_bound_session(
            &mut sessions,
            request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
            self.state.node,
            request.origin(),
            now()?,
            |session| {
                let record = session.record();
                let scope = PrincipalScope {
                    subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
                    epoch: record.owner_epoch,
                };
                if self.ledger.binding()? != BindingState::Bound(scope) {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                let method = match decoded {
                    frontdoor::api::FaceRequest::DocumentsList(_) => "documents.list",
                    frontdoor::api::FaceRequest::DocumentsRead(_) => "documents.read",
                };
                json_response(crate::faces::documents::call(
                    &self.documents,
                    &session,
                    method,
                    request.body(),
                )?)
            },
        )
    }

    fn signin(
        &self,
        request: &AdmittedRequest,
        route: OwnerRoute,
        handoff: Option<(&[canon::digest::Digest32], &[canon::digest::Digest32])>,
    ) -> Result<http::Response<Vec<u8>>> {
        use frontdoor::session::{BindingState, SessionBearer, SessionRecord, SessionScope};
        let mut identity = self.identity.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        let now = now()?;
        if route == OwnerRoute::SigninStart {
            return json_response(identity.signin_start(request.body(), now)?);
        }
        if route != OwnerRoute::SigninFinish {
            return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
        }
        let bearer = SessionBearer::generate()?;
        let mut sessions = self.sessions()?;
        let result = identity.signin_finish(request.body(), now)?;
        let (epoch, binding, subject) =
            result.transition.ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?;
        sessions.synchronize_binding(epoch, binding, subject)?;
        let scope = if binding == BindingState::Bound {
            SessionScope::OwnerFrame
        } else {
            SessionScope::BindingOnly
        };
        let expires = now
            .checked_add(frontdoor::session::MAX_LIFETIME_MS)
            .ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?;
        sessions.insert_after_ceremony(
            SessionRecord {
                token_digest: bearer.digest(),
                node: self.state.node,
                origin: request.origin().clone(),
                subject,
                owner_epoch: epoch,
                scope,
                expires_at_ms: expires,
                revoked: false,
            },
            now,
        )?;
        if scope == SessionScope::OwnerFrame {
            if let Some((correlations, owner_pending)) = handoff {
                // An expired rendezvous cannot discard the durable owner session.
                let _ = (|| -> Result<()> {
                    let mut handoffs = self.handoffs.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
                    let (correlation, owner_pending) =
                        handoffs.validate_authorization(correlations, owner_pending, now)?;
                    let boundary = self.config.boundary()?;
                    let grant = frontdoor::session::with_bound_session(
                        &mut sessions,
                        bearer.as_bytes(),
                        self.state.node,
                        request.origin(),
                        now,
                        |session| {
                            frontdoor::ingress::ShellSessionGrant::from_owner(&session, &boundary)
                        },
                    )?;
                    handoffs.authorize(correlation, owner_pending, grant, now)
                })();
            }
        }
        let mut response = json_response(result.body)?;
        response.headers_mut().insert(
            http::header::SET_COOKIE,
            bearer
                .cookie_header(scope, expires, now)?
                .parse()
                .map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?,
        );
        response.headers_mut().append(
            http::header::SET_COOKIE,
            format!(
                "{}=; {}; Max-Age=0",
                frontdoor::fd4::HANDOFF_OWNER_COOKIE,
                frontdoor::session::COOKIE_ATTRIBUTES
            )
            .parse()
            .map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?,
        );
        Ok(response)
    }

    fn with_release<T>(&self, operation: impl FnOnce(&ApprovedRelease) -> Result<T>) -> Result<T> {
        let mut assets = self.assets.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        if assets.release.is_none() {
            assets.release = Some(frontdoor::assets::load_approved(&mut assets.source)?);
        }
        assets.source.approval()?;
        let result = operation(assets.release.as_ref().ok_or(codes::SUPERVISOR_STATE)?);
        assets.source.approval()?;
        result
    }

    fn asset(
        &self,
        request: &AdmittedRequest,
        navigation: Option<&frontdoor::owner_origin::FrameNavigation>,
    ) -> Result<http::Response<Vec<u8>>> {
        if !matches!(request.method(), Method::Get | Method::Head) {
            return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
        }
        let mut assets = self.assets.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        if assets.release.is_none() {
            assets.release = Some(frontdoor::assets::load_approved(&mut assets.source)?);
        }
        let Assets {
            release, source, ..
        } = &mut *assets;
        let release = release.as_ref().ok_or(codes::SUPERVISOR_STATE)?;
        let boundary = self.config.boundary()?;
        if request.role() == HostRole::Owner {
            let context = frontdoor::owner_origin::CeremonyContext::from_boundary(&boundary)?;
            return frontdoor::owner_origin::serve_owner_asset_response(
                &context, request, navigation, release, source,
            );
        }
        let surface =
            if request.path().starts_with("/app/faces/") || request.path().starts_with("/faces/") {
                AssetSurface::Face
            } else {
                AssetSurface::Shell
            };
        let asset = frontdoor::assets::serve(release, source, surface, request.path())?;
        let mime = match asset.kind {
            frontdoor::assets::AssetKind::Html => "text/html; charset=utf-8",
            frontdoor::assets::AssetKind::Script => "text/javascript; charset=utf-8",
            frontdoor::assets::AssetKind::Style => "text/css; charset=utf-8",
            frontdoor::assets::AssetKind::Wasm => "application/wasm",
            frontdoor::assets::AssetKind::Font => "font/woff2",
            frontdoor::assets::AssetKind::Json => "application/json",
            frontdoor::assets::AssetKind::Image => image_mime(request.path())?,
        };
        let policies = frontdoor::shell::policies(&boundary.shell, &boundary.owner);
        let policy = if surface == AssetSurface::Face {
            let wasm = if asset.kind == frontdoor::assets::AssetKind::Html {
                face_uses_wasm(release, source, request.path())?
            } else {
                false
            };
            frontdoor::shell::face_policy(&boundary.shell, wasm)
        } else {
            policies.shell_csp
        };
        let size = asset.bytes.len();
        http::Response::builder()
            .header("content-type", mime)
            .header("content-length", size)
            .header("content-security-policy", policy)
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .header("referrer-policy", "strict-origin")
            .header("strict-transport-security", "max-age=31536000")
            .header("access-control-allow-origin", "*")
            .header("vary", "origin")
            .header("cross-origin-resource-policy", "cross-origin")
            .body(if request.method() == Method::Head {
                Vec::new()
            } else {
                asset.bytes
            })
            .map_err(|_| codes::SUPERVISOR_STATE)
    }
}

fn face_uses_wasm(
    release: &ApprovedRelease,
    source: &mut ReleaseFiles,
    path: &str,
) -> Result<bool> {
    let face = path
        .strip_prefix("/app/faces/")
        .or_else(|| path.strip_prefix("/faces/"))
        .and_then(|suffix| suffix.split_once('/'))
        .map(|(id, _)| id)
        .ok_or(codes::FRONTDOOR_UNKNOWN_ROUTE)?;
    let manifest = frontdoor::assets::serve(
        release,
        source,
        AssetSurface::Face,
        &format!("/app/faces/{face}/manifest.json"),
    )?;
    let value = canon::json::parse_strict(&manifest.bytes)?;
    match value.get("wasm").map(Value::view) {
        None => Ok(false),
        Some(canon::json::ValueView::Boolean(wasm)) => Ok(wasm),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}

fn handoff_response(cookies: &[String]) -> Result<http::Response<Vec<u8>>> {
    let mut response = json_response(Value::object(vec![("ok".into(), Value::boolean(true))])?)?;
    for cookie in cookies {
        response.headers_mut().append(
            http::header::SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| codes::FRONTDOOR_SESSION_REQUIRED)?,
        );
    }
    Ok(response)
}

fn image_mime(path: &str) -> Result<&'static str> {
    match path.rsplit('.').next() {
        Some("svg") => Ok("image/svg+xml"),
        Some("png") => Ok("image/png"),
        Some("webp") => Ok("image/webp"),
        Some("jpg" | "jpeg") => Ok("image/jpeg"),
        _ => Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
    }
}
pub fn now() -> Result<u64> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| codes::SUPERVISOR_STATE)?
        .as_millis();
    if value > canon::json::MAX_SAFE_INTEGER as u128 {
        return Err(codes::SUPERVISOR_STATE);
    }
    Ok(value as u64)
}
pub fn json_response(value: Value) -> Result<http::Response<Vec<u8>>> {
    let value = frontdoor::api::JsonData::new(&value)?;
    http::Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(value.as_bytes().to_vec())
        .map_err(|_| codes::SUPERVISOR_STATE)
}
