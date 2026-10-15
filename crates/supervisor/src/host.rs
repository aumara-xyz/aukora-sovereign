// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host composition for the deployed supervisor entry point.

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
    ingress::{AdmittedRequest, HostRole, Method},
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

pub struct Host {
    pub config: NodeConfig,
    pub state: HostState,
    pub ledger: Arc<HostLedger>,
    pub documents: DocumentRoot,
    sessions: File,
    assets: Arc<Mutex<Assets>>,
    pub runtime: Arc<crate::adapters::runtime::RuntimeAdapter>,
    pub health: Arc<crate::health::HealthCollector>,
    data: crate::data::HostData,
    faces: crate::faces::host::HostFaces,
    approvals: crate::approvals::ApprovalFeed,
    runtime_refusal: Mutex<Option<canon::Refusal>>,
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
    match std::fs::symlink_metadata(
        config
            .state_root
            .join("browser-sessions")
            .join("sessions-v1.json"),
    ) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DurableSessions::initialize(descriptor, state.node, boundary.shell, boundary.owner)?;
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
    let broker = Arc::new(crate::adapters::BrokerAdapter::new(
        ledger.clone(),
        Arc::new(broker::keystore::KeyInbox::new()),
        Arc::new(broker::intake::ModelSlot::new()),
    ));
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
    let faces = crate::faces::host::HostFaces::new(
        ledger.clone(),
        transcripts.clone(),
        health.clone(),
        broker.clone(),
    )
    .with_network(network);
    let runtime = Arc::new(crate::adapters::runtime::RuntimeAdapter::new(
        crate::adapters::runtime::RuntimeOrgans {
            ledger: ledger.clone(),
            gate,
            broker,
            kira: Arc::new(crate::adapters::kira::UnavailableKira),
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
    let data = crate::data::HostData::new(transcripts, health.clone(), ledger.clone());
    let host = Arc::new(Host {
        approvals: crate::approvals::ApprovalFeed::new(ledger.clone()),
        config,
        state,
        ledger,
        documents,
        sessions,
        assets,
        runtime,
        health,
        data,
        faces,
        runtime_refusal: Mutex::new(None),
    });
    crate::web::serve(host).await
}

impl Host {
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

    pub fn dispatch(
        &self,
        request: AdmittedRequest,
        headers: &http::HeaderMap,
    ) -> Result<http::Response<Vec<u8>>> {
        if !request.path().starts_with("/api/") {
            return self.asset(&request, headers);
        }
        if request.role() == HostRole::Owner {
            let route = OwnerRoute::resolve(request.role(), request.method(), request.path())?;
            if route == OwnerRoute::Claim {
                let mut claim = supervisor::claim::HostClaimService::from_host(
                    &self.config.config_directory()?,
                    self.sessions()?,
                )?;
                return frontdoor::claim::consume_claim(
                    &mut claim,
                    &request,
                    self.state.node,
                    now()?,
                )?
                .into_http_response();
            }
            if matches!(route, OwnerRoute::SigninStart | OwnerRoute::SigninFinish) {
                return Err(canon::Refusal {
                    organ: "supervisor",
                    reason: "identity-service-unavailable",
                });
            }
            let mut sessions = self.sessions()?;
            return frontdoor::session::with_owner_session(
                &mut sessions,
                request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
                self.state.node,
                request.origin(),
                route,
                now()?,
                |session| {
                    if route == OwnerRoute::Approvals {
                        let frontdoor::session::OwnerSession::Bound(session) = session else {
                            return Err(codes::AUMLOK_BINDING_REQUIRED);
                        };
                        return json_response(self.approvals.snapshot(&session, now()?)?);
                    }
                    Err(canon::Refusal {
                        organ: "supervisor",
                        reason: "identity-service-unavailable",
                    })
                },
            );
        }
        if request.path() == frontdoor::api::service_reads::PATH {
            let read = self.with_release(|release| {
                frontdoor::api::service_reads::authorize(release, &request)
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
                |session| {
                    self.data.dispatch(
                        &session,
                        endpoint,
                        &request.body().canonical_bytes(),
                        now()?,
                    )
                },
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
        headers: &http::HeaderMap,
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
            let navigation = if request.path() == "/" {
                let destination = one_header(headers, "sec-fetch-dest")?;
                let parent = one_header(headers, "referer")?;
                Some(frontdoor::owner_origin::admit_frame_navigation(
                    &context,
                    destination,
                    parent.strip_suffix('/').unwrap_or(parent),
                )?)
            } else {
                None
            };
            return frontdoor::owner_origin::serve_owner_asset_response(
                &context,
                request,
                navigation.as_ref(),
                release,
                source,
            );
        }
        let surface = if request.path().starts_with("/app/faces/") {
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
            frontdoor::shell::face_policy(&boundary.shell)
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
            .body(if request.method() == Method::Head {
                Vec::new()
            } else {
                asset.bytes
            })
            .map_err(|_| codes::SUPERVISOR_STATE)
    }
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
fn one_header<'a>(headers: &'a http::HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(codes::FRONTDOOR_ORIGIN_REFUSED)?;
    if values.next().is_some() {
        return Err(codes::FRONTDOOR_ORIGIN_REFUSED);
    }
    value.to_str().map_err(|_| codes::FRONTDOOR_ORIGIN_REFUSED)
}
