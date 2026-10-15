// SPDX-License-Identifier: AGPL-3.0-or-later
//! Guest lifecycle wiring and the sole FD 3 router owner.

use super::HostLedger;
use canon::{codes, Result};
use launcher::{
    boot::{BootFacts, BootReceipt, BootRecorder},
    cage::{LaunchRequest, RunningCage},
};
use std::{
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::Duration,
};
use supervisor::{
    ingress::{BindingState, GuestContext, PrincipalScope},
    router::{OrganPorts, Router},
    runtime::{RuntimeActivity, RuntimeMeasurement, RuntimeServices, SupervisorFacts},
    services::{
        BrokerService, CellService, GateService, KiraService, ServiceFuture, SnapshotService,
    },
    session::SessionStore,
    transport::GuestChannel,
};

/// The release organ checks the exact installed release and its owner-approved floor.
pub trait ReleaseAdmission: Send + Sync {
    fn measure(&self) -> Result<RuntimeMeasurement>;
    fn require_release(&self, measurement: RuntimeMeasurement) -> Result<()>;
}

/// Trusted provisioning supplies the pinned image and delegated cage resources.
/// The self-attack callback must complete before launcher releases the stopped child.
pub trait GuestPlan: Send + Sync {
    fn prepare(
        &self,
        scope: PrincipalScope,
        measured: RuntimeMeasurement,
        proposals: std::os::fd::OwnedFd,
        app_data: std::os::fd::OwnedFd,
    ) -> Result<LaunchRequest>;
    fn before_agent_start(&self, facts: &BootFacts) -> Result<()>;
}

pub struct UnavailableGuestPlan;
impl GuestPlan for UnavailableGuestPlan {
    fn prepare(
        &self,
        _: PrincipalScope,
        _: RuntimeMeasurement,
        _: std::os::fd::OwnedFd,
        _: std::os::fd::OwnedFd,
    ) -> Result<LaunchRequest> {
        Err(codes::SUPERVISOR_NOT_READY)
    }
    fn before_agent_start(&self, _: &BootFacts) -> Result<()> {
        Err(canon::Refusal {
            organ: "launcher",
            reason: "boot-attack-required",
        })
    }
}

pub struct RuntimeOrgans {
    pub ledger: Arc<HostLedger>,
    pub gate: Arc<dyn GateService>,
    pub broker: Arc<dyn BrokerService>,
    pub kira: Arc<dyn KiraService>,
    pub cell: Arc<dyn CellService>,
    pub sessions: Arc<dyn SessionStore>,
    pub snapshots: Arc<dyn SnapshotService>,
}

pub struct RuntimeAdapter {
    organs: RuntimeOrgans,
    admission: Arc<dyn ReleaseAdmission>,
    plan: Arc<dyn GuestPlan>,
    host_started: std::sync::atomic::AtomicBool,
    child: Mutex<Option<RunningCage>>,
    data: Mutex<Option<UnixStream>>,
    activity: Mutex<RuntimeActivity>,
    facts: Mutex<Option<SupervisorFacts>>,
}
impl RuntimeAdapter {
    pub fn new(
        organs: RuntimeOrgans,
        admission: Arc<dyn ReleaseAdmission>,
        plan: Arc<dyn GuestPlan>,
    ) -> Self {
        Self {
            organs,
            admission,
            plan,
            host_started: std::sync::atomic::AtomicBool::new(false),
            child: Mutex::new(None),
            data: Mutex::new(None),
            activity: Mutex::new(RuntimeActivity::default()),
            facts: Mutex::new(None),
        }
    }
    /// Called after the host has bound its configured HTTP listener.
    pub fn host_listener_bound(&self) {
        self.host_started
            .store(true, std::sync::atomic::Ordering::Release);
    }
    /// Transfer only FD 4's host endpoint to the authenticated data bridge.
    pub fn take_app_data(&self) -> Result<UnixStream> {
        self.data
            .lock()
            .map_err(|_| codes::SUPERVISOR_STATE)?
            .take()
            .ok_or(codes::SUPERVISOR_NOT_READY)
    }
    pub fn facts(&self) -> Result<Option<SupervisorFacts>> {
        Ok(self
            .facts
            .lock()
            .map_err(|_| codes::SUPERVISOR_STATE)?
            .clone())
    }
}
struct Recorder<'a> {
    host: &'a HostLedger,
    plan: &'a dyn GuestPlan,
    admission: &'a dyn ReleaseAdmission,
    scope: PrincipalScope,
    measured: RuntimeMeasurement,
    attacked: Option<canon::digest::Digest32>,
}
impl BootRecorder for Recorder<'_> {
    fn before_agent_start(&mut self, facts: &BootFacts) -> Result<()> {
        let digest = canon::digest::Digest32::sha256(&facts.to_body()?.canonical_bytes());
        if self.attacked != Some(digest) {
            self.plan.before_agent_start(facts)?;
            self.attacked = Some(digest);
        }
        Ok(())
    }
    fn append_boot(&mut self, facts: &BootFacts) -> Result<BootReceipt> {
        self.before_agent_start(facts)?;
        self.admission.require_release(self.measured)?;
        self.host.record_scoped_guest_boot(self.scope, facts)
    }
}
impl RuntimeServices for RuntimeAdapter {
    fn inspect_host(&self) -> Result<launcher::boot::HostBootFacts> {
        launcher::boot::inspect_host()
    }
    fn start_host_services(&self) -> ServiceFuture<'_, ()> {
        Box::pin(async {
            if self.host_started.load(std::sync::atomic::Ordering::Acquire) {
                Ok(())
            } else {
                Err(codes::SUPERVISOR_NOT_READY)
            }
        })
    }
    fn measure_release(&self) -> ServiceFuture<'_, RuntimeMeasurement> {
        Box::pin(async { self.admission.measure() })
    }
    fn bound_principal(&self) -> ServiceFuture<'_, PrincipalScope> {
        Box::pin(async {
            match self.organs.ledger.binding()? {
                BindingState::Bound(scope) => Ok(scope),
                BindingState::Unbound => Err(codes::AUMLOK_BINDING_REQUIRED),
            }
        })
    }
    fn release_ready(&self, measured: RuntimeMeasurement) -> ServiceFuture<'_, ()> {
        Box::pin(async move { self.admission.require_release(measured) })
    }
    fn record_host_boot(
        &self,
        facts: launcher::boot::HostBootFacts,
    ) -> ServiceFuture<'_, BootReceipt> {
        Box::pin(async move { self.organs.ledger.record_host_boot(&facts) })
    }
    fn launch_guest(
        &self,
        scope: PrincipalScope,
        measured: RuntimeMeasurement,
    ) -> ServiceFuture<'_, GuestChannel> {
        Box::pin(async move {
            let mut child = self.child.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
            if child.is_some() {
                return Err(codes::SUPERVISOR_STATE);
            }
            self.organs.ledger.scoped(scope, |_| Ok(()))?;
            self.admission.require_release(measured)?;
            let (fd3_host, fd3_guest) = UnixStream::pair().map_err(|_| codes::SUPERVISOR_STATE)?;
            let (fd4_host, fd4_guest) = UnixStream::pair().map_err(|_| codes::SUPERVISOR_STATE)?;
            let channel = GuestChannel::attach(fd3_host)?;
            let mut data = self.data.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
            if data.is_some() {
                return Err(codes::SUPERVISOR_STATE);
            }
            let request = self
                .plan
                .prepare(scope, measured, fd3_guest.into(), fd4_guest.into())?;
            if request.profile.kind() != launcher::profiles::ProfileKind::Auma {
                return Err(codes::SUPERVISOR_STATE);
            }
            self.organs.ledger.scoped(scope, |_| Ok(()))?;
            self.admission.require_release(measured)?;
            let mut recorder = Recorder {
                host: &self.organs.ledger,
                plan: &*self.plan,
                admission: &*self.admission,
                scope,
                measured,
                attacked: None,
            };
            let launched = launcher::cage::launch(request, &mut recorder)?;
            *data = Some(fd4_host);
            *child = Some(launched);
            Ok(channel)
        })
    }
    fn stop_guest(&self) -> ServiceFuture<'_, ()> {
        Box::pin(async {
            self.data
                .lock()
                .map_err(|_| codes::SUPERVISOR_STATE)?
                .take();
            if let Some(child) = self
                .child
                .lock()
                .map_err(|_| codes::SUPERVISOR_STATE)?
                .take()
            {
                child.terminate(Duration::from_secs(5))?;
            }
            Ok(())
        })
    }
    fn serve_guest<'a>(
        &'a self,
        channel: &'a mut GuestChannel,
        scope: PrincipalScope,
    ) -> ServiceFuture<'a, ()> {
        Box::pin(async move {
            let context = GuestContext::admit(self.organs.ledger.binding()?)?;
            if context.scope() != scope {
                return Err(codes::AUMLOK_BINDING_REQUIRED);
            }
            let ports = OrganPorts {
                binding: &*self.organs.ledger,
                gate: &*self.organs.gate,
                broker: &*self.organs.broker,
                kira: &*self.organs.kira,
                cell: &*self.organs.cell,
                sessions: &*self.organs.sessions,
                snapshots: &*self.organs.snapshots,
            };
            let mut router = Router::new(ports, context);
            router
                .serve_observed(channel, |activity| {
                    if let Ok(mut current) = self.activity.lock() {
                        *current = activity;
                    }
                })
                .await
        })
    }
    fn settle_guest(&self, scope: PrincipalScope) -> ServiceFuture<'_, ()> {
        self.organs.broker.disconnect(scope)
    }
    fn activity(&self) -> Result<RuntimeActivity> {
        Ok(self
            .activity
            .lock()
            .map_err(|_| codes::SUPERVISOR_STATE)?
            .clone())
    }
    fn observe_runtime(&self, facts: &SupervisorFacts) {
        if let Ok(mut current) = self.facts.lock() {
            *current = Some(facts.clone());
        }
    }
}
