// SPDX-License-Identifier: AGPL-3.0-or-later
//! Supervisor lifecycle wiring; binding and release policy are supplied by their organs.

use crate::{ingress::PrincipalScope, services::ServiceFuture, transport::GuestChannel};
use canon::{codes, digest::Digest32, ids::SessionId, Result};
use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Local paths originate in host configuration, never guest request text.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub state_root: PathBuf,
    pub approved_release_root: PathBuf,
    pub cage_root: PathBuf,
}

/// Current observations used to ask the floor and binding organs for admission.
/// Digests and an epoch alone do not constitute approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeMeasurement {
    pub binary_sha256: Digest32,
    pub shell_manifest_sha256: Digest32,
    pub antibody_root: Digest32,
}

/// Aura's fact-only port, separate from every authority-bearing transaction method.
pub trait BootFactService {
    /// Record the actual host probe before any child exists. The body explicitly
    /// distinguishes an unstarted cage from an installed confinement profile.
    fn append_host_boot_facts(
        &mut self,
        facts: &launcher::boot::HostBootFacts,
    ) -> Result<launcher::boot::BootReceipt>;

    /// Encode launcher facts in the body of C3 boot.facts with the supervisor clock
    /// and locked ledger context; acknowledge only after Aura's durable commit.
    fn append_boot_facts(
        &mut self,
        facts: &launcher::boot::BootFacts,
    ) -> Result<launcher::boot::BootReceipt>;
}

/// The launcher can append its boot observation without receiving an Aura connection.
pub struct AuraBootRecorder<'a> {
    service: &'a mut dyn BootFactService,
}

impl<'a> AuraBootRecorder<'a> {
    pub fn new(service: &'a mut dyn BootFactService) -> Self {
        Self { service }
    }
}

impl launcher::boot::BootRecorder for AuraBootRecorder<'_> {
    fn append_boot(
        &mut self,
        facts: &launcher::boot::BootFacts,
    ) -> Result<launcher::boot::BootReceipt> {
        self.service.append_boot_facts(facts)
    }
}

impl launcher::boot::HostBootRecorder for AuraBootRecorder<'_> {
    fn append_host_boot(
        &mut self,
        facts: &launcher::boot::HostBootFacts,
    ) -> Result<launcher::boot::BootReceipt> {
        self.service.append_host_boot_facts(facts)
    }
}

/// Lifecycle status; no running claim follows merely from constructing a config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestState {
    Stopped,
    AwaitingBinding,
    AwaitingRelease,
    Starting,
    Running,
    Stopping,
    Failed,
}

/// Plain facts supplied to immune's Body observer, never HealthEvidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisorFacts {
    pub observed_at_ms: u64,
    pub guest_state: GuestState,
    pub guest_bound_subject: Option<PrincipalScope>,
    pub measured_release: Option<RuntimeMeasurement>,
    pub fd3_reader_count: u32,
    pub pending_requests: usize,
    pub pending_proposals: usize,
    pub session_sequence: Option<(SessionId, u64)>,
    pub durable_sequence: Option<(SessionId, u64)>,
    pub memory_calls_forwarded: u64,
    pub stranger_inputs_refused: u64,
}

/// Router observations are counters and store acknowledgements, never health cells.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeActivity {
    pub pending_requests: usize,
    pub pending_proposals: usize,
    pub session_sequence: Option<(SessionId, u64)>,
    pub durable_sequence: Option<(SessionId, u64)>,
    pub memory_calls_forwarded: u64,
    pub stranger_inputs_refused: u64,
}

/// Trusted in-process boot/lifecycle adapter. It returns observations only after
/// the owning organs have completed their checks; it cannot accept guest approvals.
pub trait RuntimeServices: Send + Sync {
    /// Obtain the launcher's actual host probe before any guest is created.
    fn inspect_host(&self) -> Result<launcher::boot::HostBootFacts> {
        Err(codes::SUPERVISOR_NOT_READY)
    }

    /// Start the one-link and owner-origin services before guest admission. Their
    /// lifetime is independent of the guest so claim and approval polling continue.
    fn start_host_services(&self) -> ServiceFuture<'_, ()>;

    /// Measure the actual executable, approved shell manifest and antibody corpus.
    /// A successful measurement does not approve any of those bytes.
    fn measure_release(&self) -> ServiceFuture<'_, RuntimeMeasurement>;

    /// Read current AUMLOK binding; unbound guests never start.
    fn bound_principal(&self) -> ServiceFuture<'_, PrincipalScope>;

    /// Ask floor to compare measured bytes with the exact passkey-approved release.
    /// Neither an immune result nor a fingerprint substitutes for release approval.
    fn release_ready(&self, measured: RuntimeMeasurement) -> ServiceFuture<'_, ()>;

    /// Append the actual launcher host probe on every supervisor boot, even when
    /// binding or release admission later refuses. These facts report NotStarted;
    /// they contain no claim that a child filter or confinement was installed.
    fn record_host_boot(
        &self,
        facts: launcher::boot::HostBootFacts,
    ) -> ServiceFuture<'_, launcher::boot::BootReceipt>;

    /// Supervisor creates the socketpair and transfers only child ends to launcher.
    /// Binding and release are rechecked immediately before spawning; no shell command
    /// comes from guest input. FD 4 goes to the frontdoor data channel independently.
    fn launch_guest(
        &self,
        scope: PrincipalScope,
        measured: RuntimeMeasurement,
    ) -> ServiceFuture<'_, GuestChannel>;

    fn stop_guest(&self) -> ServiceFuture<'_, ()>;

    /// Drive this channel through the typed router. The runtime retains its one
    /// owner and cancels this future before shutting down on binding revocation.
    fn serve_guest<'a>(
        &'a self,
        _channel: &'a mut GuestChannel,
        _scope: PrincipalScope,
    ) -> ServiceFuture<'a, ()> {
        Box::pin(async { Err(codes::SUPERVISOR_NOT_READY) })
    }

    /// Settle only reservations already started by this guest. Revocation can
    /// cancel the serving future, so this cleanup is a separate awaited port.
    fn settle_guest(&self, _scope: PrincipalScope) -> ServiceFuture<'_, ()> {
        Box::pin(async { Err(codes::SUPERVISOR_NOT_READY) })
    }

    /// Snapshot actual router counters. An absent adapter is unknown observation.
    fn activity(&self) -> Result<RuntimeActivity> {
        Err(codes::SUPERVISOR_NOT_READY)
    }

    /// Publish observed raw facts to an independent Body observer. This callback
    /// returns no admission decision and the default invents no observation.
    fn observe_runtime(&self, _facts: &SupervisorFacts) {}
}

/// Owns one guest lifecycle and its last actual observations.
pub struct SupervisorRuntime {
    config: RuntimeConfig,
    state: GuestState,
    host_started: bool,
    host_boot_recorded: bool,
    measured_release: Option<RuntimeMeasurement>,
    bound_subject: Option<PrincipalScope>,
    fd3_readers: u32,
    activity: Option<RuntimeActivity>,
    observed_at_ms: Option<u64>,
}

impl SupervisorRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            state: GuestState::Stopped,
            host_started: false,
            host_boot_recorded: false,
            measured_release: None,
            bound_subject: None,
            fd3_readers: 0,
            activity: Some(RuntimeActivity::default()),
            observed_at_ms: host_time().ok(),
        }
    }

    pub const fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub const fn state(&self) -> GuestState {
        self.state
    }

    /// Row 23/128: start host owner/approval services independently of the guest.
    /// Inspect/record host boot, measure release, then check binding and release.
    /// Ask launcher to install the cage and append its separate child BootFacts
    /// before releasing the child. Failure keeps the guest stopped and leaves
    /// claim/binding/approval UI up without reporting installed confinement.
    /// Revocation or an epoch change closes the guest channel and stops the cage.
    pub async fn run(&mut self, services: &dyn RuntimeServices) -> Result<()> {
        if matches!(
            self.state,
            GuestState::Starting | GuestState::Running | GuestState::Stopping
        ) {
            return Err(codes::SUPERVISOR_STATE);
        }
        self.state = GuestState::Stopped;
        self.bound_subject = None;
        self.measured_release = None;
        self.sample_activity(services);
        if !self.host_started {
            if let Err(refusal) = services.start_host_services().await {
                self.set_state(GuestState::Failed, services);
                return Err(refusal);
            }
            self.host_started = true;
        }
        if !self.host_boot_recorded {
            let probe = match services.inspect_host() {
                Ok(probe) => probe,
                Err(refusal) => {
                    self.set_state(GuestState::Failed, services);
                    return Err(refusal);
                }
            };
            if let Err(refusal) = services.record_host_boot(probe).await {
                self.set_state(GuestState::Failed, services);
                return Err(refusal);
            }
            self.host_boot_recorded = true;
        }
        let measured = match services.measure_release().await {
            Ok(measured) => measured,
            Err(refusal) => {
                self.set_state(GuestState::AwaitingRelease, services);
                return Err(refusal);
            }
        };
        self.measured_release = Some(measured);
        self.set_state(GuestState::AwaitingBinding, services);
        let scope = services.bound_principal().await?;
        self.set_state(GuestState::AwaitingRelease, services);
        services.release_ready(measured).await?;
        self.set_state(GuestState::AwaitingBinding, services);
        if services.bound_principal().await? != scope {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        self.set_state(GuestState::AwaitingRelease, services);
        services.release_ready(measured).await?;
        self.set_state(GuestState::Starting, services);
        let mut channel = match services.launch_guest(scope, measured).await {
            Ok(channel) => channel,
            Err(refusal) => {
                self.set_state(GuestState::Failed, services);
                services.stop_guest().await?;
                return Err(refusal);
            }
        };
        if channel.is_closed() {
            self.set_state(GuestState::Failed, services);
            services.stop_guest().await?;
            return Err(codes::SUPERVISOR_STATE);
        }
        self.bound_subject = Some(scope);
        self.fd3_readers = 1;
        self.state = GuestState::Running;
        self.sample_activity(services);
        let mut revoked = false;
        let served = {
            let mut serving = services.serve_guest(&mut channel, scope);
            loop {
                match tokio::time::timeout(Duration::from_millis(100), serving.as_mut()).await {
                    Ok(result) => break result,
                    Err(_) => {
                        self.sample_activity(services);
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            services.bound_principal(),
                        )
                        .await
                        {
                            Ok(Ok(current)) if current == scope => {}
                            Ok(Ok(_)) => {
                                revoked = true;
                                break Err(codes::AUMLOK_BINDING_REQUIRED);
                            }
                            Ok(Err(refusal)) => {
                                revoked = true;
                                break Err(refusal);
                            }
                            Err(_) => {
                                revoked = true;
                                break Err(codes::SUPERVISOR_NOT_READY);
                            }
                        }
                    }
                }
            }
        };
        self.set_state(GuestState::Stopping, services);
        let closed = channel.close();
        drop(channel);
        self.fd3_readers = 0;
        let stopped = services.stop_guest().await;
        let settled = services.settle_guest(scope).await;
        self.bound_subject = None;
        self.sample_activity(services);
        if closed.is_err() || stopped.is_err() || settled.is_err() {
            self.set_state(GuestState::Failed, services);
            return closed.and(stopped).and(settled);
        }
        let final_state = if revoked {
            GuestState::AwaitingBinding
        } else if served.is_err() {
            GuestState::Failed
        } else {
            GuestState::Stopped
        };
        self.set_state(final_state, services);
        served
    }

    /// Row 128: expose observed counters from this runtime without making health cells.
    pub fn facts(&self) -> Result<SupervisorFacts> {
        let activity = self.activity.as_ref().ok_or(codes::SUPERVISOR_NOT_READY)?;
        Ok(SupervisorFacts {
            observed_at_ms: self.observed_at_ms.ok_or(codes::SUPERVISOR_STATE)?,
            guest_state: self.state,
            guest_bound_subject: self.bound_subject,
            measured_release: self.measured_release,
            fd3_reader_count: self.fd3_readers,
            pending_requests: activity.pending_requests,
            pending_proposals: activity.pending_proposals,
            session_sequence: activity.session_sequence,
            durable_sequence: activity.durable_sequence,
            memory_calls_forwarded: activity.memory_calls_forwarded,
            stranger_inputs_refused: activity.stranger_inputs_refused,
        })
    }

    fn sample_activity(&mut self, services: &dyn RuntimeServices) {
        self.activity = services.activity().ok().filter(valid_activity);
        self.observed_at_ms = host_time().ok();
        self.publish(services);
    }

    fn set_state(&mut self, state: GuestState, services: &dyn RuntimeServices) {
        self.state = state;
        self.publish(services);
    }

    fn publish(&self, services: &dyn RuntimeServices) {
        if let Ok(facts) = self.facts() {
            services.observe_runtime(&facts);
        }
    }
}

fn host_time() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| codes::SUPERVISOR_STATE)?
        .as_millis();
    if millis > canon::json::MAX_SAFE_INTEGER as u128 {
        return Err(codes::SUPERVISOR_STATE);
    }
    Ok(millis as u64)
}

fn valid_activity(activity: &RuntimeActivity) -> bool {
    let bound = canon::json::MAX_SAFE_INTEGER as u64;
    let cursors_valid = match (activity.session_sequence, activity.durable_sequence) {
        (Some((session, sequence)), Some((durable_session, durable))) => {
            session == durable_session && durable <= sequence && sequence <= bound
        }
        (Some((_, sequence)), None) => sequence <= bound,
        (None, None) => true,
        (None, Some(_)) => false,
    };
    activity.pending_requests <= crate::transport::MAX_PENDING_REQUESTS
        && activity.pending_proposals <= crate::transport::MAX_PENDING_PROPOSALS
        && cursors_valid
}
