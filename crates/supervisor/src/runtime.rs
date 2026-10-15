// SPDX-License-Identifier: AGPL-3.0-or-later
//! Supervisor lifecycle wiring; binding and release policy are supplied by their organs.

use crate::{ingress::PrincipalScope, services::ServiceFuture, transport::GuestChannel};
use canon::{digest::Digest32, ids::SessionId, Result};
use std::path::PathBuf;

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

/// Trusted in-process boot/lifecycle adapter. It returns observations only after
/// the owning organs have completed their checks; it cannot accept guest approvals.
pub trait RuntimeServices: Send + Sync {
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
}

/// Runtime startup remains unimplemented until the organ bodies land.
pub struct SupervisorRuntime {
    config: RuntimeConfig,
    state: GuestState,
}

impl SupervisorRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            state: GuestState::Stopped,
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
    pub async fn run(&mut self, _services: &dyn RuntimeServices) -> Result<()> {
        todo!("row 128")
    }

    /// Row 128: expose observed counters from this runtime without making health cells.
    pub fn facts(&self) -> Result<SupervisorFacts> {
        todo!("row 128")
    }
}
