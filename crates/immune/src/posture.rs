// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scheduled sandbox observations use C3 boot.facts bodies, never a new v1 kind.
//!
//! A posture row records what the live cage read-back showed, on a fixed cadence.
//! It is a nonauthorizing fact: it never approves a release, a grant or a start.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityRecord, AuthorityTxn, AuthorityVersion, FactKind, FactRecord},
    digest::Digest32,
    json::{SafeInteger, Value, ValueView, MAX_SAFE_INTEGER},
    Refusal, Result,
};
use launcher::{boot::CageSample, profiles::ProfileKind};

pub const CADENCE_MS: u64 = 5_000;
pub const POSTURE_SCHEMA: &str = "aukora-posture-v1";

/// Kernel seccomp mode reported for an installed filter.
const SECCOMP_MODE_FILTER: u32 = 2;
/// Number of keys in a posture body; any other key set refuses.
const BODY_KEYS: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Posture {
    pub release: Digest32,
    pub cage: Digest32,
    pub guest_instance: Digest32,
    pub fd3_supervisor_only: bool,
    pub fd4_data_only: bool,
    pub execve_denied: bool,
    pub execveat_denied: bool,
    pub sockets_denied: bool,
    pub isolation_current: bool,
    pub observed_at_ms: u64,
}

/// Live facts for one posture row: the launcher's read-back of the running cage
/// plus the supervisor's own FD 3 and FD 4 channel state. Plain data from trusted
/// host code; nothing here comes from guest or wire text.
#[derive(Clone, Copy, Debug)]
pub struct CageObservation<'a> {
    /// Approved release the guest was launched from.
    pub release: Digest32,
    /// Commitment to the cage profile the guest was launched under.
    pub cage: Digest32,
    /// Identity of this guest instance.
    pub guest_instance: Digest32,
    /// Launcher read-back of the running cage.
    pub sample: &'a CageSample,
    /// Digest of the compiled Auma seccomp filter for this host's architecture.
    pub expected_filter: Digest32,
    /// Readers of the guest's FD 3 stream counted by the supervisor, itself included.
    pub fd3_readers: u32,
    /// The supervisor holds FD 4 in its bounded data-only mode.
    pub fd4_data_only: bool,
    /// Supervisor clock when the sample was taken.
    pub observed_at_ms: u64,
}

impl Posture {
    /// Derives the posture flags from the live read-back. Refuses a stopped guest,
    /// which has no running sandbox to attest. A fact the launcher could not read
    /// leaves the flags that depend on it false.
    ///
    /// - exec denial: seccomp filter mode with no_new_privs, the Auma profile and
    ///   exactly the expected compiled filter digest;
    /// - socket denial: that filter, Landlock network denial, and a separate network
    ///   namespace with no active interface and no route;
    /// - current isolation: separate user, mount, PID, IPC, UTS and cgroup
    ///   namespaces, fully enforced Landlock with no writable subtree, and the child
    ///   attached to its cgroup with swap disabled;
    /// - FD 3: the supervisor is the only reader.
    pub fn observe(observation: &CageObservation<'_>) -> Result<Self> {
        let sample = observation.sample;
        if !sample.running {
            return Err(refusal("posture-guest-stopped"));
        }
        let filter = sample.seccomp.as_ref().is_some_and(|seccomp| {
            seccomp.mode == SECCOMP_MODE_FILTER
                && seccomp.no_new_privileges
                && seccomp.profile == ProfileKind::Auma
                && seccomp.filter_sha256 == observation.expected_filter
        });
        let landlock = sample.landlock.as_ref();
        let namespaces = sample.namespaces.as_ref();
        let network_closed = landlock.is_some_and(|l| l.network_denied)
            && namespaces.is_some_and(|n| {
                n.child_network != n.supervisor_network && n.active_interfaces == 0 && n.routes == 0
            });
        let isolated = namespaces.is_some_and(|n| {
            n.user_isolated
                && n.mounts_isolated
                && n.pids_isolated
                && n.ipc_isolated
                && n.uts_isolated
                && n.cgroup_isolated
        }) && landlock.is_some_and(|l| l.fully_enforced && l.writable_subtrees == 0)
            && sample
                .cgroup
                .as_ref()
                .is_some_and(|c| c.child_attached && c.swap_disabled);
        Ok(Self {
            release: observation.release,
            cage: observation.cage,
            guest_instance: observation.guest_instance,
            fd3_supervisor_only: observation.fd3_readers == 1,
            fd4_data_only: observation.fd4_data_only,
            execve_denied: filter,
            execveat_denied: filter,
            sockets_denied: filter && network_closed,
            isolation_current: isolated,
            observed_at_ms: observation.observed_at_ms,
        })
    }

    /// Encodes the versioned posture body carried inside a C3 boot.facts row.
    pub fn to_body(&self) -> Result<Value> {
        let at = clock(self.observed_at_ms)?;
        let text = |value: String| Value::text(value);
        Value::object(vec![
            ("schema".into(), text(POSTURE_SCHEMA.into())?),
            ("algorithm".into(), text("sha256".into())?),
            ("release".into(), text(self.release.to_string())?),
            ("cage".into(), text(self.cage.to_string())?),
            (
                "guest_instance".into(),
                text(self.guest_instance.to_string())?,
            ),
            (
                "observed_at_ms".into(),
                Value::integer(SafeInteger::new(at)?),
            ),
            (
                "fd3_supervisor_only".into(),
                Value::boolean(self.fd3_supervisor_only),
            ),
            ("fd4_data_only".into(), Value::boolean(self.fd4_data_only)),
            ("execve_denied".into(), Value::boolean(self.execve_denied)),
            (
                "execveat_denied".into(),
                Value::boolean(self.execveat_denied),
            ),
            ("sockets_denied".into(), Value::boolean(self.sockets_denied)),
            (
                "isolation_current".into(),
                Value::boolean(self.isolation_current),
            ),
        ])
    }

    /// Decodes a posture body read back from Aura. Refuses another schema or
    /// algorithm, a missing or extra key, a wrong value type, or a digest that is
    /// not 64 lowercase hexadecimal digits.
    pub fn from_body(body: &Value) -> Result<Self> {
        match body.view() {
            ValueView::Object(members) if members.len() == BODY_KEYS => {}
            _ => return Err(refusal("posture-body")),
        }
        if text(body, "schema")? != POSTURE_SCHEMA || text(body, "algorithm")? != "sha256" {
            return Err(refusal("posture-body"));
        }
        let observed_at_ms = match field(body, "observed_at_ms")? {
            ValueView::Integer(number) => {
                u64::try_from(number.get()).map_err(|_| refusal("posture-body"))?
            }
            _ => return Err(refusal("posture-body")),
        };
        Ok(Self {
            release: digest(body, "release")?,
            cage: digest(body, "cage")?,
            guest_instance: digest(body, "guest_instance")?,
            fd3_supervisor_only: flag(body, "fd3_supervisor_only")?,
            fd4_data_only: flag(body, "fd4_data_only")?,
            execve_denied: flag(body, "execve_denied")?,
            execveat_denied: flag(body, "execveat_denied")?,
            sockets_denied: flag(body, "sockets_denied")?,
            isolation_current: flag(body, "isolation_current")?,
            observed_at_ms,
        })
    }
}

/// Appends one posture row as a nonauthorizing boot.facts fact.
pub fn append(
    transaction: &mut impl AuthorityTxn,
    authority: AuthorityVersion,
    observed: &Posture,
) -> Result<AuthorityRecord> {
    transaction.append_fact(fact(authority, observed)?)
}

/// Posture rows on a fixed cadence: at most one row per `CADENCE_MS` slot, on a
/// grid anchored at the first slot. Missed slots are skipped, never replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Schedule {
    next_ms: u64,
}

impl Schedule {
    pub const fn new(first_ms: u64) -> Self {
        Self { next_ms: first_ms }
    }

    pub const fn due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_ms
    }

    pub const fn next_ms(&self) -> u64 {
        self.next_ms
    }

    /// Appends the posture when its observation time has reached the next slot;
    /// refuses an observation before it. The slot is spent before the append, so a
    /// failed append is retried at the next slot, not repeated at once.
    pub fn attest(
        &mut self,
        transaction: &mut impl AuthorityTxn,
        authority: AuthorityVersion,
        observed: &Posture,
    ) -> Result<AuthorityRecord> {
        let now_ms = observed.observed_at_ms;
        if !self.due(now_ms) {
            return Err(refusal("posture-not-due"));
        }
        let record = fact(authority, observed)?;
        let elapsed = (now_ms - self.next_ms) / CADENCE_MS;
        self.next_ms = elapsed
            .checked_add(1)
            .and_then(|slots| slots.checked_mul(CADENCE_MS))
            .and_then(|step| self.next_ms.checked_add(step))
            .ok_or(refusal("posture-clock-range"))?;
        transaction.append_fact(record)
    }
}

fn fact(authority: AuthorityVersion, observed: &Posture) -> Result<FactRecord> {
    Ok(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority,
        at: clock(observed.observed_at_ms)?,
        kind: FactKind::BootFacts,
        actor: "immune".into(),
        body: observed.to_body()?,
    })
}

fn clock(observed_at_ms: u64) -> Result<i64> {
    i64::try_from(observed_at_ms)
        .ok()
        .filter(|at| *at <= MAX_SAFE_INTEGER)
        .ok_or(refusal("posture-clock-range"))
}

fn field<'a>(body: &'a Value, key: &str) -> Result<ValueView<'a>> {
    body.get(key)
        .map(Value::view)
        .ok_or(refusal("posture-body"))
}

fn text<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    match field(body, key)? {
        ValueView::Text(value) => Ok(value),
        _ => Err(refusal("posture-body")),
    }
}

fn flag(body: &Value, key: &str) -> Result<bool> {
    match field(body, key)? {
        ValueView::Boolean(value) => Ok(value),
        _ => Err(refusal("posture-body")),
    }
}

fn digest(body: &Value, key: &str) -> Result<Digest32> {
    Digest32::from_hex(text(body, key)?).map_err(|_| refusal("posture-body"))
}

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
