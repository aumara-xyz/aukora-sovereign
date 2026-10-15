// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scheduled sandbox observations use C3 boot.facts bodies, never a new v1 kind.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityRecord, AuthorityTxn, AuthorityVersion, FactKind, FactRecord},
    digest::Digest32,
    json::{SafeInteger, Value},
    Refusal, Result,
};

pub const CADENCE_MS: u64 = 5_000;
pub const POSTURE_SCHEMA: &str = "aukora-posture-v1";

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

pub fn append(
    transaction: &mut impl AuthorityTxn,
    authority: AuthorityVersion,
    observed: &Posture,
) -> Result<AuthorityRecord> {
    let at = i64::try_from(observed.observed_at_ms).map_err(|_| Refusal {
        organ: "immune",
        reason: "posture-clock-range",
    })?;
    let text = |value: String| Value::text(value);
    let body = Value::object(vec![
        ("schema".into(), text(POSTURE_SCHEMA.into())?),
        ("algorithm".into(), text("sha256".into())?),
        ("release".into(), text(observed.release.to_string())?),
        ("cage".into(), text(observed.cage.to_string())?),
        (
            "guest_instance".into(),
            text(observed.guest_instance.to_string())?,
        ),
        (
            "observed_at_ms".into(),
            Value::integer(SafeInteger::new(at)?),
        ),
        (
            "fd3_supervisor_only".into(),
            Value::boolean(observed.fd3_supervisor_only),
        ),
        (
            "fd4_data_only".into(),
            Value::boolean(observed.fd4_data_only),
        ),
        (
            "execve_denied".into(),
            Value::boolean(observed.execve_denied),
        ),
        (
            "execveat_denied".into(),
            Value::boolean(observed.execveat_denied),
        ),
        (
            "sockets_denied".into(),
            Value::boolean(observed.sockets_denied),
        ),
        (
            "isolation_current".into(),
            Value::boolean(observed.isolation_current),
        ),
    ])?;
    transaction.append_fact(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority,
        at,
        kind: FactKind::BootFacts,
        actor: "immune".into(),
        body,
    })
}
