// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUMLOK's registered observations, separate from owner authorization.

use crate::delegation::{DelegationLevel, DelegationReadTxn, DelegationRecord};
use crate::devices::DeviceBinding;
use crate::keys::{KeyBinding, KeyId, KeyRole};
use canon::alg::AlgorithmId;
use canon::authority::{AuthorityRecord, AuthorityVersion, Kind, Phase};
use canon::digest::Digest32;
use canon::health::{
    Cell, CheckSpec, HealthEvidence, HealthReason, OrganId, CHECKS, CORNERS, HEALTH_FORMAT_VERSION,
};
use canon::Result;
use std::collections::BTreeSet;

/// Private 1: random identity root is phrase-sealed; 30-second freshness.
pub const ROOT_SEAL: CheckSpec = CHECKS[0].spec();
/// Private 2: seven words match the enrolled acrostic and list version; 30 seconds.
pub const PHRASE_FORMAT: CheckSpec = CHECKS[1].spec();
/// Private 3: root envelope uses permitted KDF and AEAD algorithms; 30 seconds.
pub const ROOT_ENVELOPE: CheckSpec = CHECKS[2].spec();
/// Private 4: credential epoch is not below its rollback guard; 5 seconds.
pub const CREDENTIAL_EPOCH: CheckSpec = CHECKS[3].spec();
/// Private 5: accepted credentials have current owner bindings; 5 seconds.
pub const CREDENTIAL_BINDINGS: CheckSpec = CHECKS[4].spec();
/// Private 6: accepted assertions require presence and verification; 5 seconds.
pub const ASSERTION_FLAGS: CheckSpec = CHECKS[5].spec();
/// Private 7: accepted assertions match the enrolled RP hash; 5 seconds.
pub const ASSERTION_RP: CheckSpec = CHECKS[6].spec();
/// Private 8: accepted ceremony and shell origins match enrolment; 5 seconds.
pub const ASSERTION_ORIGINS: CheckSpec = CHECKS[7].spec();
/// Private 9: sign counters follow the persisted counter policy; 5 seconds.
pub const SIGN_COUNTERS: CheckSpec = CHECKS[8].spec();
/// Private 10: delegated keys bind to the active root epoch; 30 seconds.
pub const DELEGATED_KEYS: CheckSpec = CHECKS[9].spec();
/// Private 11: key and signature formats name permitted algorithms; 30 seconds.
pub const ALGORITHM_BINDINGS: CheckSpec = CHECKS[10].spec();
/// Private 12: public payloads contain neither root nor phrase material; 30 seconds.
pub const PUBLIC_PAYLOADS: CheckSpec = CHECKS[11].spec();
/// Private 13: enrolled bindings retain verified credential keys; 30 seconds.
pub const PASSKEY_PUBLIC_KEYS: CheckSpec = CHECKS[12].spec();
/// Private 14: unlock admission reads the current principal's limits; 5 seconds.
pub const UNLOCK_COUNTERS: CheckSpec = CHECKS[13].spec();
/// Private 15: refused unlocks are counted without authority; 5 seconds.
pub const UNLOCK_REFUSALS: CheckSpec = CHECKS[14].spec();
/// Private 16: root rotations advance an owner-approved epoch; 30 seconds.
pub const ROOT_ROTATIONS: CheckSpec = CHECKS[15].spec();
/// Private 17: recovery evidence does not replace owner approval; 30 seconds.
pub const RECOVERY_POLICY: CheckSpec = CHECKS[16].spec();
/// Private 18: active bindings retain their Aura enrolment anchor; 30 seconds.
pub const ENROLMENT_ANCHORS: CheckSpec = CHECKS[17].spec();

/// Corner 1, AUMLOK side: owner epoch equals Aura's recorded epoch; 5 seconds.
pub const AURA_OWNER_EPOCH: CheckSpec = CORNERS[0].specs()[0];
/// Corner 2, AUMLOK side: every accepted passkey has Aura enrolment; 5 seconds.
pub const AURA_ENROLMENT: CheckSpec = CORNERS[1].specs()[0];
/// Corner 3, AUMLOK side: Kira's key uses the current root epoch; 30 seconds.
pub const KIRA_ROOT_EPOCH: CheckSpec = CORNERS[2].specs()[0];
/// Corner 4, AUMLOK side: Kira permission changes have owner signatures; 5 seconds.
pub const KIRA_PERMISSION: CheckSpec = CORNERS[3].specs()[0];
/// Corner 5, AUMLOK side: active Nostr keys are the delegated keys; 30 seconds.
pub const NETWORK_NOSTR_KEYS: CheckSpec = CORNERS[4].specs()[0];
/// Corner 6, AUMLOK side: contacts and devices have owner approvals; 5 seconds.
pub const NETWORK_RELATIONSHIPS: CheckSpec = CORNERS[5].specs()[0];
/// Corner 7, AUMLOK side: frontdoor RP and top origin match enrolment; 5 seconds.
pub const BODY_ORIGINS: CheckSpec = CORNERS[6].specs()[0];
/// Corner 8, AUMLOK side: frontdoor limits match principal counters; 5 seconds.
pub const BODY_UNLOCK_LIMITS: CheckSpec = CORNERS[7].specs()[0];

/// Every private report in canon's one-based local-index order.
pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    ROOT_SEAL,
    PHRASE_FORMAT,
    ROOT_ENVELOPE,
    CREDENTIAL_EPOCH,
    CREDENTIAL_BINDINGS,
    ASSERTION_FLAGS,
    ASSERTION_RP,
    ASSERTION_ORIGINS,
    SIGN_COUNTERS,
    DELEGATED_KEYS,
    ALGORITHM_BINDINGS,
    PUBLIC_PAYLOADS,
    PASSKEY_PUBLIC_KEYS,
    UNLOCK_COUNTERS,
    UNLOCK_REFUSALS,
    ROOT_ROTATIONS,
    RECOVERY_POLICY,
    ENROLMENT_ANCHORS,
];

/// This organ's eight independent corner reports in canon registry order.
pub const CORNER_CHECKS: [CheckSpec; 8] = [
    AURA_OWNER_EPOCH,
    AURA_ENROLMENT,
    KIRA_ROOT_EPOCH,
    KIRA_PERMISSION,
    NETWORK_NOSTR_KEYS,
    NETWORK_RELATIONSHIPS,
    BODY_ORIGINS,
    BODY_UNLOCK_LIMITS,
];

/// Supervisor snapshot context, without root material or fingerprint trits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthContext {
    /// Owner epoch inspected by the collector.
    pub epoch: u64,
    /// Aura sequence inspected by the collector.
    pub sequence: u64,
    /// Supervisor report time; it does not establish authority.
    pub observed_at_ms: u64,
    /// Exact shared context commitment for independently reported corners.
    pub commitment: Digest32,
}

/// A complete current inventory read under the authority transaction's lock.
/// Historical and revoked entries are excluded, while reserved mesh bindings remain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyHealthInventory {
    /// Every currently active key binding, including owner passkeys.
    pub keys: Vec<KeyId>,
    /// Every current delegation edge, including ancestors of current agents.
    pub delegations: Vec<Digest32>,
    /// Every currently paired device, addressed by its bound key id.
    pub devices: Vec<KeyId>,
}

/// Locked observation sources supplied by the organ's storage adapter.
/// These reads cannot consume approvals, append records or grant authority.
pub trait HealthReadTxn: DelegationReadTxn {
    /// Context of the locked supervisor collection, including its shared commitment.
    fn health_context(&mut self) -> Result<HealthContext>;
    /// Enumerate the complete current key, delegation and device indices.
    fn health_inventory(&mut self) -> Result<KeyHealthInventory>;
    /// Read a stored paired device from the locked index, never from browser input.
    fn health_device(&mut self, key: KeyId) -> Result<DeviceBinding>;
    /// Read a chain- and signature-verified Aura record by its exact sequence.
    fn health_record(&mut self, sequence: u64) -> Result<AuthorityRecord>;
    /// Read the Aura record establishing the current recorded owner epoch.
    fn health_owner_epoch_record(&mut self) -> Result<AuthorityRecord>;
    /// Read the independently stored current node and agent Nostr key identifiers.
    fn health_network_nostr_keys(&mut self) -> Result<Vec<KeyId>>;
}

const MAX_OBSERVED_KEYS: usize = 4096;

/// Without a source, implemented observers report NotChecked and unwritten
/// observers report Failed. Context metadata never manufactures an observation.
pub fn health(context: HealthContext) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .iter()
        .chain(CORNER_CHECKS.iter())
        .map(|spec| HealthEvidence {
            v: HEALTH_FORMAT_VERSION,
            algorithm: AlgorithmId::Sha256,
            check: spec.check,
            reporter: OrganId::Aumlok,
            epoch: context.epoch,
            sequence: context.sequence,
            observed_at_ms: context.observed_at_ms,
            expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
            cell: if implemented(*spec) {
                Cell::Undetermined
            } else {
                Cell::Failed
            },
            reason: if implemented(*spec) {
                HealthReason::NotChecked
            } else {
                HealthReason::Unwritten
            },
            commitment: context.commitment,
        })
        .collect()
}

fn implemented(spec: CheckSpec) -> bool {
    [
        DELEGATED_KEYS,
        ALGORITHM_BINDINGS,
        AURA_OWNER_EPOCH,
        NETWORK_NOSTR_KEYS,
    ]
    .iter()
    .any(|implemented| implemented.check == spec.check)
}

/// Observe key, delegation and device state without changing it. Other row owners'
/// observers remain Failed/Unwritten. Source failures never become positive cells.
pub fn health_in<T: HealthReadTxn + ?Sized>(
    context: HealthContext,
    txn: &mut T,
) -> Vec<HealthEvidence> {
    let mut reports = health(context);
    let transaction = txn.transaction_id();
    let source_context = match txn.health_context() {
        Ok(source) if source == context => source,
        Ok(_) => {
            replace_implemented(&mut reports, HealthReason::ContextMismatch);
            return reports;
        }
        Err(_) => {
            replace_implemented(&mut reports, HealthReason::Unreachable);
            return reports;
        }
    };
    let head = match txn.key_epoch() {
        Ok(head) if valid_version(head, source_context) && head.epoch == source_context.epoch => {
            head
        }
        Ok(_) => {
            replace_implemented(&mut reports, HealthReason::ContextMismatch);
            return reports;
        }
        Err(_) => {
            replace_implemented(&mut reports, HealthReason::Unreachable);
            return reports;
        }
    };
    match txn.key_time_ms() {
        Ok(now) if now == context.observed_at_ms => {}
        Ok(_) => {
            replace_implemented(&mut reports, HealthReason::ContextMismatch);
            return reports;
        }
        Err(_) => {
            replace_implemented(&mut reports, HealthReason::Unreachable);
            return reports;
        }
    }
    let owner = observe_owner_epoch(txn, context, head);
    set_report(&mut reports, AURA_OWNER_EPOCH, owner);
    match read_state(txn) {
        Ok(state) => {
            let keys = observe_keys(txn, context, head, &state);
            set_report(&mut reports, DELEGATED_KEYS, keys);
            set_report(
                &mut reports,
                ALGORITHM_BINDINGS,
                observe_algorithms(txn, &state),
            );
            set_report(
                &mut reports,
                NETWORK_NOSTR_KEYS,
                observe_nostr(txn, &state, keys),
            );
        }
        Err(reason) => {
            for spec in [DELEGATED_KEYS, ALGORITHM_BINDINGS, NETWORK_NOSTR_KEYS] {
                set_report(&mut reports, spec, Err(reason));
            }
        }
    }
    if txn.transaction_id() != transaction
        || txn.health_context().ok() != Some(context)
        || txn.key_epoch().ok() != Some(head)
        || txn.key_time_ms().ok() != Some(context.observed_at_ms)
    {
        replace_implemented(&mut reports, HealthReason::ContextMismatch);
    }
    reports
}

type Observation = core::result::Result<(), HealthReason>;

struct ObservedState {
    keys: Vec<(KeyBinding, AuthorityRecord, bool)>,
    edges: Vec<(DelegationRecord, AuthorityRecord)>,
    devices: Vec<(DeviceBinding, AuthorityRecord)>,
}

fn read_state<T: HealthReadTxn + ?Sized>(
    txn: &mut T,
) -> core::result::Result<ObservedState, HealthReason> {
    let inventory = txn
        .health_inventory()
        .map_err(|_| HealthReason::Unreachable)?;
    for length in [
        inventory.keys.len(),
        inventory.delegations.len(),
        inventory.devices.len(),
    ] {
        if length > MAX_OBSERVED_KEYS {
            return Err(HealthReason::InvalidEvidence);
        }
    }
    if inventory
        .keys
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        != inventory.keys.len()
        || inventory
            .delegations
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != inventory.delegations.len()
        || inventory
            .devices
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != inventory.devices.len()
    {
        return Err(HealthReason::InvalidEvidence);
    }
    let mut state = ObservedState {
        keys: Vec::new(),
        edges: Vec::new(),
        devices: Vec::new(),
    };
    for id in inventory.keys {
        let binding = txn.key_binding(id).map_err(|_| HealthReason::Unreachable)?;
        if binding.request.key_id != id {
            return Err(HealthReason::InvariantFailed);
        }
        let revoked = txn
            .key_revocation(id)
            .map_err(|_| HealthReason::Unreachable)?
            .is_some();
        let record = txn
            .health_record(binding.version.sequence)
            .map_err(|_| HealthReason::Unreachable)?;
        state.keys.push((binding, record, revoked));
    }
    for id in inventory.delegations {
        let edge = txn
            .delegation_record(id)
            .map_err(|_| HealthReason::Unreachable)?;
        if edge.id != id {
            return Err(HealthReason::InvariantFailed);
        }
        let record = txn
            .health_record(edge.version.sequence)
            .map_err(|_| HealthReason::Unreachable)?;
        state.edges.push((edge, record));
    }
    for id in inventory.devices {
        let device = txn
            .health_device(id)
            .map_err(|_| HealthReason::Unreachable)?;
        if device.request.body.device_key.key_id != id {
            return Err(HealthReason::InvariantFailed);
        }
        let record = txn
            .health_record(device.version.sequence)
            .map_err(|_| HealthReason::Unreachable)?;
        state.devices.push((device, record));
    }
    Ok(state)
}

fn observe_keys<T: HealthReadTxn + ?Sized>(
    txn: &mut T,
    context: HealthContext,
    head: AuthorityVersion,
    state: &ObservedState,
) -> Observation {
    if state.keys.is_empty() {
        return if state.edges.is_empty() && state.devices.is_empty() {
            Err(HealthReason::NotChecked)
        } else {
            Err(HealthReason::InvariantFailed)
        };
    }
    if !state
        .keys
        .iter()
        .any(|(key, _, _)| key.request.role == KeyRole::OwnerPasskey)
    {
        return Err(HealthReason::InvariantFailed);
    }
    for (binding, record, revoked) in &state.keys {
        crate::keys::validate_binding(binding).map_err(|_| HealthReason::InvariantFailed)?;
        if *revoked
            || binding.request.epoch != head.epoch
            || binding.version.epoch != head.epoch
            || !valid_version(binding.version, context)
            || binding.record_hash != record.hash
            || binding.version != record.authority
            || binding.request.scope.not_before_ms > context.observed_at_ms
            || binding.request.scope.expires_at_ms <= context.observed_at_ms
            || !binding_record(record)
            || record.operation != Some(binding.request.operation_id)
            || !key_body_matches(binding, record, state)?
        {
            return Err(HealthReason::InvariantFailed);
        }
    }
    for (edge, record) in &state.edges {
        crate::delegation::inspect_record(txn, edge, head, context.observed_at_ms)
            .map_err(|_| HealthReason::InvariantFailed)?;
        if !binding_record(record)
            || record.authority != edge.version
            || record.body
                != crate::delegation::record_value(edge)
                    .map_err(|_| HealthReason::InvariantFailed)?
            || !state
                .keys
                .iter()
                .any(|(key, _, _)| key.request.key_id == edge.issuer)
            || !state
                .keys
                .iter()
                .any(|(key, _, _)| key.request.key_id == edge.delegate)
        {
            return Err(HealthReason::InvariantFailed);
        }
        if let Some(parent_id) = edge.parent {
            let parent = state
                .edges
                .iter()
                .find(|(parent, _)| parent.id == parent_id)
                .map(|(parent, _)| parent)
                .ok_or(HealthReason::InvariantFailed)?;
            if edge.issuer != parent.delegate
                || edge.from != parent.to
                || edge.version.epoch != parent.version.epoch
                || edge.version.sequence <= parent.version.sequence
            {
                return Err(HealthReason::InvariantFailed);
            }
            crate::keys::scope_attenuates(&edge.scope, &parent.scope)
                .map_err(|_| HealthReason::InvariantFailed)?;
        } else if edge.from != DelegationLevel::Root {
            return Err(HealthReason::InvariantFailed);
        }
    }
    for (device, record) in &state.devices {
        if !valid_version(device.version, context)
            || device.version != record.authority
            || device.record_hash != record.hash
            || !binding_record(record)
            || record.operation != Some(device.request.body.operation_id)
            || record.body
                != crate::devices::request_value(&device.request)
                    .map_err(|_| HealthReason::InvariantFailed)?
            || !state.keys.iter().any(|(key, _, _)| {
                key.request.key_id == device.request.body.device_key.key_id
                    && key.request.role == KeyRole::Device
                    && key.request.material == device.request.body.device_key.material
            })
        {
            return Err(HealthReason::InvariantFailed);
        }
    }
    Ok(())
}

fn observe_algorithms<T: HealthReadTxn + ?Sized>(
    txn: &mut T,
    state: &ObservedState,
) -> Observation {
    if state.keys.is_empty() {
        return if state.edges.is_empty() && state.devices.is_empty() {
            Err(HealthReason::NotChecked)
        } else {
            Err(HealthReason::InvariantFailed)
        };
    }
    if !state
        .keys
        .iter()
        .any(|(key, _, _)| key.request.role == KeyRole::OwnerPasskey)
    {
        return Err(HealthReason::InvariantFailed);
    }
    for (key, record, _) in &state.keys {
        crate::keys::validate_request(&key.request).map_err(|_| HealthReason::InvariantFailed)?;
        check_record_algorithms(record)?;
    }
    for (edge, record) in &state.edges {
        crate::delegation::validate_record(edge).map_err(|_| HealthReason::InvariantFailed)?;
        let issuer = state
            .keys
            .iter()
            .find(|(key, _, _)| key.request.key_id == edge.issuer)
            .map(|(key, _, _)| key)
            .ok_or(HealthReason::InvariantFailed)?;
        crate::keys::verify_key_signatures(
            txn,
            issuer,
            &edge
                .signing_bytes()
                .map_err(|_| HealthReason::InvariantFailed)?,
            &edge.signatures,
        )
        .map_err(|_| HealthReason::InvariantFailed)?;
        check_record_algorithms(record)?;
    }
    for (device, record) in &state.devices {
        crate::devices::verify_pairing(txn, &device.request)
            .map_err(|_| HealthReason::InvariantFailed)?;
        check_record_algorithms(record)?;
    }
    Ok(())
}

fn key_body_matches(
    binding: &KeyBinding,
    record: &AuthorityRecord,
    state: &ObservedState,
) -> core::result::Result<bool, HealthReason> {
    if record.body
        == crate::keys::request_value(&binding.request)
            .map_err(|_| HealthReason::InvariantFailed)?
    {
        return Ok(true);
    }
    for (device, device_record) in &state.devices {
        if device.request.body.device_key == binding.request
            && device.version == binding.version
            && device.record_hash == binding.record_hash
            && device_record == record
            && record.body
                == crate::devices::request_value(&device.request)
                    .map_err(|_| HealthReason::InvariantFailed)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn observe_owner_epoch<T: HealthReadTxn + ?Sized>(
    txn: &mut T,
    context: HealthContext,
    head: AuthorityVersion,
) -> Observation {
    let record = txn
        .health_owner_epoch_record()
        .map_err(|_| HealthReason::Unreachable)?;
    check_record_algorithms(&record)?;
    if record.authority.epoch != head.epoch
        || !valid_version(record.authority, context)
        || !matches!(record.kind, Kind::AumlokEnrol | Kind::AumlokBind)
        || record.phase != Phase::Terminal
        || record.operation.is_none()
    {
        return Err(HealthReason::Disagreement);
    }
    let anchored = txn
        .health_record(record.authority.sequence)
        .map_err(|_| HealthReason::Unreachable)?;
    if anchored != record {
        return Err(HealthReason::Disagreement);
    }
    Ok(())
}

fn observe_nostr<T: HealthReadTxn + ?Sized>(
    txn: &mut T,
    state: &ObservedState,
    keys: Observation,
) -> Observation {
    keys?;
    let active = txn
        .health_network_nostr_keys()
        .map_err(|_| HealthReason::Unreachable)?;
    let observed: BTreeSet<_> = active.iter().copied().collect();
    let bound: BTreeSet<_> = state
        .keys
        .iter()
        .filter_map(|(binding, _, _)| {
            matches!(
                binding.request.role,
                KeyRole::NodeNostr | KeyRole::AgentNostr
            )
            .then_some(binding.request.key_id)
        })
        .collect();
    if observed.len() != active.len() || observed != bound {
        return Err(HealthReason::Disagreement);
    }
    if bound.is_empty() {
        return Err(HealthReason::NotChecked);
    }
    Ok(())
}

fn check_record_algorithms(record: &AuthorityRecord) -> Observation {
    if record.v != 1 || record.algorithm != AlgorithmId::Sha256 || record.signatures.version() != 1
    {
        return Err(HealthReason::InvariantFailed);
    }
    let mut seen = BTreeSet::new();
    for signature in record.signatures.components() {
        if signature.v != 1
            || signature.bytes.is_empty()
            || !seen.insert(signature.algorithm)
            || !matches!(
                signature.algorithm,
                AlgorithmId::Ed25519 | AlgorithmId::MlDsa65
            )
        {
            return Err(HealthReason::InvariantFailed);
        }
    }
    if !seen.contains(&AlgorithmId::Ed25519) {
        return Err(HealthReason::InvariantFailed);
    }
    Ok(())
}

fn binding_record(record: &AuthorityRecord) -> bool {
    record.kind == Kind::AumlokBind && record.phase == Phase::Terminal && record.operation.is_some()
}

fn valid_version(version: AuthorityVersion, context: HealthContext) -> bool {
    version.epoch <= context.epoch
        && version.epoch <= 9_007_199_254_740_991
        && version.sequence > 0
        && version.sequence <= context.sequence
        && version.sequence <= 9_007_199_254_740_991
        && (version.sequence == 1) == version.previous_hash.is_none()
}

fn replace_implemented(reports: &mut [HealthEvidence], reason: HealthReason) {
    for spec in [
        DELEGATED_KEYS,
        ALGORITHM_BINDINGS,
        AURA_OWNER_EPOCH,
        NETWORK_NOSTR_KEYS,
    ] {
        set_report(reports, spec, Err(reason));
    }
}

fn set_report(reports: &mut [HealthEvidence], spec: CheckSpec, observation: Observation) {
    if let Some(report) = reports.iter_mut().find(|report| report.check == spec.check) {
        report.reason = observation.err().unwrap_or(HealthReason::Satisfied);
        report.cell = match report.reason {
            HealthReason::Satisfied => Cell::Verified,
            HealthReason::NotChecked | HealthReason::Unreachable | HealthReason::Stale => {
                Cell::Undetermined
            }
            _ => Cell::Failed,
        };
    }
}
