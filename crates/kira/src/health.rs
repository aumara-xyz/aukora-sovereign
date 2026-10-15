// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kira's registered observation contracts; unwritten observers report failure.

use canon::alg::AlgorithmId;
use canon::digest::Digest32;
use canon::health::{
    Cell, CheckRef, CheckSpec, HealthEvidence, HealthReason, OrganId, CHECKS, CORNERS,
    HEALTH_FORMAT_VERSION,
};

/// Private 1: authentication of every retained note ciphertext, at most 30 s old.
pub const CIPHERTEXT_INTEGRITY: CheckSpec = CHECKS[36].spec();
/// Private 2: active memory key wrapping at the current root epoch, at most 30 s old.
pub const KEY_ENVELOPE: CheckSpec = CHECKS[37].spec();
/// Private 3: note identifiers commit to saved canonical content, at most 30 s old.
pub const NOTE_COMMITMENTS: CheckSpec = CHECKS[38].spec();
/// Private 4: contiguous verified memory sequence and previous hash, at most 5 s old.
pub const CHAIN_HEAD: CheckSpec = CHECKS[39].spec();
/// Private 5: the verified memory head has an Aura anchor, at most 5 s old.
pub const AURA_ANCHOR: CheckSpec = CHECKS[40].spec();
/// Private 6: recall and listing enforce the principal's permission, at most 5 s old.
pub const PRINCIPAL_PERMISSIONS: CheckSpec = CHECKS[41].spec();
/// Private 7: plaintext recalls retain note identifiers and save citations, at most 5 s old.
pub const RECALL_CITATIONS: CheckSpec = CHECKS[42].spec();
/// Private 8: forgotten listings expose metadata without cold plaintext, at most 5 s old.
pub const FORGOTTEN_LISTING: CheckSpec = CHECKS[43].spec();
/// Private 9: demotion retains the note with a later sequence, at most 5 s old.
pub const DEMOTION_RECORDS: CheckSpec = CHECKS[44].spec();
/// Private 10: permission changes have owner authorization and Aura citations, at most 5 s old.
pub const PERMISSION_RECORDS: CheckSpec = CHECKS[45].spec();
/// Private 11: quarantine changes require owner authorization, at most 5 s old.
pub const QUARANTINE_RECORDS: CheckSpec = CHECKS[46].spec();
/// Private 12: the recall index is pinned to the verified memory head, at most 5 s old.
pub const INDEX_PIN: CheckSpec = CHECKS[47].spec();
/// Private 13: memory cells are re-executed and effect digests compared, at most 5 s old.
pub const SAVE_CELL_EFFECTS: CheckSpec = CHECKS[48].spec();
/// Private 14: saved and recalled memory keeps non-owner provenance, at most 5 s old.
pub const MEMORY_PROVENANCE: CheckSpec = CHECKS[49].spec();
/// Private 15: memory permission epochs cannot roll back, at most 5 s old.
pub const PERMISSION_EPOCH: CheckSpec = CHECKS[50].spec();
/// Private 16: memory pages enforce item, cursor and frame bounds, at most 5 s old.
pub const PAGE_BOUNDS: CheckSpec = CHECKS[51].spec();
/// Private 17: disclosure receipts identify permission and cited note, at most 5 s old.
pub const DISCLOSURE_RECEIPTS: CheckSpec = CHECKS[52].spec();
/// Private 18: records and key envelopes name algorithms and versions, at most 30 s old.
pub const RECORD_FORMATS: CheckSpec = CHECKS[53].spec();

/// Kira's 18 private observations in canon's local-index order.
pub const PRIVATE_CHECKS: [CheckSpec; 18] = [
    CIPHERTEXT_INTEGRITY,
    KEY_ENVELOPE,
    NOTE_COMMITMENTS,
    CHAIN_HEAD,
    AURA_ANCHOR,
    PRINCIPAL_PERMISSIONS,
    RECALL_CITATIONS,
    FORGOTTEN_LISTING,
    DEMOTION_RECORDS,
    PERMISSION_RECORDS,
    QUARANTINE_RECORDS,
    INDEX_PIN,
    SAVE_CELL_EFFECTS,
    MEMORY_PROVENANCE,
    PERMISSION_EPOCH,
    PAGE_BOUNDS,
    DISCLOSURE_RECEIPTS,
    RECORD_FORMATS,
];

/// Corner 3: Kira's root-wrapping epoch agrees with AUMLOK, at most 30 s old.
pub const ROOT_EPOCH_CORNER: CheckSpec = CORNERS[2].specs()[1];
/// Corner 4: every permission change has an AUMLOK-verified owner signature, at most 5 s old.
pub const PERMISSION_SIGNATURE_CORNER: CheckSpec = CORNERS[3].specs()[1];
/// Corner 9: Kira's verified head agrees with its Aura anchor, at most 5 s old.
pub const AURA_HEAD_CORNER: CheckSpec = CORNERS[8].specs()[1];
/// Corner 10: demotion and quarantine counts agree with Aura, at most 5 s old.
pub const ACTION_COUNTS_CORNER: CheckSpec = CORNERS[9].specs()[1];
/// Corner 15: backup commitments agree with Kira's head, at most 60 s old.
pub const BACKUP_HEAD_CORNER: CheckSpec = CORNERS[14].specs()[0];
/// Corner 16: each disclosed memory has a Kira permission, at most 5 s old.
pub const DISCLOSURE_PERMISSION_CORNER: CheckSpec = CORNERS[15].specs()[0];
/// Corner 17: the OpenViking index pin agrees with Kira's head, at most 5 s old.
pub const INDEX_HEAD_CORNER: CheckSpec = CORNERS[16].specs()[0];
/// Corner 18: recall receipts agree with the guest's FD 3 memory calls, at most 5 s old.
pub const RECALL_RECEIPTS_CORNER: CheckSpec = CORNERS[17].specs()[0];

/// Kira's eight independent corner sides in canon's corner-index order.
pub const CORNER_CHECKS: [CheckSpec; 8] = [
    ROOT_EPOCH_CORNER,
    PERMISSION_SIGNATURE_CORNER,
    AURA_HEAD_CORNER,
    ACTION_COUNTS_CORNER,
    BACKUP_HEAD_CORNER,
    DISCLOSURE_PERMISSION_CORNER,
    INDEX_HEAD_CORNER,
    RECALL_RECEIPTS_CORNER,
];

/// The common supervisor snapshot context; these fields confer no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthContext {
    /// Owner-state epoch requested by the supervisor.
    pub epoch: u64,
    /// Aura sequence requested by the supervisor.
    pub sequence: u64,
    /// Supervisor observation time in milliseconds.
    pub observed_at_ms: u64,
    /// Commitment identifying the common context to be independently observed.
    pub commitment: Digest32,
}

/// A measured result; no variant grants an operation or permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationVerdict {
    /// The observer established its registered invariant in the measured context.
    Satisfied,
    /// The observer measured a violation of its registered invariant.
    InvariantFailed,
    /// The observer measured conflicting commitments or state.
    Disagreement,
}

/// One observer's measured context, kept separate from the requested snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedCheck {
    /// The private check or Kira corner side that was actually inspected.
    pub check: CheckRef,
    /// Independently observed epoch, sequence, time and context commitment.
    pub context: HealthContext,
    /// Maximum lifetime claimed by this observation, bounded again by its spec.
    pub expires_at_ms: u64,
    /// Result of inspecting the registered source in this context.
    pub verdict: ObservationVerdict,
}

/// An absent implementation is distinct from an implemented but unavailable check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckObservation {
    /// No observer exists for this check; this always reports failure.
    Unwritten,
    /// The implemented observer has not yet completed this check.
    NotChecked,
    /// The implemented observer cannot reach its registered source.
    Unreachable,
    /// An observation tied to its own check and inspected context.
    Measured(ObservedCheck),
}

/// Native Kira observer interface; callers supply an organ-owned implementation.
/// The default reports Unwritten for every check. No wire parser supplies observers.
pub trait HealthObserver {
    fn observe(&mut self, _spec: CheckSpec, _requested: HealthContext) -> CheckObservation {
        CheckObservation::Unwritten
    }
}

/// Reports the missing implementation of every observer without inspecting state.
#[derive(Default)]
pub struct UnwrittenChecks;

impl HealthObserver for UnwrittenChecks {}

fn registered_kira_spec(spec: CheckSpec) -> bool {
    if spec.owner != OrganId::Kira {
        return false;
    }
    match spec.check {
        CheckRef::Private(id) if id.organ() == OrganId::Kira => {
            CHECKS[36 + usize::from(id.index() - 1)].spec() == spec
        }
        CheckRef::Corner { corner, side } if side == OrganId::Kira => CORNERS
            [usize::from(corner.index() - 1)]
        .specs()
        .contains(&spec),
        _ => false,
    }
}

fn report(
    spec: CheckSpec,
    context: HealthContext,
    cell: Cell,
    reason: HealthReason,
) -> HealthEvidence {
    HealthEvidence {
        v: HEALTH_FORMAT_VERSION,
        algorithm: AlgorithmId::Sha256,
        check: spec.check,
        reporter: OrganId::Kira,
        epoch: context.epoch,
        sequence: context.sequence,
        observed_at_ms: context.observed_at_ms,
        expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
        cell,
        reason,
        commitment: context.commitment,
    }
}

fn measured_report(
    spec: CheckSpec,
    requested: HealthContext,
    measured: ObservedCheck,
) -> HealthEvidence {
    let context = measured.context;
    let mut evidence = report(spec, context, Cell::Failed, HealthReason::InvalidEvidence);
    evidence.expires_at_ms = measured.expires_at_ms.min(evidence.expires_at_ms);
    if measured.check != spec.check
        || measured.expires_at_ms < context.observed_at_ms
        || context.observed_at_ms > requested.observed_at_ms
    {
        return report(spec, requested, Cell::Failed, HealthReason::InvalidEvidence);
    }
    if context.epoch != requested.epoch
        || context.sequence != requested.sequence
        || context.commitment != requested.commitment
    {
        evidence.reason = HealthReason::ContextMismatch;
        return evidence;
    }
    match measured.verdict {
        ObservationVerdict::InvariantFailed => {
            evidence.reason = HealthReason::InvariantFailed;
        }
        ObservationVerdict::Disagreement => {
            evidence.reason = HealthReason::Disagreement;
        }
        ObservationVerdict::Satisfied if requested.observed_at_ms > evidence.expires_at_ms => {
            evidence.cell = Cell::Undetermined;
            evidence.reason = HealthReason::Stale;
        }
        ObservationVerdict::Satisfied => {
            evidence.cell = Cell::Verified;
            evidence.reason = HealthReason::Satisfied;
        }
    }
    evidence
}

/// Collects exactly Kira's 18 private checks and eight independent corner sides.
/// Unwritten checks fail. Wrong check, context or time cannot report success, and
/// freshness is bounded by canon. No other organ's corner side is reported.
pub fn health(
    context: HealthContext,
    observer: &mut (impl HealthObserver + ?Sized),
) -> Vec<HealthEvidence> {
    PRIVATE_CHECKS
        .into_iter()
        .chain(CORNER_CHECKS)
        .map(|spec| {
            if !registered_kira_spec(spec) {
                return report(spec, context, Cell::Failed, HealthReason::InvalidEvidence);
            }
            match observer.observe(spec, context) {
                CheckObservation::Unwritten => {
                    report(spec, context, Cell::Failed, HealthReason::Unwritten)
                }
                CheckObservation::NotChecked => {
                    report(spec, context, Cell::Undetermined, HealthReason::NotChecked)
                }
                CheckObservation::Unreachable => {
                    report(spec, context, Cell::Undetermined, HealthReason::Unreachable)
                }
                CheckObservation::Measured(observation) => {
                    measured_report(spec, context, observation)
                }
            }
        })
        .collect()
}

/// Completed native probes over one verified memory snapshot. The measured
/// context comes from the snapshot; a caller's requested context is never copied.
/// This type retains verdicts, not decrypted note text or key material.
pub struct MemoryChecks {
    context: HealthContext,
    principal: crate::permissions::PermissionContext,
    transaction: Digest32,
    private: [Probe; 18],
    corners: [Probe; 8],
    summary_originals: Probe,
}

#[derive(Clone, Copy)]
enum Probe {
    Unwritten,
    NotChecked,
    Unreachable,
    Measured(ObservationVerdict),
}

impl Probe {
    fn both(self, other: Self) -> Self {
        match (self, other) {
            (
                Self::Measured(ObservationVerdict::Satisfied),
                Self::Measured(ObservationVerdict::Satisfied),
            ) => self,
            _ => match self.merge(other) {
                Self::Measured(ObservationVerdict::Satisfied) => Self::NotChecked,
                combined => combined,
            },
        }
    }

    fn from_invariant(satisfied: bool) -> Self {
        Self::Measured(if satisfied {
            ObservationVerdict::Satisfied
        } else {
            ObservationVerdict::InvariantFailed
        })
    }

    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Measured(ObservationVerdict::InvariantFailed), _)
            | (_, Self::Measured(ObservationVerdict::InvariantFailed)) => {
                Self::Measured(ObservationVerdict::InvariantFailed)
            }
            (Self::Measured(ObservationVerdict::Disagreement), _)
            | (_, Self::Measured(ObservationVerdict::Disagreement)) => {
                Self::Measured(ObservationVerdict::Disagreement)
            }
            (Self::Unreachable, _) | (_, Self::Unreachable) => Self::Unreachable,
            (_, next) => next,
        }
    }
}

impl From<crate::recall::RecallProbe> for Probe {
    fn from(value: crate::recall::RecallProbe) -> Self {
        use crate::recall::RecallProbe;
        match value {
            RecallProbe::Checked => Self::from_invariant(true),
            RecallProbe::NotChecked => Self::NotChecked,
            RecallProbe::Unreachable => Self::Unreachable,
            RecallProbe::Violation => Self::from_invariant(false),
            RecallProbe::Disagreement => Self::Measured(ObservationVerdict::Disagreement),
        }
    }
}

impl HealthObserver for MemoryChecks {
    fn observe(&mut self, spec: CheckSpec, _requested: HealthContext) -> CheckObservation {
        let probe = PRIVATE_CHECKS
            .iter()
            .position(|registered| *registered == spec)
            .map(|index| self.private[index])
            .or_else(|| {
                CORNER_CHECKS
                    .iter()
                    .position(|registered| *registered == spec)
                    .map(|index| self.corners[index])
            });
        match probe.unwrap_or(Probe::Unwritten) {
            Probe::Unwritten => CheckObservation::Unwritten,
            Probe::NotChecked => CheckObservation::NotChecked,
            Probe::Unreachable => CheckObservation::Unreachable,
            Probe::Measured(verdict) => CheckObservation::Measured(ObservedCheck {
                check: spec.check,
                context: self.context,
                expires_at_ms: self
                    .context
                    .observed_at_ms
                    .saturating_add(spec.freshness_ms),
                verdict,
            }),
        }
    }
}

impl MemoryChecks {
    /// Return the epoch and Aura coordinates actually read by these probes.
    pub const fn context(&self) -> HealthContext {
        self.context
    }

    /// Whether every decrypted summary retains its original notes. None means no
    /// summary was inspected or required plaintext was unavailable. This doctrine
    /// is separate from the registered delivered-provenance observation.
    pub fn summary_originals_preserved(&self) -> Option<bool> {
        match self.summary_originals {
            Probe::Measured(ObservationVerdict::Satisfied) => Some(true),
            Probe::Measured(_) => Some(false),
            _ => None,
        }
    }

    /// Read the authority-bound snapshot before measuring records. The ledger
    /// adapter must verify its complete signed Aura history in this transaction.
    /// A refused anchor returns no observations. A corrupt local snapshot fails
    /// the chain and anchor probes; remaining inspections stay undetermined.
    pub fn inspect<T, L, C>(
        store: &crate::anchor::SqliteMemory<'_, L>,
        transaction: &mut T,
        principal: &crate::permissions::PermissionContext,
        cell: &C,
        observed_at_ms: u64,
    ) -> canon::Result<Self>
    where
        T: canon::authority::AuthorityTxn + ?Sized,
        L: crate::anchor::MemoryLedger,
        C: crate::notes::SaveCell + ?Sized,
    {
        if observed_at_ms > canon::json::MAX_SAFE_INTEGER as u64 {
            return Err(canon::codes::KIRA_INVALID_FIELD);
        }
        let anchor = store.verified_anchor(transaction, principal)?;
        let mut observed = Self {
            context: HealthContext {
                epoch: principal.owner_epoch,
                sequence: anchor.aura_sequence,
                observed_at_ms,
                commitment: anchor.aura_hash,
            },
            principal: *principal,
            transaction: transaction.transaction_id(),
            private: [Probe::Unwritten; 18],
            corners: [Probe::Unwritten; 8],
            summary_originals: Probe::NotChecked,
        };
        for index in [0, 1, 2, 3, 4, 8, 12, 13, 17] {
            observed.private[index] = Probe::NotChecked;
        }
        for index in [0, 2, 3] {
            observed.corners[index] = Probe::NotChecked;
        }
        let snapshot = match store.snapshot(transaction, principal) {
            Ok(snapshot) => snapshot,
            Err(error) if error == canon::codes::KIRA_STORE_UNAVAILABLE => {
                for index in [0, 1, 2, 3, 4, 8, 12, 13, 17] {
                    observed.private[index] = Probe::Unreachable;
                }
                for index in [0, 2, 3] {
                    observed.corners[index] = Probe::Unreachable;
                }
                return Ok(observed);
            }
            Err(_) => {
                observed.private[3] = Probe::from_invariant(false);
                observed.private[4] = Probe::from_invariant(false);
                observed.corners[2] = Probe::from_invariant(false);
                return Ok(observed);
            }
        };
        if snapshot.anchor != anchor {
            let mismatch = Probe::Measured(ObservationVerdict::Disagreement);
            observed.private[3] = mismatch;
            observed.private[4] = mismatch;
            observed.corners[2] = mismatch;
            observed.corners[3] = mismatch;
            return Ok(observed);
        }
        for index in [0, 2, 4, 8, 12, 17] {
            observed.private[index] = Probe::from_invariant(true);
        }
        observed.corners[2] = Probe::from_invariant(true);
        let mut demoted = 0_u64;
        let mut quarantined = 0_u64;
        for (id, retained) in &snapshot.notes {
            let encrypted = &retained.encrypted;
            let wrapped = &retained.wrapped_key;
            let formats = encrypted.validate().is_ok()
                && wrapped.validate().is_ok()
                && retained.receipt.commitment.version == 1
                && retained.receipt.commitment.algorithm == AlgorithmId::Sha256;
            observed.private[17] = observed.private[17].merge(Probe::from_invariant(formats));
            let commitment = crate::notes::SaveCommitment::from_encrypted(encrypted)
                .is_ok_and(|value| value == retained.receipt.commitment);
            let citation = retained.receipt.cite_seq > 0
                && retained.receipt.cite_seq <= snapshot.anchor.aura_sequence
                && retained.receipt.anchor.owner == snapshot.anchor.owner
                && id == &encrypted.note_id;
            observed.private[2] =
                observed.private[2].merge(Probe::from_invariant(commitment && citation));
            if let Some(demotion) = &retained.demotion {
                demoted += 1;
                let valid = demotion.note_id == *id
                    && demotion.save_sequence == retained.receipt.cite_seq
                    && demotion.demoted_sequence > demotion.save_sequence
                    && demotion.demoted_sequence <= snapshot.anchor.aura_sequence
                    && demotion.demoted_at_ms <= canon::json::MAX_SAFE_INTEGER as u64
                    && demotion.head.validate().is_ok();
                observed.private[8] = observed.private[8].merge(Probe::from_invariant(valid));
            }
            quarantined += u64::from(retained.quarantined);
            let active = retained.demotion.is_none() && !retained.quarantined;
            if active {
                let bound = formats
                    && wrapped.root_epoch == principal.owner_epoch
                    && wrapped.key_id == encrypted.key_id;
                // The transaction exposes no AUMLOK root epoch to confirm a match.
                if !bound {
                    observed.private[1] = Probe::from_invariant(false);
                }
            }
            match store.decrypt(retained) {
                Ok(payload) => {
                    if let crate::notes::NoteForm::Summary { originals } = &payload.form {
                        for original in originals {
                            let preserved = match snapshot.notes.get(original) {
                                Some(note) if original != id => match store.decrypt(note) {
                                    Ok(original) => Probe::from_invariant(matches!(
                                        original.form,
                                        crate::notes::NoteForm::Original
                                    )),
                                    Err(error) if error == canon::codes::KIRA_STORE_UNAVAILABLE => {
                                        Probe::Unreachable
                                    }
                                    Err(_) => Probe::from_invariant(false),
                                },
                                _ => Probe::from_invariant(false),
                            };
                            observed.summary_originals =
                                observed.summary_originals.merge(preserved);
                        }
                    }
                    observed.private[2] = observed.private[2].merge(Probe::from_invariant(
                        payload.content.category() == retained.category
                            && payload.at_ms == retained.at_ms
                            && payload.root_epoch == encrypted.root_epoch,
                    ));
                    let replay = match cell.replay(&payload.content) {
                        Ok(replayed) => Probe::from_invariant(replayed == retained.cell),
                        Err(error) if error == canon::codes::KIRA_STORE_UNAVAILABLE => {
                            Probe::Unreachable
                        }
                        Err(_) => Probe::from_invariant(false),
                    };
                    observed.private[12] = observed.private[12].merge(replay);
                }
                Err(error) => {
                    let failure = if error == canon::codes::KIRA_STORE_UNAVAILABLE {
                        Probe::Unreachable
                    } else {
                        Probe::from_invariant(false)
                    };
                    for index in [0, 2, 12] {
                        observed.private[index] = observed.private[index].merge(failure);
                    }
                    observed.summary_originals = observed.summary_originals.merge(failure);
                    if active {
                        observed.private[1] = observed.private[1].merge(failure);
                    }
                }
            }
        }
        observed.corners[3] = Probe::from_invariant(
            snapshot.anchor.counts.saved == snapshot.notes.len() as u64
                && snapshot.anchor.counts.demoted == demoted
                && snapshot.anchor.counts.quarantined == quarantined,
        );
        Ok(observed)
    }
}

/// Native permission, listing and recall probes over the supplied scopes.
/// These scopes do not establish completeness of the permission history.
pub struct PermissionChecks {
    checks: MemoryChecks,
    listing: Probe,
    disclosure: Option<crate::permissions::PermissionReceipt>,
    may_disclose: Option<bool>,
}

impl HealthObserver for PermissionChecks {
    fn observe(&mut self, spec: CheckSpec, requested: HealthContext) -> CheckObservation {
        self.checks.observe(spec, requested)
    }
}

impl MemoryChecks {
    /// Combine measurements only for the same principal, transaction and Aura context.
    pub fn with_permissions(mut self, permissions: PermissionChecks) -> canon::Result<Self> {
        if self.context != permissions.checks.context
            || self.principal != permissions.checks.principal
            || self.transaction != permissions.checks.transaction
        {
            return Err(canon::codes::KIRA_LEDGER_UNVERIFIED);
        }
        for index in [5, 6, 7, 9, 13, 14, 15, 16] {
            self.private[index] = permissions.checks.private[index];
        }
        self.corners[1] = permissions.checks.corners[1];
        Ok(self)
    }
}

impl PermissionChecks {
    /// Complete the read probes with the actual recall service and its index and
    /// embedder. Plaintext, provenance and receipts are compared with this same
    /// locked snapshot; no receipt or health verdict authorizes a later read.
    pub fn with_recall<T, L>(
        mut self,
        store: &mut crate::anchor::SqliteMemory<'_, L>,
        transaction: &mut T,
        principal: &crate::permissions::PermissionContext,
        request_id: &canon::frame::FrameId,
        request: &canon::fd3_payloads::MemoryRecall,
        index: &mut dyn crate::openviking::OpenViking,
        embedder: &mut dyn crate::embed::LocalEmbedder,
    ) -> canon::Result<Self>
    where
        T: canon::authority::AuthorityTxn + ?Sized,
        L: crate::anchor::MemoryLedger,
    {
        if self.checks.principal != *principal
            || self.checks.transaction != transaction.transaction_id()
        {
            return Err(canon::codes::KIRA_LEDGER_UNVERIFIED);
        }
        let snapshot = store.snapshot(transaction, principal)?;
        if self.checks.context.epoch != principal.owner_epoch
            || self.checks.context.sequence != snapshot.anchor.aura_sequence
            || self.checks.context.commitment != snapshot.anchor.aura_hash
        {
            return Err(canon::codes::KIRA_LEDGER_UNVERIFIED);
        }
        let recalled = crate::recall::inspect_recall(
            store,
            transaction,
            principal,
            &snapshot,
            self.disclosure.as_ref(),
            self.may_disclose,
            request_id,
            request,
            index,
            embedder,
        );
        let permission = Probe::from(recalled.permissions);
        let citations = Probe::from(recalled.citations).both(permission);
        self.checks.private[5] = self.checks.private[5].merge(self.listing.both(citations));
        self.checks.private[6] = self.checks.private[6].merge(citations);
        self.checks.private[13] = self.checks.private[13].merge(recalled.provenance.into());
        self.checks.private[16] = self.checks.private[16].merge(recalled.receipt.into());
        if store.verified_anchor(transaction, principal)? != snapshot.anchor {
            for position in [5, 6, 13, 16] {
                self.checks.private[position] = Probe::Measured(ObservationVerdict::Disagreement);
            }
        }
        Ok(self)
    }

    /// Invoke the native permission reader and both listing tiers in the locked
    /// snapshot. Recall-dependent checks remain NotChecked until `with_recall`.
    /// This does not authorize, append, or change any permission.
    pub fn inspect<T, L>(
        store: &mut crate::anchor::SqliteMemory<'_, L>,
        transaction: &mut T,
        principal: &crate::permissions::PermissionContext,
        scopes: &[crate::permissions::PermissionRequest],
        observed_at_ms: u64,
    ) -> canon::Result<Self>
    where
        T: canon::authority::AuthorityTxn + ?Sized,
        L: crate::anchor::MemoryLedger,
    {
        use crate::permissions::{
            LedgerPermissions, Permission, PermissionAction, PermissionRequest, PermissionScope,
        };
        use canon::fd3_payloads::MemoryTier;
        if observed_at_ms > canon::json::MAX_SAFE_INTEGER as u64 || scopes.len() > 100 {
            return Err(canon::codes::KIRA_INVALID_FIELD);
        }
        let snapshot = store.snapshot(transaction, principal)?;
        let mut checks = MemoryChecks {
            context: HealthContext {
                epoch: principal.owner_epoch,
                sequence: snapshot.anchor.aura_sequence,
                observed_at_ms,
                commitment: snapshot.anchor.aura_hash,
            },
            principal: *principal,
            transaction: transaction.transaction_id(),
            private: [Probe::Unwritten; 18],
            corners: [Probe::Unwritten; 8],
            summary_originals: Probe::NotChecked,
        };
        for index in [5, 6, 7, 9, 13, 14, 15, 16] {
            checks.private[index] = Probe::NotChecked;
        }
        checks.corners[1] = Probe::NotChecked;
        let disclosure = PermissionRequest {
            permission: Permission::Disclose,
            scope: PermissionScope::hosted_model_context(),
        };
        let permissions = LedgerPermissions;
        let mut may_disclose = None;
        let mut disclosure_receipt = None;
        for request in std::iter::once(&disclosure).chain(scopes.iter()) {
            match permissions.inspect(transaction, principal, request) {
                Ok(Some(receipt)) => {
                    let cited = receipt.change.context.owner_subject == principal.owner_subject
                        && receipt.change.context.current_principal == principal.current_principal
                        && receipt.change.request == *request
                        && receipt.record.authority.sequence > 0
                        && receipt.record.authority.sequence <= snapshot.anchor.aura_sequence;
                    let epoch = receipt.record.authority.epoch
                        == receipt.change.context.owner_epoch
                        && receipt.record.authority.epoch <= principal.owner_epoch;
                    let row = Probe::from_invariant(cited && epoch);
                    checks.private[9] = checks.private[9].merge(row);
                    // Latest-row metadata exposes neither historical epochs nor
                    // an independently checked AUMLOK owner-signature result.
                    if !epoch {
                        checks.private[14] = Probe::from_invariant(false);
                    }
                    if !cited {
                        checks.corners[1] = Probe::from_invariant(false);
                    }
                    if !cited || !epoch {
                        checks.private[5] = Probe::from_invariant(false);
                    }
                    if request == &disclosure {
                        let current = cited
                            && epoch
                            && receipt.change.action == PermissionAction::Grant
                            && receipt.change.context.owner_epoch == principal.owner_epoch;
                        may_disclose = Some(current);
                        disclosure_receipt = current.then_some(receipt);
                    }
                }
                Ok(None) => {
                    if request == &disclosure {
                        may_disclose = Some(false);
                    }
                }
                Err(error) => {
                    let failure = if error == canon::codes::KIRA_STORE_UNAVAILABLE {
                        Probe::Unreachable
                    } else {
                        Probe::from_invariant(false)
                    };
                    for index in [5, 9, 14] {
                        checks.private[index] = checks.private[index].merge(failure);
                    }
                    checks.corners[1] = checks.corners[1].merge(failure);
                }
            }
        }
        let remembered = if may_disclose == Some(false) {
            use crate::recall::MemoryRecallService;
            let anchors = crate::anchor::SqliteMemory::new(store.sql, store.ledger, store.keys);
            match store.list(
                transaction,
                &mut LedgerPermissions,
                &anchors,
                principal,
                &canon::fd3_payloads::MemoryList {
                    tier: MemoryTier::Remembered,
                    before: None,
                },
            ) {
                Ok(_) => PageObservation::Violation,
                Err(error) => PageObservation::Refused(error),
            }
        } else {
            inspect_pages(
                store,
                transaction,
                principal,
                &snapshot,
                MemoryTier::Remembered,
            )
        };
        let permission_probe = match (may_disclose, remembered) {
            (Some(true), PageObservation::Checked) => Probe::from_invariant(true),
            (Some(false), PageObservation::Refused(error))
                if error == canon::codes::KIRA_DISCLOSURE_NOT_PERMITTED =>
            {
                Probe::from_invariant(true)
            }
            (Some(false), PageObservation::Checked) | (_, PageObservation::Violation) => {
                Probe::from_invariant(false)
            }
            (Some(true), PageObservation::Refused(error))
                if error == canon::codes::KIRA_DISCLOSURE_NOT_PERMITTED =>
            {
                Probe::Measured(ObservationVerdict::Disagreement)
            }
            (_, PageObservation::Refused(error))
                if error == canon::codes::KIRA_STORE_UNAVAILABLE =>
            {
                Probe::Unreachable
            }
            _ => Probe::NotChecked,
        };
        let listing = checks.private[5].merge(permission_probe);
        checks.private[5] = match listing {
            Probe::Measured(ObservationVerdict::Satisfied) => Probe::NotChecked,
            other => other,
        };
        let forgotten = inspect_pages(
            store,
            transaction,
            principal,
            &snapshot,
            MemoryTier::Forgotten,
        );
        checks.private[7] = page_probe(forgotten);
        checks.private[15] = match (remembered, forgotten) {
            (PageObservation::Refused(error), right)
                if error == canon::codes::KIRA_DISCLOSURE_NOT_PERMITTED =>
            {
                page_probe(right)
            }
            (PageObservation::Checked, PageObservation::Checked) => Probe::from_invariant(true),
            (PageObservation::Violation, _) | (_, PageObservation::Violation) => {
                Probe::from_invariant(false)
            }
            (PageObservation::Refused(error), _) | (_, PageObservation::Refused(error))
                if error == canon::codes::KIRA_STORE_UNAVAILABLE =>
            {
                Probe::Unreachable
            }
            _ => Probe::NotChecked,
        };
        if store.verified_anchor(transaction, principal)? != snapshot.anchor {
            for index in [5, 6, 7, 9, 13, 14, 15, 16] {
                checks.private[index] = Probe::Measured(ObservationVerdict::Disagreement);
            }
            checks.corners[1] = Probe::Measured(ObservationVerdict::Disagreement);
        }
        Ok(Self {
            checks,
            listing,
            disclosure: disclosure_receipt,
            may_disclose,
        })
    }
}

#[derive(Clone, Copy)]
enum PageObservation {
    Checked,
    Refused(canon::Refusal),
    Violation,
}

fn page_probe(observed: PageObservation) -> Probe {
    match observed {
        PageObservation::Checked => Probe::from_invariant(true),
        PageObservation::Refused(error) if error == canon::codes::KIRA_STORE_UNAVAILABLE => {
            Probe::Unreachable
        }
        PageObservation::Refused(_) => Probe::NotChecked,
        PageObservation::Violation => Probe::from_invariant(false),
    }
}

fn inspect_pages<T, L>(
    store: &mut crate::anchor::SqliteMemory<'_, L>,
    transaction: &mut T,
    principal: &crate::permissions::PermissionContext,
    snapshot: &crate::anchor::MemorySnapshot,
    tier: canon::fd3_payloads::MemoryTier,
) -> PageObservation
where
    T: canon::authority::AuthorityTxn + ?Sized,
    L: crate::anchor::MemoryLedger,
{
    use crate::recall::MemoryRecallService;
    use canon::fd3_payloads::{MemoryList, MemoryTier};
    let mut permissions = crate::permissions::LedgerPermissions;
    let anchors = crate::anchor::SqliteMemory::new(store.sql, store.ledger, store.keys);
    let expected: std::collections::BTreeSet<_> = snapshot
        .notes
        .iter()
        .filter(|(_, note)| match tier {
            MemoryTier::Remembered => note.demotion.is_none() && !note.quarantined,
            MemoryTier::Forgotten => note.demotion.is_some(),
        })
        .map(|(id, _)| id.clone())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut before = None;
    let mut previous_sequence = u64::MAX;
    loop {
        let reply = match store.list(
            transaction,
            &mut permissions,
            &anchors,
            principal,
            &MemoryList {
                tier,
                before: before.clone(),
            },
        ) {
            Ok(reply) => reply,
            Err(error) => return PageObservation::Refused(error),
        };
        if reply.tier != tier
            || reply.items.len() > crate::recall::MAX_RECALL_ITEMS
            || crate::recall::list_frame(&reply)
                .map_or(true, |bytes| bytes.len() > canon::frame::MAX_FRAME_BYTES)
        {
            return PageObservation::Violation;
        }
        for item in &reply.items {
            let Some(note) = snapshot.notes.get(&item.note_id) else {
                return PageObservation::Violation;
            };
            if !expected.contains(&item.note_id)
                || !seen.insert(item.note_id.clone())
                || item.cite_seq != note.receipt.cite_seq
                || item.cite_seq >= previous_sequence
                || item.at != note.at_ms
                || item.category != note.category
            {
                return PageObservation::Violation;
            }
            previous_sequence = item.cite_seq;
            let valid = match tier {
                MemoryTier::Remembered => {
                    let payload = match store.decrypt(note) {
                        Ok(payload) => payload,
                        Err(error) => return PageObservation::Refused(error),
                    };
                    item.text.as_deref() == Some(payload.content.statement())
                        && item.demoted_seq.is_none()
                        && item.demoted_at.is_none()
                }
                MemoryTier::Forgotten => note.demotion.as_ref().is_some_and(|demotion| {
                    item.text.is_none()
                        && item.demoted_seq == Some(demotion.demoted_sequence)
                        && item.demoted_at == Some(demotion.demoted_at_ms)
                        && demotion.demoted_sequence > item.cite_seq
                }),
            };
            if !valid {
                return PageObservation::Violation;
            }
        }
        match reply.next {
            None => {
                return if seen == expected {
                    PageObservation::Checked
                } else {
                    PageObservation::Violation
                }
            }
            Some(next) => {
                if reply.items.last().map(|item| &item.note_id) != Some(&next)
                    || before.as_ref() == Some(&next)
                    || seen.len() >= expected.len()
                {
                    return PageObservation::Violation;
                }
                before = Some(next);
            }
        }
    }
}
