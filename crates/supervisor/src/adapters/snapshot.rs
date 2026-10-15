// SPDX-License-Identifier: AGPL-3.0-or-later
//! Public observations use verified records and owning-organ counters only.

use super::HostLedger;
use canon::{
    authority::Kind,
    codes,
    digest::Digest32,
    fd3_payloads::{
        AumlokStatus, AuraSource, AuraSourceName, AuraStatus, KiraStatus, NostrStatus, OrgansReply,
        SourceAbsence, StatusReply, WasmStatus,
    },
    Result,
};
use std::sync::Arc;
use supervisor::{
    ingress::BindingState,
    services::{ServiceFuture, SnapshotService},
};

pub struct PublicCounters {
    pub aumlok: AumlokStatus,
    pub kira: KiraStatus,
    pub nostr: NostrStatus,
}
pub struct ActiveGrant {
    pub id: String,
    pub remaining: u64,
}

/// A source must read each owning organ in the supplied locked authority snapshot.
pub trait PublicSnapshots: Send + Sync {
    fn counters(&self, transaction: &mut aura::LedgerTxn<'_>) -> Result<PublicCounters>;
    fn active_grant(&self, transaction: &mut aura::LedgerTxn<'_>) -> Result<Option<ActiveGrant>>;
    fn ready(&self) -> bool;
}

/// No missing counter is represented as a fabricated zero or empty identity.
pub struct UnavailablePublicSnapshots;
impl PublicSnapshots for UnavailablePublicSnapshots {
    fn counters(&self, _: &mut aura::LedgerTxn<'_>) -> Result<PublicCounters> {
        Err(codes::SUPERVISOR_NOT_READY)
    }
    fn active_grant(&self, _: &mut aura::LedgerTxn<'_>) -> Result<Option<ActiveGrant>> {
        Err(codes::SUPERVISOR_NOT_READY)
    }
    fn ready(&self) -> bool {
        false
    }
}

pub struct SnapshotAdapter {
    ledger: Arc<HostLedger>,
    public: Arc<dyn PublicSnapshots>,
    module: Digest32,
    owner_origin: String,
}
impl SnapshotAdapter {
    pub fn new(
        ledger: Arc<HostLedger>,
        public: Arc<dyn PublicSnapshots>,
        module: Digest32,
        owner_origin: String,
    ) -> Result<Self> {
        frontdoor::tls::Origin::parse(&owner_origin)?;
        Ok(Self {
            ledger,
            public,
            module,
            owner_origin,
        })
    }
}
impl SnapshotService for SnapshotAdapter {
    fn status(&self) -> ServiceFuture<'_, StatusReply> {
        Box::pin(async {
            let bound = matches!(self.ledger.binding()?, BindingState::Bound(_));
            let grant = self
                .ledger
                .transaction(|txn| self.public.active_grant(txn))?;
            Ok(StatusReply {
                ready: bound && self.public.ready(),
                bound,
                grant_id: grant.as_ref().map(|grant| grant.id.clone()),
                grant_remaining: grant.map(|grant| grant.remaining),
            })
        })
    }
    fn organs(&self) -> ServiceFuture<'_, OrgansReply> {
        Box::pin(async {
            self.ledger.transaction(|txn| {
                let counters = self.public.counters(txn)?;
                let context = txn.current_version()?;
                let sequence = context
                    .sequence
                    .checked_sub(1)
                    .ok_or(codes::AURA_UNVERIFIED)?;
                if sequence > 65_536 {
                    return Err(codes::SUPERVISOR_NOT_READY);
                }
                let mut sources = [
                    empty(AuraSourceName::GateLedger, SourceAbsence::GateLedgerEmpty),
                    empty(AuraSourceName::KiraChain, SourceAbsence::KiraLedgerEmpty),
                    empty(AuraSourceName::CodeChain, SourceAbsence::CodeRecordMissing),
                ];
                let mut tree = aura::merkle::Frontier::default();
                let mut previous = None;
                for index in 1..=sequence {
                    let record = txn
                        .floor_record_at_sequence(index)?
                        .ok_or(codes::AURA_UNVERIFIED)?;
                    if record.authority.previous_hash != previous {
                        return Err(codes::AURA_UNVERIFIED);
                    }
                    previous = Some(record.hash);
                    tree.push(record.hash)?;
                    let source = match record.kind {
                        Kind::GatePropose
                        | Kind::GateReview
                        | Kind::GateConsume
                        | Kind::GateApply
                        | Kind::GateRetire
                        | Kind::GateRefuse
                        | Kind::GateExpire
                        | Kind::GateRecover => Some(0),
                        Kind::KiraSave | Kind::KiraDemote | Kind::KiraPermission => Some(1),
                        Kind::FloorAdvance => Some(2),
                        _ => None,
                    };
                    if let Some(index) = source {
                        let source = &mut sources[index];
                        source.entries += 1;
                        source.head = Some(record.hash);
                        source.absence = None;
                    }
                }
                if previous != context.previous_hash {
                    return Err(codes::AURA_UNVERIFIED);
                }
                let pending = txn.pending_proposals(10_001)?;
                if pending.len() > 10_000 {
                    return Err(codes::SUPERVISOR_NOT_READY);
                }
                Ok(OrgansReply {
                    approvals_pending: pending.len() as u64,
                    aumlok: counters.aumlok,
                    kira: counters.kira,
                    nostr: counters.nostr,
                    aura: AuraStatus {
                        sequence,
                        root: tree.root(),
                        sources,
                    },
                    wasm: WasmStatus {
                        module_sha256: self.module,
                    },
                    owner_origin: self.owner_origin.clone(),
                })
            })
        })
    }
}
fn empty(name: AuraSourceName, absence: SourceAbsence) -> AuraSource {
    AuraSource {
        name,
        head: None,
        entries: 0,
        absence: Some(absence),
    }
}
