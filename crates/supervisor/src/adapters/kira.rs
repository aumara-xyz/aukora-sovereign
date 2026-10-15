// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scoped Kira reads distinguish verified absence from unavailable retained storage.

use super::HostLedger;
use canon::{
    authority::Kind,
    codes,
    fd3_payloads::{Accepted, MemoryList, MemoryListReply, MemoryPut, MemoryRecall, Outcome, Recall},
    frame::FrameId,
    ids::ProposalId,
    Result,
};
use kira::{
    embed::{EmbedInput, EmbedPurpose},
    notes::{NoteContent, SaveCell},
    permissions::{
        LedgerPermissions, MemoryPermissions, Permission, PermissionContext, PermissionRequest,
        PermissionScope,
    },
    recall::{CitedRecall, MAX_RECALL_ITEMS},
};
use std::sync::Arc;
use supervisor::{
    ingress::PrincipalScope,
    services::{KiraService, ServiceFuture},
};

pub struct KiraAdapter {
    ledger: Arc<HostLedger>,
    cell: MemoryCell,
}

impl KiraAdapter {
    pub fn new(ledger: Arc<HostLedger>) -> Result<Self> {
        Ok(Self {
            ledger,
            cell: MemoryCell(wasmcell::Runner::new()?),
        })
    }
}

impl KiraService for KiraAdapter {
    fn put<'a>(
        &'a self,
        scope: PrincipalScope,
        _: &'a FrameId,
        request: MemoryPut,
    ) -> ServiceFuture<'a, Accepted> {
        Box::pin(async move {
            self.ledger.scoped(scope, |transaction| {
                let content = NoteContent::new(request.category, request.statement, request.quote)?;
                if self.cell.replay(&content)? != request.cell {
                    return Err(codes::WASMCELL_EVIDENCE_MISMATCH);
                }
                LedgerPermissions.require(
                    transaction,
                    &context(scope),
                    &PermissionRequest {
                        permission: Permission::Store,
                        scope: PermissionScope::local_memory(),
                    },
                )?;
                // No acknowledgement precedes an atomic Kira save and its Aura citation.
                Err(codes::KIRA_STORE_UNAVAILABLE)
            })
        })
    }

    fn recall(&self, scope: PrincipalScope, request: MemoryRecall) -> ServiceFuture<'_, Recall> {
        Box::pin(async move {
            self.ledger.scoped(scope, |transaction| {
                if request.limit == 0 || usize::from(request.limit) > MAX_RECALL_ITEMS {
                    return Err(codes::KIRA_INVALID_FIELD);
                }
                EmbedInput::new(EmbedPurpose::Query, &request.query)
                    .map_err(|_| codes::KIRA_INVALID_FIELD)?;
                disclose(transaction, scope)?;
                require_no_retained_notes(transaction)?;
                Ok(CitedRecall::empty().c4_body())
            })
        })
    }

    fn list(
        &self,
        scope: PrincipalScope,
        request: MemoryList,
    ) -> ServiceFuture<'_, MemoryListReply> {
        Box::pin(async move {
            self.ledger.scoped(scope, |transaction| {
                disclose(transaction, scope)?;
                require_no_retained_notes(transaction)?;
                if request.before.is_some() {
                    return Err(codes::KIRA_INVALID_FIELD);
                }
                Ok(MemoryListReply {
                    tier: request.tier,
                    items: Vec::new(),
                    next: None,
                })
            })
        })
    }

    fn outcome(&self, scope: PrincipalScope, _: ProposalId) -> ServiceFuture<'_, Option<Outcome>> {
        Box::pin(async move {
            self.ledger.scoped(scope, |transaction| {
                disclose(transaction, scope)?;
                require_no_retained_notes(transaction)?;
                Ok(None)
            })
        })
    }
}

fn context(scope: PrincipalScope) -> PermissionContext {
    PermissionContext {
        owner_subject: scope.subject,
        current_principal: scope.subject,
        owner_epoch: scope.epoch,
    }
}

fn disclose(transaction: &mut aura::LedgerTxn<'_>, scope: PrincipalScope) -> Result<()> {
    LedgerPermissions
        .require(
            transaction,
            &context(scope),
            &PermissionRequest {
                permission: Permission::Disclose,
                scope: PermissionScope::hosted_model_context(),
            },
        )
        .map(|_| ())
}

fn require_no_retained_notes(transaction: &aura::LedgerTxn<'_>) -> Result<()> {
    if !transaction.kira_retention_tables_empty()? {
        return Err(codes::KIRA_STORE_UNAVAILABLE);
    }
    let version = transaction.current_version()?;
    let mut previous = None;
    for sequence in 1..version.sequence {
        let record = transaction
            .floor_record_at_sequence(sequence)?
            .ok_or(codes::KIRA_LEDGER_UNVERIFIED)?;
        if record.authority.previous_hash != previous {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        previous = Some(record.hash);
        if matches!(record.kind, Kind::KiraSave | Kind::KiraDemote) {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
    }
    if previous != version.previous_hash {
        return Err(codes::KIRA_LEDGER_UNVERIFIED);
    }
    Ok(())
}

struct MemoryCell(wasmcell::Runner);
impl SaveCell for MemoryCell {
    fn replay(&self, content: &NoteContent) -> Result<canon::authority::CellCommitment> {
        let bytes = content.canonical_value()?;
        let input = wasmcell::CellInput::new(
            wasmcell::CellKey::new(format!(
                "memory:{}",
                canon::digest::Digest32::sha256(&bytes)
            ))?,
            canon::json::parse_strict(&bytes)?,
        )?;
        Ok(self.0.run(&input)?.commitments())
    }
}
