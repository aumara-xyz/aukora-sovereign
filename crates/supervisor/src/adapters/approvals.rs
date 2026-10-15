// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bound-browser approval notifications read gate's recorded proposal data.

use super::HostLedger;
use canon::{codes, ids::ProposalId, session::Items, Result};
use frontdoor::{
    approvals::{ApprovalService, PendingApproval, PendingPage, MAX_PENDING},
    session::BoundSession,
};
use std::sync::Arc;
use supervisor::ingress::PrincipalScope;

const MAX_SCAN: usize = 10_000;

pub struct ApprovalAdapter {
    ledger: Arc<HostLedger>,
}
impl ApprovalAdapter {
    pub fn new(ledger: Arc<HostLedger>) -> Self {
        Self { ledger }
    }
}
impl ApprovalService for ApprovalAdapter {
    fn pending(
        &mut self,
        session: &BoundSession<'_>,
        after: Option<ProposalId>,
    ) -> Result<PendingPage> {
        let record = session.record();
        let scope = PrincipalScope {
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
        };
        self.ledger.scoped(scope, |txn| {
            let sequence = txn
                .current_version()?
                .sequence
                .checked_sub(1)
                .ok_or(codes::SUPERVISOR_STATE)?;
            if sequence > canon::json::MAX_SAFE_INTEGER as u64 {
                return Err(codes::SUPERVISOR_STATE);
            }
            let mut proposals = txn.pending_proposals(MAX_SCAN + 1)?;
            if proposals.len() > MAX_SCAN {
                return Err(canon::Refusal {
                    organ: "supervisor",
                    reason: "approval-limit",
                });
            }
            proposals.retain(|proposal| {
                proposal.authority.epoch == scope.epoch
                    && after.is_none_or(|cursor| proposal.proposal > cursor)
            });
            proposals.sort_by_key(|proposal| proposal.proposal);
            let more = proposals.len() > MAX_PENDING;
            let mut page = Vec::with_capacity(MAX_PENDING.min(proposals.len()));
            for stored in proposals.into_iter().take(MAX_PENDING) {
                let proposal = gate::service::read_proposal(txn, stored.proposal)?;
                if proposal.authority.epoch != scope.epoch
                    || proposal.state != gate::proposal::ProposalState::Pending
                {
                    return Err(codes::SUPERVISOR_STATE);
                }
                let expires_at_ms =
                    u64::try_from(proposal.expires_at_ms).map_err(|_| codes::SUPERVISOR_STATE)?;
                page.push(PendingApproval {
                    proposal: proposal.id,
                    expires_at_ms,
                });
            }
            let next = if more {
                Some(page.last().ok_or(codes::SUPERVISOR_STATE)?.proposal)
            } else {
                None
            };
            Ok(PendingPage {
                sequence,
                proposals: Items::new(page)?,
                next,
            })
        })
    }
}
