// SPDX-License-Identifier: AGPL-3.0-or-later
//! Missing Aura-owned memory storage refuses before reading or writing notes.

use canon::{
    codes,
    fd3_payloads::{
        Accepted, MemoryList, MemoryListReply, MemoryPut, MemoryRecall, Outcome, Recall,
    },
    frame::FrameId,
    ids::ProposalId,
};
use supervisor::{
    ingress::PrincipalScope,
    services::{KiraService, ServiceFuture},
};

pub struct UnavailableKira;
impl KiraService for UnavailableKira {
    fn put<'a>(
        &'a self,
        _: PrincipalScope,
        _: &'a FrameId,
        _: MemoryPut,
    ) -> ServiceFuture<'a, Accepted> {
        Box::pin(async { Err(codes::KIRA_STORE_UNAVAILABLE) })
    }
    fn recall(&self, _: PrincipalScope, _: MemoryRecall) -> ServiceFuture<'_, Recall> {
        Box::pin(async { Err(codes::KIRA_LEDGER_UNVERIFIED) })
    }
    fn list(&self, _: PrincipalScope, _: MemoryList) -> ServiceFuture<'_, MemoryListReply> {
        Box::pin(async { Err(codes::KIRA_LEDGER_UNVERIFIED) })
    }
    fn outcome(&self, _: PrincipalScope, _: ProposalId) -> ServiceFuture<'_, Option<Outcome>> {
        Box::pin(async { Err(codes::KIRA_LEDGER_UNVERIFIED) })
    }
}
