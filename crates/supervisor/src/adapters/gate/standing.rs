// SPDX-License-Identifier: AGPL-3.0-or-later
//! The door's standing grants as a gate target (`door/standing-grants.json`, critical): proposed by the node's starter
//! keeper (`door/starter.rs`), approved by the owner's passkey on the generic content card, read back by the door's
//! slider only as the applied, digest-checked bytes. The guest's own `propose` refuses `door/` targets.

use super::GateAdapter;
use canon::{codes, ids::ProposalId};
use supervisor::ingress::PrincipalScope;
use supervisor::services::ServiceFuture;

impl GateAdapter {
    /// Open the owner's review of a standing grant set. Bytes `laya::GrantSet::parse` refuses never become a proposal.
    pub fn propose_standing_grants(&self, scope: PrincipalScope, note: String, set: Vec<u8>) -> ServiceFuture<'_, ProposalId> {
        if laya::GrantSet::parse(&set).is_err() {
            return Box::pin(async { Err(codes::GATE_UNKNOWN_TARGET) });
        }
        self.propose_reserved(scope, laya::grant::GRANT_TARGET.to_owned(), note, set)
    }
}
