// SPDX-License-Identifier: AGPL-3.0-or-later
//! Installed release approvals use metadata registered by the verified release source.

use super::HostLedger;
use canon::{authority::OwnerAssertion, codes, ids::ProposalId, Result};
use supervisor::ingress::PrincipalScope;

impl HostLedger {
    pub(crate) fn configure_release_approval(
        &self,
        context: crate::release::ReleaseApproval,
    ) -> Result<()> {
        let mut current = self
            .release_approval
            .lock()
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        if current.is_some() {
            return Err(codes::SUPERVISOR_STATE);
        }
        *current = Some(context);
        Ok(())
    }

    pub(crate) fn ensure_release_proposal(&self, scope: PrincipalScope) -> Result<()> {
        self.release_approval_context()?.ensure_proposal(self, scope)
    }

    pub(crate) fn approve_release(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        assertion: OwnerAssertion,
    ) -> Result<gate::service::Outcome> {
        self.release_approval_context()?
            .approve(self, scope, proposal, assertion)
    }

    fn release_approval_context(&self) -> Result<crate::release::ReleaseApproval> {
        self.release_approval
            .lock()
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?
            .clone()
            .ok_or(codes::SUPERVISOR_NOT_READY)
    }
}
