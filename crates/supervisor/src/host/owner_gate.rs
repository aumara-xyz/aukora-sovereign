// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-session gate dispatch shares the runtime's gate and current ledger scope.

use super::Host;
use canon::{authority::AuthorityTxn, codes, json::Value, Result};
use frontdoor::{
    owner_origin::{self, GateRequest, OwnerRoute},
    session::{BoundSession, SessionScope},
};
use supervisor::{
    ingress::{BindingState, PrincipalScope},
    services::GateService,
};

impl Host {
    pub(super) fn owner_gate_request(
        &self,
        session: &BoundSession<'_>,
        route: OwnerRoute,
        body: &Value,
    ) -> Result<crate::identity::Reply> {
        let record = session.record();
        let scope = PrincipalScope {
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
        };
        if record.scope != SessionScope::OwnerFrame
            || self.ledger.binding()? != BindingState::Bound(scope)
        {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        let request = owner_origin::decode_gate_request(route, body)?;
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        let body = match request {
            GateRequest::Review { proposal, action } => {
                let review = runtime.block_on(self.gate.review(scope, proposal, action))?;
                owner_origin::encode_gate_review(
                    review.proposal_id,
                    &review.authorization,
                    &review.authorization_bytes,
                    &review.card_bytes,
                )?
            }
            GateRequest::Assertion {
                proposal,
                action,
                assertion,
            } => {
                let algorithm = self.ledger.scoped(scope, |transaction| {
                    Ok(transaction
                        .owner_binding(assertion.credential_id())?
                        .algorithm)
                })?;
                let assertion = assertion.into_owner_assertion(algorithm)?;
                let outcome = runtime.block_on(
                    self.gate
                        .owner_assertion(scope, proposal, action, assertion),
                )?;
                owner_origin::encode_gate_outcome(&outcome)?
            }
        };
        if self.ledger.binding()? != BindingState::Bound(scope) {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        Ok(crate::identity::Reply {
            body,
            transition: None,
        })
    }
}

pub(super) fn owner_gate_response(value: Value) -> Result<http::Response<Vec<u8>>> {
    let bytes = value.canonical_bytes();
    if bytes.len() > owner_origin::MAX_GATE_RESPONSE_BYTES {
        return Err(codes::FRONTDOOR_RESPONSE_TOO_LARGE);
    }
    http::Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(bytes)
        .map_err(|_| codes::SUPERVISOR_STATE)
}
