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
            GateRequest::Decline { proposal } => {
                let outcome = runtime.block_on(self.gate.decline(scope, proposal))?;
                owner_origin::encode_gate_outcome(&outcome)?
            }
            GateRequest::Again { proposal } => {
                let fresh = runtime.block_on(self.gate.again(scope, proposal))?;
                owner_origin::encode_gate_again(fresh)?
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
    let timeout = owner_gate_timeout(&value)?;
    let bytes = value.canonical_bytes();
    if bytes.len() > owner_origin::MAX_GATE_RESPONSE_BYTES {
        return Err(codes::FRONTDOOR_RESPONSE_TOO_LARGE);
    }
    http::Response::builder()
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("x-aukora-ceremony-timeout-ms", timeout.to_string())
        .body(bytes)
        .map_err(|_| codes::SUPERVISOR_STATE)
}

fn owner_gate_timeout(value: &Value) -> Result<u64> {
    use canon::json::ValueView;
    let invalid = codes::FRONTDOOR_APPROVAL_REVIEW_INVALID;
    match value.get("schema").map(Value::view) {
        Some(ValueView::Text("aukora-owner-outcome-v1" | "aukora-owner-again-v1")) => Ok(0),
        Some(ValueView::Text("aukora-owner-review-v1")) => {
            let Some(ValueView::Text(bytes)) = value.get("authorization").map(Value::view) else {
                return Err(invalid);
            };
            let authorization = canon::json::parse_strict(bytes.as_bytes()).map_err(|_| invalid)?;
            let Some(ValueView::Integer(expiry)) = authorization.get("expires_at").map(Value::view) else {
                return Err(invalid);
            };
            let expiry = u64::try_from(expiry.get()).map_err(|_| invalid)?;
            let remaining = expiry.checked_sub(super::now()?).ok_or(codes::GATE_EXPIRED)?;
            if remaining == 0 {
                return Err(codes::GATE_EXPIRED);
            }
            if remaining > 300_000 {
                return Err(invalid);
            }
            Ok(remaining)
        }
        _ => Err(invalid),
    }
}
