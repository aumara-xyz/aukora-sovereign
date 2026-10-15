// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host-provisioned claim consumption is an AUMLOK transaction, never a frontdoor grant.

use crate::{session::SessionRecord, tls::Origin};
use canon::{
    codes,
    digest::Digest32,
    ids::NodeId,
    json::{self, Value, ValueView},
    Result,
};

pub const MAX_CLAIM_TOKEN_BYTES: usize = 512;

/// A claim candidate is untrusted until the durable AUMLOK consume operation succeeds.
pub struct ClaimRequest {
    pub node: NodeId,
    pub token: Vec<u8>,
    pub session_digest: Digest32,
    pub session_origin: Origin,
    pub expires_at_ms: u64,
}

/// Implemented by the supervisor's AUMLOK adapter, using spawn's host-side commitment.
pub trait ClaimService {
    /// Atomic single-use consume plus binding-only session insert; fsync before cookie issuance.
    /// Never accept a secret provisioned in the request or reopen the claim after restart.
    /// Pinned failures: aumlok:claim-unknown and aumlok:claim-spent.
    fn consume_and_create_session(&mut self, request: ClaimRequest) -> Result<SessionRecord>;
}

/// Parses the pinned `/api/claim` body `{token}`. No alternate field names or default token.
pub fn decode_claim(body: &Value) -> Result<Vec<u8>> {
    let ValueView::Object(fields) = body.view() else {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    };
    if fields.len() != 1 || fields[0].0 != "token" {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    }
    let ValueView::Text(token) = fields[0].1.view() else {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    };
    if token.is_empty() || token.len() > MAX_CLAIM_TOKEN_BYTES {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    }
    Ok(token.as_bytes().to_vec())
}

#[derive(Clone, Copy, Debug)]
pub struct ClaimFacts {
    pub host_commitment_present: bool,
    pub durable_claim_consumed: bool,
}

/// The durable consume has completed before this response can exist.
pub struct ClaimResponse {
    session: SessionRecord,
    set_cookie: String,
}

impl ClaimResponse {
    pub fn session(&self) -> &SessionRecord {
        &self.session
    }

    pub fn set_cookie(&self) -> &str {
        &self.set_cookie
    }

    pub fn into_http_response(self) -> Result<http::Response<Vec<u8>>> {
        http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::CACHE_CONTROL, "no-store")
            .header(http::header::SET_COOKIE, self.set_cookie)
            .header("x-content-type-options", "nosniff")
            .header("referrer-policy", "no-referrer")
            .body(br#"{"ok":true,"state":"claim-open"}"#.to_vec())
            .map_err(|_| codes::FRONTDOOR_BODY_INVALID)
    }
}

/// The node and clock come from the host. The browser supplies only the claim candidate.
pub fn consume_claim(
    service: &mut impl ClaimService,
    request: &crate::ingress::AdmittedRequest,
    node: NodeId,
    now_ms: u64,
) -> Result<ClaimResponse> {
    consume_claim_with_lifetime(
        service,
        request,
        node,
        now_ms,
        crate::session::MAX_LIFETIME_MS,
    )
}

pub fn consume_claim_with_lifetime(
    service: &mut impl ClaimService,
    request: &crate::ingress::AdmittedRequest,
    node: NodeId,
    now_ms: u64,
    lifetime_ms: u64,
) -> Result<ClaimResponse> {
    use crate::{
        owner_origin::OwnerRoute,
        session::{SessionBearer, SessionScope, MAX_LIFETIME_MS},
    };
    if OwnerRoute::resolve(request.role(), request.method(), request.path())? != OwnerRoute::Claim {
        return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
    }
    if !(1000..=MAX_LIFETIME_MS).contains(&lifetime_ms) {
        return Err(codes::FRONTDOOR_SESSION_REQUIRED);
    }
    let token = decode_claim(request.body())?;
    let bearer = SessionBearer::generate()?;
    let digest = bearer.digest();
    let expires = now_ms
        .checked_add(lifetime_ms)
        .filter(|time| *time <= json::MAX_SAFE_INTEGER as u64)
        .ok_or(codes::FRONTDOOR_BODY_INVALID)?;
    let session = service.consume_and_create_session(ClaimRequest {
        node,
        token,
        session_digest: digest,
        session_origin: request.origin().clone(),
        expires_at_ms: expires,
    })?;
    if session.token_digest != digest
        || session.node != node
        || &session.origin != request.origin()
        || session.subject.is_some()
        || session.scope != SessionScope::BindingOnly
        || session.expires_at_ms != expires
        || session.revoked
    {
        return Err(codes::FRONTDOOR_SESSION_REQUIRED);
    }
    let set_cookie = bearer.cookie_header(SessionScope::BindingOnly, expires, now_ms)?;
    Ok(ClaimResponse {
        session,
        set_cookie,
    })
}
