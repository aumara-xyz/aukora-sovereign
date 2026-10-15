// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ceremony routes exist on the owner host; no top-level owner navigation route exists.

use crate::{
    ingress::{validate_path, HostRole, Method},
    session::BoundSession,
    tls::Origin,
};
use canon::{ids::ProposalId, json::Value, Refusal, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerRoute {
    Claim,
    EnrolStart,
    EnrolFinish,
    BindingPrepare,
    BindingConfirm,
    BindingRefresh,
    BindingRefreshPrepare,
    SigninStart,
    SigninFinish,
    Approvals,
    ApprovalRetireChallenge,
}

impl OwnerRoute {
    pub fn resolve(host: HostRole, method: Method, path: &str) -> Result<Self> {
        validate_path(path)?;
        if host != HostRole::Owner {
            return Err(Refusal {
                organ: "frontdoor",
                reason: "unknown-route",
            });
        }
        match (method, path) {
            (Method::Post, "/api/claim") => Ok(Self::Claim),
            (Method::Post, "/api/enrol/start") => Ok(Self::EnrolStart),
            (Method::Post, "/api/enrol/finish") => Ok(Self::EnrolFinish),
            (Method::Post, "/api/binding/prepare") => Ok(Self::BindingPrepare),
            (Method::Post, "/api/binding/confirm") => Ok(Self::BindingConfirm),
            (Method::Post, "/api/binding/refresh") => Ok(Self::BindingRefresh),
            (Method::Post, "/api/binding/refresh/prepare") => Ok(Self::BindingRefreshPrepare),
            (Method::Post, "/api/signin/start") => Ok(Self::SigninStart),
            (Method::Post, "/api/signin/finish") => Ok(Self::SigninFinish),
            (Method::Get, "/api/approvals") => Ok(Self::Approvals),
            (Method::Post, "/api/approvals/retire/challenge") => Ok(Self::ApprovalRetireChallenge),
            _ => Err(Refusal {
                organ: "frontdoor",
                reason: "unknown-route",
            }),
        }
    }
}

/// Mandatory context passed unchanged to AUMLOK, never taken from clientDataJSON.
#[derive(Clone, Debug)]
pub struct CeremonyContext {
    pub relying_party_id: String,
    pub owner_origin: Origin,
    pub expected_top_origin: Origin,
}

/// The identity adapter supplies the verifier; frontdoor cannot verify or grant locally.
pub trait IdentityService {
    /// The verifier requires crossOrigin=true and exact topOrigin. It parses WebAuthn's
    /// clientDataJSON itself; the nested clientDataJSON bytes do not use canon's C1 parser.
    fn ceremony(
        &mut self,
        context: &CeremonyContext,
        route: OwnerRoute,
        session_digest: Option<canon::digest::Digest32>,
        body: Value,
    ) -> Result<Value>;
}

/// Exact supervisor-owned card and authorization bytes for one proposal; never shell-supplied.
#[derive(Clone, Debug)]
pub struct ReviewBytes {
    pub proposal_id: ProposalId,
    pub card: Vec<u8>,
    pub authorization: Vec<u8>,
}

pub trait OwnerReviewService {
    fn load_by_id(
        &mut self,
        session: &BoundSession<'_>,
        proposal: ProposalId,
    ) -> Result<ReviewBytes>;
}

/// The admitted owner-document navigation, distinct from a JSON API request.
pub struct FrameNavigation {
    context: CeremonyContext,
}

impl FrameNavigation {
    pub fn context(&self) -> &CeremonyContext {
        &self.context
    }
}

/// Embedded navigation contract: destination=iframe, exact shell parent, owner CSP restricted
/// to that shell; top-level document requests refuse instead of redirecting.
pub fn admit_frame_navigation(
    _context: &CeremonyContext,
    _fetch_dest: &str,
    _parent_origin: &str,
) -> Result<FrameNavigation> {
    todo!("rows 18, 19")
}

/// GET `/` on the owner host serves its approved index only after frame admission.
/// Remaining owner assets resolve only in AssetSurface::Owner. No redirect or top-level
/// owner page is returned, and the response carries frame-ancestors for the exact shell.
pub fn serve_document(
    _navigation: &FrameNavigation,
    _release: &crate::assets::ApprovedRelease,
    _source: &mut impl crate::assets::ReleaseSource,
) -> Result<crate::assets::AssetResponse> {
    todo!("rows 18, 19")
}

#[derive(Clone, Debug)]
pub struct OwnerOriginFacts {
    pub relying_party_id: String,
    pub accepted_top_origin: Origin,
    pub active_principal_limits: Vec<(canon::digest::Digest32, u32)>,
}
