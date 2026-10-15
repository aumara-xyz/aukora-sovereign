// SPDX-License-Identifier: AGPL-3.0-or-later
//! A shadow result has no conversion into an owner proof or an applied effect.

use crate::hostile::Limits;
use canon::{
    authority::BaseDigest,
    digest::Digest32,
    ids::{OperationDigest, ProposalId},
    Result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowRequest {
    pub proposal: ProposalId,
    pub operation: OperationDigest,
    pub target: String,
    pub base: BaseDigest,
    pub source_snapshot: Digest32,
    pub exact_proposed_bytes: Vec<u8>,
    pub release: Digest32,
    pub limits: Limits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Clear,
    Refused,
    Undetermined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowObservation {
    pub proposal: ProposalId,
    pub operation: OperationDigest,
    pub source_snapshot: Digest32,
    pub shadow_snapshot: Digest32,
    pub live_before: Digest32,
    pub live_after: Digest32,
    pub verdict: Verdict,
    pub findings: Vec<String>,
    pub budget_exhausted: bool,
}

pub trait ShadowDriver {
    fn inspect_shadow(&mut self, request: &ShadowRequest) -> Result<ShadowObservation>;
}

pub fn inspect(
    request: &ShadowRequest,
    driver: &mut impl ShadowDriver,
) -> Result<ShadowObservation> {
    request.limits.validate()?;
    if request.target.is_empty()
        || request.target.len() > 256
        || request.exact_proposed_bytes.len() > 65_536
    {
        return Err(canon::Refusal {
            organ: "immune",
            reason: "shadow-input",
        });
    }
    let observation = driver.inspect_shadow(request)?;
    if observation.proposal != request.proposal
        || observation.operation != request.operation
        || observation.source_snapshot != request.source_snapshot
        || observation.live_before != observation.live_after
        || observation.findings.len() > 128
        || observation.findings.iter().map(String::len).sum::<usize>() > 65_536
        || observation.budget_exhausted
    {
        return Err(canon::Refusal {
            organ: "immune",
            reason: "shadow-incomplete",
        });
    }
    Ok(observation)
}
