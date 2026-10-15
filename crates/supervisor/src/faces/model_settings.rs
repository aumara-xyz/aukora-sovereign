// SPDX-License-Identifier: AGPL-3.0-or-later
//! Non-secret projection of broker-owned values into the Models face contract.
use super::{settings, wire};
use broker::{
    grant::{GrantTerms, GrantUsage},
    identity::VerifiedIdentity,
    intake::ModelSlot,
    provider::ModelSource,
    receipt::{ReceiptBody, SettlementOutcome},
};
use canon::{json::Value, Result};

pub struct GrantReport<'a> {
    pub terms: &'a GrantTerms,
    pub usage: GrantUsage,
    pub frozen: bool,
}

/// Absence means the owning source observed none; an unavailable source must return an error before projection.
pub fn project(
    slot: &ModelSlot,
    key_present: bool,
    grant: Option<GrantReport<'_>>,
    last: Option<&ReceiptBody>,
) -> Result<Value> {
    let model = slot
        .admitted()
        .map(|admitted| {
            let candidate = admitted.candidate();
            let source = match candidate.source {
                ModelSource::Hosted(provider) => {
                    wire::object([("provider", wire::text(provider.name())?)])?
                }
                ModelSource::Local { artifact } => {
                    wire::object([("artifact", wire::text(artifact.to_string())?)])?
                }
            };
            wire::object([
                ("name", wire::text(candidate.model.as_str())?),
                ("source", source),
            ])
        })
        .transpose()?
        .unwrap_or_else(Value::null);
    let grant = grant
        .map(|grant| {
            let terms = grant.terms;
            wire::object([
                (
                    "completion_microusd_per_token",
                    wire::number(terms.prices.completion_microusd_per_token)?,
                ),
                ("expires_at_ms", wire::number(terms.expires_at_ms)?),
                ("frozen", Value::boolean(grant.frozen)),
                ("max_requests", wire::number(terms.max_requests)?),
                (
                    "per_request_cap_microusd",
                    wire::number(terms.per_request_cap_microusd)?,
                ),
                (
                    "prompt_microusd_per_token",
                    wire::number(terms.prices.prompt_microusd_per_token)?,
                ),
                ("requests", wire::number(grant.usage.requests)?),
                (
                    "reserved_microusd",
                    wire::number(grant.usage.reserved_microusd)?,
                ),
                ("spent_microusd", wire::number(grant.usage.spent_microusd)?),
                (
                    "total_cap_microusd",
                    wire::number(terms.total_cap_microusd)?,
                ),
            ])
        })
        .transpose()?
        .unwrap_or_else(Value::null);
    let last = last
        .map(|receipt| {
            receipt.validate()?;
            let verified = match &receipt.identity.verified {
                VerifiedIdentity::Unverified => {
                    wire::object([("status", wire::text("unverified")?)])?
                }
                VerifiedIdentity::Verified {
                    model, verifier, ..
                } => wire::object([
                    ("status", wire::text("verified")?),
                    ("model", wire::text(model.as_str())?),
                    ("verifier", wire::text(verifier)?),
                ])?,
            };
            let identity = wire::object([
                (
                    "requested",
                    wire::text(receipt.identity.requested.as_str())?,
                ),
                (
                    "reported",
                    receipt
                        .identity
                        .reported
                        .as_ref()
                        .map(|name| wire::text(name.as_str()))
                        .transpose()?
                        .unwrap_or_else(Value::null),
                ),
                ("verified", verified),
            ])?;
            let outcome = match receipt.outcome {
                SettlementOutcome::Completed => "completed",
                SettlementOutcome::Cancelled => "cancelled",
                SettlementOutcome::Refused => "refused",
                SettlementOutcome::Unknown => "unknown",
            };
            wire::object([
                ("charged_microusd", wire::number(receipt.charged_microusd)?),
                ("cost_unknown", Value::boolean(receipt.cost_unknown)),
                ("identity", identity),
                ("outcome", wire::text(outcome)?),
            ])
        })
        .transpose()?
        .unwrap_or_else(Value::null);
    let value = wire::object([
        ("model", model),
        (
            "key",
            wire::object([("present", Value::boolean(key_present))])?,
        ),
        ("grant", grant),
        ("last_reply", last),
    ])?;
    settings::validate("settings.models", &value)?;
    wire::bounded(value)
}
