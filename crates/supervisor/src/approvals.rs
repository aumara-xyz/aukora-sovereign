// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded notification channels use Frontdoor's poll cadence and Gate's stored proposals.

use crate::adapters::{approvals::ApprovalAdapter, HostLedger};
use canon::{codes, digest::Digest32, json::Value, Refusal, Result};
use frontdoor::{approvals::ApprovalPoller, session::BoundSession};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use supervisor::ingress::{BindingState, PrincipalScope};

struct Channel {
    expires: u64,
    poller: ApprovalPoller,
}

pub struct ApprovalFeed {
    ledger: Arc<HostLedger>,
    channels: Mutex<BTreeMap<Digest32, Channel>>,
}

impl ApprovalFeed {
    pub fn new(ledger: Arc<HostLedger>) -> Self {
        Self {
            ledger,
            channels: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn snapshot(&self, session: &BoundSession<'_>, now: u64) -> Result<Value> {
        let record = session.record();
        let scope = PrincipalScope {
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
        };
        if self.ledger.binding()? != BindingState::Bound(scope) {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        self.ledger.ensure_release_proposal(scope)?;
        let mut channels = self.channels.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        channels.retain(|_, channel| channel.expires > now);
        if !channels.contains_key(&record.token_digest) && channels.len() >= 64 {
            return Err(refuse("approval-channels-full"));
        }
        let channel = channels
            .entry(record.token_digest)
            .or_insert_with(|| Channel {
                expires: record.expires_at_ms,
                poller: ApprovalPoller::new(),
            });
        let update = channel
            .poller
            .poll(&mut ApprovalAdapter::new(self.ledger.clone()), session, now)?
            .ok_or(refuse("approval-poll-not-due"))?;
        let mut proposals = Vec::with_capacity(update.proposals.len());
        for proposal in update.proposals {
            proposals.push(Value::object(vec![
                (
                    "proposal".into(),
                    Value::text(proposal.proposal.to_string())?,
                ),
                ("expires_at_ms".into(), number(proposal.expires_at_ms)?),
            ])?);
        }
        // The owner's standing Declines among the node's own requests: what the owner may ask for again (O19).
        let declined = self
            .ledger
            .scoped(scope, |txn| txn.owner_declines(16))?
            .into_iter()
            .map(|(proposal, _)| Value::text(proposal.to_string()))
            .collect::<Result<Vec<_>>>()?;
        let value = Value::object(vec![
            ("sequence".into(), number(update.sequence)?),
            ("proposals".into(), Value::array(proposals)?),
            ("declined".into(), Value::array(declined)?),
        ])?;
        if self.ledger.binding()? != BindingState::Bound(scope) {
            channel.poller.clear();
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        frontdoor::api::JsonData::new(&value)?;
        Ok(value)
    }
}

fn number(value: u64) -> Result<Value> {
    let integer = i64::try_from(value).map_err(|_| codes::SUPERVISOR_STATE)?;
    Ok(Value::integer(canon::json::SafeInteger::new(integer)?))
}

const fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "supervisor",
        reason,
    }
}
