// SPDX-License-Identifier: AGPL-3.0-or-later
//! Approval notifications have no dependency on the guest process or its readiness.

use crate::{
    session::{with_bound_session, BoundSession, SessionScope, SessionStore},
    shell::{OwnerFrame, Popup, ShellHost},
    tls::Origin,
};
use canon::{
    digest::Digest32,
    ids::{NodeId, ProposalId, SubjectId},
    session::Items,
    Refusal, Result,
};
use std::collections::BTreeSet;

pub const MAX_PENDING: usize = 100;
pub const POLL_INTERVAL_MS: u64 = 1_000;

#[derive(Clone, Debug)]
pub struct PendingApproval {
    pub proposal: ProposalId,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug)]
pub struct PendingPage {
    pub sequence: u64,
    pub proposals: Items<PendingApproval, MAX_PENDING>,
    pub next: Option<ProposalId>,
}

/// Gate-backed reads continue while Auma is stopped. A notification cannot apply a proposal.
pub trait ApprovalService {
    fn pending(
        &mut self,
        session: &BoundSession<'_>,
        after: Option<ProposalId>,
    ) -> Result<PendingPage>;
}

#[derive(Clone, Copy, Debug)]
pub struct ApprovalFacts {
    pub last_poll_at_ms: Option<u64>,
    pub last_gate_sequence: Option<u64>,
    pub pending_count: u64,
    pub poll_failures: u64,
}

/// A full notification scan is bounded even when the source never ends its pages.
pub const MAX_PENDING_PAGES: usize = 100;
const MAX_WIRE_INTEGER: u64 = 9_007_199_254_740_991;

/// Notification data contains no card, authorization, credential or effect bytes.
#[derive(Clone, Debug)]
pub struct PendingUpdate {
    pub sequence: u64,
    pub proposals: Vec<PendingApproval>,
}

/// Supplied by the host's validated connection and clock, never by a face message.
pub struct PollAdmission<'a> {
    pub cookie: &'a [u8],
    pub node: NodeId,
    pub origin: &'a Origin,
    pub now_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PollScope {
    token: Digest32,
    node: NodeId,
    subject: SubjectId,
    epoch: u64,
    origin: Origin,
    scope: SessionScope,
}

/// One instance belongs to one browser notification channel. The host calls `poll`
/// on its timer inside live-session admission, including while the guest is stopped.
pub struct ApprovalPoller {
    scope: Option<PollScope>,
    attempted_at_ms: Option<u64>,
    pending: Vec<PendingApproval>,
    shown: BTreeSet<ProposalId>,
    active: Option<ProposalId>,
    facts: ApprovalFacts,
}

impl Default for ApprovalPoller {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalPoller {
    pub const fn new() -> Self {
        Self {
            scope: None,
            attempted_at_ms: None,
            pending: Vec::new(),
            shown: BTreeSet::new(),
            active: None,
            facts: ApprovalFacts {
                last_poll_at_ms: None,
                last_gate_sequence: None,
                pending_count: 0,
                poll_failures: 0,
            },
        }
    }

    /// Each host timer tick enters durable admission afresh. No BoundSession is
    /// retained across ticks or asynchronous browser delivery.
    pub fn poll_admitted<S: SessionStore>(
        &mut self,
        store: &mut S,
        service: &mut impl ApprovalService,
        admission: PollAdmission<'_>,
    ) -> Result<Option<PendingUpdate>> {
        let mut admitted = false;
        let result = with_bound_session(
            store,
            admission.cookie,
            admission.node,
            admission.origin,
            admission.now_ms,
            |session| {
                admitted = true;
                self.poll(service, &session, admission.now_ms)
            },
        );
        if !admitted {
            self.clear();
        }
        result
    }

    /// Returns no update before the next interval. Failed or inconsistent scans
    /// discard notification candidates; they never turn an old snapshot into a new one.
    pub fn poll(
        &mut self,
        service: &mut impl ApprovalService,
        session: &BoundSession<'_>,
        now_ms: u64,
    ) -> Result<Option<PendingUpdate>> {
        self.bind(session, now_ms)?;
        if self
            .attempted_at_ms
            .is_some_and(|at| now_ms >= at && now_ms - at < POLL_INTERVAL_MS)
        {
            return Ok(None);
        }
        self.attempted_at_ms = Some(now_ms);
        match scan(service, session, now_ms, self.facts.last_gate_sequence) {
            Ok(update) => {
                let live: BTreeSet<_> = update.proposals.iter().map(|p| p.proposal).collect();
                self.shown.retain(|id| live.contains(id));
                self.pending = update.proposals.clone();
                self.facts.last_poll_at_ms = Some(now_ms);
                self.facts.last_gate_sequence = Some(update.sequence);
                self.facts.pending_count = self.pending.len() as u64;
                Ok(Some(update))
            }
            Err(error) => {
                self.pending.clear();
                self.facts.pending_count = 0;
                self.facts.poll_failures = self.facts.poll_failures.saturating_add(1);
                Err(error)
            }
        }
    }

    /// Only a ShellHost creates a frame. At most one proposal is offered until the
    /// shell reports it closed; closing a notification never declines the proposal.
    pub fn next_popup(
        &mut self,
        session: &BoundSession<'_>,
        shell: &ShellHost,
        now_ms: u64,
    ) -> Result<Option<OwnerFrame>> {
        self.bind(session, now_ms)?;
        if self.active.is_some() {
            return Ok(None);
        }
        let Some(observed) = self.facts.last_poll_at_ms else {
            return Ok(None);
        };
        if now_ms < observed || now_ms - observed > POLL_INTERVAL_MS {
            return Ok(None);
        }
        let candidate = self.pending.iter().find(|pending| {
            pending.expires_at_ms > now_ms && !self.shown.contains(&pending.proposal)
        });
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let proposal = candidate.proposal;
        self.shown.insert(proposal);
        self.active = Some(proposal);
        Ok(Some(shell.popup(Popup::Approval(proposal))))
    }

    /// A shell callback, never a message from a face. This carries no authority.
    pub fn closed(
        &mut self,
        session: &BoundSession<'_>,
        proposal: ProposalId,
        now_ms: u64,
    ) -> Result<()> {
        self.bind(session, now_ms)?;
        if self.active != Some(proposal) {
            return Err(refusal("approval-notification-mismatch"));
        }
        self.active = None;
        self.attempted_at_ms = None;
        Ok(())
    }

    pub fn facts(&self) -> ApprovalFacts {
        self.facts
    }

    /// Call on session loss or channel disposal; no bearer or pending ids survive it.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    fn bind(&mut self, session: &BoundSession<'_>, now_ms: u64) -> Result<()> {
        let record = session.record();
        if now_ms > MAX_WIRE_INTEGER
            || record.revoked
            || record.expires_at_ms <= now_ms
            || record.scope == SessionScope::BindingOnly
        {
            self.clear();
            return Err(refusal("session-refused"));
        }
        let Some(subject) = record.subject else {
            self.clear();
            return Err(refusal("session-refused"));
        };
        let scope = PollScope {
            token: record.token_digest,
            node: record.node,
            subject,
            epoch: record.owner_epoch,
            origin: record.origin.clone(),
            scope: record.scope,
        };
        if self.scope.as_ref() != Some(&scope) {
            self.clear();
            self.scope = Some(scope);
        }
        Ok(())
    }
}

/// Pages are strictly increasing by proposal id with an exclusive last-id cursor.
/// Every page in a scan must name the same gate sequence. Expiry only hides a
/// notification; gate remains responsible for expiring or consuming a proposal.
fn scan(
    service: &mut impl ApprovalService,
    session: &BoundSession<'_>,
    now_ms: u64,
    previous_sequence: Option<u64>,
) -> Result<PendingUpdate> {
    let mut after = None;
    let mut sequence = None;
    let mut pending = Vec::new();
    for _ in 0..MAX_PENDING_PAGES {
        let page = service.pending(session, after)?;
        if page.sequence > MAX_WIRE_INTEGER
            || previous_sequence.is_some_and(|previous| page.sequence < previous)
            || sequence.is_some_and(|expected| page.sequence != expected)
        {
            return Err(refusal("approval-sequence-changed"));
        }
        sequence = Some(page.sequence);
        let mut last = after;
        for proposal in page.proposals.as_slice() {
            if proposal.expires_at_ms > MAX_WIRE_INTEGER
                || last.is_some_and(|id| proposal.proposal <= id)
            {
                return Err(refusal("approval-page-invalid"));
            }
            last = Some(proposal.proposal);
            if proposal.expires_at_ms > now_ms {
                pending.push(proposal.clone());
            }
        }
        match page.next {
            None => {
                return Ok(PendingUpdate {
                    sequence: page.sequence,
                    proposals: pending,
                })
            }
            Some(next) if Some(next) == last && Some(next) != after => after = Some(next),
            Some(_) => return Err(refusal("approval-page-invalid")),
        }
    }
    Err(refusal("approval-page-limit"))
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason,
    }
}
