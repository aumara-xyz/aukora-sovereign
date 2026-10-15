// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host-assigned context; none of these observations is an owner approval.

use canon::{
    codes,
    fd3::Request,
    frame::Frame,
    ids::{SessionId, SubjectId},
    provenance::{Provenance, Source},
    session::SessionEntry,
    Result,
};

/// Principal and current binding epoch supplied by the identity organ.
/// Every authority operation still verifies the passkey in its owning organ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrincipalScope {
    pub subject: SubjectId,
    pub epoch: u64,
}

/// An observation of identity state, not permission to execute the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingState {
    Unbound,
    Bound(PrincipalScope),
}

/// Conversation selected through authenticated host ingress, outside the C4 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversationCursor {
    pub session_id: SessionId,
    pub sequence: u64,
}

/// Context retained by the supervisor for a single admitted guest channel.
/// The fields cannot be populated from an FD 3 body.
#[derive(Debug)]
pub struct GuestContext {
    scope: PrincipalScope,
    conversation: Option<ConversationCursor>,
}

impl GuestContext {
    /// Construct context from a binding observation, refusing unbound state.
    /// This method neither starts a process nor approves a release.
    pub fn admit(binding: BindingState) -> Result<Self> {
        match binding {
            BindingState::Unbound => Err(codes::AUMLOK_BINDING_REQUIRED),
            BindingState::Bound(scope) => Ok(Self {
                scope,
                conversation: None,
            }),
        }
    }

    pub const fn scope(&self) -> PrincipalScope {
        self.scope
    }

    pub const fn conversation(&self) -> Option<ConversationCursor> {
        self.conversation
    }

    /// Retain the router's scoped store cursor; this does not create a durable receipt.
    pub(crate) fn select(&mut self, cursor: ConversationCursor) {
        self.conversation = Some(cursor);
    }
}

/// Stamp a canonical request from the sole guest channel, refusing upgraded labels.
/// This boundary consumes typed values only after canon has validated wire bytes.
pub fn guest_request(mut frame: Frame<Request>) -> Result<Frame<Request>> {
    if frame.provenance.source != Source::Auma {
        return Err(codes::FRAME_PROVENANCE);
    }
    frame.provenance = Provenance {
        source: Source::Auma,
    };
    Ok(frame)
}

/// A guest may persist only its own entries, regardless of role or embedded wording.
/// Live owner input is appended on the host before it is forwarded to the guest.
pub fn guest_entry(entry: &SessionEntry) -> Result<()> {
    if entry.provenance.source != Source::Auma || entry.role == canon::session::SessionRole::Owner {
        return Err(codes::FRAME_PROVENANCE);
    }
    Ok(())
}

/// Trusted host classification of data forwarded to the harness.
/// Stranger observations are recorded outside this return value and never delivered.
pub fn deliverable(source: &Source) -> Result<()> {
    if matches!(source, Source::Stranger) {
        return Err(codes::FRAME_PROVENANCE);
    }
    Ok(())
}
