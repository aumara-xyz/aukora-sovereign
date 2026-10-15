// SPDX-License-Identifier: AGPL-3.0-or-later
//! Borrowed node-signing context; raw keys are private to this module.

use canon::ids::NodeId;
use nostr::{
    identity::{self, BoundIdentities, DelegationState, EventDraft, IdentityRole},
    PublicKey, SecretKey, VerifiedEvent,
};

/// NIP-42 authentication kind, fixed independently from message and head kinds.
pub const RELAY_AUTH_KIND: u16 = 22_242;
/// Maximum UTF-8 bytes retained from one remote authentication challenge.
pub const MAX_AUTH_CHALLENGE_BYTES: usize = 2_048;

/// Borrowed credentials for a current node-delegation check on every signing use.
/// Construction retains references only; it does not establish current authority.
pub struct AuthContext<'a> {
    delegations: &'a mut dyn DelegationState,
    binding: &'a BoundIdentities,
    secret: &'a SecretKey,
}

impl<'a> AuthContext<'a> {
    /// Retain trusted-host references without exporting the secret to client code.
    pub fn new(
        delegations: &'a mut dyn DelegationState,
        binding: &'a BoundIdentities,
        secret: &'a SecretKey,
    ) -> Self {
        Self {
            delegations,
            binding,
            secret,
        }
    }

    /// Node identifier retained in the checked binding.
    pub fn node(&self) -> NodeId {
        self.binding.binding().node
    }

    /// Epoch retained in the binding; signing separately checks current state.
    pub fn epoch(&self) -> u64 {
        self.binding.binding().authority.epoch
    }

    /// Bound node role's public key; no scalar bytes leave this module.
    pub fn public_key(&self) -> PublicKey {
        self.binding.binding().node_key
    }

    /// Bound a challenge to one validated relay, then enter current delegation
    /// verification. The challenge stays data in the NIP-42 tag value.
    pub fn sign_relay_auth(
        &mut self,
        relay: &crate::ValidatedRelay,
        challenge: &str,
        created_at_seconds: u64,
    ) -> crate::Result<VerifiedEvent> {
        if challenge.is_empty() || challenge.len() > MAX_AUTH_CHALLENGE_BYTES {
            return Err(canon::Refusal {
                organ: "relay",
                reason: "auth-invalid",
            });
        }
        self.sign(EventDraft {
            created_at_seconds,
            kind: RELAY_AUTH_KIND,
            tags: vec![
                vec![String::from("relay"), relay.url().to_owned()],
                vec![String::from("challenge"), challenge.to_owned()],
            ],
            content: String::new(),
        })
    }

    /// Every relay signing path enters the same current-delegation boundary.
    pub(crate) fn sign(&mut self, draft: EventDraft) -> crate::Result<VerifiedEvent> {
        identity::sign_delegated(
            self.delegations,
            self.binding,
            IdentityRole::Node,
            self.secret,
            draft,
        )
    }
}
