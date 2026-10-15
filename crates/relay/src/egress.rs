// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-relay egress contracts. Validation and connection admission are row-70 stubs.

use canon::digest::Digest32;
use std::net::{IpAddr, SocketAddr};

/// Bound on one configured relay URL in UTF-8 bytes.
pub const MAX_URL_BYTES: usize = 2_048;
/// Bound on independently scoped relay entries in a policy.
pub const MAX_RELAYS: usize = 16;
/// Bound on pinned addresses belonging to one relay.
pub const MAX_ADDRESSES_PER_RELAY: usize = 16;
/// Version of the internal egress-policy object, not a Nostr wire key.
pub const EGRESS_POLICY_VERSION: u16 = 1;

/// A local policy input. Possession of this value is not owner authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayRule {
    /// Configured WSS URL input, including its path; validation remains separate.
    pub url: String,
    /// Effective destination port explicitly permitted for this relay.
    pub port: u16,
    /// Explicit permitted destination addresses for this relay only.
    pub addresses: Vec<IpAddr>,
}

/// Supervisor-provided configuration whose digest can be compared with host egress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Only `EGRESS_POLICY_VERSION` is defined.
    pub v: u16,
    /// Rollback epoch of the installed egress policy.
    pub epoch: u64,
    /// Exact digest of the installed host policy, not a claimed health verdict.
    pub host_policy_digest: Digest32,
    /// Per-relay address scopes; no entry grants access to another entry's addresses.
    pub relays: Vec<RelayRule>,
}

/// Private construction boundary for a relay URL and its address scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRelay {
    url: String,
    tls_server_name: String,
    destinations: Vec<SocketAddr>,
    policy_epoch: u64,
    policy_digest: Digest32,
}

impl ValidatedRelay {
    /// Row-70 validation boundary; currently panics.
    ///
    /// The implementation must reject unknown versions, empty/duplicate scopes,
    /// non-WSS URLs, credentials, fragments, wildcards, port mismatches and nonpublic IPs.
    /// It must pin each approved address to this URL's host and TLS server name.
    pub fn from_policy(_policy: &EgressPolicy, _relay_url: &str) -> crate::Result<Self> {
        todo!("row 70")
    }

    /// Exact URL retained by the egress validation boundary.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Host used for TLS SNI and certificate verification.
    pub fn tls_server_name(&self) -> &str {
        &self.tls_server_name
    }

    /// Direct connection targets; no DNS lookup is part of these values.
    pub fn destinations(&self) -> &[SocketAddr] {
        &self.destinations
    }

    /// Epoch attached to this validated policy scope.
    pub const fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    /// Host policy commitment attached to this scope.
    pub const fn policy_digest(&self) -> Digest32 {
        self.policy_digest
    }

    /// Row-70 final peer check against this exact scope; currently panics.
    /// The connector must dial a pinned address directly and forbid redirects,
    /// proxy fallback, secondary DNS resolution and address-family substitution.
    pub fn check_peer(
        &self,
        _peer: SocketAddr,
        _current_policy_epoch: u64,
        _current_policy_digest: Digest32,
    ) -> crate::Result<()> {
        todo!("row 70")
    }
}
