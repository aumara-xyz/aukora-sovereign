// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay-specific destination pins bound to the installed host-policy commitment.

use canon::digest::Digest32;
use std::{
    net::{IpAddr, SocketAddr},
    sync::OnceLock,
};

static POLICY_OBSERVER: OnceLock<fn() -> (u64, Digest32)> = OnceLock::new();

/// Install the trusted host's current-policy observer once.
///
/// The host must atomically return the installed policy's current epoch and digest.
/// These values describe host policy and confer no owner authorization.
pub fn install_policy_observer(observer: fn() -> (u64, Digest32)) -> crate::Result<()> {
    POLICY_OBSERVER
        .set(observer)
        .map_err(|_| refusal("egress-observer-already-set"))
}

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
    /// Validate every scope before retaining the requested relay's destination pins.
    ///
    /// The implementation must reject unknown versions, empty/duplicate scopes,
    /// non-WSS URLs, credentials, fragments, wildcards, port mismatches and nonpublic IPs.
    /// It must pin each approved address to this URL's host and TLS server name.
    pub fn from_policy(policy: &EgressPolicy, relay_url: &str) -> crate::Result<Self> {
        if policy.v != EGRESS_POLICY_VERSION {
            return Err(refusal("egress-version"));
        }
        if policy.relays.is_empty() || policy.relays.len() > MAX_RELAYS {
            return Err(refusal("egress-policy"));
        }
        parse_url(relay_url)?;
        let mut seen = Vec::with_capacity(policy.relays.len());
        let mut selected = None;
        for rule in &policy.relays {
            let parsed = parse_url(&rule.url)?;
            if seen.contains(&parsed) {
                return Err(refusal("egress-duplicate"));
            }
            if parsed.port_or_known_default() != Some(rule.port) || rule.port == 0 {
                return Err(refusal("egress-port"));
            }
            if rule.addresses.is_empty() || rule.addresses.len() > MAX_ADDRESSES_PER_RELAY {
                return Err(refusal("egress-address"));
            }
            let literal = match parsed.host() {
                Some(url::Host::Ipv4(value)) => Some(IpAddr::V4(value)),
                Some(url::Host::Ipv6(value)) => Some(IpAddr::V6(value)),
                _ => None,
            };
            let mut destinations = Vec::with_capacity(rule.addresses.len());
            for address in &rule.addresses {
                let destination = SocketAddr::new(*address, rule.port);
                if !public_address(*address)
                    || literal.is_some_and(|host| host != *address)
                    || destinations.contains(&destination)
                {
                    return Err(refusal("egress-address"));
                }
                destinations.push(destination);
            }
            if rule.url == relay_url {
                selected = Some(Self {
                    url: rule.url.clone(),
                    tls_server_name: match parsed.host() {
                        Some(url::Host::Domain(host)) => host.to_owned(),
                        Some(url::Host::Ipv4(host)) => host.to_string(),
                        Some(url::Host::Ipv6(host)) => host.to_string(),
                        None => return Err(refusal("url-invalid")),
                    },
                    destinations,
                    policy_epoch: policy.epoch,
                    policy_digest: policy.host_policy_digest,
                });
            }
            seen.push(parsed);
        }
        selected.ok_or(refusal("egress-unlisted"))
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

    pub(crate) fn check_current_peer(&self, peer: SocketAddr) -> crate::Result<()> {
        let observer = POLICY_OBSERVER.get().ok_or(refusal("egress-unavailable"))?;
        let (epoch, digest) = observer();
        self.check_peer(peer, epoch, digest)
    }

    /// Check the exact destination and current host-policy commitment.
    /// The connector must dial a pinned address directly and forbid redirects,
    /// proxy fallback, secondary DNS resolution and address-family substitution.
    pub fn check_peer(
        &self,
        peer: SocketAddr,
        current_policy_epoch: u64,
        current_policy_digest: Digest32,
    ) -> crate::Result<()> {
        if current_policy_epoch != self.policy_epoch || current_policy_digest != self.policy_digest
        {
            return Err(refusal("egress-stale"));
        }
        if !self.destinations.contains(&peer) {
            return Err(refusal("egress-peer"));
        }
        Ok(())
    }
}

fn refusal(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "relay",
        reason,
    }
}

fn parse_url(raw: &str) -> crate::Result<url::Url> {
    if raw.len() > MAX_URL_BYTES {
        return Err(refusal("url-too-long"));
    }
    if raw.is_empty()
        || raw
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || raw.contains('\\')
    {
        return Err(refusal("url-invalid"));
    }
    if raw.contains('#') {
        return Err(refusal("url-fragment"));
    }
    let parsed = url::Url::parse(raw).map_err(|_| refusal("url-invalid"))?;
    if parsed.scheme() != "wss" {
        return Err(refusal("url-scheme"));
    }
    let authority = raw
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?']).next().unwrap_or_default())
        .ok_or(refusal("url-invalid"))?;
    if authority.is_empty() {
        return Err(refusal("url-invalid"));
    }
    if authority.contains('@') || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(refusal("url-userinfo"));
    }
    match parsed.host() {
        Some(url::Host::Domain(host)) => {
            if host.is_empty()
                || host.len() > 253
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            {
                return Err(refusal("url-invalid"));
            }
        }
        Some(url::Host::Ipv4(address)) if public_address(address.into()) => {}
        Some(url::Host::Ipv6(address)) if public_address(address.into()) => {}
        _ => return Err(refusal("url-invalid")),
    }
    Ok(parsed)
}

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(a == 0
                || a == 10
                || (a == 100 && (64..=127).contains(&b))
                || a == 127
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 && (c == 0 || c == 2) || b == 88 && c == 99 || b == 168))
                || (a == 198 && (b == 18 || b == 19 || b == 51 && c == 100))
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            // Admit global unicast, excluding protocol assignments, transition and documentation.
            segments[0] & 0xe000 == 0x2000
                && !(segments[0] == 0x2001 && segments[1] & 0xfe00 == 0)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
        }
    }
}
