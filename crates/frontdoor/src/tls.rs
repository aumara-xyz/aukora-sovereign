// SPDX-License-Identifier: AGPL-3.0-or-later
//! Listener facts and the private TLS-termination boundary; no public plaintext mode.

use crate::ingress::HostRole;
use canon::{Refusal, Result};
use std::net::{IpAddr, SocketAddr};

/// An exact HTTPS DNS origin without a path, port, userinfo or trailing dot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Origin(String);

impl Origin {
    pub fn parse(text: &str) -> Result<Self> {
        let host = text.strip_prefix("https://").ok_or(Refusal {
            organ: "frontdoor",
            reason: "config-invalid",
        })?;
        if host.is_empty()
            || host.len() > 253
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(Refusal {
                organ: "frontdoor",
                reason: "config-invalid",
            });
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn host(&self) -> &str {
        &self.0[8..]
    }
}

/// Supplied by deployment, never populated from incoming forwarding headers.
#[derive(Clone, Debug)]
pub struct CaddyBoundary {
    pub shell: Origin,
    pub owner: Origin,
    /// Deployment's registered site; both HTTPS hosts must be under this same site.
    /// A public suffix is not a registered site. Host headers cannot select this value.
    pub registered_site: Origin,
    pub allowed_proxy_peers: Vec<IpAddr>,
}

/// Actual connection observations; duplicate forwarded fields are retained for refusal.
#[derive(Clone, Debug)]
pub struct ProxyObservation {
    pub peer: IpAddr,
    pub forwarded_proto: Vec<String>,
    pub host: Vec<String>,
}

/// Produced only by TLS-boundary validation; a claimed HTTPS header alone is insufficient.
#[derive(Debug)]
pub struct SecureRequest {
    pub(crate) origin: Origin,
    role: HostRole,
}

impl SecureRequest {
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    pub fn role(&self) -> HostRole {
        self.role
    }
}

impl CaddyBoundary {
    /// Deployment supplies the registered site; request headers cannot widen it.
    pub fn validate(&self) -> Result<()> {
        let site = self.registered_site.host();
        if self.shell == self.owner
            || site.split('.').count() < 2
            || site.parse::<IpAddr>().is_ok()
            || !under_site(self.shell.host(), site)
            || !under_site(self.owner.host(), site)
            || self.allowed_proxy_peers.is_empty()
            || self
                .allowed_proxy_peers
                .iter()
                .any(|peer| peer.is_unspecified() || peer.is_multicast())
        {
            return Err(configuration_refused());
        }
        Ok(())
    }

    /// Only a configured peer may assert HTTPS. Both fields must occur exactly once.
    pub fn admit(&self, observation: ProxyObservation) -> Result<SecureRequest> {
        if !self.allowed_proxy_peers.contains(&observation.peer) {
            return Err(canon::codes::FRONTDOOR_HTTPS_REQUIRED);
        }
        self.validate()?;
        if observation.forwarded_proto.len() != 1 || observation.forwarded_proto[0] != "https" {
            return Err(canon::codes::FRONTDOOR_HTTPS_REQUIRED);
        }
        let [host] = observation.host.as_slice() else {
            return Err(canon::codes::FRONTDOOR_HOST_REFUSED);
        };
        let (origin, role) = if host == self.shell.host() {
            (self.shell.clone(), HostRole::Shell)
        } else if host == self.owner.host() {
            (self.owner.clone(), HostRole::Owner)
        } else {
            return Err(canon::codes::FRONTDOOR_HOST_REFUSED);
        };
        Ok(SecureRequest { origin, role })
    }

    /// One TLS site block serves both configured hosts through a loopback listener.
    /// Caddy preserves the incoming Host and replaces the HTTPS forwarding field.
    pub fn caddy_block(&self, upstream: SocketAddr) -> Result<String> {
        self.validate()?;
        if !upstream.ip().is_loopback()
            || upstream.port() == 0
            || !self.allowed_proxy_peers.contains(&upstream.ip())
        {
            return Err(configuration_refused());
        }
        Ok(format!(
            "{shell}, {owner} {{\n    reverse_proxy {upstream} {{\n        header_up X-Forwarded-Proto https\n    }}\n}}\n",
            shell = self.shell.as_str(),
            owner = self.owner.as_str(),
        ))
    }
}

fn under_site(host: &str, site: &str) -> bool {
    host == site
        || host
            .strip_suffix(site)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn configuration_refused() -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason: "config-invalid",
    }
}

/// Measurements only; no map, cell, fingerprint or authority decision is represented.
#[derive(Clone, Debug)]
pub struct TlsFacts {
    pub shell_origin: Origin,
    pub owner_origin: Origin,
    pub observed_certificate_digest: Option<[u8; 32]>,
    pub observed_proxy_peers: Vec<IpAddr>,
}
