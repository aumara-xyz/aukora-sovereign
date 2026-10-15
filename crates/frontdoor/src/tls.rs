// SPDX-License-Identifier: AGPL-3.0-or-later
//! Listener facts and the private TLS-termination boundary; no public plaintext mode.

use canon::{Refusal, Result};
use std::net::IpAddr;

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
}

impl SecureRequest {
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
}

impl CaddyBoundary {
    /// Wave-1 implementation must validate the peer before exact host and HTTPS fields.
    /// Pins: frontdoor:https-required, frontdoor:host-refused. Startup rejects equal origins
    /// and different schemeful sites; SameSite=Strict cookies require the configured shared site.
    pub fn admit(&self, _observation: ProxyObservation) -> Result<SecureRequest> {
        todo!("row 24")
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
