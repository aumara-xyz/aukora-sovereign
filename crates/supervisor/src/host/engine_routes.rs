// SPDX-License-Identifier: AGPL-3.0-or-later
//! The host's side of the engine (deploy/engine/NODE.md): what the engine controller reads from the host, and the
//! shell origin's `GET /engine/open`, which sends a bound owner to the engine origin with a one-time ticket.

use super::{now, Host};
use canon::{codes, Result};
use frontdoor::ingress::AdmittedRequest;
use supervisor::ingress::{BindingState, PrincipalScope};

impl Host {
    /// The gate, for the engine controller's plugin-set reads and proposals.
    pub fn engine_gate(&self) -> &crate::adapters::GateAdapter {
        &self.gate
    }

    /// Whether the installed release is the one the owner approved (the release floor), now.
    pub fn release_approved(&self) -> bool {
        self.with_release(|_| Ok(())).is_ok()
    }

    /// The active release's id (`release` in `active.json`, the SHA-256 of its release.json); `None` if unreadable,
    /// and then no admission is written (Grok review of the node commit, part 4 #2).
    pub fn release_digest(&self) -> Option<String> {
        std::fs::read(&self.config.release_state)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value.get("release").and_then(serde_json::Value::as_str).map(str::to_owned))
            .filter(|text| text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    /// `GET /engine/open` on the shell origin: a bound owner (shell session) is sent to the engine origin with a fresh
    /// one-time ticket. Only a top-level navigation carries the shell cookie here; the engine origin never sees it.
    pub(super) fn engine_open(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        let engine = self.engine.as_ref().ok_or(codes::FRONTDOOR_UNKNOWN_ROUTE)?;
        self.with_release(|_| Ok(()))?;
        let mut sessions = self.sessions()?;
        let url = frontdoor::session::with_bound_session(
            &mut sessions,
            request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
            self.state.node,
            request.origin(),
            now()?,
            |session| {
                let record = session.record();
                let scope = PrincipalScope {
                    subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
                    epoch: record.owner_epoch,
                };
                if self.ledger.binding()? != BindingState::Bound(scope) {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                engine.enter_url(scope, now()?)
            },
        )?;
        http::Response::builder()
            .status(http::StatusCode::SEE_OTHER)
            .header("location", url)
            .header("cache-control", "no-store")
            .header("referrer-policy", "no-referrer")
            .body(Vec::new())
            .map_err(|_| codes::SUPERVISOR_STATE)
    }

}
