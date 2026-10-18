// SPDX-License-Identifier: AGPL-3.0-or-later
//! The host's side of the engine (deploy/engine/NODE.md): what the engine controller reads from the host, the
//! shell origin's `GET /engine/open`, which sends a bound owner to the engine origin with a one-time ticket, and the
//! shell origin's model-key entry (`GET /engine/model-key`, `POST /api/engine/model-key`, section 7).

mod model_key_page;

use super::{now, Host};
use canon::{codes, json::Value, Result};
use frontdoor::ingress::AdmittedRequest;
use supervisor::ingress::{BindingState, PrincipalScope};

/// The release floor's answer for the engine. `Unknown` ("cannot read it now") is never taken for either answer:
/// nothing starts on it and nothing is served on it, but it alone does not stop a running engine (NODE.md O11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseStanding {
    /// The owner's passkey advanced the floor to the running release.
    Approved,
    /// The floor names another release, or only the install's starting floor.
    NotApproved,
    /// The floor could not be read just now (another reader holds its lock, I/O, a transition in flight).
    Unknown,
}

impl Host {
    pub(super) fn sessions(&self) -> Result<frontdoor::session::DurableSessions> {
        let boundary = self.config.boundary()?;
        frontdoor::session::DurableSessions::open(
            self.sessions.try_clone().map_err(|_| codes::SUPERVISOR_STATE)?,
            self.state.node,
            boundary.shell,
            boundary.owner,
        )
    }

    /// Engine authority failures share the owner's existing notice poll without hiding approval cards.
    pub(super) fn approval_snapshot(&self, session: &frontdoor::session::BoundSession<'_>, at: u64) -> Result<Value> {
        let snapshot = self.approvals.snapshot(session, at)?;
        with_engine_refusal(snapshot, self.engine.as_ref().and_then(|engine| engine.runtime_refusal()))
    }

    /// The gate, for the engine controller's plugin-set reads and proposals.
    pub fn engine_gate(&self) -> &crate::adapters::GateAdapter {
        &self.gate
    }

    /// What the release floor says about the running release, now, for the engine (NODE.md section 2 and O11). Only
    /// a floor the owner's passkey advanced to this very release is `Approved`: the install's starting floor lets the
    /// shell serve before the first card, but it is nobody's approval, so the engine waits for the release card.
    pub fn release_standing(&self) -> ReleaseStanding {
        let Ok(assets) = self.assets.lock() else { return ReleaseStanding::Unknown };
        match assets.source.owner_approved() {
            Ok(true) => ReleaseStanding::Approved,
            Ok(false) => ReleaseStanding::NotApproved,
            Err(_) => ReleaseStanding::Unknown,
        }
    }

    /// The running release's id (the SHA-256 of its release.json, what the floor names), if it is also the active
    /// release (`release` in `active.json`, which the root pre-start compares). `None` if either is unreadable or they
    /// differ (a switch in progress): then no admission is written (Grok review of the node commit, part 4 #2; O11).
    pub fn release_digest(&self) -> Option<String> {
        let running = self.assets.lock().ok()?.source.release_digest.to_string();
        std::fs::read(&self.config.release_state)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value.get("release").and_then(serde_json::Value::as_str).map(str::to_owned))
            .filter(|active| *active == running)
    }

    /// Whether the shell session with this store digest is still live for this owner scope (not expired, not
    /// revoked, its owner epoch and parent intact, still a shell session of this node's shell origin). `Ok(false)`
    /// is "ended"; an `Err` is a store that could not be read now.
    pub fn shell_session_live(&self, shell: canon::digest::Digest32, scope: PrincipalScope, now_ms: u64) -> Result<bool> {
        use frontdoor::session::SessionStore as _;
        let mut sessions = self.sessions()?;
        let shell_origin = frontdoor::tls::Origin::parse(&self.config.shell_origin)?;
        match sessions.with_live_session(shell, now_ms, |record| {
            Ok(record.scope == frontdoor::session::SessionScope::Shell
                && record.node == self.state.node
                && record.origin == shell_origin
                && record.subject == Some(scope.subject)
                && record.owner_epoch == scope.epoch)
        }) {
            Ok(live) => Ok(live),
            Err(refusal) if refusal == codes::FRONTDOOR_SESSION_REQUIRED || refusal == codes::AUMLOK_BINDING_REQUIRED => Ok(false),
            Err(refusal) => Err(refusal),
        }
    }

    /// `GET /engine/open` on the shell origin: a bound owner (shell session) is sent to the engine origin with a fresh
    /// one-time ticket. Only a top-level navigation carries the shell cookie here; the engine origin never sees it.
    pub(super) fn engine_open(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        let engine = self.engine.as_ref().ok_or(codes::FRONTDOOR_UNKNOWN_ROUTE)?;
        self.with_release(|_| Ok(()))?;
        // No ticket for an engine that may not run: the owner has not approved this release yet (O11).
        if self.release_standing() != ReleaseStanding::Approved {
            return Err(canon::Refusal { organ: "supervisor", reason: "release-not-approved" });
        }
        let mut sessions = self.sessions()?;
        let url = frontdoor::session::with_bound_session(
            &mut sessions,
            request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
            self.state.node,
            request.origin(),
            now()?,
            |session| {
                let record = session.record();
                if record.scope != frontdoor::session::SessionScope::Shell {
                    return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
                }
                let scope = PrincipalScope {
                    subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
                    epoch: record.owner_epoch,
                };
                if self.ledger.binding()? != BindingState::Bound(scope) {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                // The engine session is this shell session's: it ends when this one does (O12).
                engine.enter_url(scope, record.token_digest, record.expires_at_ms, now()?)
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

    /// The model key's standing for the owner's Models row (`GET /.aukora/model-key` on the engine origin, answered by
    /// the engine proxy after its own admission). `None` when this node has no model broker.
    pub async fn model_key_status(&self) -> Option<Result<crate::model_broker::KeyStatus>> {
        let broker = self.model_broker.as_ref()?;
        Some(broker.key_status().await)
    }

    /// The shell origin's engine routes and its sign-out, or `None` for any other request.
    pub(super) fn engine_route(&self, request: &AdmittedRequest) -> Option<Result<http::Response<Vec<u8>>>> {
        if request.role() != frontdoor::ingress::HostRole::Shell {
            return None;
        }
        let get = request.method() == frontdoor::ingress::Method::Get;
        match request.path() {
            "/engine/open" if get => Some(self.engine_open(request)),
            "/engine/model-key" if get => Some(self.model_key_page()),
            "/api/engine/model-key" => Some(self.model_key_entry(request)),
            "/api/session/end" => Some(self.shell_sign_out(request)),
            // The door's taint, for the owner (door_routes.rs).
            "/engine/door" if get => Some(self.door_page()),
            "/api/engine/door" if get => Some(self.door_status(request)),
            "/api/engine/door/clear-taint" => Some(self.door_clear_taint(request)),
            _ => None,
        }
    }

    /// End the shell's owner session family durably, then clear the browser's shell cookie (O12).
    pub(super) fn shell_sign_out(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        if request.method() != frontdoor::ingress::Method::Post {
            return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
        }
        let mut sessions = self.sessions()?;
        let shell = frontdoor::session::with_bound_session(
            &mut sessions,
            request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
            self.state.node,
            request.origin(),
            now()?,
            |session| {
                let record = session.record();
                if record.scope != frontdoor::session::SessionScope::Shell {
                    return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
                }
                Ok(record.token_digest)
            },
        )?;
        sessions.end_shell_session(shell, now()?)?;
        drop(sessions);
        if let Some(engine) = self.engine.as_ref() {
            engine.end_shell(shell);
        }
        let mut response = super::json_response(Value::object(vec![("ended".into(), Value::boolean(true))])?)?;
        response.headers_mut().insert(
            http::header::SET_COOKIE,
            format!("{}=; {}; Max-Age=0", frontdoor::session::SHELL_COOKIE, frontdoor::session::COOKIE_ATTRIBUTES)
                .parse()
                .map_err(|_| codes::SUPERVISOR_STATE)?,
        );
        Ok(response)
    }

    /// The owner origin clears its own host cookie; cleanup also succeeds after shell sign-out revoked it.
    pub(super) fn owner_sign_out(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        use frontdoor::session::{session_digest, SessionScope, SessionStore as _, COOKIE_ATTRIBUTES, OWNER_COOKIE};
        let mut sessions = self.sessions()?;
        if let Some(cookie) = request.cookie() {
            let digest = session_digest(cookie)?;
            if let Some(record) = sessions.lookup(digest)? {
                if record.scope == SessionScope::Shell || record.origin != *request.origin() {
                    return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
                }
            }
            sessions.revoke(digest)?;
        }
        let mut response = super::json_response(Value::object(vec![("ended".into(), Value::boolean(true))])?)?;
        response.headers_mut().insert(
            http::header::SET_COOKIE,
            format!("{OWNER_COOKIE}=; {COOKIE_ATTRIBUTES}; Max-Age=0")
                .parse()
                .map_err(|_| codes::SUPERVISOR_STATE)?,
        );
        Ok(response)
    }

    /// `GET /engine/model-key` on the shell origin: the one page where the owner types the provider key
    /// (`model_key_page.rs`). The Models row on the engine origin links here and never holds the key itself. Nothing on
    /// it is the node's state; the key goes to `POST /api/engine/model-key` and is never shown again.
    pub(super) fn model_key_page(&self) -> Result<http::Response<Vec<u8>>> {
        self.model_broker.as_ref().ok_or(codes::FRONTDOOR_UNKNOWN_ROUTE)?;
        let (page, policy) = model_key_page::page();
        http::Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .header("content-security-policy", policy)
            .header("cache-control", "no-store")
            .header("referrer-policy", "no-referrer")
            .header("x-frame-options", "DENY")
            .header("x-content-type-options", "nosniff")
            .body(page.into_bytes())
            .map_err(|_| codes::SUPERVISOR_STATE)
    }

    /// `POST /api/engine/model-key` on the shell origin, `{"key": "sk-..."}`, from the bound owner's shell session (the
    /// frontdoor already required same-origin, JSON and one Origin). The key is held by the broker; the passkey decides.
    pub(super) fn model_key_entry(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        let broker = self.model_broker.as_ref().ok_or(codes::FRONTDOOR_UNKNOWN_ROUTE)?;
        if request.method() != frontdoor::ingress::Method::Post {
            return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
        }
        self.with_release(|_| Ok(()))?;
        let key = match request.body().view() {
            canon::json::ValueView::Object(fields) if fields.len() == 1 => match request.body().get("key").map(Value::view) {
                Some(canon::json::ValueView::Text(key)) => key.trim().to_owned(),
                _ => return Err(codes::BROKER_KEY_INVALID),
            },
            _ => return Err(codes::BROKER_KEY_INVALID),
        };
        let mut sessions = self.sessions()?;
        let scope = frontdoor::session::with_bound_session(
            &mut sessions,
            request.cookie().ok_or(codes::FRONTDOOR_SESSION_REQUIRED)?,
            self.state.node,
            request.origin(),
            now()?,
            |session| {
                let record = session.record();
                if record.scope != frontdoor::session::SessionScope::Shell {
                    return Err(codes::FRONTDOOR_COOKIE_HOST_REFUSED);
                }
                let scope = PrincipalScope {
                    subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
                    epoch: record.owner_epoch,
                };
                if self.ledger.binding()? != BindingState::Bound(scope) {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                Ok(scope)
            },
        )?;
        drop(sessions);
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        let staged = runtime.block_on(broker.stage_key(scope, key, now()?))?;
        let (state, fingerprint) = match staged {
            crate::model_broker::KeyStage::Active(fingerprint) => ("active", fingerprint),
            crate::model_broker::KeyStage::AwaitingApproval(fingerprint) => ("awaiting-approval", fingerprint),
        };
        super::json_response(Value::object(vec![
            ("fingerprint".into(), Value::text(fingerprint)?),
            ("state".into(), Value::text(state.to_owned())?),
        ])?)
    }
}

fn with_engine_refusal(snapshot: Value, refusal: Option<&str>) -> Result<Value> {
    let canon::json::ValueView::Object(fields) = snapshot.view() else { return Err(codes::SUPERVISOR_STATE) };
    let mut fields = fields.to_vec();
    fields.push(("engine_refusal".into(), match refusal {
        Some(reason) => Value::text(format!("supervisor:{reason}"))?,
        None => Value::null(),
    }));
    let snapshot = Value::object(fields)?;
    frontdoor::api::JsonData::new(&snapshot)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_notice_keeps_the_approval_snapshot_intact() {
        let snapshot = canon::json::parse_strict(br#"{"declined":[],"proposals":[{"expires_at_ms":1,"proposal":"0123456789abcdef0123456789abcdef"}],"sequence":7}"#).unwrap();
        let result = with_engine_refusal(snapshot.clone(), Some("authority-plugin-missing")).unwrap();
        for field in ["declined", "proposals", "sequence"] {
            assert_eq!(result.get(field), snapshot.get(field));
        }
        assert_eq!(result.get("engine_refusal"), Some(&Value::text("supervisor:authority-plugin-missing".into()).unwrap()));
        assert_eq!(with_engine_refusal(snapshot, None).unwrap().get("engine_refusal"), Some(&Value::null()));
    }
}
