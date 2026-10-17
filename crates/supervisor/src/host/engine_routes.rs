// SPDX-License-Identifier: AGPL-3.0-or-later
//! The host's side of the engine (deploy/engine/NODE.md): what the engine controller reads from the host, the
//! shell origin's `GET /engine/open`, which sends a bound owner to the engine origin with a one-time ticket, and the
//! shell origin's model-key entry (`GET /engine/model-key`, `POST /api/engine/model-key`, section 7).

use super::{now, Host};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use canon::{codes, json::Value, Result};
use sha2::{Digest, Sha256};
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
            _ => None,
        }
    }

    /// `POST /api/session/end` on the shell origin: sign out. The caller's own shell session is revoked in the store
    /// (with anything derived from it), every engine-origin session minted from it ends at once, and the browser's
    /// shell cookie is cleared (O12). Nothing else is touched: the owner origin's session and the binding stay.
    pub(super) fn shell_sign_out(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        use frontdoor::session::SessionStore as _;
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
        sessions.revoke(shell)?;
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

    /// `GET /engine/model-key` on the shell origin: one self-contained page where the owner types the provider key.
    /// Nothing on it is the node's state; the key goes to `POST /api/engine/model-key` and is never shown again.
    pub(super) fn model_key_page(&self) -> Result<http::Response<Vec<u8>>> {
        self.model_broker.as_ref().ok_or(codes::FRONTDOOR_UNKNOWN_ROUTE)?;
        let hash = |text: &str| format!("'sha256-{}'", STANDARD.encode(Sha256::digest(text.as_bytes())));
        let policy = format!(
            "default-src 'none'; script-src {}; style-src {}; connect-src 'self'; form-action 'none'; \
             frame-ancestors 'none'; base-uri 'none'",
            hash(MODEL_KEY_SCRIPT),
            hash(MODEL_KEY_STYLE)
        );
        let page = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
             content=\"width=device-width, initial-scale=1\"><title>Model key</title><style>{MODEL_KEY_STYLE}</style>\
             </head><body><main><h1>DeepSeek key for Auma</h1><p>Type or paste your own DeepSeek API key. It stays in \
             your node's broker and never enters the engine. You approve it next with your passkey.</p>\
             <form id=\"f\"><input id=\"key\" type=\"password\" autocomplete=\"off\" spellcheck=\"false\" \
             placeholder=\"sk-...\" required><button type=\"submit\">Hand to the broker</button></form>\
             <p id=\"out\" role=\"status\"></p></main><script>{MODEL_KEY_SCRIPT}</script></body></html>"
        );
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

const MODEL_KEY_STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#0d0d10;color:#ececf1}\
main{max-width:34rem;margin:12vh auto;padding:0 1rem}input{width:100%;box-sizing:border-box;padding:.7rem;\
font:inherit;border-radius:.5rem;border:1px solid #444;background:#16161b;color:inherit}button{margin-top:.8rem;\
padding:.6rem 1rem;font:inherit;border-radius:.5rem;border:0;background:#e8e8ee;color:#111}#out{min-height:3em}";

/// Sends the key once and forgets it: the field is cleared before the request leaves.
const MODEL_KEY_SCRIPT: &str = "document.getElementById('f').addEventListener('submit',async(e)=>{e.preventDefault();\
const input=document.getElementById('key');const out=document.getElementById('out');const key=input.value.trim();\
input.value='';out.textContent='Sending to your node...';try{const r=await fetch('/api/engine/model-key',\
{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({key}),credentials:'same-origin',\
cache:'no-store'});const j=await r.json();if(!r.ok){out.textContent='Refused: '+(j.error||r.status);return}\
out.textContent=j.state==='active'?'This key ('+j.fingerprint+') is already approved: Auma can use it now.':\
'Now approve the card for engine/model-key.json with your passkey (Approvals). Its key_sha256 must begin with '+\
j.fingerprint+'.'}catch(_){out.textContent='Your node did not answer.'}});";
