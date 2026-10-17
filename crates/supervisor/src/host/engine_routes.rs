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
