// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner's view of the door's taint (crates/supervisor/DOOR.md, "Taint"), on the shell origin: `GET /engine/door`
//! (one self-contained page), `GET /api/engine/door` (the state) and `POST /api/engine/door/clear-taint` (the owner's
//! action that ends it). Both API routes need the bound owner's shell session; the engine origin cannot reach them
//! (another origin; the shell cookie is host-only and SameSite=Strict, and the frontdoor requires same-origin JSON).

use super::{now, Host};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use canon::{codes, json::Value, Result};
use frontdoor::ingress::AdmittedRequest;
use sha2::{Digest, Sha256};
use supervisor::ingress::{BindingState, PrincipalScope};

impl Host {
    /// The bound owner behind this shell-origin request, or the refusal.
    fn bound_shell_owner(&self, request: &AdmittedRequest) -> Result<PrincipalScope> {
        let mut sessions = self.sessions()?;
        frontdoor::session::with_bound_session(
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
                let scope = PrincipalScope { subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?, epoch: record.owner_epoch };
                if self.ledger.binding()? != BindingState::Bound(scope) {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                Ok(scope)
            },
        )
    }

    fn door_state_value(&self) -> Result<Value> {
        let status = crate::door::taint_status(&self.config).map_err(|_| codes::FRONTDOOR_UNKNOWN_ROUTE)?;
        let tainted = status.is_some();
        let (since, cause) = status.unwrap_or((0, String::new()));
        Value::object(vec![
            ("cause".into(), Value::text(cause)?),
            ("since_ms".into(), Value::integer(canon::json::SafeInteger::new(since.max(0))?)),
            ("tainted".into(), Value::boolean(tainted)),
        ])
    }

    /// `GET /api/engine/door`: `{"tainted", "since_ms", "cause"}`.
    pub(super) fn door_status(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        self.bound_shell_owner(request)?;
        super::json_response(self.door_state_value()?)
    }

    /// `POST /api/engine/door/clear-taint` (`{}`): the owner says the engine is clean again; its net calls and memory
    /// writes go back to the slider and the grants.
    pub(super) fn door_clear_taint(&self, request: &AdmittedRequest) -> Result<http::Response<Vec<u8>>> {
        if request.method() != frontdoor::ingress::Method::Post {
            return Err(codes::FRONTDOOR_UNKNOWN_ROUTE);
        }
        self.bound_shell_owner(request)?;
        let was = crate::door::clear_taint(&self.config).map_err(|_| codes::SUPERVISOR_STATE)?;
        super::json_response(Value::object(vec![("cleared".into(), Value::boolean(was))])?)
    }

    /// `GET /engine/door`: the page. Nothing on it is state; the script asks `GET /api/engine/door`.
    pub(super) fn door_page(&self) -> Result<http::Response<Vec<u8>>> {
        crate::door::taint_status(&self.config).map_err(|_| codes::FRONTDOOR_UNKNOWN_ROUTE)?;
        let hash = |text: &str| format!("'sha256-{}'", STANDARD.encode(Sha256::digest(text.as_bytes())));
        let policy = format!(
            "default-src 'none'; script-src {}; style-src {}; connect-src 'self'; form-action 'none'; \
             frame-ancestors 'none'; base-uri 'none'",
            hash(DOOR_SCRIPT),
            hash(DOOR_STYLE)
        );
        let page = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
             content=\"width=device-width, initial-scale=1\"><title>Door</title><style>{DOOR_STYLE}</style></head><body>\
             <main><h1>Auma's door</h1><p id=\"state\" role=\"status\">Reading your node...</p><p>Once a fetched page \
             (or a memory note taken from the web) has reached Auma, every further web fetch and every memory write asks \
             you with a card, whatever your grants allow, until you say the engine is clean again. Do that only when \
             you have read what she fetched, or after starting fresh sessions.</p><button id=\"clear\" hidden>The engine \
             is clean again</button><p id=\"out\"></p></main><script>{DOOR_SCRIPT}</script></body></html>"
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
}

const DOOR_STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#0d0d10;color:#ececf1}\
main{max-width:34rem;margin:12vh auto;padding:0 1rem}button{margin-top:.8rem;padding:.6rem 1rem;font:inherit;\
border-radius:.5rem;border:0;background:#e8e8ee;color:#111}#out{min-height:3em}";

const DOOR_SCRIPT: &str = "const s=document.getElementById('state'),b=document.getElementById('clear'),o=document.\
getElementById('out');async function load(){try{const r=await fetch('/api/engine/door',{credentials:'same-origin',\
cache:'no-store'});const j=await r.json();if(!r.ok){s.textContent='Refused: '+(j.error||r.status);return}\
if(j.tainted){s.textContent='Tainted'+(j.since_ms?' since '+new Date(j.since_ms).toLocaleString():'')+' ('+j.cause+\
'): web fetches and memory writes each ask you.';b.hidden=false}else{s.textContent='Clean: your grants apply.';\
b.hidden=true}}catch(_){s.textContent='Your node did not answer.'}}b.addEventListener('click',async()=>{try{const r=\
await fetch('/api/engine/door/clear-taint',{method:'POST',headers:{'content-type':'application/json'},body:'{}',\
credentials:'same-origin',cache:'no-store'});const j=await r.json();o.textContent=r.ok?'Done.':'Refused: '+\
(j.error||r.status)}catch(_){o.textContent='Your node did not answer.'}load()});load();";
