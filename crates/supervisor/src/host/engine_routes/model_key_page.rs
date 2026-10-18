// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner's DeepSeek key page on the SHELL origin (`GET https://<shell>/engine/model-key`, NODE.md section 7): the one
//! place the key is meant to be typed. The Models row of the Spatial face (engine origin) only links here, and engine
//! script cannot read this origin. What that does not cover: the engine can draw a lookalike form of its own on
//! engine.<shell>, and a key typed there is the engine's. The browser cannot stop that; the owner's address-bar check
//! can, so the page names its exact address and asks for it (advice, not an enforced barrier).
//!
//! One self-contained page: the primitives (`primitives.css`, verbatim, SPATIAL-DESIGN-RULES rule 10) and the page's
//! own style and script are inline and pinned by hash in a strict CSP (no other source, no inline handler, no frame
//! ancestor, no form action). The script sends the key once to `POST /api/engine/model-key`, clears the field before
//! the request leaves, and never writes the key anywhere; the reply's 12-hex fingerprint is the only thing it shows.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};

/// The primitives, byte for byte the face's copy (`ui/owner/primitives.css` is the same file).
const PRIMITIVES: &str = include_str!("../../../../../engine/plugins/aukora-face/layout/src/client/primitives/primitives.css");

/// The page and its Content-Security-Policy.
pub(super) fn page() -> (String, String) {
    let hash = |text: &str| format!("'sha256-{}'", STANDARD.encode(Sha256::digest(text.as_bytes())));
    let policy = format!(
        "default-src 'none'; script-src {}; style-src {} {}; img-src 'none'; connect-src 'self'; form-action 'none'; \
         frame-ancestors 'none'; base-uri 'none'",
        hash(SCRIPT),
        hash(PRIMITIVES),
        hash(STYLE)
    );
    let body = BODY.replace("GLYPH", GLYPH);
    let page = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width, initial-scale=1\"><meta name=\"color-scheme\" content=\"dark\">\
         <title>DeepSeek key</title><style>{PRIMITIVES}</style><style>{STYLE}</style></head><body>{body}\
         <script>{SCRIPT}</script></body></html>"
    );
    (page, policy)
}

const GLYPH: &str = "viewBox=\"0 0 24 24\" aria-hidden=\"true\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.4\" \
stroke-linecap=\"round\" stroke-linejoin=\"round\"";

/// The markup. Glyphs are the primitives' own (`icons.tsx`: model, approvals, lock, out).
const BODY: &str = concat!(
    "<main class=\"ak-app ak-tone-mint\"><div class=\"ak-canvas\">",
    "<header class=\"ak-header\"><div class=\"ak-header__copy\"><p class=\"ak-header__eyebrow\">Settings · Models</p>",
    "<h1 class=\"ak-header__title\">DeepSeek key</h1></div><div class=\"ak-header__badges\">",
    "<span class=\"ak-badge ak-tone-mint\"><svg GLYPH><rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2.5\"/>",
    "<path d=\"M8 11V8a4 4 0 0 1 8 0v3\"/></svg>Outside the engine</span></div></header>",
    "<p class=\"ak-lead\">Your key goes to your node's broker, outside the wall. Auma's engine never sees it; it can only \
     ask the broker to make a call. Your passkey approves the key next.</p>",
    // The one check only the owner can make: a page the engine serves could imitate this one, but not its address. The
    // script fills in this page's own host (the address to learn); without it the line still reads.
    "<p class=\"address\" id=\"address\">Check the address bar: your key page is always <b id=\"host\">your node's \
     own address</b>. Never type your key on a page whose address starts with engine.</p>",
    // Step 1: the one field.
    "<section class=\"ak-portal ak-tone-mint\" data-open=\"yes\" aria-labelledby=\"s1\">",
    "<div class=\"ak-portal__head\"><span class=\"ak-icon-tile\"><svg GLYPH><path d=\"M12 3c.6 4.8 3.2 7.4 8 8-4.8.6-7.4 \
     3.2-8 8-.6-4.8-3.2-7.4-8-8 4.8-.6 7.4-3.2 8-8Z\"/></svg></span><span class=\"ak-portal__copy\">",
    "<span class=\"ak-portal__title\" id=\"s1\">Your DeepSeek API key</span><span class=\"ak-portal__summary\">Typed \
     here, on your node's own page. Never shown again.</span></span><span class=\"ak-portal__end\">",
    "<span class=\"ak-pill ak-tone-mint\">Step 1</span></span></div>",
    "<form id=\"f\" class=\"ak-portal__body\" method=\"post\" autocomplete=\"off\"><label class=\"ak-label\" for=\"key\">API key</label>",
    "<input id=\"key\" class=\"key-field\" type=\"password\" autocomplete=\"off\" autocapitalize=\"off\" \
     autocorrect=\"off\" spellcheck=\"false\" placeholder=\"sk-…\" minlength=\"16\" maxlength=\"4096\" required>",
    "<div class=\"ak-actionrow\"><button class=\"ak-action ak-tone-mint\" type=\"submit\" id=\"send\">Hand it to your \
     node</button><span class=\"ak-action__note\">A new key takes over as soon as its card is up. While it waits for \
     approval, Auma can't reach the model. If you decline it, enter a key again.</span></div>\
     <p id=\"out\" role=\"status\" aria-live=\"polite\"></p></form></section>",
    // Step 2: the passkey.
    "<section class=\"ak-portal ak-tone-blue\" id=\"step2\" data-open=\"no\" aria-labelledby=\"s2\">",
    "<div class=\"ak-portal__head\"><span class=\"ak-icon-tile\"><svg GLYPH><circle cx=\"12\" cy=\"12\" r=\"8\"/>",
    "<path d=\"m8.5 12.2 2.4 2.4 4.6-5\"/></svg></span><span class=\"ak-portal__copy\"><span class=\"ak-portal__title\" \
     id=\"s2\">Approve it with your passkey</span><span class=\"ak-portal__summary\" id=\"s2sum\">After you hand over \
     the key, one card asks for it.</span></span><span class=\"ak-portal__end\"><span class=\"ak-pill ak-tone-blue\" \
     id=\"s2pill\">Step 2</span></span></div>",
    "<div class=\"ak-portal__body\" id=\"s2body\" hidden><p class=\"ak-label\">Fingerprint</p>",
    "<p class=\"fingerprint\" id=\"fp\"></p><dl class=\"ak-fields\"><dt>Card</dt><dd>engine/model-key.json</dd>",
    "<dt>Check</dt><dd>its key_sha256 begins with these 12 digits</dd></dl>",
    "<div class=\"ak-actionrow\" id=\"approve\"><a class=\"ak-action ak-tone-blue\" href=\"/\"><svg GLYPH>",
    "<rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2.5\"/><path d=\"M8 11V8a4 4 0 0 1 8 0v3\"/></svg>Open your \
     approvals<svg GLYPH><path d=\"M9 6h9v9\"/><path d=\"M18 6 7 17\"/></svg></a><span class=\"ak-action__note\">Your \
     node opens the card; your passkey decides.</span></div></div></section>",
    "<p class=\"ak-footnote\"><a id=\"back\" class=\"back\" href=\"/engine/open\">Back to Auma</a></p>",
    "</div></main>"
);

/// The page's own layout on top of the primitives: the dark spatial canvas (the shell's, at night), one field, the
/// fingerprint large enough to compare at a glance.
const STYLE: &str = ":root{color-scheme:dark}*{box-sizing:border-box}[hidden]{display:none!important}\
html,body{margin:0;min-height:100%}body{min-height:100vh;color:var(--ak-text);font:14px/1.5 system-ui,-apple-system,\
'Segoe UI',sans-serif;background:radial-gradient(1200px 800px at 18% -10%,rgba(129,212,180,.1),transparent 60%),\
radial-gradient(1100px 760px at 82% 110%,rgba(196,170,255,.12),transparent 60%),radial-gradient(900px 700px at 50% 50%,\
rgba(150,180,255,.07),transparent 65%),linear-gradient(160deg,rgb(9,10,18) 0%,rgb(11,13,24) 55%,rgb(8,9,16) 100%);\
background-attachment:fixed}.ak-app{height:auto;min-height:100vh;overflow:visible;padding:clamp(24px,9vh,96px) 16px}\
.ak-canvas{width:min(100%,560px)}.ak-portal__head{cursor:default}.ak-portal[data-open='no'] .ak-portal__summary{\
color:var(--ak-muted)}.key-field{display:block;width:100%;min-height:42px;padding:9px 12px;border:1px solid \
var(--ak-hairline);border-radius:var(--ak-tile-radius);background:transparent;color:var(--ak-text);\
font:13px/22px var(--ak-mono);letter-spacing:.04em;transition:border-color var(--ak-ease),box-shadow var(--ak-ease)}\
.key-field:focus{border-color:color-mix(in srgb,var(--ak-mint) 70%,transparent);box-shadow:0 0 14px \
color-mix(in srgb,var(--ak-mint) 14%,transparent);outline:none}.ak-actionrow{margin-top:12px}\
.ak-action:disabled{opacity:.5;cursor:default}#out{min-height:18px;margin:10px 0 0;color:var(--ak-muted);\
font-size:11.5px}#out[data-tone='bad']{color:var(--ak-red)}#out[data-tone='gold']{color:var(--ak-gold)}\
.fingerprint{margin:0 0 10px;color:var(--ak-blue);font:500 24px/32px var(--ak-mono);letter-spacing:.16em}\
.address{margin:-6px 0 0;padding:8px 12px;border:1px solid var(--ak-hairline);border-radius:var(--ak-tile-radius);\
color:var(--ak-text-2);font-size:12px;line-height:18px}.back{color:var(--ak-muted);text-decoration:none}.back:hover{color:var(--ak-text)}";

/// Sends the key once and forgets it: the field is cleared before the request leaves, and only the reply's fingerprint
/// (12 hex digits of its SHA-256) is ever written to the page, as text.
const SCRIPT: &str = "'use strict';const $=(id)=>document.getElementById(id);const form=$('f'),input=$('key'),\
out=$('out'),send=$('send');const say=(text,tone)=>{out.textContent=text;if(tone)out.dataset.tone=tone;else delete \
out.dataset.tone};const plain={'frontdoor:session-required':'Sign in to your node first: open it, then come back here.',\
'frontdoor:session-expired':'Your sign-in to your node ended: open it again, then come back here.',\
'aumlok:binding-required':'Sign in to your node first: open it, then come back here.','broker:key-invalid':\
'That is not a DeepSeek API key (it begins with sk-).','gate:awaiting-other-approval':'Another key is waiting for your \
passkey: approve or decline that card first.'};const step2=(fingerprint,active)=>{$('step2').dataset.open='yes';\
$('s2body').hidden=false;$('fp').textContent=fingerprint.match(/.{4}/g).join(' ');$('approve').hidden=active;\
$('s2sum').textContent=active?'Already approved: this is the key your node uses.':'Your card is up: compare \
the fingerprint, then approve.';$('s2pill').textContent=active?'Approved':'Waiting for you'};form.addEventListener(\
'submit',async(e)=>{e.preventDefault();const key=input.value.trim();input.value='';if(!key){return}send.disabled=true;\
say('Handing it to your node…');try{const r=await fetch('/api/engine/model-key',{method:'POST',headers:\
{'content-type':'application/json'},body:JSON.stringify({key}),credentials:'same-origin',cache:'no-store',\
redirect:'error'});const j=await r.json();if(!r.ok){const code=typeof j.error==='string'?j.error:String(r.status);\
say(plain[code]||('Your node refused it: '+code),'bad');return}if(typeof j.fingerprint!=='string'||\
!/^[0-9a-f]{12}$/.test(j.fingerprint)){say('Your node gave an answer this page does not read.','bad');return}\
const active=j.state==='active';step2(j.fingerprint,active);say(active?'Your node already holds this key, approved.':\
'Your node holds the key. Until you approve it, Auma can’t reach the model.',active?undefined:'gold')}catch(_){\
say('Your node did not answer.','bad')}finally{send.disabled=false}});$('host').textContent=location.origin+\
'/engine/model-key';if(location.hash==='#from=models'){$('back').addEventListener('click',(e)=>{\
e.preventDefault();window.close();setTimeout(()=>location.assign('/engine/open'),300)})}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_is_self_contained_and_pinned_and_never_holds_a_key() {
        let (page, policy) = page();
        // Everything inline is pinned; nothing else may load or run, nothing may frame it, the form posts nowhere.
        for directive in [
            "default-src 'none'", "img-src 'none'", "connect-src 'self'", "form-action 'none'", "frame-ancestors 'none'",
            "base-uri 'none'",
        ] {
            assert!(policy.contains(directive), "{directive}");
        }
        assert!(!policy.contains("unsafe-inline") && !policy.contains("unsafe-eval") && !policy.contains("http"));
        assert_eq!(policy.matches("'sha256-").count(), 3, "one script and two styles");
        assert_eq!(page.matches("<script>").count(), 1);
        assert_eq!(page.matches("<style>").count(), 2);
        assert!(!page.contains(" onclick=") && !page.contains(" onsubmit=") && !page.contains(" onload="), "no inline handler");
        assert!(!page.contains("src=") && !page.contains("<link") && !page.contains("<iframe"));
        // The address check, said once and calmly.
        assert!(page.contains("Check the address bar: your key page is always <b id=\"host\">your node's own address</b>. \
                               Never type your key on a page whose address starts with engine."));
        assert!(SCRIPT.contains("$('host').textContent=location.origin+'/engine/model-key'"), "the exact address, as text");
        // A new key's card refuses calls until it is approved; declining does not restore the old key. Say so.
        assert!(page.contains("While it waits for approval, Auma can't reach the model. If you decline it, enter a key again."));
        assert!(!page.contains("wait for your passkey") && !SCRIPT.contains("Auma can use this key now"));
        // The one field: masked, never autofilled, never spell-checked; nothing on the page is a key.
        assert_eq!(page.matches("<input").count(), 1);
        for attribute in ["type=\"password\"", "autocomplete=\"off\"", "spellcheck=\"false\"", "autocapitalize=\"off\""] {
            assert!(page.contains(attribute), "{attribute}");
        }
        assert!(!page.contains("sk-0") && !page.contains(" value=\""), "the field starts empty");
        // Even a native submit (script blocked or failed) carries no key: the field has no name, the form posts (never a
        // GET with the key in the address), CSP form-action 'none' blocks it, and the shell refuses any query string.
        let input = &page[page.find("<input").unwrap()..];
        let input = &input[..input.find('>').unwrap()];
        assert!(!input.contains("name="), "no named field, so a native submit has nothing to send: {input}");
        assert_eq!(page.matches("<form ").count(), 1);
        assert!(page.contains("<form id=\"f\" class=\"ak-portal__body\" method=\"post\""));
        assert!(SCRIPT.contains("preventDefault()"));
        assert!(frontdoor::ingress::validate_path("/engine/model-key").is_ok());
        for path in ["/engine/model-key?deepseek-key=sk-123", "/engine/model-key?", "/engine/model-key#x"] {
            assert!(frontdoor::ingress::validate_path(path).is_err(), "{path}");
        }
        // The primitives are the face's file, verbatim, and the glyph placeholder was filled in.
        assert!(page.contains(PRIMITIVES) && PRIMITIVES.contains(".ak-portal__head"));
        assert_eq!(PRIMITIVES, include_str!("../../../../../ui/owner/primitives.css"), "the owner origin's copy is the same");
        assert!(!page.contains("GLYPH") && page.contains("stroke-width=\"1.4\""));
    }

    #[test]
    fn the_script_clears_the_field_before_sending_and_writes_only_text() {
        let clear = SCRIPT.find("input.value=''").unwrap();
        let fetch = SCRIPT.find("fetch(").unwrap();
        assert!(clear < fetch, "the field is empty before the request leaves");
        assert!(!SCRIPT.contains("innerHTML") && !SCRIPT.contains("insertAdjacentHTML") && !SCRIPT.contains("document.write"));
        assert!(!SCRIPT.contains("localStorage") && !SCRIPT.contains("sessionStorage") && !SCRIPT.contains("console"));
        // The fingerprint is shown only if it is exactly 12 hex digits.
        assert!(SCRIPT.contains("/^[0-9a-f]{12}$/.test(j.fingerprint)"));
        // Back to the app: the shell's own hand-off to the engine origin, never a link into the engine with a key.
        assert!(BODY.contains("href=\"/engine/open\"") && BODY.contains("href=\"/\""));
    }
}
