/* Sign-in (OWNER-API §7): the node is already bound or released but this
   browser holds no session. One action — the passkey — runs
   navigator.credentials.get over the server's options, then state reloads.
   The claim screen stays for unclaimed nodes. */

import { api, decodeRequestOptions, encodeAssertion } from '../api.js';
import { ICONS } from '../icons.js';

const devBypassOk = resp =>
  resp && resp.dev_bypass === true && ['localhost', '127.0.0.1'].includes(location.hostname);

export async function showSignIn(app, { onDone }) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage';
  app.appendChild(panel);

  const h = document.createElement('h1');
  h.className = 'wordless';
  h.innerHTML = ICONS.key;
  panel.appendChild(h);

  const col = document.createElement('div');
  col.className = 'center-col';
  const note = document.createElement('p');
  note.className = 'instruct';
  note.textContent = 'This node already knows its owner. Sign in with the passkey.';
  const btn = document.createElement('button');
  btn.className = 'primary';
  btn.textContent = 'sign in with passkey';
  const err = document.createElement('p');
  err.className = 'instruct warn';
  err.hidden = true;
  col.append(note, btn, err);
  panel.appendChild(col);

  btn.onclick = async () => {
    btn.disabled = true;
    err.hidden = true;
    try {
      const started = await api.signinStart();
      let assertion;
      if (devBypassOk(started) || !window.PublicKeyCredential) {
        if (!devBypassOk(started)) throw Object.assign(new Error('no passkey support in this browser'), { code: 'aumlok:webauthn-unavailable' });
        assertion = { kind: 'dev-bypass' };
      } else {
        const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(started.public_key) });
        if (!credential) throw Object.assign(new Error('cancelled'), { code: 'aumlok:signin-cancelled' });
        assertion = encodeAssertion(credential);
      }
      await api.signinFinish(started.ceremony_id, assertion);
      await onDone();
    } catch (ex) {
      err.textContent = ex.code ?? String(ex);
      err.hidden = false;
      btn.disabled = false;
    }
  };
}
