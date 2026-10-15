/* Claim + first passkey enrolment (SPEC §5 bootstrap: claim opens the session,
   then the first and only passkey enrolment). */

import { api, decodeCreationOptions, decodeRequestOptions, encodeAssertion, encodeAttestation } from '../api.js';
import { ICONS } from '../icons.js';
import { takeLinkClaim } from '../claim-link.js';

const devBypassOk = resp =>
  resp && resp.dev_bypass === true && ['localhost', '127.0.0.1'].includes(location.hostname);

export async function showClaim(app, { stage, onDone }) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage';
  app.appendChild(panel);

  if (stage === 'claim') {
    const h = document.createElement('h1');
    h.className = 'wordless';
    h.innerHTML = ICONS.key;
    panel.appendChild(h);

    const form = document.createElement('form');
    const input = document.createElement('input');
    input.type = 'password';
    input.autocomplete = 'off';
    input.placeholder = 'claim token';
    input.setAttribute('aria-label', 'claim token');
    input.required = true;
    const go = document.createElement('button');
    go.type = 'submit';
    go.className = 'primary';
    go.textContent = 'claim';
    form.append(input, go);
    form.style.display = 'flex';
    form.style.gap = '10px';

    // A claim link arrives as #claim=<token>: the fragment never reaches a server,
    // and claim-link.js scrubs it from the address bar as soon as the page loads.
    const fromLink = takeLinkClaim();
    if (fromLink) input.value = fromLink;

    const err = document.createElement('p');
    err.className = 'instruct warn';
    err.hidden = true;

    form.onsubmit = async e => {
      e.preventDefault();
      go.disabled = true;
      err.hidden = true;
      try {
        await api.claim(input.value.trim());
        onDone();
      } catch (ex) {
        err.textContent = ex.code ?? String(ex);
        err.hidden = false;
        go.disabled = false;
      }
    };
    panel.append(form, err);
    return;
  }

  // stage === 'enrol': one passkey, enrolled once, then enrolment closes.
  const h = document.createElement('h1');
  h.className = 'wordless';
  h.innerHTML = ICONS.key;
  panel.appendChild(h);

  const col = document.createElement('div');
  col.className = 'center-col';
  const note = document.createElement('p');
  note.className = 'instruct';
  note.textContent = 'Create the passkey that will authorise every change on this node. This happens once.';
  const btn = document.createElement('button');
  btn.className = 'primary';
  btn.textContent = 'create passkey';
  const err = document.createElement('p');
  err.className = 'instruct warn';
  err.hidden = true;
  col.append(note, btn, err);
  panel.appendChild(col);

  btn.onclick = async () => {
    btn.disabled = true;
    err.hidden = true;
    try {
      const started = await api.enrolStart();
      if (devBypassOk(started) || !window.PublicKeyCredential) {
        if (!devBypassOk(started)) throw Object.assign(new Error('no passkey support in this browser'), { code: 'aumlok:webauthn-unavailable' });
        await api.enrolFinish(started.enrolment_id, { kind: 'dev-bypass' });
      } else {
        // A registered but unproven passkey resumes at the possession step.
        let pending = started.state === 'possession-required' ? started : null;
        if (!pending) {
          const credential = await navigator.credentials.create({ publicKey: decodeCreationOptions(started.public_key) });
          if (!credential) throw Object.assign(new Error('cancelled'), { code: 'aumlok:enrol-cancelled' });
          const finished = await api.enrolFinish(started.enrolment_id, encodeAttestation(credential));
          if (finished?.state === 'possession-required') pending = finished;
        }
        if (pending) {
          const proof = await navigator.credentials.get({ publicKey: decodeRequestOptions(pending.public_key) });
          if (!proof) throw Object.assign(new Error('cancelled'), { code: 'aumlok:enrol-cancelled' });
          await api.enrolProve(pending.enrolment_id, encodeAssertion(proof));
        }
      }
      onDone();
    } catch (ex) {
      err.textContent = ex.code ?? String(ex);
      err.hidden = false;
      btn.disabled = false;
    }
  };
}
