/* Model screen (OWNER-API §8): whether a key is set (fingerprint only) and
   the live grant (spent / cap in dollars, expiry). "Set key" hashes the key
   locally, proposes the hash, and sends the owner to the approval card; the
   key itself is delivered once by the approvals screen after the approval is
   applied (keyflow.js). "New grant" validates client-side, proposes, and goes
   to the same card. */

import { ownerRoute } from '../embed.js';
import { api } from '../api.js';
import { ICONS } from '../icons.js';
import { keyFlow } from '../keyflow.js';
import { validateGrant, microToUsd } from '../grant.js';

const PROVIDER_REFUSALS = new Map([
  ['broker:provider-key-rejected', 'the provider rejected the model key: replace it on the owner page'],
  ['broker:provider-no-credit', 'the provider account has no credit'],
  ['broker:provider-rate-limited', 'the provider is rate limiting: try again shortly'],
  ['broker:provider-request-rejected', 'the provider rejected the request: model name or parameters'],
  ['broker:provider-unavailable', 'the provider is unavailable'],
  ['broker:provider-refused', 'the provider refused the call'],
]);

export async function showModel(app) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage';
  app.appendChild(panel);

  const h = document.createElement('h1');
  h.className = 'wordless';
  h.innerHTML = ICONS.model;
  panel.appendChild(h);

  let info;
  try {
    info = await api.broker();
  } catch (ex) {
    const err = document.createElement('p');
    err.className = 'instruct warn';
    err.textContent = ex.code ?? String(ex);
    panel.appendChild(err);
    return;
  }

  if (info.last_refusal) {
    const refusal = document.createElement('p');
    refusal.className = 'instruct warn';
    // Provider text and unknown codes never enter the display.
    const message = PROVIDER_REFUSALS.get(info.last_refusal.code) ?? 'the model call was refused';
    refusal.textContent = `last model refusal: ${message}`;
    panel.appendChild(refusal);
  }

  // ---- key ---------------------------------------------------------------
  const keyLine = document.createElement('p');
  keyLine.className = 'instruct';
  if (info.key?.present) {
    keyLine.textContent = 'key set · fingerprint ';
    const fp = document.createElement('code');
    fp.textContent = info.key.sha256_prefix; // fingerprint only, never the key
    keyLine.appendChild(fp);
  } else {
    keyLine.textContent = 'no key set';
    keyLine.classList.add('muted');
  }
  panel.appendChild(keyLine);

  const keyForm = document.createElement('form');
  keyForm.className = 'form-row';
  const keyInput = document.createElement('input');
  keyInput.type = 'password';
  keyInput.autocomplete = 'off';
  keyInput.placeholder = 'model provider key';
  keyInput.setAttribute('aria-label', 'model provider key');
  keyInput.required = true;
  const keyGo = document.createElement('button');
  keyGo.type = 'submit';
  keyGo.className = 'primary';
  keyGo.textContent = 'set key';
  keyForm.append(keyInput, keyGo);
  const keyErr = document.createElement('p');
  keyErr.className = 'instruct warn';
  keyErr.hidden = true;
  panel.append(keyForm, keyErr);

  keyForm.onsubmit = async e => {
    e.preventDefault();
    keyGo.disabled = true;
    keyErr.hidden = true;
    const key = keyInput.value;
    keyInput.value = ''; // out of the DOM at once; it never goes back in
    if (!key) { keyGo.disabled = false; return; }
    try {
      // A fingerprint the owner already approved (the key was lost on a reload) takes the
      // key directly; otherwise the hash is proposed for a passkey approval first.
      const delivered = await api.brokerKeyDeliverApproved(key).catch(ex => {
        if (ex.code === 'broker:key-not-approved') return null;
        throw ex;
      });
      if (delivered) {
        showModel(app);
        return;
      }
      await keyFlow.proposeKey(key); // hashes locally, holds the key in memory only
      location.hash = ownerRoute(location.hash).embedded ? '#/embed/approvals' : '#/approvals';
    } catch (ex) {
      keyFlow.discard(keyFlow.pendingId());
      keyErr.textContent = ex.code ?? String(ex);
      keyErr.hidden = false;
      keyGo.disabled = false;
    }
  };

  // ---- grant ---------------------------------------------------------------
  const grantLine = document.createElement('div');
  grantLine.className = 'grant-status';
  if (info.grant) {
    const g = info.grant;
    const line = (label, value) => {
      const p = document.createElement('p');
      p.className = 'instruct';
      p.textContent = `${label} `;
      const v = document.createElement('code');
      v.textContent = value;
      p.appendChild(v);
      grantLine.appendChild(p);
    };
    line('grant', g.model);
    line('spent / cap', `$${microToUsd(g.spent_microusd)} / $${microToUsd(g.cap_microusd)}`);
    line('expires', new Date(g.expires_at).toLocaleString());
    if (g.frozen) line('frozen', 'yes');
  } else {
    const p = document.createElement('p');
    p.className = 'instruct muted';
    p.textContent = 'no active grant';
    grantLine.appendChild(p);
  }
  panel.appendChild(grantLine);

  const grantForm = document.createElement('form');
  grantForm.className = 'form-grid';
  const modelSel = document.createElement('select');
  modelSel.setAttribute('aria-label', 'model');
  for (const m of info.models ?? []) {
    const opt = document.createElement('option');
    opt.value = m;
    opt.textContent = m;
    modelSel.appendChild(opt);
  }
  const field = (label, inputmode) => {
    const input = document.createElement('input');
    input.type = 'text';
    input.inputMode = inputmode;
    input.placeholder = label;
    input.setAttribute('aria-label', label);
    input.required = true;
    return input;
  };
  const capIn = field('cap $', 'decimal');
  const perReqIn = field('per request $', 'decimal');
  const maxReqIn = field('max requests', 'numeric');
  const hoursIn = field('hours (1-24)', 'numeric');
  const grantGo = document.createElement('button');
  grantGo.type = 'submit';
  grantGo.className = 'primary';
  grantGo.textContent = 'new grant';
  grantForm.append(modelSel, capIn, perReqIn, maxReqIn, hoursIn, grantGo);
  const grantErr = document.createElement('p');
  grantErr.className = 'instruct warn';
  grantErr.hidden = true;
  panel.append(grantForm, grantErr);

  grantForm.onsubmit = async e => {
    e.preventDefault();
    grantGo.disabled = true;
    grantErr.hidden = true;
    try {
      const grant = validateGrant({
        model: modelSel.value,
        capUsd: capIn.value.trim(),
        perRequestUsd: perReqIn.value.trim(),
        maxRequests: maxReqIn.value.trim(),
        hours: hoursIn.value.trim(),
      }, info.models ?? []);
      await api.brokerGrantPropose(grant);
      location.hash = ownerRoute(location.hash).embedded ? '#/embed/approvals' : '#/approvals';
    } catch (ex) {
      grantErr.textContent = ex.code ?? String(ex);
      grantErr.hidden = false;
      grantGo.disabled = false;
    }
  };
}
