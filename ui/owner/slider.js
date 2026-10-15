/* Slider changes use the same exact-card passkey ceremony as other permissions. */
import { api, b64urlToBytes, decodeRequestOptions, encodeAssertion } from './api.js';
import { canonicalJSON, ownerAuthChallenge } from './canon.js';
import { browserSha256 } from './pentora.js';
import { mountCard } from './card.js';

const modes = ['ask', 'risky', 'limits'];
const labels = ['Ask me for everything', 'Ask me only for risky things', "Don't ask within today's limits"];
const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
const hash = value => browserSha256(new TextEncoder().encode(canonicalJSON(value)));
async function request(method, path, body) {
  const response = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const result = await response.json();
  if (!response.ok) throw Object.assign(new Error(result.error), { code: result.error });
  return result;
}

export async function mountSlider(parent) {
  const section = document.createElement('section');
  section.setAttribute('aria-label', 'When to ask for approval');
  parent.appendChild(section);
  const status = document.createElement('p');
  const error = document.createElement('p');
  error.className = 'instruct warn';
  section.append(status, error);
  try {
    let current = await request('GET', '/api/slider');
    const range = document.createElement('input');
    range.type = 'range'; range.min = '0'; range.max = '2'; range.step = '1';
    range.setAttribute('aria-label', 'Approval preference');
    const label = document.createElement('p');
    const count = document.createElement('input');
    count.type = 'number'; count.min = '1'; count.max = '1000000'; count.value = String(current.max_count || 20);
    count.setAttribute('aria-label', 'Maximum changes');
    const hours = document.createElement('input');
    hours.type = 'number'; hours.min = '1'; hours.max = '24'; hours.value = '24';
    hours.setAttribute('aria-label', 'Permission hours');
    const scope = document.createElement('div');
    const choices = (current.available_targets || []).map(target => {
      const row = document.createElement('label');
      const check = document.createElement('input'); check.type = 'checkbox';
      check.checked = (current.targets || []).includes(target);
      const name = document.createElement('span'); name.textContent = target;
      row.append(check, name); scope.appendChild(row);
      return { target, check };
    });
    const help = document.createElement('p');
    help.textContent = 'Maximum changes / hours (up to 24). Choose the exact files below. Risky changes always ask. Expiry or exhaustion asks again.';
    const prepare = document.createElement('button'); prepare.textContent = 'Review preference';
    const review = document.createElement('div');
    section.append(range, label, help, count, hours, scope, prepare, review);
    const show = () => {
      const index = Number(range.value);
      label.textContent = labels[index]; range.setAttribute('aria-valuetext', labels[index]);
    };
    const refresh = () => {
      range.value = String(Math.max(0, modes.indexOf(current.mode))); show();
      status.textContent = current.active ? `${labels[modes.indexOf(current.mode)]} · ${current.remaining} changes left · expires ${new Date(current.expires_at).toISOString()}` : 'Asking for every change';
    };
    range.oninput = show; refresh();
    prepare.onclick = async () => {
      prepare.disabled = true; error.textContent = ''; review.replaceChildren();
      try {
        const desired = { mode: modes[Number(range.value)], targets: choices.filter(c => c.check.checked).map(c => c.target),
          max_count: Number(count.value), hours: Number(hours.value) };
        if (desired.mode === 'ask') { desired.targets = []; desired.max_count = 0; }
        const raised = await request('POST', '/api/slider/propose', desired);
        const ch = await api.approvalChallenge(raised.id);
        const challenge = await ownerAuthChallenge(ch.auth, browserSha256);
        const sent = b64urlToBytes(ch.public_key.challenge);
        const record = JSON.parse(ch.card.from_to.new);
        if (ch.id !== raised.id || ch.auth.proposal !== raised.id || ch.auth.op !== 'permission'
          || ch.auth.target !== 'gate/permission' || ch.auth.display_sha256 !== ch.display_sha256
          || hex(await hash(ch.card)) !== ch.display_sha256
          || hex(await browserSha256(new TextEncoder().encode(ch.card.from_to.new))) !== ch.auth.new_sha256
          || record.mode !== desired.mode || canonicalJSON(record.targets) !== canonicalJSON(desired.targets)
          || record.max_count !== desired.max_count || canonicalJSON(record.kinds) !== '["put"]'
          || sent.length !== challenge.length || !challenge.every((byte, i) => byte === sent[i])) {
          throw Object.assign(new Error('gate:permission-mismatch'), { code: 'gate:permission-mismatch' });
        }
        mountCard(review, ch.card);
        const approve = document.createElement('button'); approve.textContent = 'Approve preference with passkey';
        review.appendChild(approve);
        approve.onclick = async () => {
          approve.disabled = true;
          try {
            if (!window.PublicKeyCredential) throw new Error('aumlok:webauthn-unavailable');
            const credential = await navigator.credentials.get({ publicKey: { ...decodeRequestOptions(ch.public_key), userVerification: 'required' } });
            if (!credential) throw new Error('aumlok:approval-cancelled');
            const result = await api.approvalDecide(raised.id, true, encodeAssertion(credential));
            if (result.state !== 'applied') throw new Error(`gate:${result.state}`);
            current = await request('GET', '/api/slider'); refresh(); review.replaceChildren();
          } catch (ex) { error.textContent = ex.code || ex.message; approve.disabled = false; }
        };
      } catch (ex) { error.textContent = ex.code || ex.message; }
      finally { prepare.disabled = false; }
    };
  } catch (ex) { error.textContent = ex.code || ex.message || 'gate:slider-unavailable'; }
  return section;
}
