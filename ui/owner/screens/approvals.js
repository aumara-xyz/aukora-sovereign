/* Gate cards are checked before a passkey prompt. Retire and reconcile show
   the fresh action card and require confirmation before the passkey prompt. */

import { api, decodeRequestOptions, encodeAssertion, b64urlToBytes } from '../api.js';
import { mountCard } from '../card.js';
import { canonicalJSON, ownerAuthChallenge } from '../canon.js';
import { browserSha256 } from '../pentora.js';
import { keyFlow } from '../keyflow.js';
import { ICONS } from '../icons.js';
import { mountNostrSendPreview } from '../nostr-preview.js';
import { mountSlider } from '../slider.js';

const devBypassOk = resp =>
  resp && resp.dev_bypass === true && ['localhost', '127.0.0.1'].includes(location.hostname);

const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const utf8 = s => new TextEncoder().encode(s);

async function checkChallenge(ch, id, operation) {
  const expected = await ownerAuthChallenge(ch.auth, browserSha256);
  const sent = b64urlToBytes(ch.public_key.challenge);
  if (ch.id !== id || ch.auth.proposal !== id || ch.auth.op !== operation
    || expected.length !== sent.length || !expected.every((b, i) => b === sent[i])) {
    throw Object.assign(new Error('challenge is not the authorization digest'), { code: 'gate:challenge-mismatch' });
  }
  if (ch.auth.display_sha256 !== ch.display_sha256) {
    throw Object.assign(new Error('card does not match authorization'), { code: 'gate:card-changed' });
  }
}

async function getAssertion(ch, allowDevBypass = true) {
  if (allowDevBypass && devBypassOk(ch)) return { kind: 'dev-bypass' };
  if (!window.PublicKeyCredential) {
    throw Object.assign(new Error('no passkey support in this browser'), { code: 'aumlok:webauthn-unavailable' });
  }
  const credential = await navigator.credentials.get({ publicKey: {
    ...decodeRequestOptions(ch.public_key), userVerification: 'required',
  } });
  if (!credential) throw Object.assign(new Error('cancelled'), { code: 'aumlok:approval-cancelled' });
  return encodeAssertion(credential);
}

function confirmAction(target, card, operation) {
  const review = document.createElement('div');
  const actionCard = mountCard(review, card);
  const actions = document.createElement('div');
  actions.className = 'actions';
  const confirm = document.createElement('button');
  confirm.className = 'primary';
  confirm.textContent = `confirm ${operation}`;
  const cancel = document.createElement('button');
  cancel.textContent = 'cancel';
  actions.append(confirm, cancel);
  actionCard.appendChild(actions);
  target.appendChild(review);
  return new Promise(resolve => {
    const finish = accepted => { actions.remove(); resolve(accepted); };
    confirm.onclick = () => finish(true);
    cancel.onclick = () => { review.remove(); finish(false); };
  });
}

export async function showApprovals(app, { onDecided, embedded = false } = {}) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage wide';
  app.appendChild(panel);

  const h = document.createElement('h1');
  h.className = 'wordless';
  h.innerHTML = ICONS.approvals;
  panel.appendChild(h);

  // Agent status (OWNER-API §9): one small icon, colour only; the pending
  // release approval, when there is one, is an ordinary card below.
  try {
    const rel = await api.release();
    const s = document.createElement('span');
    s.className = 'agent-status';
    s.dataset.agent = rel.agent;
    s.innerHTML = ICONS.agent;
    s.title = `agent ${rel.agent}`;
    s.setAttribute('aria-label', `agent ${rel.agent}`);
    h.appendChild(s);
    if (typeof rel.floor_refusal === 'string' && rel.floor_refusal) {
      const warn = document.createElement('p');
      warn.className = 'instruct warn';
      warn.textContent = rel.floor_refusal;
      panel.appendChild(warn);
    }
  } catch { /* the status is best-effort; approvals still render */ }

  await mountSlider(panel);

  let pending;
  try {
    ({ pending } = await api.approvals());
  } catch (ex) {
    const err = document.createElement('p');
    err.className = 'instruct warn';
    err.textContent = ex.code ?? String(ex);
    panel.appendChild(err);
    return;
  }

  if (pending.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-note';
    empty.textContent = 'nothing waits for approval';
    panel.appendChild(empty);
    return;
  }

  for (const item of pending) {
    const wrap = document.createElement('div');
    const cardEl = mountCard(wrap, item.card);

    // The card must hash to what the gate says it showed (display_sha256, C5/C6).
    let cardOk = false;
    try {
      const digest = await browserSha256(utf8(canonicalJSON(item.card)));
      cardOk = hex(new Uint8Array(digest)) === item.display_sha256;
    } catch { cardOk = false; }
    if (!cardOk) {
      cardEl.dataset.risk = 'critical';
      const warn = document.createElement('p');
      warn.className = 'instruct warn';
      warn.textContent = 'card bytes do not match display_sha256 — approve stays off';
      cardEl.appendChild(warn);
    }

    let previewOk = item.target !== 'plugins/nostr/send.json';
    if (!previewOk && cardOk) {
      try { await mountNostrSendPreview(cardEl, item); previewOk = true; }
      catch {
        const warn = document.createElement('p');
        warn.className = 'instruct warn';
        warn.textContent = 'nostr:preview-refused';
        cardEl.appendChild(warn);
      }
    }
    const actions = document.createElement('div');
    actions.className = 'actions';
    const state = item.state ?? 'pending';
    const superseded = item.superseded === true;
    const overrideRequired = item.override_required === true;
    const approveUnavailable = () => !cardOk || !previewOk || superseded || overrideRequired || state !== 'pending';
    const approve = document.createElement('button');
    approve.className = 'primary';
    approve.textContent = 'approve';
    approve.disabled = approveUnavailable();
    const err = document.createElement('p');
    err.className = 'instruct warn';
    err.hidden = true;
    if (state === 'pending') actions.appendChild(approve);
    const despite = document.createElement('button');
    despite.textContent = 'approve despite failing antibodies';
    despite.disabled = !cardOk || superseded;
    if (state === 'pending' && overrideRequired) actions.appendChild(despite);
    const retry = document.createElement('button');
    retry.textContent = 'retry antibodies';
    if (item.retry_available === true) actions.appendChild(retry);
    let action = ['incomplete', 'conflict'].includes(state) ? 'reconcile'
      : state === 'pending' && (item.reviewed || item.operator_only) ? 'retire' : null;
    const ownerAction = document.createElement('button');
    if (action) {
      ownerAction.textContent = embedded && action === 'retire' ? 'refuse' : action;
      actions.appendChild(ownerAction);
    }
    const refuse = document.createElement('button');
    refuse.textContent = 'refuse';
    if (state === 'pending' && !item.reviewed && !item.operator_only) actions.appendChild(refuse);
    refuse.onclick = async () => {
      if (state !== 'pending' || item.reviewed || item.operator_only || refuse.disabled) return;
      refuse.disabled = true;
      approve.disabled = true;
      err.hidden = true;
      try {
        await api.approvalDecide(item.id, false);
        keyFlow.discard(item.id);
        status.textContent = 'refused';
        actions.remove();
        await onDecided?.();
      } catch (ex) {
        err.textContent = ex.code ?? String(ex);
        err.hidden = false;
        refuse.disabled = false;
        approve.disabled = approveUnavailable();
      }
    };
    const status = document.createElement('p');
    status.className = 'instruct';
    status.textContent = superseded ? 'superseded: retire it' : state;
    cardEl.appendChild(status);
    cardEl.append(actions, err);

    approve.onclick = async () => {
      if (approveUnavailable()) return;
      approve.disabled = true;
      err.hidden = true;
      try {
        const ch = await api.approvalChallenge(item.id);
        refuse.remove();
        item.reviewed = true;
        if (!action) {
          action = 'retire';
          ownerAction.textContent = embedded && action === 'retire' ? 'refuse' : action;
          actions.appendChild(ownerAction);
        }
        await checkChallenge(ch, item.id, item.target === 'gate/permission' ? 'permission' : item.target === 'release' ? 'release' : 'apply');
        if (ch.display_sha256 !== item.display_sha256) {
          throw Object.assign(new Error('card changed between list and challenge'), { code: 'gate:card-changed' });
        }
        if (action) ownerAction.disabled = true;
        const assertion = await getAssertion(ch);
        const result = await api.approvalDecide(item.id, true, assertion);
        cardEl.style.opacity = '0.55';
        let delivered = false;
        if (result.state === 'applied') {
          // §8 step 3: an applied key proposal is redeemed exactly once, here.
          // The key is cleared on every path inside keyflow.
          delivered = Boolean(await keyFlow.deliverIfApproved(item.id, result.state));
        } else {
          keyFlow.discard(item.id);
        }
        const done = document.createElement('p');
        done.className = 'instruct';
        done.textContent = `${result.state} · record ${result.seq}${delivered ? ' · key delivered' : ''}`;
        cardEl.appendChild(done);
        actions.remove();
        await onDecided?.();
        err.remove();
      } catch (ex) {
        err.textContent = ex.code ?? String(ex);
        err.hidden = false;
        approve.disabled = approveUnavailable();
        if (action) ownerAction.disabled = false;
      }
    };
    ownerAction.onclick = async () => {
      ownerAction.disabled = true;
      approve.disabled = true;
      err.hidden = true;
      try {
        const challenge = action === 'retire' ? api.approvalRetireChallenge : api.approvalReconcileChallenge;
        const decide = action === 'retire' ? api.approvalRetire : api.approvalReconcile;
        const ch = await challenge(item.id);
        await checkChallenge(ch, item.id, action);
        const display = hex(new Uint8Array(await browserSha256(utf8(canonicalJSON(ch.card)))));
        if (display !== ch.display_sha256) {
          throw Object.assign(new Error('action card does not match display_sha256'), { code: 'gate:card-changed' });
        }
        if (!await confirmAction(wrap, ch.card, action)) return;
        const assertion = await getAssertion(ch);
        const result = await decide(item.id, assertion);
        keyFlow.discard(item.id);
        cardEl.style.opacity = '0.55';
        const done = document.createElement('p');
        done.className = 'instruct';
        done.textContent = `${result.state} · record ${result.seq}`;
        cardEl.appendChild(done);
        actions.remove();
        await onDecided?.();
      } catch (ex) {
        err.textContent = ex.code ?? String(ex);
        err.hidden = false;
      } finally {
        ownerAction.disabled = false;
        approve.disabled = approveUnavailable();
      }
    };
    despite.onclick = async () => {
      if (!cardOk || superseded || !overrideRequired || state !== 'pending') return;
      despite.disabled = true;
      ownerAction.disabled = true;
      retry.disabled = true;
      err.hidden = true;
      try {
        const ch = await api.approvalDespiteChallenge(item.id);
        await checkChallenge(ch, item.id, 'release');
        const display = hex(new Uint8Array(await browserSha256(utf8(canonicalJSON(ch.card)))));
        if (display !== ch.display_sha256) {
          throw Object.assign(new Error('override card does not match display_sha256'), { code: 'gate:card-changed' });
        }
        if (!await confirmAction(wrap, ch.card, 'approve despite failing antibodies')) return;
        const assertion = await getAssertion(ch, false);
        const result = await api.approvalDespiteDecide(item.id, assertion);
        keyFlow.discard(item.id);
        cardEl.style.opacity = '0.55';
        const done = document.createElement('p');
        done.className = 'instruct';
        done.textContent = `${result.state} · record ${result.seq}`;
        cardEl.appendChild(done);
        actions.remove();
        await onDecided?.();
        err.remove();
      } catch (ex) {
        err.textContent = ex.code ?? String(ex);
        err.hidden = false;
      } finally {
        despite.disabled = !cardOk || superseded;
        ownerAction.disabled = false;
        retry.disabled = false;
        approve.disabled = approveUnavailable();
      }
    };
    retry.onclick = async () => {
      if (item.retry_available !== true) return;
      retry.disabled = true;
      err.hidden = true;
      try {
        await api.releaseRetry();
        await showApprovals(app, { onDecided, embedded });
      } catch (ex) {
        err.textContent = ex.code ?? String(ex);
        err.hidden = false;
      } finally {
        retry.disabled = false;
      }
    };
    panel.appendChild(wrap);
  }
}
