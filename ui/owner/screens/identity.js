// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from '../api.js';
import { checkPermissionChallenge, permissionAssertion } from '../owner-permission.js';
import { addSignOutEverywhere } from '../session-controls.js';
import { mountCard } from '../card.js';
import { mountPhraseCeremony, mountPhraseComplete } from './binding.js';
import { addBackupControls } from '../backup.js';
import { ICONS } from '../icons.js';

const storageKey = state => `aukora.refresh.${state.node}.${state.subject}`;
const savedId = state => {
  try { return localStorage.getItem(storageKey(state)); } catch { return null; }
};
const saveId = (state, id) => {
  try {
    if (id) localStorage.setItem(storageKey(state), id);
    else localStorage.removeItem(storageKey(state));
  } catch { /* restart recovery needs browser storage */ }
};
const refreshDone = {
  doneText: 'Phrase replaced. Your previous phrase no longer unlocks this node. Download the new envelope backup. Choose a passkey-bound backup on Identity, or the optional phrase-only recovery copy below. Phrase-only copies are guessable offline: store them like cash. Previously downloaded backups still open only with the old phrase.',
  doneLink: { href: '/api/binding/envelope', download: 'aukora-envelope.json', label: 'Download phrase-only recovery copy (guessable offline; store like cash)' },
};

export const checkRefreshChallenge = (ch, state) => checkPermissionChallenge(ch, state, 'aumlok/binding/refresh', 'aumlok:refresh-challenge-mismatch');

export function refreshError(ex) {
  if (ex.code === 'aumlok:refresh-live' && Number.isSafeInteger(ex.detail?.expires_at)) {
    return `Another owner session is replacing the phrase. Retry after ${new Date(ex.detail.expires_at).toLocaleString()}. Use Sign out everywhere on Identity to end that ceremony now.`;
  }
  const message = ex.code ?? String(ex);
  if (!ex.code || ex.status === 401 || ex.status >= 500 || ex.code === 'frontdoor:session-required' || ['aumlok:ceremony-expired', 'aumlok:ceremony-spent', 'aumlok:ceremony-unknown', 'aumlok:ceremony-principal'].includes(ex.code)) {
    return `${message}; the replacement may have completed: try your new phrase, else the old one`;
  }
  return message;
}

export async function showIdentity(app, { embedded = false } = {}) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage wide';
  app.appendChild(panel);
  const err = document.createElement('p');
  err.className = 'instruct warn';
  err.hidden = true;
  try {
    const state = await api.state();
    const heading = document.createElement('h1');
    heading.textContent = embedded ? 'AUMLOK' : 'Identity';
    const subject = document.createElement('p');
    subject.className = 'instruct';
    subject.textContent = state.subject;
    const replace = document.createElement('button');
    replace.className = 'primary';
    replace.textContent = savedId(state) ? 'Resume phrase replacement' : 'Replace phrase';
    replace.onclick = () => showCurrentPhrase(panel, state, () => showIdentity(app, { embedded }));
    if (embedded) {
      panel.classList.add('aumlok-surface');
      mountAumlokFace(panel, state, heading);
      replace.textContent = savedId(state) ? 'Resume phrase replacement' : 'Refresh phrase';
      panel.append(subject, replace, err);
    } else panel.append(heading, subject, replace, err);
    addBackupControls(panel);
    if (embedded) {
      const passkeys = document.createElement('p');
      passkeys.className = 'instruct';
      passkeys.textContent = 'Passkeys · use your bound passkey for phrase refresh and passkey-bound backups.';
      panel.appendChild(passkeys);
    } else addSignOutEverywhere(panel, state);
  } catch (ex) {
    err.textContent = refreshError(ex);
    err.hidden = false;
    panel.appendChild(err);
  }
}

function mountAumlokFace(panel, state, heading) {
  const eyebrow = document.createElement('p');
  eyebrow.className = 'aumlok-eyebrow';
  eyebrow.textContent = 'SEVEN-WORD BINDING PHRASE';
  const hero = document.createElement('header');
  hero.className = 'aumlok-hero';
  const badge = document.createElement('span');
  badge.className = 'aumlok-badge';
  badge.textContent = ['bound', 'released'].includes(state.state) ? 'BOUND' : 'UNBOUND';
  hero.append(heading, badge);
  const handle = document.createElement('section');
  handle.className = 'aumlok-handle';
  const label = document.createElement('strong');
  label.textContent = 'YOUR HANDLE';
  const value = document.createElement('div');
  value.className = 'aumlok-handle-value';
  value.textContent = state.handle ?? 'Handle unavailable';
  const locked = document.createElement('span');
  locked.className = 'aumlok-locked';
  locked.innerHTML = ICONS.key;
  locked.append('Locked');
  handle.append(label, value, locked);
  panel.append(eyebrow, hero, handle);
  const anchor = document.createElement('section');
  anchor.className = 'aumlok-anchor';
  const word = document.createElement('strong');
  word.textContent = 'WORD 1';
  const mask = document.createElement('span');
  mask.className = 'aumlok-anchor-boxes';
  mask.setAttribute('aria-label', 'word 1 masked');
  for (let i = 0; i < 6; i++) {
    const box = document.createElement('span');
    box.textContent = '•';
    box.setAttribute('aria-hidden', 'true');
    mask.appendChild(box);
  }
  anchor.append(word, mask);
  panel.appendChild(anchor);
  for (const [name, positions] of [['ROOT', [2, 3]], ['UNITE', [4, 5]], ['RISE', [6, 7]]]) {
    const band = document.createElement('section');
    band.className = 'aumlok-band';
    band.dataset.band = name.toLowerCase();
    const title = document.createElement('strong');
    title.textContent = name;
    band.appendChild(title);
    for (const position of positions) {
      const row = document.createElement('div');
      row.className = 'aumlok-word';
      row.dataset.word = String(position);
      row.setAttribute('aria-label', `word ${position} masked`);
      const number = document.createElement('span');
      number.textContent = String(position);
      const dots = document.createElement('span');
      dots.textContent = '•  •  •  •  •';
      dots.setAttribute('aria-hidden', 'true');
      row.append(number, dots);
      band.appendChild(row);
    }
    panel.appendChild(band);
  }
}

function showCurrentPhrase(panel, state, onDone) {
  panel.replaceChildren();
  const note = document.createElement('p');
  note.className = 'instruct';
  note.textContent = 'Type your current seven words, in order.';
  const current = document.createElement('input');
  current.type = 'text';
  current.setAttribute('autocomplete', 'off');
  current.setAttribute('spellcheck', 'false');
  current.setAttribute('autocorrect', 'off');
  current.setAttribute('autocapitalize', 'off');
  current.setAttribute('aria-label', 'current phrase');
  current.addEventListener('paste', event => event.preventDefault());
  current.addEventListener('drop', event => event.preventDefault());
  const next = document.createElement('button');
  next.className = 'primary';
  next.textContent = savedId(state) ? 'Resume replacement' : 'Continue';
  const err = document.createElement('p');
  err.className = 'instruct warn';
  err.hidden = true;
  const back = document.createElement('button');
  back.textContent = 'Back to Identity';
  back.onclick = async () => { current.value = ''; await onDone(); };
  panel.append(note, current, next, back, err);
  const cancel = async id => {
    const result = await api.bindingRefreshCancel(id);
    current.value = '';
    saveId(state, null);
    if (result.state === 'committed') mountPhraseComplete(panel, { ...refreshDone, onDone });
    else await onDone();
  };
  if (savedId(state)) {
    const stop = document.createElement('button');
    stop.textContent = 'Cancel replacement';
    stop.onclick = async () => {
      stop.disabled = true;
      err.hidden = true;
      try { await cancel(savedId(state)); } catch (ex) {
        stop.disabled = false;
        err.textContent = refreshError(ex);
        err.hidden = false;
      }
    };
    panel.appendChild(stop);
  }
  current.focus();
  next.onclick = async () => {
    let phrase = current.value.trim().toLowerCase().split(/\s+/).join(' ');
    if (phrase.split(' ').length !== 7) {
      err.textContent = 'all seven current words are needed';
      err.hidden = false;
      return;
    }
    current.value = '';
    next.disabled = true;
    err.hidden = true;
    try {
      let draw;
      const id = savedId(state);
      if (id) {
        draw = await api.bindingRefreshResume(id, phrase);
      } else {
        const ch = await api.bindingRefresh();
        if (ch.state === 'live') {
          saveId(state, ch.ceremony_id);
          draw = await api.bindingRefreshResume(ch.ceremony_id, phrase);
        } else {
          await checkRefreshChallenge(ch, state);
          panel.replaceChildren();
          mountCard(panel, ch.card);
          const touch = document.createElement('button');
          touch.className = 'primary';
          touch.textContent = 'Touch ID — replace phrase';
          panel.append(touch, err);
          const proof = await new Promise((resolve, reject) => {
            touch.onclick = async () => {
              touch.disabled = true;
              try { resolve(await permissionAssertion(ch)); } catch (ex) { reject(ex); }
            };
          });
          draw = await api.bindingRefreshPrepare(ch.ceremony_id, phrase, proof);
        }
      }
      if (draw.state === 'live') {
        saveId(state, draw.ceremony_id);
        draw = await api.bindingRefreshResume(draw.ceremony_id, phrase);
      }
      if (draw.state === 'committed') {
        phrase = '';
        saveId(state, null);
        mountPhraseComplete(panel, { ...refreshDone, onDone });
        return;
      }
      saveId(state, draw.ceremony_id);
      panel.replaceChildren();
      mountPhraseCeremony(panel, draw, {
        exact: true,
        errorText: refreshError,
        label: 'Replace phrase',
        ...refreshDone,
        onDone,
        cancel: async () => {
          const result = await api.bindingRefreshCancel(draw.ceremony_id);
          phrase = '';
          saveId(state, null);
          if (result.state !== 'committed') await onDone();
          return result;
        },
        confirm: async words => {
          const result = await api.bindingRefreshConfirm(draw.ceremony_id, phrase, words);
          phrase = '';
          saveId(state, null);
          return result;
        },
      });
    } catch (ex) {
      phrase = '';
      if (['aumlok:ceremony-expired', 'aumlok:ceremony-spent', 'aumlok:ceremony-unknown', 'aumlok:ceremony-principal'].includes(ex.code)) saveId(state, null);
      showCurrentPhrase(panel, state, onDone);
      err.textContent = refreshError(ex);
      err.hidden = false;
      panel.appendChild(err);
    }
  };
}
