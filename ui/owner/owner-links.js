// SPDX-License-Identifier: AGPL-3.0-or-later
/* Owner backup choices and the chat origin's one-time handoff. */
import { ICONS } from './icons.js';
import { addSignOut } from './session-controls.js';
import { configuredChatOrigin } from './embed.js';

async function post(path, body) {
  const response = await fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const value = await response.json();
  if (!response.ok) throw Object.assign(new Error(value.error), { code: value.error });
  return value;
}

export async function chatSessionUrl() {
  const origin = await configuredChatOrigin();
  const opened = await post('/api/chat-session', {});
  let target;
  try { target = new URL(opened?.url); } catch { /* refused below */ }
  if (!target || target.origin !== origin || target.username || target.password
    || target.pathname !== '/__aukora/chat' || target.search
    || !/^#ticket=[a-f0-9]{64}$/.test(target.hash)) {
    throw Object.assign(new Error('frontdoor:backend-invalid'), { code: 'frontdoor:backend-invalid' });
  }
  return target.href;
}

export function addOwnerLinks(nav) {
  const backup = document.createElement('a');
  backup.href = '#/identity';
  backup.title = 'Choose a passkey-bound backup or a phrase-only recovery copy';
  backup.setAttribute('aria-label', 'identity backup');
  backup.innerHTML = ICONS.download;
  nav.appendChild(backup);
  const chat = document.createElement('a');
  chat.href = '#';
  chat.setAttribute('aria-label', 'open chat');
  chat.innerHTML = ICONS.chat;
  chat.onclick = async event => {
    event.preventDefault();
    try {
      location.assign(await chatSessionUrl());
    } catch (ex) {
      chat.title = ex.code ?? String(ex);
    }
  };
  nav.appendChild(chat);
  addSignOut(nav);
}
