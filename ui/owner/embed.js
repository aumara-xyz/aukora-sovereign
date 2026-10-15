// SPDX-License-Identifier: AGPL-3.0-or-later
export const EMBED_PANES = ['approvals', 'aumlok', 'aura', 'memory', 'model', 'nostr'];

export function ownerRoute(hash) {
  const path = hash.replace(/^#\//, '') || 'approvals';
  const embedded = path.startsWith('embed/');
  const pane = embedded ? path.slice(6) : path;
  if (embedded && !EMBED_PANES.includes(pane)) return { embedded, pane: null };
  return { embedded, pane };
}

export async function configuredChatOrigin() {
  const response = await fetch('/', {
    method: 'HEAD', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
  });
  const value = response.headers.get('aukora-chat-origin');
  let url;
  try { url = new URL(value); } catch { /* invalid configuration is refused below */ }
  if (!response.ok || !url || url.protocol !== 'https:' || url.origin !== value
    || !url.hostname.startsWith('chat-')) {
    throw Object.assign(new Error('frontdoor:chat-origin-invalid'), { code: 'frontdoor:chat-origin-invalid' });
  }
  return value;
}

export function postDecision(chatOrigin, pending) {
  if (!Number.isSafeInteger(pending) || pending < 0 || window.parent === window) return;
  window.parent.postMessage({ kind: 'aukora-owner', event: 'decided', pending }, chatOrigin);
}
