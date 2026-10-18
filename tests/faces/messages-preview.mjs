// SPDX-License-Identifier: AGPL-3.0-or-later
// Static review fixture. The real shell and sandboxed faces use in-memory services only: no transport, owner origin,
// fetch, persistence or relay worker is connected here. Rebuild app/release before opening this page.
import { mountShell } from '../../app/release/app/shell/main.js';

const root = document.getElementById('aukora-shell');
const status = document.getElementById('preview-status');
const date = Date.UTC(2026, 9, 18, 7, 30);
const sessionId = '1'.repeat(32);
const npub = digit => `npub1${digit.repeat(58)}`;
const maya = npub('q');
const sam = npub('p');
const ana = npub('r');
const jun = npub('s');
const lee = npub('t');
// ?contacts=none previews the first-run state: no approved contact and no message yet.
const empty = new URLSearchParams(location.search).get('contacts') === 'none';

function freeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

const summary = freeze({
  algorithm: 'sha256', archived: false, created_at_ms: date - 3_600_000, mode: 'chat', sequence: 2,
  session_id: sessionId, thread_id: '2'.repeat(32), title: 'Auma · Our day', updated_at_ms: date - 60_000, v: 2,
});
const entries = freeze([
  {
    algorithm: 'sha256', at_ms: date - 120_000, commitment: '3'.repeat(64), content: 'Can you help me plan a quiet afternoon?',
    provenance: { source: 'owner' }, role: 'owner', sequence: 1, session_id: sessionId, tool_call_id: null, tool_calls: [], v: 2,
  },
  {
    algorithm: 'sha256', at_ms: date - 60_000, commitment: '4'.repeat(64), content: 'A walk by the water, then time to read. Leave some room for whatever catches your eye.',
    provenance: { source: 'auma' }, role: 'auma', sequence: 2, session_id: sessionId, tool_call_id: null, tool_calls: [], v: 2,
  },
]);
const contacts = freeze(empty ? [] : [
  { npub: maya, label: 'Maya', pairing: { method: 'screen-to-screen', verified_at: date - 86_400_000 } },
  { npub: sam, label: 'Sam', pairing: { method: 'remote', verified_at: date - 172_800_000 } },
  { npub: ana, label: 'Anastasia Wolkenstein-Marchetti', pairing: { method: 'screen-to-screen', verified_at: date - 259_200_000 } },
  { npub: jun, label: 'Jun', pairing: null },
  { npub: lee, label: 'Lee', pairing: { method: 'remote', verified_at: date - 3_600_000 } },
]);
const messages = freeze(empty ? [] : [
  { id: 'maya-3', direction: 'in', contact: maya, at: date, text: 'See you by the water at five?', transport: 'nostr-relays', state: null, code: null },
  { id: 'maya-2', direction: 'out', contact: maya, at: date - 600_000, text: 'A walk sounds lovely. Where shall we meet?', transport: 'nostr-relays', state: 'published', code: null },
  { id: 'maya-1', direction: 'in', contact: maya, at: date - 900_000, text: 'Are you free for a walk later?', transport: 'nostr-relays', state: null, code: null },
  { id: 'sam-2', direction: 'out', contact: sam, at: date - 3_600_000, text: 'Thanks, Sam. I will bring the book tomorrow.', transport: 'nostr-relays', state: 'queued', code: null },
  { id: 'sam-1', direction: 'in', contact: sam, at: date - 4_000_000, text: 'I found the book we were talking about.', transport: 'nostr-relays', state: null, code: null },
  { id: 'ana-2', direction: 'in', contact: ana, at: date - 90_000_000, text: 'The photos from the weekend are lovely. I will send the rest once I am home and have a proper connection again.', transport: 'nostr-relays', state: null, code: null },
  { id: 'ana-1', direction: 'out', contact: ana, at: date - 95_000_000, text: 'How was the trip?', transport: 'nostr-relays', state: 'unconfirmed', code: null },
  { id: 'jun-1', direction: 'out', contact: jun, at: date - 400_000_000, text: 'Happy birthday, Jun!', transport: 'nostr-relays', state: 'failed', code: 'messaging:transport-rejected' },
]);
const identity = freeze({
  agent_npub: null, contact_code: null, label: 'Peter', node_key_bound: true, node_npub: npub('z'),
  safety: [], subject: `aukora:1:${'5'.repeat(64)}`,
});
const refusals = freeze({
  envelope: 0, signature: 0, recipient: 0, stranger: 0, replay: 0, payload: 0, stale_contact: 0,
  total: 0, last_aura_sequence: 0,
});

// The owner's own marks: Anastasia pinned, Jun archived. Kept in this page only.
const marks = new Map(empty ? [] : [[ana, { pinned: true, archived: false }], [jun, { pinned: false, archived: true }]]);

function unavailable() { throw new Error('preview:service-unavailable'); }
const body = {
  call(method, params) {
    if (method === 'session.list') return { items: params.include_archived ? [] : [summary], next: null };
    if (method === 'session.open' && params.session_id === sessionId) {
      return { summary, entries: entries.filter(entry => entry.sequence > params.after_sequence), next_sequence: null };
    }
    if (['session.create', 'chat.turn', 'model.cancel'].includes(method)) {
      status.textContent = 'Preview only. Auma actions are not saved or sent.';
    }
    return unavailable();
  },
  subscribe(topic) { if (topic !== 'session.event') return unavailable(); return () => {}; },
};
const network = {
  call(method, params) {
    if (method === 'contacts.list') return { items: contacts, next: null };
    if (method === 'messages.list') {
      const thread = messages.filter(message => !params.npub || message.contact === params.npub);
      const start = params.before === null ? 0 : thread.findIndex(message => message.id === params.before) + 1;
      const items = thread.slice(start, start + params.limit);
      return { items, next: start + items.length < thread.length ? items.at(-1).id : null };
    }
    if (method === 'refusals.counts') return refusals;
    if (method === 'conversations.marks') return { items: [...marks].map(([key, mark]) => ({ npub: key, ...mark })) };
    if (method === 'conversation.mark') {
      if (params.pinned || params.archived) marks.set(params.npub, { pinned: params.pinned, archived: params.archived });
      else marks.delete(params.npub);
      status.textContent = 'Mark kept in this page only. Nothing saved.';
      return {};
    }
    if (method === 'contact.propose') {
      status.textContent = 'Contact approval simulated. Nothing saved; no passkey approval requested.';
      return { proposal_id: '6'.repeat(32) };
    }
    if (method === 'send') {
      status.textContent = 'Send simulated. Nothing saved; no relay contacted.';
      return { queued: true };
    }
    return unavailable();
  },
};
const aumlok = { call(method) { return method === 'identity' ? identity : unavailable(); } };

// Optional ?auma=thread shows the saved Auma chat on the left through the real shell navigation protocol.
let shell;
window.addEventListener('message', event => {
  const frame = root.querySelector('iframe[title="Threads"]');
  if (new URLSearchParams(location.search).get('auma') !== 'thread' || event.source !== frame?.contentWindow
    || event.origin !== 'null' || event.data?.type !== 'aukora:spatial-navigation:v1' || event.data?.action !== 'ready') return;
  shell.openFace('threads');
  event.source.postMessage({ type: 'aukora:spatial-navigation:v1', action: 'open-thread', sessionId }, '*');
});
shell = mountShell({ root, services: new Map([['body', body], ['network', network], ['aumlok', aumlok]]) });
root.querySelector('button[data-menu-tab="apps"]').click();
root.querySelector('button[data-face="messages"]').click();
root.querySelector('button[data-menu-tab="system"]').click();
window.addEventListener('pagehide', () => { void shell.dispose(); }, { once: true });
