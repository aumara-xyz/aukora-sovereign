// SPDX-License-Identifier: AGPL-3.0-or-later
// Static review fixture: the owner origin's real approval pane showing an Add contact card, so the card can be reviewed
// beside the Messages face. The card is built here the way the node builds it (gate::messaging::contact_card: the
// exact action's fields as facts, the contact key in from_to, critical risk, no model note) and its `says` line copies
// gate::messaging::contact_says; the node's own bytes are the authority, this page only pictures them. No passkey,
// transport or owner session is connected. Rebuild app/release before opening this page.
import { ApprovalCards } from '../../app/release/ui/owner/cards/index.js';
import { canonical, domainDigest, hex, sha256 } from '../../app/release/ui/owner/cards/codec.js';

// The NIP-19 example key and its npub (the same pair the gate's own test uses).
const key = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';
const npub = 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6';
const action = { key, label: 'Ravi', op: 'contact.add', pairing: null, schema: 'aukora:messaging-action:v1' };
const card = {
  v: 1, risk: 'critical',
  says: `Approve this exact Aukora ID as a contact: ${npub}. This approves the ID, not the person. Before you approve, compare it with them in person or on a call you trust.`,
  facts: Object.keys(action).sort().map(name => [name, action[name]]),
  from_to: { contact: key }, model_note: '',
};
const proposalId = '6'.repeat(32);
const encode = value => new TextEncoder().encode(canonical(value));
const cardBytes = encode(card);
const operation = { v: 1, node: '7'.repeat(32), target: 'messaging/contacts.json', base_sha256: 'absent', new_sha256: hex(await sha256(encode(action))), cell: null };
const authorization = {
  ...operation, subject: `aukora:1:${'5'.repeat(64)}`, op: 'apply', proposal: proposalId,
  display_sha256: hex(await sha256(cardBytes)), challenge: '8'.repeat(32), expires_at: Date.now() + 300_000, epoch: 1,
  operation: hex(await domainDigest('aukora:operation-content:v1', encode(operation))),
};
const refused = () => Promise.reject(new Error('preview:no-passkey'));
const lifetime = new AbortController();
new ApprovalCards({ submitAuthorization: refused, decline: refused, again: refused }).mount(
  { host: document.getElementById('pane'), route: { pane: 'approval', proposalId }, signal: lifetime.signal, shellOrigin: location.origin, complete() {} },
  { loadByProposalId: async () => ({ proposalId, canonicalCard: cardBytes, canonicalAuthorization: encode(authorization), relativeTimeoutMs: 300_000 }) },
  { mount: () => () => {}, assertExact: refused },
);
window.addEventListener('pagehide', () => lifetime.abort(), { once: true });
