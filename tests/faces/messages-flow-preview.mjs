// SPDX-License-Identifier: AGPL-3.0-or-later
// The genuine Messages face with fixture-only services. ?state=form|added|pending selects the screenshot stage.
// A pending result only pictures the face's card wording: this page cannot request or supply a passkey.
import { mountMessages } from '../../app/release/app/faces/messages/view.js';

const state = new URLSearchParams(location.search).get('state') ?? 'form';
const contacts = [];
const npub = digit => `npub1${digit.repeat(58)}`;
const life = new AbortController();
const client = {
  async call(service, method, params) {
    if (service === 'aumlok' && method === 'identity') return {
      label: 'Owner', subject: `aukora:1:${'1'.repeat(64)}`, node_npub: npub('z'), node_key_bound: true,
      agent_npub: null, contact_code: null, safety: [],
    };
    if (service !== 'network') throw new Error('preview:service-unavailable');
    if (method === 'contacts.list') return { items: [...contacts], next: null };
    if (method === 'messages.list') return { items: [], next: null };
    if (method === 'contact.propose') {
      if (state === 'pending') return { state: 'pending', proposal_id: '6'.repeat(32) };
      contacts.push({ npub: params.npub, label: params.label ?? 'Ravi', pairing: null });
      return { state: 'applied' };
    }
    throw new Error('preview:service-unavailable');
  },
};
const root = document.getElementById('face');
mountMessages(root, client, life.signal, new Set(['contacts.list', 'messages.list', 'contact.propose']));
root.querySelector('[aria-controls="panel-contact"]').click();
const form = root.querySelector('.contact-form');
form.elements.npub.value = 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6';
form.elements.label.value = 'Ravi';
if (state === 'added' || state === 'pending') form.requestSubmit();
window.addEventListener('pagehide', () => life.abort(), { once: true });
