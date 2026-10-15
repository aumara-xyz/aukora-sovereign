// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from './api.js';

function validRelay(value) {
  if (typeof value !== 'string' || value.length > 2048 || /[\u0000-\u0020\u007f]/.test(value)) return false;
  try {
    const url = new URL(value);
    return !url.username && !url.password && !url.hash &&
      (url.protocol === 'wss:' || url.protocol === 'ws:' && ['127.0.0.1', '[::1]'].includes(url.hostname));
  } catch { return false; }
}

function mountRelayWitness(section, witness) {
  const block = document.createElement('div');
  block.className = 'nostr-witness';
  section.appendChild(block);
  const valid = witness && Array.isArray(witness.relays) && witness.relays.length <= 8 &&
    witness.relays.every(validRelay) && Number.isSafeInteger(witness.accepted) &&
    witness.accepted >= 0 && witness.accepted <= witness.relays.length &&
    (witness.sequence === null || Number.isSafeInteger(witness.sequence) && witness.sequence >= 0) &&
    (witness.at === null || Number.isSafeInteger(witness.at) && witness.at >= 0 && witness.at <= 8640000000000000) &&
    ((witness.sequence === null) === (witness.at === null)) &&
    (witness.sequence !== null || witness.accepted === 0) &&
    (witness.relays.length > 0 || witness.sequence === null);
  if (!valid) {
    block.textContent = 'Relay head witness unavailable';
    return;
  }
  const label = document.createElement('div');
  label.textContent = 'Relay head witness';
  const status = document.createElement('div');
  status.textContent = witness.relays.length === 0 ? 'Off' : witness.sequence === null
    ? 'Waiting for first publish'
    : `${witness.accepted} of ${witness.relays.length} relays accepted head #${witness.sequence}`;
  block.append(label, status);
  if (witness.at !== null) {
    const time = document.createElement('div');
    time.textContent = `Last attempt ${new Date(witness.at).toISOString()}`;
    block.appendChild(time);
  }
  for (const relay of witness.relays) {
    const value = document.createElement('div');
    value.className = 'hash';
    value.textContent = relay;
    block.appendChild(value);
  }
}

export async function mountNostrIdentity(parent) {
  const section = document.createElement('section');
  section.className = 'nostr-identities';
  parent.appendChild(section);
  let identity;
  try { identity = await api.nostr(); }
  catch {
    section.textContent = 'Nostr identities unavailable';
    return;
  }
  for (const name of ['node', 'agent']) {
    const npub = identity[name]?.npub;
    if (typeof npub !== 'string' || !/^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$/.test(npub)) {
      section.textContent = 'Nostr identities unavailable';
      return;
    }
  }
  for (const name of ['node', 'agent']) {
    const row = document.createElement('div');
    const label = document.createElement('div');
    label.textContent = `${name === 'node' ? 'Node' : 'Agent'} Nostr identity`;
    const value = document.createElement('div');
    value.className = 'hash';
    value.textContent = identity[name].npub;
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.textContent = 'Copy';
    copy.setAttribute('aria-label', `Copy ${name} npub`);
    copy.onclick = async () => {
      try {
        await navigator.clipboard.writeText(identity[name].npub);
        copy.textContent = 'Copied';
      } catch { copy.textContent = 'Copy unavailable'; }
    };
    row.append(label, value, copy);
    section.appendChild(row);
  }
  mountRelayWitness(section, identity.witness);
}
