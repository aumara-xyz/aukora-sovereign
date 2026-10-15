/* Model key flow (OWNER-API §8). The key is hashed locally, only the hash is
   proposed; the key itself is held in memory alone — never in a URL, the DOM,
   a log or localStorage — and is POSTed exactly once, to /api/broker/key,
   after the approval is applied. It is cleared right after that one POST
   (and immediately on any non-applied outcome). */

import { api } from './api.js';
import { browserSha256 } from './pentora.js';

const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');

export function createKeyFlow({ propose, deliver, sha256 }) {
  let held = null; // { id, key } — the only place the key ever rests
  return {
    /* Hash the exact key bytes locally, propose the hash, keep the key until
       the owner approves. Returns the proposal id. */
    async proposeKey(key) {
      const digest = await sha256(new TextEncoder().encode(key));
      const { id } = await propose(hex(digest));
      held = { id, key };
      return id;
    },
    /* Called by the approvals screen after a decide. Delivers once when the
       proposal was applied; clears the key on every path. */
    async deliverIfApproved(id, state) {
      if (!held || held.id !== id) return null;
      if (state !== 'applied') { held = null; return null; }
      const { key } = held;
      try {
        return await deliver(id, key);
      } finally {
        held = null; // cleared right after the one delivery POST
      }
    },
    discard(id) { if (held && held.id === id) held = null; },
    pendingId: () => held?.id ?? null,
  };
}

export const keyFlow = createKeyFlow({
  propose: key_sha256 => api.brokerKeyPropose(key_sha256),
  deliver: (id, key) => api.brokerKeyDeliver(id, key),
  sha256: browserSha256,
});
