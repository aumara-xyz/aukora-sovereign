// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from './api.js';
import { browserSha256 } from './pentora.js';
import { checkPresentedHead, loadWitnessHead } from './head-witness.js';

export async function observeOwnerHead({ head = api.auraHead, load = loadWitnessHead, check = checkPresentedHead, sha256 = browserSha256 } = {}) {
  for (let attempt = 0; ; attempt++) {
    let kept, presented;
    let failureReason = 'witness:store-unavailable';
    try {
      kept = await load();
      failureReason = 'witness:head-unavailable';
      presented = await head(kept?.treeSize);
      failureReason = 'witness:check-unavailable';
      return { head: presented, witness: await check(presented, sha256, kept) };
    } catch (error) {
      // A newer retained head needs a fresh proof before checking again.
      if (attempt === 0 && error.code === 'witness:observation-changed') continue;
      return { head: presented, witness: {
        state: 'alarm', verdict: 'UNDETERMINED', kept,
        reason: error.code ?? failureReason,
      } };
    }
  }
}

// The screen and owner controls render without waiting for storage or the node.
export function mountOwnerWitness(target, observe = observeOwnerHead) {
  const status = document.createElement('aside');
  status.className = 'owner-witness instruct';
  status.setAttribute('role', 'status');
  status.textContent = 'Aura witness: checking the head retained by this browser…';
  target.appendChild(status);
  const observation = Promise.resolve().then(observe).catch(() => ({ witness: { state: 'alarm', reason: 'witness:check-unavailable' } }));
  observation.then(({ witness }) => {
    status.dataset.witness = witness.state;
    status.className = witness.state === 'alarm' ? 'owner-witness witness-alarm' : 'owner-witness instruct';
    if (witness.state === 'alarm') {
      status.setAttribute('role', 'alert');
      status.textContent = `Aura witness warning: the node has not proved an extension of this browser's retained head (${witness.reason}). Owner actions remain available.`;
    } else {
      status.textContent = witness.state === 'first'
        ? 'Aura witness: first head retained in this browser. Earlier completeness is UNCHECKED.'
        : `Aura witness: history extends this browser's retained head (tree ${witness.retained.treeSize}).`;
    }
    const retained = witness.kept ?? witness.retained;
    if (retained) {
      const download = document.createElement('a');
      download.textContent = ' Download browser witness';
      download.download = 'aukora-browser-witness.json';
      const checkpoint = Object.fromEntries(['schema', 'leafConvention', 'sequence', 'hash', 'treeSize', 'root'].map(key => [key, retained[key]]));
      download.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(checkpoint));
      status.appendChild(download);
    }
  });
  return observation;
}
