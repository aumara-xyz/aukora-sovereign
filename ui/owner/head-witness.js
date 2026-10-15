// SPDX-License-Identifier: AGPL-3.0-or-later
import { verifyConsistency } from './consistency.js';
import { pentoraDigits } from './pentora.js';

const DB_NAME = 'aukora-owner-witness';
const STORE = 'heads';
const KEY = 'last';
const LEAF = 'rfc6962-leaf-sha256-0x00-prefixed-v1';
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const failure = reason => Object.assign(new Error(reason), { code: reason });

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(failure('witness:store-unavailable'));
    req.onblocked = () => reject(failure('witness:store-unavailable'));
  });
}

function readHead(db) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(KEY);
    let value;
    req.onsuccess = () => { value = req.result ?? null; };
    tx.oncomplete = () => resolve(value);
    tx.onabort = tx.onerror = () => reject(failure('witness:store-unavailable'));
  });
}

// The comparison and write share one transaction across tabs; success means commit.
function replaceHead(db, expected, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    const req = store.get(KEY);
    let changed = false;
    req.onsuccess = () => {
      if (JSON.stringify(req.result ?? null) !== JSON.stringify(expected)) {
        changed = true;
        tx.abort();
        return;
      }
      store.put(value, KEY);
    };
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(failure(changed ? 'witness:observation-changed' : 'witness:store-unavailable'));
  });
}

export async function loadWitnessHead() {
  const db = await openDb();
  try { return await readHead(db); } finally { db.close(); }
}

function validHead(head, schema) {
  return head && head.schema === schema && head.leafConvention === LEAF
    && Number.isSafeInteger(head.treeSize) && head.treeSize > 0
    && head.sequence === head.treeSize && digest(head.root) && digest(head.hash);
}

async function tritsFor(head, sha256) {
  return Array.from(await pentoraDigits(Uint8Array.from(head.root.match(/../g), byte => parseInt(byte, 16)), sha256));
}

export async function checkPresentedHead(presented, sha256, observation) {
  const kept = observation === undefined ? await loadWitnessHead() : observation;
  const alarm = reason => ({ state: 'alarm', verdict: 'UNDETERMINED', reason, kept });
  if (!validHead(presented, 'aukora-aura-presented-head-v1')) return alarm('witness:head-invalid');
  if (kept !== null) {
    if (!validHead(kept, 'aukora-aura-retained-head-v1')) return alarm('witness:retained-invalid');
    const expectedTrits = await tritsFor(kept, sha256);
    // Older retained heads have no trits; the next verified observation adds them.
    if (kept.trits !== undefined && JSON.stringify(kept.trits) !== JSON.stringify(expectedTrits)) return alarm('witness:trits-mismatch');
    if (presented.retainedTreeSize !== kept.treeSize) return alarm('witness:proof-size-mismatch');
    if (presented.treeSize < kept.treeSize) return alarm('witness:rollback');
    if (presented.treeSize === kept.treeSize && presented.hash !== kept.hash) return alarm('witness:hash-mismatch');
    const result = await verifyConsistency({
      m: kept.treeSize, n: presented.treeSize, root1: kept.root, root2: presented.root,
      proof: presented.proofFromPrevious,
    }, sha256);
    if (result.verdict !== 'APPEND_ONLY') return { state: 'alarm', ...result, kept };
  }
  const trits = await tritsFor(presented, sha256);
  const retained = {
    schema: 'aukora-aura-retained-head-v1', leafConvention: LEAF,
    sequence: presented.sequence, hash: presented.hash, sig: presented.sig ?? null,
    treeSize: presented.treeSize, root: presented.root, trits, keptAt: Date.now(),
  };
  const db = await openDb();
  try { await replaceHead(db, kept, retained); } finally { db.close(); }
  return { state: kept === null ? 'first' : kept.treeSize === presented.treeSize ? 'same' : 'extended', retained, trits };
}
