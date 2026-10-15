/* Aura screen: record head, recent rows, the Pentora drawn from the root, and
   the external witness — the last signed head lives in IndexedDB on this origin
   and a rollback or fork raises the red alarm. */

import { api } from '../api.js';
import { drawPentora, browserSha256, pentoraDigits, mountTritComparison } from '../pentora.js';
import { observeOwnerHead } from '../owner-witness.js';
import { ICONS } from '../icons.js';
import { mountNostrIdentity } from '../nostr-identity.js';

export async function showAura(app, { observation } = {}) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage wide';
  app.appendChild(panel);

  const h = document.createElement('h1');
  h.className = 'wordless';
  h.innerHTML = ICONS.record;
  const download = document.createElement('a');
  download.href = '/api/aura/export';
  download.setAttribute('aria-label', 'download cold proof: Aura history, public key and head');
  download.title = 'download cold proof: Aura history, public key and head';
  download.innerHTML = ICONS.download;
  download.style.color = 'inherit';
  h.appendChild(download);
  panel.appendChild(h);

  const alarm = document.createElement('div');
  alarm.className = 'witness-alarm';
  alarm.hidden = true;
  panel.appendChild(alarm);

  const headBlock = document.createElement('div');
  headBlock.className = 'head-block';
  const pentoraWrap = document.createElement('div');
  pentoraWrap.className = 'pentora-wrap';
  const meta = document.createElement('div');
  meta.className = 'head-meta';
  headBlock.append(pentoraWrap, meta);
  panel.appendChild(headBlock);

  const table = document.createElement('table');
  table.className = 'rows';
  panel.appendChild(table);

  const { head: presented, witness } = await (observation ?? observeOwnerHead());
  const retained = witness.kept;
  const showRetained = witness.state === 'alarm' && retained && /^[0-9a-f]{64}$/.test(retained.root);
  const head = showRetained ? retained : presented;
  headBlock.dataset.source = showRetained ? 'browser' : 'node';
  if (!head) {
    alarm.hidden = false;
    alarm.textContent = `Aura witness warning: ${witness.reason}. The browser witness is unchanged.`;
    return;
  }

  if (witness.state === 'alarm') {
    alarm.hidden = false;
    alarm.innerHTML = ICONS.alarm;
    alarm.append(` the record presented is not an extension of the head this browser kept (${witness.reason})`);
    headBlock.dataset.witness = 'alarm';
  }

  const drawn = await drawPentora(pentoraWrap, head.root);
  if (drawn === 'pentora:displayed') {
    const trits = Array.from(await pentoraDigits(Uint8Array.from(head.root.match(/../g), byte => parseInt(byte, 16)), browserSha256));
    const comparison = document.createElement('section');
    comparison.className = 'pentora-comparison';
    mountTritComparison(comparison, trits);
    panel.appendChild(comparison);
  } else {
    alarm.hidden = false;
    alarm.textContent = `Pentora unavailable (${drawn}).`;
  }

  const source = document.createElement('div');
  source.textContent = showRetained ? 'Retained browser witness' : 'Head presented by the node';
  meta.appendChild(source);
  if (showRetained && presented) {
    const rejected = document.createElement('div');
    rejected.className = 'hash';
    rejected.textContent = `Unverified node presentation: tree ${presented.treeSize}, root ${presented.root}`;
    meta.appendChild(rejected);
  }
  const seq = document.createElement('div');
  seq.textContent = `seq ${head.sequence} · tree ${head.treeSize}`;
  const hash = document.createElement('div');
  hash.className = 'hash';
  hash.textContent = head.hash;
  const root = document.createElement('div');
  root.className = 'hash';
  root.textContent = `root ${head.root}`;
  meta.append(seq, hash, root);

  await mountNostrIdentity(meta);

  try {
    const { rows } = await api.auraRecent(20);
    for (const row of rows) {
      const tr = document.createElement('tr');
      const seqTd = document.createElement('td');
      seqTd.className = 'seq';
      seqTd.textContent = row.seq;
      const kindTd = document.createElement('td');
      kindTd.className = 'kind';
      kindTd.textContent = row.kind;
      const phaseTd = document.createElement('td');
      phaseTd.className = 'phase';
      phaseTd.textContent = row.phase;
      const hashTd = document.createElement('td');
      hashTd.className = 'hash';
      hashTd.textContent = row.hash.slice(0, 12);
      tr.append(seqTd, kindTd, phaseTd, hashTd);
      table.appendChild(tr);
    }
  } catch { /* rows are secondary to the head */ }
}
