// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { checkPresentedHead, loadWitnessHead } from '../head-witness.js';
import { observeOwnerHead, mountOwnerWitness } from '../owner-witness.js';
import { PENTORA, pentoraDigest, pentoraDigits, compareTrits, mountTritComparison, drawPentora } from '../pentora.js';
import { verifyConsistency } from '../consistency.js';
import { showAura } from '../screens/aura.js';
import { api } from '../api.js';

const sha256 = async bytes => createHash('sha256').update(bytes).digest();
const leaf = 'rfc6962-leaf-sha256-0x00-prefixed-v1';
const root1 = '01'.repeat(32);
const root2 = '02'.repeat(32);
const pairRoot = createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(root1, 'hex'), Buffer.from(root2, 'hex')])).digest('hex');
const head = (size = 1, root = root1, proof = []) => ({ schema: 'aukora-aura-presented-head-v1', leafConvention: leaf,
  sequence: size, treeSize: size, hash: 'ab'.repeat(32), sig: 'test-signature', root, retainedTreeSize: 1, proofFromPrevious: proof });

// Transactions serialize and may abort after a successful put request.
function storage(t, options = {}) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
  const data = new Map();
  let queue = Promise.resolve();
  const db = {
    close() {}, createObjectStore() {},
    transaction(_name, mode) {
      const tx = { active: true, requests: [], committed: false };
      let snapshot;
      let release;
      const prior = queue;
      queue = new Promise(resolve => { release = resolve; });
      tx.abort = () => {
        if (!tx.active) return;
        tx.active = false;
        data.clear(); snapshot.forEach((value, key) => data.set(key, value));
        setImmediate(() => { tx.onabort?.(); release(); });
      };
      tx.objectStore = () => ({
        get(key) { const request = {}; tx.requests.push(() => {
          if (options.failRead) return tx.abort();
          request.result = structuredClone(data.get(key)); request.onsuccess?.();
        }); return request; },
        put(value, key) { const request = {}; tx.requests.push(() => {
          data.set(key, structuredClone(value)); request.onsuccess?.();
          if (options.abortWrite) tx.abort();
        }); return request; },
      });
      prior.then(() => { snapshot = new Map(structuredClone([...data])); setImmediate(function step() {
        if (!tx.active) return;
        const request = tx.requests.shift();
        if (request) { request(); setImmediate(step); }
        else {
          tx.active = false; tx.committed = true;
          options.onCommit?.(mode); tx.oncomplete?.(); release();
        }
      }); });
      return tx;
    },
  };
  Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: { open() {
    const request = {};
    setImmediate(() => {
      if (options.failOpen) request.onerror?.();
      else { request.result = db; request.onsuccess?.(); }
    });
    return request;
  } } });
  t.after(() => previous ? Object.defineProperty(globalThis, 'indexedDB', previous) : delete globalThis.indexedDB);
  return { data, options };
}

class Element {
  constructor(tag, doc) { this.tagName = tag; this.ownerDocument = doc; this.children = []; this.dataset = {}; this.style = {}; this.value = ''; this.classList = { add() {} }; }
  appendChild(child) { if (typeof child === 'string') { const text = new Element('#text', this.ownerDocument); text.textContent = child; child = text; } this.children.push(child); return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren(...children) { this.children = []; this._text = ''; this.append(...children); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get textContent() { return (this._text ?? '') + this.children.map(child => child.textContent).join(''); }
  setAttribute(name, value) { this[name] = String(value); }
  set innerHTML(value) { this.html = value; }
}
const descendants = element => [element, ...element.children.flatMap(descendants)];
function dom(t) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'document');
  const doc = { createElement: tag => new Element(tag, doc), createElementNS: (_ns, tag) => new Element(tag, doc) };
  Object.defineProperty(globalThis, 'document', { configurable: true, value: doc });
  t.after(() => previous ? Object.defineProperty(globalThis, 'document', previous) : delete globalThis.document);
  return doc.createElement('div');
}

async function kept(t) {
  const fixture = storage(t);
  await checkPresentedHead(head(), sha256);
  return { ...fixture, original: structuredClone(fixture.data.get('last')) };
}

async function preservesEvidence(t, presented, reason) {
  const fixture = await kept(t);
  const result = await checkPresentedHead(presented, sha256);
  assert.equal(result.state, 'alarm'); assert.equal(result.reason, reason);
  assert.deepEqual(fixture.data.get('last'), fixture.original);
}
test('antibody_owner_witness_empty_rollback_preserves_evidence', t => preservesEvidence(t, head(0), 'witness:head-invalid'));
test('antibody_owner_witness_fork_preserves_evidence', t => preservesEvidence(t, head(1, root2), 'same_size_root_mismatch'));
test('antibody_owner_witness_false_chain_tip_preserves_evidence', t => preservesEvidence(t, { ...head(), hash: 'cd'.repeat(32) }, 'witness:hash-mismatch'));
test('antibody_owner_witness_proof_anchor_preserves_evidence', t => preservesEvidence(t, { ...head(2, pairRoot, [root2]), retainedTreeSize: 2 }, 'witness:proof-size-mismatch'));
test('antibody_owner_witness_missing_proof_preserves_evidence', t => preservesEvidence(t, head(2, pairRoot), 'empty_proof_for_different_sizes'));
test('antibody_owner_witness_invalid_proof_preserves_evidence', t => preservesEvidence(t, head(2, pairRoot, [root1]), 'POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE'));
test('antibody_owner_witness_malformed_head_preserves_evidence', t => preservesEvidence(t, { ...head(), sequence: 2 }, 'witness:head-invalid'));

test('antibody_owner_witness_positive_extension_retains_head_and_110_trits', async t => {
  storage(t);
  const first = await checkPresentedHead(head(), sha256);
  assert.equal(first.state, 'first');
  const extended = await checkPresentedHead(head(2, pairRoot, [root2]), sha256);
  assert.equal(extended.state, 'extended');
  assert.deepEqual(extended.retained.trits, Array.from(await pentoraDigits(Buffer.from(pairRoot, 'hex'), sha256)));
  assert.equal(extended.retained.trits.length, 110);
  assert.deepEqual(await loadWitnessHead(), extended.retained);
  const same = await checkPresentedHead({ ...head(2, pairRoot), retainedTreeSize: 2 }, sha256);
  assert.equal(same.state, 'same');
});

test('antibody_owner_witness_rollback_from_nonempty_head_preserves_evidence', async t => {
  const fixture = await kept(t);
  await checkPresentedHead(head(2, pairRoot, [root2]), sha256);
  const original = structuredClone(fixture.data.get('last'));
  const result = await checkPresentedHead({ ...head(), retainedTreeSize: 2 }, sha256);
  assert.equal(result.reason, 'witness:rollback');
  assert.deepEqual(fixture.data.get('last'), original);
});

test('antibody_owner_witness_corrupt_local_trits_preserves_evidence', async t => {
  const fixture = await kept(t);
  fixture.data.get('last').trits[0] = 9;
  const original = structuredClone(fixture.data.get('last'));
  assert.equal((await checkPresentedHead(head(), sha256)).reason, 'witness:trits-mismatch');
  assert.deepEqual(fixture.data.get('last'), original);
});

test('antibody_owner_witness_storage_failure_never_becomes_first_visit', async t => {
  const fixture = await kept(t);
  fixture.options.failRead = true;
  let requested = false;
  const observation = await observeOwnerHead({ head: () => { requested = true; return head(); }, sha256 });
  assert.equal(observation.witness.state, 'alarm');
  assert.equal(observation.witness.reason, 'witness:store-unavailable');
  assert.equal(requested, false);
  assert.deepEqual(fixture.data.get('last'), fixture.original);
});

test('antibody_owner_witness_transaction_abort_does_not_report_retention', async t => {
  const fixture = await kept(t);
  fixture.options.abortWrite = true;
  const result = await observeOwnerHead({ head: () => head(2, pairRoot, [root2]), sha256 });
  assert.equal(result.witness.state, 'alarm');
  assert.equal(result.witness.reason, 'witness:store-unavailable');
  assert.deepEqual(fixture.data.get('last'), fixture.original);
});

test('antibody_owner_witness_stale_tab_cannot_overwrite_newer_observation', async t => {
  const fixture = await kept(t);
  await checkPresentedHead(head(2, pairRoot, [root2]), sha256);
  const original = structuredClone(fixture.data.get('last'));
  await assert.rejects(checkPresentedHead(head(), sha256, fixture.original), { code: 'witness:observation-changed' });
  assert.deepEqual(fixture.data.get('last'), original);
});

test('antibody_owner_witness_concurrent_tabs_keep_the_committed_observation', async t => {
  const fixture = await kept(t);
  const outcomes = await Promise.allSettled([
    checkPresentedHead(head(2, pairRoot, [root2]), sha256, fixture.original),
    checkPresentedHead(head(2, pairRoot, [root2]), sha256, fixture.original),
  ]);
  assert.equal(outcomes.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(outcomes.find(value => value.status === 'rejected').reason.code, 'witness:observation-changed');
  assert.equal(fixture.data.get('last').treeSize, 2);
});

test('antibody_owner_witness_observation_race_refetches_once_before_alarm', async t => {
  const fixture = await kept(t);
  const requests = [];
  const result = await observeOwnerHead({ sha256, head: async since => {
    requests.push(since);
    if (requests.length === 1) {
      await checkPresentedHead(head(2, pairRoot, [root2]), sha256);
      return head(2, pairRoot, [root2]);
    }
    return { ...head(2, pairRoot), retainedTreeSize: 2 };
  } });
  assert.deepEqual(requests, [1, 2]);
  assert.equal(result.witness.state, 'same');
  assert.equal(result.witness.retained.treeSize, 2);
  assert.deepEqual(fixture.data.get('last'), result.witness.retained);
});

test('antibody_owner_witness_retry_keeps_fork_checks_and_committed_evidence', async t => {
  const fixture = await kept(t);
  const requests = [];
  let committed;
  const result = await observeOwnerHead({ sha256, head: async since => {
    requests.push(since);
    if (requests.length === 1) {
      await checkPresentedHead(head(2, pairRoot, [root2]), sha256);
      committed = structuredClone(fixture.data.get('last'));
      return head(2, pairRoot, [root2]);
    }
    return { ...head(2, root2), retainedTreeSize: 2 };
  } });
  assert.deepEqual(requests, [1, 2]);
  assert.equal(result.witness.state, 'alarm');
  assert.equal(result.witness.reason, 'same_size_root_mismatch');
  assert.deepEqual(result.witness.kept, committed);
  assert.deepEqual(fixture.data.get('last'), committed);
});

test('antibody_owner_witness_second_observation_race_still_alarms', async t => {
  const fixture = await kept(t);
  const root3 = '03'.repeat(32);
  const tripleRoot = createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(pairRoot, 'hex'), Buffer.from(root3, 'hex')])).digest('hex');
  const requests = [];
  let committed;
  const result = await observeOwnerHead({ sha256, head: async since => {
    requests.push(since);
    if (requests.length === 1) {
      await checkPresentedHead(head(2, pairRoot, [root2]), sha256);
      return head(2, pairRoot, [root2]);
    }
    if (requests.length === 2) {
      const presented = { ...head(3, tripleRoot, [root3]), retainedTreeSize: 2 };
      await checkPresentedHead(presented, sha256);
      committed = structuredClone(fixture.data.get('last'));
      return presented;
    }
    return { ...head(3, tripleRoot), retainedTreeSize: 3 };
  } });
  assert.deepEqual(requests, [1, 2]);
  assert.equal(result.witness.state, 'alarm');
  assert.equal(result.witness.reason, 'witness:observation-changed');
  assert.equal(result.witness.kept.treeSize, 2);
  assert.deepEqual(fixture.data.get('last'), committed);
  assert.equal(committed.treeSize, 3);
});

test('antibody_owner_witness_corrupt_local_head_preserves_evidence', async t => {
  const fixture = await kept(t);
  fixture.data.get('last').leafConvention = 'other';
  const original = structuredClone(fixture.data.get('last'));
  assert.equal((await checkPresentedHead(head(), sha256)).reason, 'witness:retained-invalid');
  assert.deepEqual(fixture.data.get('last'), original);
});

test('antibody_owner_witness_falsy_corrupt_storage_is_not_an_empty_browser', async t => {
  const fixture = storage(t);
  for (const corrupt of [false, 0, '']) {
    fixture.data.set('last', corrupt);
    const result = await checkPresentedHead(head(), sha256);
    assert.equal(result.reason, 'witness:retained-invalid');
    assert.equal(fixture.data.get('last'), corrupt);
  }
});

test('antibody_owner_witness_since_refusal_warns_without_erasing_evidence', async t => {
  const fixture = await kept(t);
  const observation = await observeOwnerHead({ sha256, head: async since => {
    assert.equal(since, 1);
    throw Object.assign(new Error('too large'), { code: 'aura:invalid-export-range' });
  } });
  assert.equal(observation.witness.state, 'alarm');
  assert.equal(observation.witness.reason, 'aura:invalid-export-range');
  assert.deepEqual(fixture.data.get('last'), fixture.original);
});

test('antibody_owner_witness_alarm_is_visible_and_owner_actions_stay_available', async t => {
  const target = dom(t);
  const action = document.createElement('button'); action.textContent = 'Approve'; target.appendChild(action);
  let release;
  const promise = mountOwnerWitness(target, () => new Promise(resolve => { release = resolve; }));
  await Promise.resolve();
  assert.equal(action.disabled, undefined);
  release({ witness: { state: 'alarm', reason: 'witness:rollback', kept: { ...head(2), schema: 'aukora-aura-retained-head-v1', trits: [0], keptAt: 1 } } });
  await promise; await Promise.resolve();
  const warning = descendants(target).find(element => element.role === 'alert');
  assert.match(warning.textContent, /witness:rollback/);
  assert.equal(warning.hidden, undefined);
  assert.equal(action.disabled, undefined);
  const download = warning.children.find(element => element.download === 'aukora-browser-witness.json');
  assert.ok(download);
  const checkpoint = JSON.parse(decodeURIComponent(download.href.split(',')[1]));
  assert.deepEqual(Object.keys(checkpoint), ['schema', 'leafConvention', 'sequence', 'hash', 'treeSize', 'root']);
  assert.equal(checkpoint.treeSize, 2);
});

test('antibody_owner_router_checks_every_route_without_blocking_signout', async t => {
  const target = dom(t);
  const fixture = await kept(t);
  document.body = { classList: { toggle() {} } };
  document.getElementById = () => target;
  const globals = ['location', 'window'];
  const previous = globals.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  let changed;
  const loc = { hash: '#/approvals', hostname: 'owner.example' };
  Object.defineProperty(globalThis, 'location', { configurable: true, value: loc });
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { addEventListener: (_name, callback) => { changed = callback; } } });
  t.after(() => globals.forEach((name, index) => previous[index] ? Object.defineProperty(globalThis, name, previous[index]) : delete globalThis[name]));
  const methods = ['state', 'auraHead', 'auraRecent', 'approvals', 'release', 'broker'];
  const originals = methods.map(name => api[name]);
  t.after(() => methods.forEach((name, index) => { api[name] = originals[index]; }));
  let requests = 0;
  api.state = async () => ({ state: 'bound', session: true, subject: 'test' });
  api.auraHead = async since => { assert.equal(since, 1); requests++; return head(1, root2); };
  api.auraRecent = async () => ({ rows: [] });
  api.approvals = async () => ({ pending: [] });
  api.release = async () => ({ agent: 'stopped' });
  api.broker = async () => ({ key: null, grant: null, models: [] });
  const waitForAlarm = async () => {
    for (let index = 0; index < 100; index++) {
      if (descendants(target).some(element => element.role === 'alert')) return;
      await new Promise(resolve => setImmediate(resolve));
    }
    assert.fail('owner route did not display witness alarm');
  };
  await import(`../app.js?witness-test=${Date.now()}`);
  await waitForAlarm();
  assert.equal(requests, 1);
  for (const route of ['model', 'aura', 'memory', 'identity', 'approvals']) {
    loc.hash = `#/${route}`; await changed();
    await waitForAlarm();
    const signout = descendants(target).find(element => element.tagName === 'button' && element.textContent === 'Sign out');
    assert.ok(signout); assert.notEqual(signout.disabled, true);
    assert.deepEqual(fixture.data.get('last'), fixture.original);
  }
  assert.equal(requests, 6);
});

test('antibody_pentora_rust_vectors_match_all_5360_digest_and_trit_bytes', async () => {
  let count = 0;
  for (const name of ['expansion_vectors_1006.json', 'expansion_vectors_4354.json']) {
    const vectors = JSON.parse(await readFile(new URL(`../../../crates/pentora/vectors/${name}`, import.meta.url), 'utf8'));
    for (const vector of vectors) {
      const bytes = Buffer.from(vector.head, 'hex');
      assert.equal(Buffer.from(await pentoraDigest(bytes, sha256)).toString('hex'), vector.sha256);
      const trits = await pentoraDigits(bytes, sha256);
      assert.equal(Buffer.from(trits).toString('hex'), vector.wire_hex);
      if (vector.balanced) assert.deepEqual(Array.from(trits, value => value - 1), vector.balanced);
      count++;
    }
  }
  assert.equal(count, 5360);
});

test('antibody_pentora_geometry_matches_rust_normative_indices_and_projection', async () => {
  const vector = JSON.parse(await readFile(new URL('../../../crates/pentora/vectors/geometry_index_table_v1.json', import.meta.url), 'utf8'));
  assert.equal(PENTORA.centre, vector.centre_index);
  assert.deepEqual(PENTORA.mutable, vector.mutable_indices);
  assert.deepEqual(PENTORA.cubes, vector.cubes.map(cube => cube.slots.map(slot => slot.global_index)));
  assert.deepEqual(PENTORA.edges, vector.cubes.flatMap(cube => cube.edges_global_indices.map(edge => [...edge].sort((a, b) => a - b))));
  const phi = (1 + Math.sqrt(5)) / 2;
  for (const point of vector.points) {
    const coordinates = point.coordinates.map(value => Number(((value.a[0] / value.a[1] + value.b[0] / value.b[1] * phi) / Math.sqrt(3)).toFixed(6)));
    assert.deepEqual(PENTORA.points[point.global_index], coordinates);
  }
});

test('antibody_pentora_comparison_uses_all_numeric_trits_and_rejects_malformed_input', () => {
  const ours = Array.from({ length: 110 }, (_, index) => index % 3);
  assert.equal(compareTrits(ours, ours.join(' ')).state, 'same');
  const other = [...ours]; other[109] = 2;
  assert.deepEqual(compareTrits(ours, other.join('')), { state: 'different', differences: [110] });
  for (const text of ['0'.repeat(109), '0'.repeat(111), '3'.repeat(110), '0'.repeat(109) + 'a']) assert.equal(compareTrits(ours, text).state, 'invalid');
});

test('antibody_pentora_visible_trits_and_comparison_match_drawn_cells', async t => {
  const target = dom(t);
  const trits = Array.from(await pentoraDigits(Buffer.from(root1, 'hex'), sha256));
  await drawPentora(target, root1, sha256);
  const cells = descendants(target).filter(element => element['data-digit'] !== undefined);
  assert.equal(cells.length, 110);
  assert.deepEqual(cells.map(element => Number(element['data-digit'])), trits);
  mountTritComparison(target, trits);
  const own = descendants(target).find(element => element['aria-label'] === 'this device Pentora trits');
  assert.equal(own.value, trits.join('')); assert.equal(own.readOnly, true);
  const other = descendants(target).find(element => element['aria-label'] === 'other device Pentora trits');
  const compare = descendants(target).find(element => element.tagName === 'button');
  other.value = own.value; compare.onclick();
  assert.match(target.textContent, /All 110 trits match/);
});

test('antibody_owner_aura_offers_cold_proof_and_visible_trits', async t => {
  const target = dom(t);
  const original = api.auraRecent; api.auraRecent = async () => ({ rows: [] }); t.after(() => { api.auraRecent = original; });
  const originalNostr = api.nostr;
  api.nostr = async () => ({ node: { npub: `npub1${'q'.repeat(58)}` }, agent: { npub: `npub1${'p'.repeat(58)}` } });
  t.after(() => { api.nostr = originalNostr; });
  await showAura(target, { observation: Promise.resolve({ head: head(), witness: { state: 'first' } }) });
  assert.ok(descendants(target).some(element => element.href === '/api/aura/export'));
  assert.ok(descendants(target).some(element => element['aria-label'] === 'this device Pentora trits' && element.value.length === 110));
  const block = descendants(target).find(element => element.className === 'head-block');
  assert.ok(block.textContent.includes(`npub1${'q'.repeat(58)}`));
  assert.ok(block.textContent.includes(`npub1${'p'.repeat(58)}`));
});

test('antibody_owner_aura_shows_retained_pentora_after_fork_or_head_request_failure', async t => {
  const target = dom(t);
  const original = api.auraRecent; api.auraRecent = async () => ({ rows: [] }); t.after(() => { api.auraRecent = original; });
  const retained = { ...head(), schema: 'aukora-aura-retained-head-v1', trits: Array.from(await pentoraDigits(Buffer.from(root1, 'hex'), sha256)) };
  for (const presented of [head(1, root2), undefined]) {
    const observation = Promise.resolve({ head: presented, witness: { state: 'alarm', reason: presented ? 'same_size_root_mismatch' : 'aura:invalid-export-range', kept: retained } });
    await showAura(target, { observation });
    assert.ok(target.textContent.includes('Retained browser witness'));
    const block = descendants(target).find(element => element.className === 'head-block');
    assert.equal(block.dataset.source, 'browser');
    const own = descendants(target).find(element => element['aria-label'] === 'this device Pentora trits');
    assert.equal(own.value, retained.trits.join(''));
    const circles = descendants(block).filter(element => element['data-digit'] !== undefined);
    assert.deepEqual(circles.map(element => Number(element['data-digit'])), retained.trits);
    assert.ok(descendants(target).some(element => element.className === 'witness-alarm' && element.hidden === false));
    if (presented) assert.ok(target.textContent.includes(`Unverified node presentation: tree 1, root ${root2}`));
  }
});

test('antibody_consistency_safe_integer_sizes_do_not_truncate_to_32_bits', async () => {
  const node = (left, right) => createHash('sha256').update(Buffer.concat([Buffer.from([1]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')])).digest('hex');
  const cache = new Map([[1, root1]]);
  const split = size => 2 ** Math.floor(Math.log2(size - 1));
  const root = size => {
    if (!cache.has(size)) { const k = split(size); cache.set(size, node(root(k), root(size - k))); }
    return cache.get(size);
  };
  const proof = (m, n, complete = true) => {
    if (m === n) return complete ? [] : [root(n)];
    const k = split(n);
    return m <= k ? [...proof(m, k, complete), root(n - k)] : [...proof(m - k, n - k, false), root(k)];
  };
  const size = 2 ** 32 + 1;
  const result = await verifyConsistency({ m: size, n: size + 1, root1: root(size), root2: root(size + 1), proof: proof(size, size + 1) }, sha256);
  assert.equal(result.verdict, 'APPEND_ONLY');
});

// Registered antibody (#27): the witness runs on every owner route and authenticated boot stage;
// the boot stages are its subtests.
test('antibody_owner_witness_runs_on_every_owner_route_and_authenticated_boot_stage', async t => {
  for (const state of ['claim-open', 'enrolled']) {
  await t.test(`antibody_owner_witness_boot_${state}`, async t => {
    const target = dom(t);
    document.body = { classList: { toggle() {} } };
    document.getElementById = () => null;
    const names = ['location', 'window'];
    const previous = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, 'location', { configurable: true, value: { hash: '#/identity' } });
    Object.defineProperty(globalThis, 'window', { configurable: true, value: { addEventListener() {} } });
    t.after(() => names.forEach((name, i) => previous[i] ? Object.defineProperty(globalThis, name, previous[i]) : delete globalThis[name]));
    const original = api.state, prepare = api.bindingPrepare;
    t.after(() => { api.state = original; api.bindingPrepare = prepare; });
    api.state = async () => ({ state, session: true });
    api.bindingPrepare = async () => { throw new Error('fixture binding unavailable'); };
    const { mountOwnerApp } = await import('../app.js');
    await mountOwnerApp(target).boot();
    assert.ok(descendants(target).some(el => el.className?.includes('owner-witness')));
    assert.ok(descendants(target).some(el => el.textContent === 'Sign out'));
  });
}
});
