#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Two real engines whose "cameras" are slow and unreliable: each looks at the other screen's current frame 8 times a second and misses a
// given share of the looks (the default, 0.88, is about one successful look a second, an iPhone decoding a full 1080 by 1920 frame).
// Counts how many exchanges finish. A manual measurement, not part of check.sh (it is random and takes about 10 s a run).
//
//   node tests/copresence/slow-reader.mjs [--runs=8] [--miss=0.88] [--dwell=2]
//
// Measured on 2026-10-17 with 12 runs each: the round-8 engine finished 8 of 12 at 1.6 looks a second, 5 of 12 at 1.0, 2 of 12 at 0.5;
// this engine finished 12 of 12, 12 of 12 and 11 of 12 (compare with PORTAL_SRC=<an older checkout's portal> node tests/copresence/slow-reader.mjs).
import { compilePortal } from './portal-compile.mjs';

const arg = Object.fromEntries(process.argv.slice(2).map(a => { const [k, v] = a.replace(/^--/, '').split('='); return [k, v ?? '1']; }));
const runs = Number(arg.runs || 8), miss = Number(arg.miss || 0.88), dwell = Number(arg.dwell || 2);
const portal = compilePortal();
const { BrowserCopresenceEngine } = await portal.load('engine.js');
const { hex } = await portal.load('bytes.js');
const store = () => { let n = 0; const spent = new Set(); return { attempts: { reserve: async () => `${++n}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`, finish: async () => {} },
  consumeReceipt: async d => { if (spent.has(d)) throw new Error('spent'); spent.add(d); } }; };
const make = () => { const s = store(); return new BrowserCopresenceEngine({ node: '11'.repeat(16), deviceEpoch: 1, attempts: s.attempts, consumeReceipt: s.consumeReceipt,
  contextFormatPinned: () => true, legacyVerifier: async () => { throw new Error('legacy'); }, dwell }); };

let done = 0;
const refusals = [];
for (let run = 1; run <= runs; ++run) {
  const controller = new AbortController(), exchanges = [];
  for (let i = 0; i < 2; ++i) exchanges.push(await make().begin({ domain: 'copresence.v1', attemptId: `${i + 1}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`, method: 'optical',
    contextBytes: new TextEncoder().encode('slow reader'), approvedText: null }, controller.signal));
  const current = [null, null], phase = ['', ''];
  const started = Date.now();
  exchanges.forEach((e, i) => e.subscribe(o => { current[i] = o.frameBytes; phase[i] = o.phase + (o.verdict?.code ? ` ${o.verdict.code}` : ''); }));
  const readers = [0, 1].map(i => setInterval(() => { if (current[1 - i] && Math.random() > miss) exchanges[i].receive(current[1 - i]).catch(() => {}); }, 125));
  while (Date.now() - started < 50_000 && !(phase[0] === 'BLOOM' && phase[1] === 'BLOOM') && !phase.some(p => p.startsWith('REFUSED'))) await new Promise(r => setTimeout(r, 100));
  const ok = phase[0] === 'BLOOM' && phase[1] === 'BLOOM';
  if (ok) ++done; else refusals.push(phase.join(' / '));
  console.log(`run ${run}: ${ok ? 'finished' : 'did not finish'} in ${((Date.now() - started) / 1000).toFixed(1)} s  ${ok ? '' : phase.join(' / ')}`);
  readers.forEach(clearInterval); exchanges.forEach(e => e.stop());
}
console.log(`${done} of ${runs} finished at ${((1 - miss) * 8).toFixed(1)} successful looks a second (dwell ${dwell})`);
portal.cleanup();
