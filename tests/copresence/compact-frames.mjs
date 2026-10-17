#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The compact frame wire ("compact-v1", portal/wire.ts): the shared vectors (crates/copresence/vectors/compact-frames-v1.json, which the
// Rust reference codec also checks), point compression against WebCrypto, base45, the QR size of every frame, and two real engines
// running a whole exchange on compact frames (and, for regression, on the original JSON frames), ending with byte-identical receipts.
//
//   node tests/copresence/compact-frames.mjs [--quick]       (--quick skips the three two-engine exchanges, about 20 s)
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { compilePortal, ROOT } from './portal-compile.mjs';

const quick = process.argv.includes('--quick');
let failed = 0;
const check = (ok, label, detail = '') => { if (!ok || process.env.VERBOSE) console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`); if (!ok) failed++; };
const throws = async (fn) => { try { await fn(); return false; } catch { return true; } };

const portal = compilePortal();
const wire = await portal.load('wire.js'), bytes = await portal.load('bytes.js'), p256 = await portal.load('p256.js');
const base45 = await portal.load('base45.js'), frameText = await portal.load('frame-text.js'), qr = await portal.load('qr.js');
const { hex, unhex, concat } = bytes;
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, 'crates', 'copresence', 'vectors', 'compact-frames-v1.json'), 'utf8'));
const sandbox = {}; sandbox.self = sandbox.window = sandbox.globalThis = sandbox;
vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'portal', 'vendor', 'jsQR.min.js'), 'utf8'), sandbox);

// --- keys ---
for (const side of ['a', 'b']) {
  const k = vectors.keys[side];
  check(hex(p256.compressKey(unhex(k.uncompressed, 65))) === k.compressed, `key ${side}: compressed form matches the vector`);
  check(hex(p256.decompressKey(unhex(k.compressed, 33))) === k.uncompressed, `key ${side}: decompression matches the vector`);
}
let roundTrips = 0;
for (let n = 0; n < 300; ++n) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  if (hex(p256.decompressKey(p256.compressKey(raw))) === hex(raw)) ++roundTrips;
}
check(roundTrips === 300, '300 fresh WebCrypto keys compress and decompress to themselves', `${roundTrips}/300`);
for (const bad of vectors.invalid_keys) check(await throws(() => p256.decompressKey(unhex(bad.compressed, 33))), `invalid key refused: ${bad.name}`);

// --- base45 ---
for (const item of vectors.base45) {
  const raw = item.bytes ? unhex(item.bytes, item.bytes.length / 2) : new Uint8Array(0);
  check(base45.encode45(raw) === item.text && hex(base45.decode45(item.text)) === item.bytes, `base45 round trip: ${item.bytes || '(empty)'}`);
}
check(base45.encode45(new TextEncoder().encode('Hello!!')) === '%69 VD92EX0' && base45.encode45(new TextEncoder().encode('ietf!')) === 'QED8WEX0',
  'base45 matches the RFC 9285 examples');
for (const bad of ['GGW', '!!', 'A', 'ZZZZ']) check(await throws(() => base45.decode45(bad)), `base45 refuses ${JSON.stringify(bad)}`);

// --- digests the frames carry ---
const participants = { a: { ...vectors.participants.a, device_key: vectors.keys.a.uncompressed }, b: { ...vectors.participants.b, device_key: vectors.keys.b.uncompressed } };
const layers = { sound: false, motion: false, intent_ack: false };
const context = { a: participants.a, b: participants.b, method: vectors.context.method, required_layers: layers, purpose: vectors.context.purpose, intent: null };
check(hex(await wire.contextDigest(context)) === vectors.context.digest, 'the context digest in the vectors is the one the engine computes');
const byName = Object.fromEntries(vectors.frames.map(item => [item.name, item]));
const transcript = hex(await wire.transcript(['face-a', 'face-b', 'seenyou-a', 'seenyou-b'].map(name => unhex(byName[name].frame, byName[name].frame.length / 2))));
check(transcript === vectors.core.transcript, 'the transcript is the unchanged v1 function over the four compact frames');
const core = { context, nonce_a: vectors.core.nonce_a, nonce_b: vectors.core.nonce_b, t_a_seconds: vectors.core.t_a_seconds, t_b_seconds: vectors.core.t_b_seconds, transcript, channels: { sound: null, motion: null } };
check(hex(await wire.coreDigest(core)) === vectors.core.digest, 'the core digest is the unchanged v1 function');

// --- every vector frame: decode, re-encode, signature, digest, QR ---
const decodeQr = (modules) => {
  const border = 4, scale = 6, side = (modules.length + border * 2) * scale;
  const data = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < modules.length; ++y) for (let x = 0; x < modules.length; ++x) {
    if (!modules[y][x]) continue;
    for (let dy = 0; dy < scale; ++dy) for (let dx = 0; dx < scale; ++dx) { const at = (((y + border) * scale + dy) * side + (x + border) * scale + dx) * 4; data[at] = data[at + 1] = data[at + 2] = 0; }
  }
  return sandbox.jsQR(data, side, side, { inversionAttempts: 'dontInvert' })?.data;
};
for (const item of vectors.frames) {
  const raw = unhex(item.frame, item.frame.length / 2);
  const decoded = wire.decodeCompact(raw);
  const f = decoded.frame;
  const agrees = Object.entries(item.fields).every(([key, value]) => (key === 't_seconds' || key === 'frame_index') ? f[key] === value : JSON.stringify(f[key]) === JSON.stringify(value));
  check(agrees, `${item.name}: decoded fields match the vector`);
  check(hex(wire.encodeCompact(f)) === hex(decoded.body) && hex(concat(wire.encodeCompact(f), unhex(decoded.signature, 64))) === item.frame, `${item.name}: re-encodes to the same bytes`);
  check(hex(await wire.compactDigest(decoded.body)) === item.digest, `${item.name}: digest matches`);
  await bytes.verify(vectors.keys[item.signer].uncompressed, decoded.signature, await wire.compactDigest(decoded.body));
  check(await throws(() => bytes.verify(vectors.keys[item.signer === 'a' ? 'b' : 'a'].uncompressed, decoded.signature, new Uint8Array(32))), `${item.name}: another key does not verify it`);
  check(frameText.frameQrText(raw) === item.qr_text && hex(frameText.frameFromQrText(item.qr_text)) === item.frame, `${item.name}: QR text round trip`);
  const payload = qr.framePayload(raw);
  const version = qr.qrVersionOf(payload);
  check(payload.kind === 'alnum' && version >= 6 && version <= 10, `${item.name}: ${raw.length} bytes fit QR version ${version} (v1 JSON frames needed 19 to 27)`, `${17 + 4 * version} modules`);
  check(decodeQr(qr.qrModulesOf(payload)) === item.qr_text, `${item.name}: the QR code reads back the same text with jsQR`);
}
check(vectors.frames.every(item => item.frame.length / 2 <= 233) && ['face-a', 'seenyou-a', 'handshake-b', 'bloom-a'].every(name => byName[name].frame.length / 2 <= 201),
  'frames stay within 201 bytes (233 with an intent signature)');
for (const bad of vectors.invalid) check(await throws(() => wire.decodeCompact(unhex(bad.frame, bad.frame.length / 2 || 1))) || bad.frame === '', `malformed frame refused: ${bad.name}`);
for (const bad of vectors.tampered) {
  const raw = unhex(bad.frame, bad.frame.length / 2);
  let accepted = false;
  try { const d = wire.decodeCompact(raw); await bytes.verify(vectors.keys[bad.signer].uncompressed, d.signature, await wire.compactDigest(d.body)); accepted = true; } catch { /* refused */ }
  check(!accepted, `tampered frame does not verify: ${bad.name}`);
}
check(await throws(() => wire.validateCompact(unhex(byName['face-a'].frame, byName['face-a'].frame.length / 2), 1_900_000_000)), 'a stale frame is refused');
check(await throws(() => wire.validateCompact(unhex(byName['face-a'].frame, byName['face-a'].frame.length / 2), 1_700_000_000)), 'a frame from the future is refused');
const faceBytes = unhex(byName['face-a'].frame, byName['face-a'].frame.length / 2), faceTime = byName['face-a'].fields.t_seconds;
check(!await throws(() => wire.validateCompact(faceBytes, faceTime + 30)) && await throws(() => wire.validateCompact(faceBytes, faceTime + 31)), 'a compact frame is readable for 30 seconds, not 31 (the screen redraws its first frames; json-v1 keeps 5)');
check(!await throws(() => wire.validateCompact(unhex(byName['face-a'].frame, byName['face-a'].frame.length / 2), vectors.core.t_a_seconds)), 'a fresh FACE validates and verifies');

// --- two real engines, one whole exchange ---
function memoryStore() {
  let n = 0; const spent = new Set();
  return { attempts: { reserve: async () => `${++n}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`, finish: async () => {} },
    consumeReceipt: async (digest) => { if (spent.has(digest)) throw new Error('copresence:receipt-spent'); spent.add(digest); } };
}
async function exchange(label, frames, approved) {
  const { BrowserCopresenceEngine } = await portal.load('engine.js');
  const make = (side) => { const store = memoryStore(); return new BrowserCopresenceEngine({ node: '11'.repeat(16), deviceEpoch: 1, attempts: store.attempts, consumeReceipt: store.consumeReceipt,
    contextFormatPinned: () => true, legacyVerifier: async () => { throw new Error('legacy'); }, frames }); };
  const engines = [make('x'), make('y')], controller = new AbortController();
  const exchanges = [];
  const seen = [{ phase: '', receipt: null }, { phase: '', receipt: null }];
  const sizes = new Set();
  const started = Date.now();
  for (let i = 0; i < 2; ++i) {
    const ex = await engines[i].begin({ domain: 'copresence.v1', attemptId: `${i + 1}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`, method: 'optical',
      contextBytes: new TextEncoder().encode('AUKORA compact frame test'), approvedText: approved ? new TextEncoder().encode(approved) : null }, controller.signal);
    exchanges.push(ex);
  }
  exchanges.forEach((ex, i) => ex.subscribe(observation => {
    seen[i].phase = observation.phase; seen[i].receipt = observation.receiptBytes;
    if (observation.frameBytes) { sizes.add(observation.frameBytes.length); void exchanges[1 - i].receive(observation.frameBytes).catch(() => {}); }
  }));
  while (Date.now() - started < 40_000 && !(seen.every(s => s.phase === 'BLOOM' && s.receipt) || seen.some(s => s.phase === 'REFUSED'))) await new Promise(r => setTimeout(r, 100));
  const done = seen.every(s => s.phase === 'BLOOM' && s.receipt);
  check(done, `${label}: both engines reach BLOOM`, `${((Date.now() - started) / 1000).toFixed(1)} s, phases ${seen.map(s => s.phase)}`);
  if (done) check(hex(seen[0].receipt) === hex(seen[1].receipt), `${label}: both hold the same receipt, byte for byte`, `${seen[0].receipt.length} bytes`);
  exchanges.forEach(ex => ex.stop());
  return sizes;
}
// --- receipt freshness: 20 s from the second timestamp (it was 10) ---
async function receiptAge() {
  const { BrowserCopresenceEngine } = await portal.load('engine.js');
  const store = () => ({ attempts: { reserve: async () => `1.${hex(crypto.getRandomValues(new Uint8Array(16)))}`, finish: async () => {} }, consumeReceipt: async () => {} });
  const make = () => { const s = store(); return new BrowserCopresenceEngine({ node: '11'.repeat(16), deviceEpoch: 1, attempts: s.attempts, consumeReceipt: s.consumeReceipt,
    contextFormatPinned: () => true, legacyVerifier: async () => { throw new Error('legacy'); } }); };
  const engines = [make(), make()], controller = new AbortController(), exchanges = [], seen = [null, null];
  for (let i = 0; i < 2; ++i) exchanges.push(await engines[i].begin({ domain: 'copresence.v1', attemptId: `${i + 1}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`, method: 'optical',
    contextBytes: new TextEncoder().encode('receipt age'), approvedText: null }, controller.signal));
  exchanges.forEach((ex, i) => ex.subscribe(o => { if (o.receiptBytes) seen[i] = o.receiptBytes; if (o.frameBytes) void exchanges[1 - i].receive(o.frameBytes).catch(() => {}); }));
  for (let wait = 0; wait < 100 && !(seen[0] && seen[1]); ++wait) await new Promise(r => setTimeout(r, 100));
  const receipt = seen[0];
  if (!receipt) { check(false, 'a receipt to age'); return; }
  const tB = JSON.parse(new TextDecoder().decode(receipt)).body.core.t_b_seconds;
  const realNow = Date.now;
  const verdictAt = async seconds => { Date.now = () => (tB + seconds) * 1000; try { return (await engines[0].verifyContextReceipt(receipt, null, controller.signal)); } finally { Date.now = realNow; } };
  const at15 = await verdictAt(15), at20 = await verdictAt(20), at21 = await verdictAt(21);
  check(at15.verdict === 'UNDETERMINED' && at15.code === null, 'a receipt 15 s after its second timestamp is accepted', JSON.stringify(at15));
  check(at20.verdict === 'UNDETERMINED' && at20.code === null, 'a receipt 20 s after its second timestamp is still accepted');
  check(at21.verdict === 'SUSPICIOUS' && at21.code === 'copresence:receipt-stale', 'a receipt 21 s after its second timestamp is refused', JSON.stringify(at21));
  check(wire.RECEIPT_FRESH_SECONDS === 20, 'the engine and the node both say 20 seconds');
  exchanges.forEach(ex => ex.stop());
}
await receiptAge();
if (!quick) {
  const compact = await exchange('compact frames', 'compact-v1', null);
  check(Math.max(...compact) <= 201, 'every frame an engine drew was within 201 bytes', [...compact].sort((a, b) => a - b).join(', '));
  const intent = await exchange('compact frames with an intent acknowledgement', 'compact-v1', 'I approve this pairing');
  check(Math.max(...intent) <= 233, 'with an intent signature the largest frame is within 233 bytes', [...intent].sort((a, b) => a - b).join(', '));
  const legacy = await exchange('original JSON frames (regression)', 'json-v1', null);
  check(Math.min(...legacy) > 600, 'the JSON frames are still the large ones', [...legacy].sort((a, b) => a - b).join(', '));
}
portal.cleanup();
console.log(failed ? `${failed} FAILED` : 'ALL OK');
process.exit(failed ? 1 : 0);
