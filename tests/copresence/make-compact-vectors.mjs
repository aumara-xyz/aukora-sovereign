#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Writes crates/copresence/vectors/compact-frames-v1.json: real compact frames (portal/wire.ts) with real WebCrypto signatures,
// the digests they carry, and malformed frames both implementations must refuse. The Rust reference codec
// (crates/copresence/src/compact.rs) and tests/copresence/compact-frames.mjs both check this one file. Run once to create it:
//
//   node tests/copresence/make-compact-vectors.mjs
//
// Signatures are randomised by ECDSA, so the file is not reproducible byte for byte; it is committed, and the tests read it.
import fs from 'node:fs';
import path from 'node:path';
import { compilePortal, ROOT } from './portal-compile.mjs';

const portal = compilePortal();
const wire = await portal.load('wire.js');
const bytes = await portal.load('bytes.js');
const text = await portal.load('base45.js');
const { hex, unhex, sign, concat, utf8, domain } = bytes;

const pair = async () => {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
  return { keys, raw, compressed: (await portal.load('p256.js')).compressKey(raw) };
};
const A = await pair(), B = await pair();
// Which key is "A" follows the engine: the lower uncompressed hex.
const [low, high] = hex(A.raw) < hex(B.raw) ? [A, B] : [B, A];
const who = (k, n, seq, session) => ({ node: '11'.repeat(16), device_key: hex(k.raw), device_epoch: 1, session_id: session.repeat(16), attempt_sequence: seq });
const a = who(low, 'a', 3, '5a'), b = who(high, 'b', 7, '6b');
const layers = { sound: false, motion: false, intent_ack: false };
const context = { a, b, method: 'screen-to-screen', required_layers: layers, purpose: 'AUKORA compact frame vector', intent: null };
const contextDigest = await wire.contextDigest(context);
const nonceA = '0a'.repeat(32), nonceB = '0b'.repeat(32);
const now = 1_800_000_000;

const frame = async (signer, fields, at = now, index = 1) => {
  const body = { ...fields, t_seconds: at, frame_index: index };
  const raw = wire.encodeCompact(body);
  const digest = await wire.compactDigest(raw);
  const signature = await sign(signer.keys.privateKey, digest);
  const full = concat(raw, unhex(signature, 64));
  return { body, full, digest: hex(digest) };
};
const faceA = await frame(low, { type: 'FACE', participant: a, method: 'screen-to-screen', required_layers: layers, nonce_commitment: hex(await wire.nonceCommitment(a, nonceA)) }, now, 1);
const faceB = await frame(high, { type: 'FACE', participant: b, method: 'screen-to-screen', required_layers: layers, nonce_commitment: hex(await wire.nonceCommitment(b, nonceB)) }, now, 1);
const hashOf = async f => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', f.full)));
const revealA = await frame(low, { type: 'SEENYOU', sender: 'A', context_digest: hex(contextDigest), face_a: await hashOf(faceA), face_b: await hashOf(faceB), nonce: nonceA }, now + 1, 2);
const revealB = await frame(high, { type: 'SEENYOU', sender: 'B', context_digest: hex(contextDigest), face_a: await hashOf(faceA), face_b: await hashOf(faceB), nonce: nonceB }, now + 2, 2);
const transcript = hex(await wire.transcript([faceA.full, faceB.full, revealA.full, revealB.full]));
const core = { context, nonce_a: nonceA, nonce_b: nonceB, t_a_seconds: now + 1, t_b_seconds: now + 2, transcript, channels: { sound: null, motion: null } };
const coreDigest = await wire.coreDigest(core);
const sigB = await sign(high.keys.privateKey, coreDigest), sigA = await sign(low.keys.privateKey, coreDigest);
const handshake = await frame(high, { type: 'HANDSHAKE', core_digest: hex(coreDigest), sig_b: sigB }, now + 3, 3);
const bloom = await frame(low, { type: 'BLOOM', core_digest: hex(coreDigest), sig_a: sigA, intent_sig: null }, now + 4, 3);
const intentSig = await sign(low.keys.privateKey, await domain('copresence.intent-ack.v2', coreDigest, contextDigest, unhex('cd'.repeat(32), 32), new Uint8Array([0])));
const bloomAck = await frame(low, { type: 'BLOOM', core_digest: hex(coreDigest), sig_a: sigA, intent_sig: intentSig }, now + 4, 4);

const entry = (name, signer, f, fields) => ({ name, signer, frame: hex(f.full), digest: f.digest, qr_text: text.encode45(f.full), fields });
const frames = [
  entry('face-a', 'a', faceA, { nonce_commitment: faceA.body.nonce_commitment }),
  entry('face-b', 'b', faceB, { nonce_commitment: faceB.body.nonce_commitment }),
  entry('seenyou-a', 'a', revealA, { sender: 'A', context_digest: revealA.body.context_digest, face_a: revealA.body.face_a, face_b: revealA.body.face_b, nonce: nonceA }),
  entry('seenyou-b', 'b', revealB, { sender: 'B', context_digest: revealB.body.context_digest, face_a: revealB.body.face_a, face_b: revealB.body.face_b, nonce: nonceB }),
  entry('handshake-b', 'b', handshake, { core_digest: hex(coreDigest), sig_b: sigB }),
  entry('bloom-a', 'a', bloom, { core_digest: hex(coreDigest), sig_a: sigA, intent_sig: null }),
  entry('bloom-a-with-intent', 'a', bloomAck, { core_digest: hex(coreDigest), sig_a: sigA, intent_sig: intentSig }),
];
const times = [faceA, faceB, revealA, revealB, handshake, bloom, bloomAck];
frames.forEach((item, i) => { item.fields.t_seconds = times[i].body.t_seconds; item.fields.frame_index = times[i].body.frame_index; });

// Malformed frames, each derived from a good one. Every reader must refuse all of them.
const flip = (f, at, to) => { const out = f.slice(); out[at] = to; return out; };
const good = faceA.full, shake = handshake.full;
const invalid = [
  ['empty', new Uint8Array(0)],
  ['wrong-magic', flip(good, 0, 0x7b)],
  ['json-frame-start', utf8.encode('{"body":{}}')],
  ['unknown-type', flip(good, 1, 9)],
  ['type-zero', flip(good, 1, 0)],
  ['truncated-by-one', good.slice(0, good.length - 1)],
  ['extra-byte', concat(good, new Uint8Array([0]))],
  ['face-bad-method', flip(good, 75, 3)],
  ['face-bad-layers', flip(good, 76, 8)],
  ['face-key-prefix-5', flip(good, 18, 5)],
  ['face-key-x-off-curve', (() => { const out = good.slice(); out.set(unhex('ff'.repeat(32), 32), 19); return out; })()],
  ['seenyou-bad-sender', flip(revealA.full, 2, 2)],
  ['seenyou-short', revealA.full.slice(0, revealA.full.length - 5)],
  ['handshake-long', concat(shake, new Uint8Array(3))],
  ['bloom-bad-flags', flip(bloom.full, 2, 2)],
  ['bloom-flag-without-signature', flip(bloom.full, 2, 1)],
  ['bloom-signature-without-flag', flip(bloomAck.full, 2, 0)],
].map(([name, value]) => ({ name, frame: hex(value) }));

// Frames that decode but do not verify against the right key (the signature check, not the codec, must refuse them).
const tampered = [
  ['face-signed-by-someone-else', 'b', hex(faceA.full)],
  ['handshake-body-changed', 'b', hex(flip(shake, 5, shake[5] ^ 1))],
  ['seenyou-signature-changed', 'a', hex(flip(revealA.full, revealA.full.length - 1, revealA.full[revealA.full.length - 1] ^ 1))],
].map(([name, signer, frame]) => ({ name, signer, frame }));

const base45 = [['AB', '4142'], ['Hello!!', '48656c6c6f2121'], ['base-45', '626173652d3435'], ['ietf!', '6965746621'], ['', ''], ['00', '00'], ['ffff', 'ffff']].map(([, value]) => {
  const raw = value ? unhex(value, value.length / 2) : new Uint8Array(0); return { bytes: value, text: text.encode45(raw) };
});

// An invalid compressed key (no square root for this x) found by search, and x >= p.
const { decompressKey } = await portal.load('p256.js');
let offCurve = null;
for (let n = 1; n < 100 && !offCurve; ++n) { const c = new Uint8Array(33); c[0] = 2; c[32] = n; try { decompressKey(c); } catch { offCurve = hex(c); } }

const out = {
  schema: 'aukora.copresence.compact-frames.v1',
  note: 'Written by tests/copresence/make-compact-vectors.mjs; checked by crates/copresence (compact.rs) and tests/copresence/compact-frames.mjs.',
  keys: { a: { uncompressed: hex(low.raw), compressed: hex(low.compressed) }, b: { uncompressed: hex(high.raw), compressed: hex(high.compressed) } },
  participants: { a: { node: a.node, session_id: a.session_id, device_epoch: a.device_epoch, attempt_sequence: a.attempt_sequence },
    b: { node: b.node, session_id: b.session_id, device_epoch: b.device_epoch, attempt_sequence: b.attempt_sequence } },
  context: { method: 'screen-to-screen', layers: 0, purpose: context.purpose, digest: hex(contextDigest) },
  core: { nonce_a: nonceA, nonce_b: nonceB, t_a_seconds: core.t_a_seconds, t_b_seconds: core.t_b_seconds, transcript, digest: hex(coreDigest) },
  frames, invalid, tampered, base45,
  invalid_keys: [{ name: 'prefix-5', compressed: '05' + '00'.repeat(31) + '01' }, { name: 'x-not-a-curve-point', compressed: offCurve }, { name: 'x-at-least-p', compressed: '02' + 'ff'.repeat(32) }],
  sizes: Object.fromEntries(frames.map(item => [item.name, item.frame.length / 2])),
};
const target = path.join(ROOT, 'crates', 'copresence', 'vectors', 'compact-frames-v1.json');
fs.writeFileSync(target, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', target, JSON.stringify(out.sizes));
portal.cleanup();
