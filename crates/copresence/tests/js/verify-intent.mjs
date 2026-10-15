#!/usr/bin/env node
// verify-intent.mjs — checks that a co-presence receipt approves one exact text. Standalone: Node 20+, no dependencies.
//
//   node verify-intent.mjs <receipt.json> --text "<exact text>" [--approver <pk hex>] [--max-age <seconds>]
//
// Exit 0 and one JSON line on success; exit 1 and "invalid <reason>" otherwise. It checks, in order:
//   1. the receipt passes the frozen verify.mjs beside this file (two P-256 signatures over the core, time window);
//   2. intent.text is exactly the text and intent.digest = SHA-256("copresence.intent.v1" || 0 || utf8(text));
//   3. the asking side's signed nonce = first 8 bytes of SHA-256("copresence.intent-nonce.v1" || 0 || digest || salt);
//   4. the other side's key signed SHA-256("copresence.intent-ack.v1" || 0 || digest || asker_pk || approver_nonce);
//   5. if --approver is given, that the signing key is that key (65-byte uncompressed P-256, 130 hex, starts 04);
//   6. if --max-age is given, that t_B is no older than that and not more than 5 s in the future.
// A pass is evidence that the approver device showed this text and its key signed it for this one session.
// It is not proof that a human was present, who tapped, or that anything was then done. Single use is the caller's job
// (remember `core`).
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { webcrypto as crypto } from 'node:crypto';
import path from 'node:path';

const fail = (why) => { console.log('invalid ' + why); process.exit(1); };
const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const file = args[0], text = opt('--text'), approver = (opt('--approver') || '').toLowerCase(), maxAge = opt('--max-age');
if (!file || text === undefined) fail('usage: verify-intent.mjs <receipt.json> --text "<text>" [--approver <pk>] [--max-age <s>]');

const here = path.dirname(fileURLToPath(import.meta.url));
const base = spawnSync(process.execPath, [path.join(here, 'verify.mjs'), file], { encoding: 'utf8' });
if (base.status !== 0) fail('receipt: ' + (base.stdout || base.stderr || '').trim().replace(/^invalid\s*/, ''));

let r;
try { r = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { fail('unreadable receipt'); }
const hex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/i.test(s);
const bytes = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const toHex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
const cat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const sha = async (...p) => new Uint8Array(await crypto.subtle.digest('SHA-256', cat(...p)));
const dom = (label, ...p) => sha(new TextEncoder().encode(label), new Uint8Array([0]), ...p);

const it = r.intent;
if (!it || typeof it !== 'object') fail('no_intent: this bloom was not made in approval mode');
const digest = toHex(await dom('copresence.intent.v1', new TextEncoder().encode(text)));
if (it.text !== text || String(it.digest).toLowerCase() !== digest) fail('intent_mismatch: this bloom approved a different text');
const side = it.side, other = side === 'A' ? 'B' : side === 'B' ? 'A' : null;
if (!other || !hex(it.salt, 32)) fail('malformed_intent');
const nonce = toHex((await dom('copresence.intent-nonce.v1', bytes(digest), bytes(it.salt))).subarray(0, 8));
if (String(r['nonce_' + side]).toLowerCase() !== nonce) fail('intent_not_committed: the signed nonce does not commit to this text');
const askerPk = String(r['pk_' + side]).toLowerCase(), approverPk = String(r['pk_' + other]).toLowerCase();
if (askerPk === approverPk) fail('same_key_on_both_sides');
if (!it.ack || !hex(it.ack.sig, 128)) fail('no_owner_signature: the approver device did not sign this text');
const msg = await dom('copresence.intent-ack.v1', bytes(digest), bytes(askerPk), bytes(String(r['nonce_' + other]).toLowerCase()));
let ok = false;
try {
  const key = await crypto.subtle.importKey('raw', bytes(approverPk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bytes(it.ack.sig.toLowerCase()), msg);
} catch (e) { ok = false; }
if (!ok) fail('bad_owner_signature: the signature over this text is not the approver key\'s for this session');
if (approver && approver !== approverPk) fail('wrong_approver: the text was signed by a different key than the one named');
if (maxAge !== undefined) {
  const age = Date.now() / 1000 - r.t_B;
  if (!(Number(maxAge) >= 0) || age > Number(maxAge)) fail('stale_receipt: ' + Math.round(age) + ' s old');
  if (age < -5) fail('receipt_from_the_future');
}
const core = toHex(await dom('copresence.v0', bytes(r.pk_A), bytes(r.pk_B), bytes(r.nonce_A), bytes(r.nonce_B),
  (() => { const o = new Uint8Array(8); let v = BigInt(r.t_B); for (let i = 7; i >= 0; i--) { o[i] = Number(v & 255n); v >>= 8n; } return o; })()));
console.log(JSON.stringify({ valid: true, core, text_digest: digest, approver_key: approverPk, asker_key: askerPk, t_B: r.t_B }));
