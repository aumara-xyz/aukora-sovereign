#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The pairing feedback (portal/feedback.ts): the four plain states follow what the engine and camera report, the ring only ever
// fills, and the sounds stay silent under a reduced-motion preference or when switched off. Pure logic with stubbed browser globals.
//
//   node tests/copresence/feedback.mjs
import { stripTypeScriptTypes } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
let failed = 0;
const check = (ok, label, detail = '') => { if (!ok || process.env.VERBOSE) console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`); if (!ok) failed++; };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'feedback-'));
fs.writeFileSync(path.join(dir, 'feedback.mjs'), stripTypeScriptTypes(fs.readFileSync(path.join(ROOT, 'portal', 'feedback.ts'), 'utf8')));
const url = pathToFileURL(path.join(dir, 'feedback.mjs')).href;

const { feedbackFor, chimes } = await import(url);
const state = (phase, seen) => feedbackFor(phase, seen).state;
check(state('FACE', false) === 'searching' && feedbackFor('FACE', false).fill === 0, 'before any code is read: searching, the ring empty');
check(state('FACE', true) === 'seen', 'the first code read: seen');
check(state('SEENYOU', false) === 'seen' && state('SEENYOU', true) === 'seen', 'seen-you is a seen state either way');
check(state('HANDSHAKE', true) === 'exchanging', 'handshake: exchanging');
check(state('BLOOM', true) === 'verified' && feedbackFor('BLOOM', true).fill === 1, 'bloom: verified, the ring full');
let last = -1, rising = true;
for (const [phase, seen] of [['FACE', false], ['FACE', true], ['SEENYOU', true], ['HANDSHAKE', true], ['BLOOM', true]]) {
  const fill = feedbackFor(phase, seen).fill; if (fill < last) rising = false; last = fill;
}
check(rising, 'the ring only ever fills as the exchange advances');
for (const phase of ['FACE', 'SEENYOU', 'HANDSHAKE', 'BLOOM']) {
  const text = feedbackFor(phase, true).message;
  check(text.length > 0 && !/spirit/i.test(text), `a message for ${phase}`, text);
}

// Sound: counts oscillators; a reduced-motion preference and an explicit "off" keep it silent.
let made = 0, buzzes = 0;
class FakeContext {
  currentTime = 0; destination = {}; state = 'running';
  resume() { return Promise.resolve(); }
  createGain() { return { gain: { setValueAtTime() {}, linearRampToValueAtTime() {}, exponentialRampToValueAtTime() {} }, connect(next) { return next; } }; }
  createOscillator() { made++; return { frequency: {}, connect(next) { return next; }, start() {}, stop() {} }; }
}
globalThis.AudioContext = FakeContext;
Object.defineProperty(globalThis, 'navigator', { value: { vibrate: () => { buzzes++; return true; } }, configurable: true });
const storage = new Map();
globalThis.localStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) };
globalThis.matchMedia = () => ({ matches: false });
let sound = chimes();
sound.unlock(); sound.seen(); sound.locked();
check(made === 3 && buzzes === 2, 'with sound on: one ping, two notes, two short buzzes', `${made} notes, ${buzzes} buzzes`);
sound.mute(true);
made = 0; buzzes = 0; sound.seen(); sound.locked();
check(made === 0 && buzzes === 0 && storage.get('aukora.sound') === 'off', 'muted: silent, and the choice is remembered');
sound = chimes();
made = 0; sound.unlock(); sound.seen();
check(made === 0 && sound.muted, 'a remembered mute holds on the next page');
storage.clear();
globalThis.matchMedia = () => ({ matches: true });
sound = chimes();
made = 0; sound.unlock(); sound.seen(); sound.locked();
check(made === 0 && sound.muted, 'reduced motion: silent by default');
fs.rmSync(dir, { recursive: true, force: true });
console.log(failed ? `${failed} FAILED` : 'ALL OK');
process.exit(failed ? 1 : 0);
