#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The QR codes use the smallest version that holds their bytes (portal/qr.ts qrModulesFit), for the phone link and for the
// signed exchange frames alike: the same payload in fewer, larger modules. Every version 1 to 40, at its capacity and at one
// byte over the version below, must pick the right size and decode with the vendored jsQR the pages themselves load, in both
// polarities (dark on light, and light on dark, which jsQR reads with inversionAttempts attemptBoth). The version 40 reference
// qrModules is pinned byte for byte to what it drew before this change.
//
//   node tests/copresence/qr-fit.mjs
import { stripTypeScriptTypes } from 'node:module';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(here, '..', '..');
let failed = 0;
const check = (ok, label, detail = '') => { if (!ok || process.env.VERBOSE) console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`); if (!ok) failed++; };

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qr-fit-'));
for (const name of ['qr', 'bytes', 'base45', 'frame-text']) {
  fs.writeFileSync(path.join(dir, `${name}.js`), stripTypeScriptTypes(fs.readFileSync(path.join(ROOT, 'portal', `${name}.ts`), 'utf8')));
}
const { qrModules, qrModulesFit, qrCapacity, qrVersionFor, qrVersionOf, qrModulesOf } = await import(pathToFileURL(path.join(dir, 'qr.js')).href);
const sandbox = {};
sandbox.self = sandbox.window = sandbox.globalThis = sandbox;
vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'portal', 'vendor', 'jsQR.min.js'), 'utf8'), sandbox);
const jsQR = sandbox.jsQR;

const decode = (modules, inverted) => {
  const border = 4, scale = 6, side = (modules.length + border * 2) * scale;
  const data = new Uint8ClampedArray(side * side * 4);
  const [off, on] = inverted ? [10, 245] : [255, 0];
  for (let i = 0; i < side * side; ++i) { data[i * 4] = data[i * 4 + 1] = data[i * 4 + 2] = off; data[i * 4 + 3] = 255; }
  for (let y = 0; y < modules.length; ++y) for (let x = 0; x < modules.length; ++x) {
    if (!modules[y][x]) continue;
    for (let dy = 0; dy < scale; ++dy) for (let dx = 0; dx < scale; ++dx) {
      const at = (((y + border) * scale + dy) * side + (x + border) * scale + dx) * 4;
      data[at] = data[at + 1] = data[at + 2] = on;
    }
  }
  return jsQR(data, side, side, { inversionAttempts: 'attemptBoth' })?.binaryData;
};
const sameBytes = (a, b) => !!a && a.length === b.length && b.every((v, i) => a[i] === v);
const payload = length => new Uint8Array(length).map((_, i) => (i * 131 + 7 + length) & 255);

check(qrCapacity(1) === 17 && qrCapacity(9) === 230 && qrCapacity(10) === 271 && qrCapacity(40) === 2953, 'capacities match the standard (17, 230, 271, 2953)');
// Version 23 is skipped on purpose: jsQR 1.4.0 cannot read it (an independent encoder's version 23 fails the same way).
for (let version = 1, previous = 0; version <= 40; previous = version++) {
  if (version === 23) { previous = 22; continue; }
  const cap = qrCapacity(version);
  for (const length of previous === 0 ? [1, cap] : [qrCapacity(previous) + 1, cap]) {
    const bytes = payload(length);
    const modules = qrModulesFit(bytes);
    check(qrVersionFor(length) === version && modules.length === 17 + 4 * version, `${length} bytes uses version ${version}`, `${modules.length} modules`);
    check(sameBytes(decode(modules, false), bytes), `${length} bytes at version ${version} decodes, dark on light`);
    check(sameBytes(decode(modules, true), bytes), `${length} bytes at version ${version} decodes, light on dark`);
  }
}
check(qrVersionFor(qrCapacity(22) + 1) === 24, 'a payload that would land on version 23 is drawn at version 24');
// Alphanumeric mode (compact frames travel as base45 text): the standard level-L capacities, and the text reads back.
const alnumCapacity = [25, 47, 77, 114, 154, 195, 224, 279, 335, 395];
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const sample = n => Array.from({ length: n }, (_, i) => ALPHABET[(i * 7 + 3) % 45]).join('');
for (let version = 1; version <= 10; ++version) {
  const text = sample(alnumCapacity[version - 1]), over = sample(alnumCapacity[version - 1] + 1);
  check(qrVersionOf({ kind: 'alnum', text }) === version, `${text.length} alphanumeric characters use version ${version}`);
  if (version < 10) check(qrVersionOf({ kind: 'alnum', text: over }) === version + 1 + (version + 1 === 23 ? 1 : 0), `${over.length} alphanumeric characters use version ${version + 1}`);
  const modules = qrModulesOf({ kind: 'alnum', text });
  const border = 4, scale = 6, side = (modules.length + border * 2) * scale;
  const data = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < modules.length; ++y) for (let x = 0; x < modules.length; ++x) if (modules[y][x]) for (let dy = 0; dy < scale; ++dy) for (let dx = 0; dx < scale; ++dx) { const at = (((y + border) * scale + dy) * side + (x + border) * scale + dx) * 4; data[at] = data[at + 1] = data[at + 2] = 0; }
  check(jsQR(data, side, side, { inversionAttempts: 'dontInvert' })?.data === text, `version ${version} alphanumeric code reads back with jsQR`);
}
check(qrVersionFor(2954) === 0, '2954 bytes fit no version');

const pin = bytes => crypto.createHash('sha256').update(JSON.stringify(qrModules(bytes))).digest('hex');
check(pin(new Uint8Array(500).map((_, i) => (i * 37 + 11) & 255)) === '3092e6d483764e0d3ac48544d2214354d241eab1c9dbb9dbf3345bdc85d52daf', 'version 40 reference: 500 bytes unchanged');
check(pin(new Uint8Array(2953).map((_, i) => (i * 91 + 5) & 255)) === 'eb337cb8fa0aa21d1091410f1fa628fe55d026e7efb1d29813c51dcb585b5783', 'version 40 reference: 2953 bytes unchanged');
const forty = payload(2953);
check(JSON.stringify(qrModules(forty)) === JSON.stringify(qrModulesFit(forty)), 'at 2953 bytes the fitted code is the version 40 code');

const real = new TextEncoder().encode('https://192.168.1.20:8443/pair#j=' + 'A'.repeat(43));
check(qrModulesFit(real).length < 40, 'a real join link is a small code', `${qrModulesFit(real).length} modules`);
fs.rmSync(dir, { recursive: true, force: true });
console.log(failed ? `${failed} FAILED` : 'ALL OK');
process.exit(failed ? 1 : 0);
