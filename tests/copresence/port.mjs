#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The owner port's renewal timer (sweep C13): near expiry it renews an unjoined pairing's phone link, and it never
// replaces a pairing a phone has joined (a new start closes the owner's open and joined pairings). Node only: the port
// is compiled from portal/ as app/build.mjs strips TypeScript; the node client and the device key are fakes.
//   node tests/copresence/port.mjs
import { stripTypeScriptTypes } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'copresence-port-')));
function compile(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const source = path.join(from, entry.name);
    if (entry.isDirectory()) compile(source, path.join(to, entry.name));
    else if (entry.name.endsWith('.ts')) fs.writeFileSync(path.join(to, entry.name.replace(/\.ts$/, '.js')), stripTypeScriptTypes(fs.readFileSync(source, 'utf8'), { mode: 'strip' }));
    else if (entry.name.endsWith('.json')) fs.copyFileSync(source, path.join(to, entry.name));
  }
}
compile(path.join(here, '..', '..', 'portal'), path.join(tmp, 'portal'));
fs.writeFileSync(path.join(tmp, 'package.json'), '{"type":"module"}');
const { createNodePairingPort } = await import(pathToFileURL(path.join(tmp, 'portal/node/pairing-port.js')).href);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let failed = 0;
const check = (ok, label, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`); if (!ok) failed++; };

function fakeNode(stateOf) {
  const starts = [];
  return {
    starts,
    client: {
      async start() {
        const now = Date.now(), pairing = String(starts.length + 1).padStart(32, '0');
        starts.push(pairing);
        // 21.5 s left: the renewal check falls 1.5 s after the start.
        return { schema: 'aukora.copresence.pairing-start.v1', pairing, join: 'j', joinPath: '/pair#j=j', expiresAtMs: now + 21_500, nodeTimeMs: now };
      },
      async status(pairing) { return { pairing, state: stateOf(pairing), context: null, verdict: null }; },
    },
  };
}
const options = node => ({ client: node.client, origin: 'https://owner.example.org', deviceKey: async () => ({ keys: null, publicKey: '04' }) });
// A canvas stand-in: drawing the link needs only width, height and a 2D context.
const canvas = () => ({ width: 0, height: 0, dataset: {}, getContext: () => ({ fillRect() {}, clearRect() {}, set fillStyle(_) {} }) });

{
  const node = fakeNode(() => 'joined');
  const port = createNodePairingPort(options(node));
  port.phoneLink.draw(canvas());
  await sleep(2_500);
  check(node.starts.length === 1, 'a joined pairing is not replaced by the renewal timer', `starts=${node.starts.length}`);
  const again = await port.session();
  check(again.pairing === node.starts[0] && node.starts.length === 1, 'session() inside the last 20 s keeps the joined pairing');
}
{
  const node = fakeNode(() => 'open');
  const port = createNodePairingPort(options(node));
  port.phoneLink.draw(canvas());
  await sleep(2_500);
  check(node.starts.length === 2, 'an unjoined pairing near expiry gets a fresh phone link', `starts=${node.starts.length}`);
}
{
  const node = fakeNode(() => 'spent');
  const port = createNodePairingPort(options(node));
  port.phoneLink.draw(canvas());
  await sleep(2_500);
  check(node.starts.length === 1, 'a spent pairing is not renewed', `starts=${node.starts.length}`);
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(failed ? `PORT FAILED (${failed})` : 'PORT PASSED');
process.exit(failed ? 1 : 0);
