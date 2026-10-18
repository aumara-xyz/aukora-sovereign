// SPDX-License-Identifier: AGPL-3.0-or-later
// The shell parks an inactive face with visibility:hidden, which a sandboxed frame cannot observe; the shell tells it
// with one boolean message. The real face client, against a minimal window double.
// Run with: node --test tests/shell/face-shown.mjs
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const built = mkdtempSync(join(tmpdir(), 'face-shown-'));
writeFileSync(join(built, 'package.json'), '{"type":"module"}');
for (const name of ['client', 'data', 'rpc', 'organism']) {
  writeFileSync(join(built, `${name}.js`), stripTypeScriptTypes(readFileSync(join(root, `app/core/${name}.ts`), 'utf8')));
}
const { connectFace } = await import(pathToFileURL(join(built, 'client.js')).href);
const { RPC_CHANNEL } = await import(pathToFileURL(join(built, 'rpc.js')).href);
after(() => rmSync(built, { recursive: true, force: true }));

const SHELL = 'https://node.example';

function frameWindow() {
  const listeners = new Map();
  const parent = { posted: [], postMessage(data, origin) { this.posted.push({ data, origin }); } };
  const window = {
    parent,
    addEventListener(type, listener) { listeners.set(listener, type); },
    removeEventListener(type, listener) { listeners.delete(listener); },
    deliver(event) {
      for (const [listener, type] of [...listeners]) if (type === 'message') listener({ ports: [], ...event });
    },
  };
  globalThis.window = window;
  return window;
}

const shown = (value, extra = {}) => ({ channel: RPC_CHANNEL, type: 'shown', pluginId: 'messages', shown: value, ...extra });

test('a face starts shown and follows the shell\'s park and show messages', () => {
  const window = frameWindow();
  const client = connectFace({ shellOrigin: SHELL, pluginId: 'messages' });
  assert.equal(client.shown, true);
  const seen = [];
  const stop = client.onShown(value => seen.push(value));
  window.deliver({ source: window.parent, origin: SHELL, data: shown(false) });
  assert.equal(client.shown, false);
  window.deliver({ source: window.parent, origin: SHELL, data: shown(false) });
  window.deliver({ source: window.parent, origin: SHELL, data: shown(true) });
  assert.deepEqual(seen, [false, true], 'one call per change');
  stop();
  window.deliver({ source: window.parent, origin: SHELL, data: shown(false) });
  assert.deepEqual(seen, [false, true], 'a removed listener is not called');
  client.dispose();
});

test('only the shell frame, with exactly one boolean, can park a face', () => {
  const window = frameWindow();
  const client = connectFace({ shellOrigin: SHELL, pluginId: 'messages' });
  window.deliver({ source: {}, origin: SHELL, data: shown(false) });
  window.deliver({ source: window.parent, origin: 'https://other.example', data: shown(false) });
  window.deliver({ source: window.parent, origin: SHELL, data: shown(false, { pluginId: 'documents' }) });
  window.deliver({ source: window.parent, origin: SHELL, data: shown('no') });
  window.deliver({ source: window.parent, origin: SHELL, data: shown(false, { extra: 1 }) });
  assert.equal(client.shown, true);
  client.dispose();
});

test('the shell announces a face\'s visibility when it changes and when the face says hello', () => {
  const shell = readFileSync(join(root, 'app/shell/main.ts'), 'utf8');
  assert.match(shell, /type: 'shown', pluginId: slot\.manifest\.id, shown: slot\.element\.dataset\.active === 'true'/);
  assert.match(shell, /if \(changed\) announceShown\(value\);/);
  assert.match(shell, /\.type === 'hello'\) announceShown\(slot\);/);
  assert.match(readFileSync(join(root, 'app/shell/shell.css'), 'utf8'), /\.face-slot\[data-active='false'\] \{ visibility: hidden;/);
});
