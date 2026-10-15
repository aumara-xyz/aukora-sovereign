// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, isAbsolute, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { primeFile } from '../../tests/support/prime.mjs';

const overlayFile = fileURLToPath(new URL('../sovereign.patch.yml', import.meta.url));
const patchFile = new URL('../../patches/webserver-listen-inherited-fd.patch.json', import.meta.url);
const overlay = JSON.parse(readFileSync(overlayFile, 'utf8'));
const readHarness = path => readFileSync(primeFile(`vendor/dsh/${path}`), 'utf8');

// Read only the pinned bundle's row inventory, not arbitrary YAML configuration.
function bundleInventory(path) {
  const patches = [];
  let insert;
  let row;
  let indent;
  for (const line of readHarness(path).split('\n')) {
    if (line === '- insert:') {
      insert = [];
      patches.push({ insert });
      row = undefined;
      continue;
    }
    const entry = /^( *)- id: ([A-Za-z0-9_-]+)$/.exec(line);
    if (entry) {
      indent = entry[1].length;
      assert.ok(indent === 0 || indent === 4, 'pinned inventory row layout changed');
      row = { id: entry[2] };
      if (indent === 0) patches.push(row);
      else {
        assert.ok(insert, 'pinned inserted row has no insert');
        insert.push(row);
      }
      continue;
    }
    if (!row) continue;
    const field = /^( *)(name|disabled): (.+)$/.exec(line);
    if (!field || field[1].length !== indent + 2) continue;
    if (field[2] === 'name') {
      assert.match(field[3], /^'[^']+'$/);
      row.name = field[3].slice(1, -1);
    } else {
      assert.ok(['true', 'false'].includes(field[3]) || field[3].startsWith('!!js '));
      row.disabled = field[3] === 'true' ? true
        : field[3] === 'false' ? false : { __jsExpr: field[3].slice(5) };
    }
  }
  assert.ok(patches.length > 0);
  return patches;
}

function functionFromSource(source, start, stop, bindings = {}) {
  const first = source.indexOf(start);
  assert.notEqual(first, -1);
  const last = source.indexOf(stop, first);
  assert.notEqual(last, -1);
  const code = stripTypeScriptTypes(source.slice(first, last)).replace(/^export /, '');
  const name = /function (\w+)/.exec(code)[1];
  return new Function(...Object.keys(bindings), `${code}\nreturn ${name};`)(...Object.values(bindings));
}

const applyPatches = functionFromSource(
  readHarness('vendor/include/src/index.ts'),
  'export function applyEntryPatches(',
  '/** Runtime patch applied',
);
const anchorPluginNames = functionFromSource(
  readHarness('packages/boot/app-boot/src/index.ts'),
  'function anchorInsertedPluginNames(',
  '/**\n * Parse one loader patch list',
  { dirname, resolve, isAbsolute, pathToFileURL },
);

test('overlay disables the pinned effect, network, spend, and preset rows', () => {
  const prime = readFileSync(primeFile('scripts/materialize-aukora-release.py'), 'utf8');
  const tuple = /BROWSER_DISABLED_ROWS = \(([\s\S]*?)\n\)/.exec(prime)[1];
  const browserRows = [...tuple.matchAll(/'([^']+)'/g)].map(match => match[1]);
  const base = bundleInventory('packages/bundle/base/cordis.patch.yml');
  const web = bundleInventory('packages/bundle/web-app/cordis.patch.yml');
  const warnings = [];
  const rows = applyPatches([], [...base, ...web, ...overlay], message => warnings.push(message));
  const indexed = new Map(rows.map(row => [row.id, row]));
  const configured = new Map(overlay.filter(row => row.id).map(row => [row.id, row]));
  const searchRows = rows.filter(row => row.id?.startsWith('web-search-')).map(row => row.id);
  const required = new Set([...browserRows, ...searchRows,
    'llm-deepseek', 'llm-pi-ai', 'session-title-llm', 'session-telemetry-otel',
    'session-log-deepseek', 'plugin-package-inventory-deepseek', 'web-fetch-http',
    'open-in-app', 'ui-open-in-app', 'sandbox', 'client-hmr', 'agent-presets', 'ui-agent-preset',
    'deepseek-llm-api-extensions', 'web', 'ui-settings-plugins', 'ui-settings-plugin-inventory',
  ]);
  for (const id of required) {
    assert.equal(configured.get(id)?.disabled, true, `${id} overlay refusal missing`);
    if (indexed.has(id)) assert.equal(indexed.get(id).disabled, true, `${id} remains enabled`);
  }
  assert.equal(indexed.get('file-upload').disabled, undefined);
  assert.equal(indexed.get('session-controller').disabled, undefined);
  assert.ok(readHarness('packages/api/session-controller/src/agent.ts').includes(
    "if (presets === undefined) {\n      return { setup: (_agentCtx, agent) => { this.installSelection(agent) } }",
  ));
  assert.ok(warnings.length > 0, 'absent optional Prime rows are reported by the pinned patcher');
});

test('overlay restates FD 4 and the complete web, trust, and model configs', () => {
  const rows = new Map(overlay.filter(row => row.id).map(row => [row.id, row.config]));
  assert.deepEqual(rows.get('webserver'), {
    host: '127.0.0.1', port: 3080, listenFd: 4,
    compression: 'gzip', compressionLevel: 1, compressionThresholdBytes: 1024,
  });
  assert.deepEqual(rows.get('web-runtime'), {
    openBrowser: false, printUrl: true, surfaceContext: false,
    trustedHosts: { __jsExpr: 'ctx.webStartup.trustedHosts' },
  });
  assert.deepEqual(rows.get('connection'), {
    trustedHosts: { __jsExpr: 'ctx.webRuntime.trustedHosts' }, cookieMaxAgeDays: 1,
  });
  assert.equal(rows.get('agent-default-model').provider, 'sovereign');
  const expression = rows.get('agent-default-model').model;
  assert.equal(typeof expression.__jsExpr, 'string');
  const evaluate = functionFromSource(
    readHarness('vendor/loader/src/config/utils.ts'),
    'export function isJsExpr(',
    '/** Serialized JavaScript expression',
  );
  assert.equal(evaluate(expression), true);
});

test('the CLI anchors the spatial app faces and the bridge beside the overlay', () => {
  const anchored = anchorPluginNames(structuredClone(overlay), overlayFile);
  const inserted = anchored.flatMap(row => row.insert ?? []);
  const faces = ['layout', 'sidebar', 'threads', 'apps', 'messages', 'documents', 'settings', 'memory', 'organs'];
  assert.deepEqual(inserted.map(row => row.id), ['aukora-foundation', ...faces.map(face => `aukora-face-${face}`), 'aukora-face-services', 'aukora-face-stock-apps', 'aukora-branding', 'sovereign-bridge']);
  for (const [index, face] of faces.entries()) {
    // Browser-only: the face's no-op host half, never Prime's host module.
    assert.equal(inserted[index + 1].name, new URL(`../faces/${face}/lib/host.mjs`, import.meta.url).href);
  }
  const bridge = inserted.at(-1);
  assert.equal(bridge.name, new URL('../plugin.mjs', import.meta.url).href);
  assert.deepEqual(bridge.config.model, new Map(overlay.filter(row => row.id)
    .map(row => [row.id, row.config])).get('agent-default-model').model);
  // The faces replace the stock layout, sidebar, workspace and general settings.
  const disabled = new Set(overlay.filter(row => row.disabled).map(row => row.id));
  for (const id of ['ui-layout', 'ui-sidebar', 'ui-workspace', 'ui-settings-general']) assert.ok(disabled.has(id), id);
});

function applyListenerPatch() {
  const patch = JSON.parse(readFileSync(patchFile, 'utf8'));
  assert.equal(patch.formatVersion, 1);
  let source = readHarness('packages/host/webserver/src/index.ts');
  for (const edit of patch.edits) {
    assert.equal(edit.path, 'packages/host/webserver/src/index.ts');
    assert.equal(source.split(edit.find).length - 1, edit.occurrences);
    source = source.replaceAll(edit.find, edit.replace);
  }
  for (const expected of patch.expectAfterApply) assert.ok(source.includes(expected.contains));
  return source;
}

test('inherited-listener replacements apply once to the pinned patched source', () => {
  const patched = applyListenerPatch();
  assert.ok(patched.includes('listenFd?: number'));
  assert.ok(!patched.includes('AddressInfo'));
});

test('listenFd schema refuses stdio, negative values, and fractional descriptors', async () => {
  const source = applyListenerPatch();
  const { default: z } = await import(pathToFileURL(primeFile('vendor/dsh/vendor/schemastery/lib/index.mjs')).href);
  const line = /    listenFd: (.+),\n/.exec(source);
  assert.ok(line, 'listenFd schema missing');
  const fdSchema = new Function('z', `return ${line[1]};`)(z);
  for (const fd of [-1, 0, 1, 2, 3.5, '4']) assert.throws(() => fdSchema(fd));
  assert.equal(fdSchema(3), 3);
  assert.equal(fdSchema(4), 4);
  assert.equal(fdSchema(undefined), undefined);
});

async function listenWith(config, address) {
  const source = applyListenerPatch();
  const begin = source.indexOf('    await new Promise<void>((resolve, reject) => {');
  const end = source.indexOf('\n\n    // Node does not include upgraded sockets', begin);
  assert.ok(begin !== -1 && end !== -1);
  const block = stripTypeScriptTypes(source.slice(begin, end));
  const calls = [];
  const receiver = {
    config, ctx: { logger: { error() {} } },
    server: {
      once() {}, off() {}, on() {}, address() { return address; },
      listen(...args) { calls.push(args.slice(0, -1)); args.at(-1)(); },
    },
  };
  const run = new Function(`return async function () { ${block} };`)();
  await run.call(receiver);
  return { calls, port: receiver.listenedPort };
}

test('inherited listener uses only FD 4 and guards null and Unix addresses', async () => {
  for (const address of [null, '/run/chat.sock']) {
    assert.deepEqual(await listenWith({ listenFd: 4, port: 3080, host: '127.0.0.1' }, address), {
      calls: [[{ fd: 4 }]], port: 3080,
    });
  }
});

test('ordinary harness listener still uses its host and bound TCP port', async () => {
  assert.deepEqual(await listenWith({ port: 3080, host: '127.0.0.1' }, { port: 40123 }), {
    calls: [[3080, '127.0.0.1']], port: 40123,
  });
});
