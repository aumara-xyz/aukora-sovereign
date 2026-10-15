// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants, promises as fs } from 'node:fs';
import { cp, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apply, createStockAppRoutes } from '../faces/stock-apps.mjs';
import { primeFile } from '../../tests/support/prime.mjs';

const vendorRoot = fileURLToPath(new URL('../faces/apps/vendor/', import.meta.url));
const licenseRoot = fileURLToPath(new URL('../faces/apps/LICENSES/', import.meta.url));
const manifest = JSON.parse(await readFile(new URL('../faces/apps/stock-manifest.json', import.meta.url), 'utf8'));
const allow = { requestRejection: () => undefined };
const routes = await createStockAppRoutes({ connection: allow });
const hash = body => createHash('sha256').update(body).digest('hex');

function response() {
  return {
    status: 0, headers: {}, body: Buffer.alloc(0),
    writeHead(status, headers = {}) { this.status = status; this.headers = headers; },
    end(body) { this.body = body === undefined ? Buffer.alloc(0) : Buffer.from(body); },
  };
}

async function request(route, url = route.path, method = 'GET') {
  const res = response();
  assert.doesNotThrow(() => route.handler({ url, method }, res), String(url));
  return res;
}

function routeFor(path, mounted = routes) {
  return mounted.find(route => route.kind === 'exact' && route.path === path)
    ?? mounted.find(route => route.kind === 'prefix' && path.startsWith(route.path));
}

async function filesUnder(root, prefix = '') {
  const files = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = prefix + entry.name;
    if (entry.isDirectory()) files.push(...await filesUnder(join(root, entry.name), path + '/'));
    else files.push(path);
  }
  return files.sort();
}

async function fixture(t) {
  const root = await mkdtemp(fileURLToPath(new URL('./.stock-fixture-', import.meta.url)));
  t.after(() => rm(root, { recursive: true, force: true }));
  const vendor = join(root, 'vendor');
  await cp(vendorRoot, vendor, { recursive: true });
  return { root, vendor, file: join(vendor, manifest.routes[0].relative) };
}

async function patchFs(name, replacement, run) {
  const original = fs[name];
  fs[name] = replacement(original);
  syncBuiltinESMExports();
  try { return await run(); }
  finally { fs[name] = original; syncBuiltinESMExports(); }
}

test('stock manifest selects exactly the five Dakini Code Prime runtime files', async () => {
  const prime = JSON.parse(await readFile(primeFile('packages/ui/baseline-manifest.json'), 'utf8'));
  const expected = prime.files.filter(item => item.path.startsWith('faces/apps/vendor/dakini-code/'));
  assert.equal(manifest.schema, 'aukora-stock-apps-v1');
  assert.equal(manifest.donorCommit, '645d3213b8aede3b544269b4224ae09df06b0a42');
  assert.equal(manifest.donorCommit, prime.commit);
  assert.equal(manifest.routes.length, 5);
  assert.deepEqual(manifest.routes.map(item => item.donorPath).sort(), expected.map(item => item.path).sort());
  assert.deepEqual(await filesUnder(vendorRoot), manifest.routes.map(item => item.relative).sort());
  for (const item of manifest.routes) {
    const pin = expected.find(entry => entry.path === item.donorPath);
    assert.equal(item.bytes, pin.bytes, item.path);
    assert.equal(item.sha256, pin.sha256, item.path);
    const body = await readFile(join(vendorRoot, item.relative));
    assert.deepEqual(body, await readFile(primeFile(`plugins/aukora-face/apps/vendor/${item.relative}`)), item.path);
    assert.equal(body.length, item.bytes, item.path);
    assert.equal(hash(body), item.sha256, item.path);
  }
});

test('stock routes are exact manifest routes plus a single refusal fallback', () => {
  assert.deepEqual(routes.map(route => [route.kind, route.path]), [
    ...manifest.routes.map(item => ['exact', item.path]), ['prefix', '/stock-apps'],
  ]);
});

test('antibody stock Auma Lingwa and Auma Live stay withheld pending voice qualification', async () => {
  const served = ['assets/index-C2MMIvhO.css', 'assets/index-t74FFCZZ.js',
    'assets/space-Bu4O81zr.js', 'favicon.svg', 'index.html']
    .map(name => '/stock-apps/dakini-code/' + name);
  assert.deepEqual(routes.map(route => [route.kind, route.path]), [
    ...served.map(path => ['exact', path]), ['prefix', '/stock-apps'],
  ]);
  const withheld = ['/stock-apps/auma-lingwa.html', '/stock-apps/auma-live.html',
    '/stock-apps/auma-lingwa/index.html', '/stock-apps/auma-live/index.html',
    '/stock-apps/auma-lingwa/runtime/auma-lingwa.html',
    '/stock-apps/auma-live/runtime/auma-live.html'];
  for (const method of ['GET', 'HEAD', 'POST']) {
    const zeta = await request(routeFor('/stock-apps/zeta-harp/index.html'),
      '/stock-apps/zeta-harp/index.html', method);
    assert.equal(zeta.status, method === 'POST' ? 405 : 404);
    assert.equal(zeta.body.length, 0);
    for (const path of withheld) {
      for (const suffix of ['', '?cache=1']) {
        const res = await request(routeFor(path), path + suffix, method);
        assert.equal(res.status, zeta.status, path);
        assert.deepEqual(res.headers, zeta.headers, path);
        assert.deepEqual(res.body, zeta.body, path);
      }
    }
  }
  for (const path of ['/app/auma/auma.css', '/app/auma/auma.js', '/app/auma/canon-v16.json',
    '/app/auma/readers-v1.json', '/app/aumalive-audio.js', '/app/aumalive-duplex.js',
    '/app/aumalive-mind-choice.js', '/app/aumalive.js', '/app/aura-core.js', '/app/aura-trace.js',
    '/app/chat-log-key.js', '/app/field-directives.js', '/app/field-quality.js',
    '/app/home-session.js', '/app/lane-bridge.js', '/app/style.css', '/assets/aumara-icon-96.png']) {
    assert.equal(routeFor(path), undefined, path);
  }
  assert.deepEqual(await filesUnder(vendorRoot), served.map(path => path.slice('/stock-apps/'.length)));
  for (const relative of ['auma-lingwa/runtime/auma-lingwa.html', 'auma-live/runtime/auma-live.html',
    'auma-lingwa/runtime/app/auma/auma.js', 'auma-live/runtime/app/aumalive.js']) {
    const candidate = structuredClone(manifest);
    Object.assign(candidate.routes[0], { relative, path: '/stock-apps/' + relative,
      contentType: relative.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8' });
    await assert.rejects(createStockAppRoutes({ manifest: candidate, connection: allow }),
      { code: 'stock-apps:invalid-manifest' });
  }
});

test('stock GET serves every pinned byte with its MIME, length and nosniff', async () => {
  for (const item of manifest.routes) {
    const res = await request(routeFor(item.path), item.path + '?cache=1');
    assert.equal(res.status, 200, item.path);
    assert.deepEqual(res.body, await readFile(join(vendorRoot, item.relative)), item.path);
    assert.equal(res.headers['content-type'], item.contentType, item.path);
    assert.equal(res.headers['content-length'], String(item.bytes), item.path);
    assert.equal(res.headers['x-content-type-options'], 'nosniff', item.path);
    assert.equal(res.headers['content-security-policy'], undefined, item.path);
  }
});

test('stock HEAD has GET headers and no body for every file', async () => {
  for (const item of manifest.routes) {
    const route = routeFor(item.path);
    const get = await request(route);
    const head = await request(route, item.path, 'HEAD');
    assert.equal(head.status, 200, item.path);
    assert.deepEqual(head.headers, get.headers, item.path);
    assert.equal(head.body.length, 0, item.path);
  }
});

test('stock routes allow only GET and HEAD', async () => {
  for (const route of routes) {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'get', undefined]) {
      const res = response();
      await route.handler({ url: route.path, method }, res);
      assert.equal(res.status, 405, `${method} ${route.path}`);
      assert.equal(res.headers.allow, 'GET, HEAD');
      assert.equal(res.body.length, 0);
    }
  }
});

test('stock session rejection passes through before methods and raw paths are read', async () => {
  for (const status of [401, 403]) {
    const checked = [];
    const mounted = await createStockAppRoutes({ connection: { requestRejection(req) { checked.push(req); return status; } } });
    for (const route of mounted) {
      const req = { get method() { throw new Error('method read before session check'); },
        get url() { throw new Error('path read before session check'); } };
      const res = response();
      assert.doesNotThrow(() => route.handler(req, res));
      assert.equal(res.status, status);
      assert.equal(res.body.length, 0);
      assert.equal(checked.at(-1), req);
    }
    assert.equal(checked.length, mounted.length);
  }
});

test('stock missing session checker refuses access', async () => {
  for (const connection of [undefined, {}, { requestRejection: null }]) {
    for (const route of await createStockAppRoutes({ connection })) {
      assert.equal((await request(route)).status, 403, route.path);
    }
  }
});

test('stock raw targets refuse traversal, encoded separators and malformed URLs', async () => {
  const targets = [
    '/stock-apps/../auma-live.html', '/stock-apps/dakini-code/../../auma-live.html',
    '/stock-apps/%2e%2e/auma-live.html', '/stock-apps/dakini-code%2findex.html',
    '/stock-apps/dakini-code%2Findex.html', '/stock-apps/dakini-code%5cindex.html',
    '/stock-apps/%252e%252e/auma-live.html', '/stock-apps/%',
    '/stock-apps\\dakini-code/index.html', '/stock-apps//dakini-code/index.html',
    '/stock-apps/./auma-live.html', '//stock-apps/auma-live.html',
    '/stock-apps/auma-live.html\0', '/stock-apps/auma-live.html\n',
    '/stock-apps/auma-live.html\u007f', '/stock-apps/auma live.html',
    '/stock-apps/auma-live.html#fragment', 'http://other.invalid/stock-apps/auma-live.html',
    'http://[broken', 'stock-apps/auma-live.html', undefined, 7,
  ];
  for (const target of targets) {
    for (const route of [routes[0], routes.at(-1)]) {
      const res = response();
      assert.doesNotThrow(() => route.handler({ method: 'GET', url: target }, res), String(target));
      assert.equal(res.status, 400, String(target));
      assert.equal(res.body.length, 0, String(target));
    }
  }
});

test('stock directories, unlisted paths and Zeta Harp are never served', async () => {
  for (const path of ['/stock-apps', '/stock-apps/', '/stock-apps/dakini-code/',
    '/stock-apps/auma-live/runtime/', '/stock-apps/auma-live/runtime/app/field-directives.d.ts',
    '/stock-apps/auma-live/voice/index.js', '/stock-apps/auma-lingwa/canonical/auma-canon-v16.json',
    '/stock-apps/dakini-code/source/index.js', '/stock-apps/three/LICENSE',
    '/stock-apps/zeta-harp/index.html', '/stock-apps/zeta-harp/assets/index.js',
    '/stock-apps/LICENSES/DAKINI-REACT-NOTICES.md', '/stock-apps/no-such-file.js']) {
    const res = await request(routeFor(path), path);
    assert.equal(res.status, 404, path);
    assert.equal(res.body.length, 0, path);
  }
});

test('stock exact handlers do not serve another route or unlisted file', async t => {
  const fixtureRoot = await fixture(t);
  await writeFile(join(fixtureRoot.vendor, 'secret.txt'), 'private');
  const mounted = await createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow });
  for (const route of mounted.filter(item => item.kind === 'exact')) {
    const other = manifest.routes.find(item => item.path !== route.path).path;
    assert.equal((await request(route, other)).status, 404, route.path);
    assert.equal((await request(route, '/stock-apps/secret.txt')).status, 404, route.path);
  }
  assert.equal(mounted.length, routes.length);
});

test('stock manifest rejects changed schema, donor, incomplete or duplicate routes', async () => {
  const changed = [
    { ...manifest, schema: 'aukora-stock-apps-v2' }, { ...manifest, donorCommit: '0'.repeat(40) },
    { ...manifest, routes: undefined }, { ...manifest, routes: [] },
    { ...manifest, routes: manifest.routes.slice(1) },
    { ...manifest, routes: [...manifest.routes, manifest.routes[0]] },
    { ...manifest, routes: manifest.routes.map((item, i) => i === 1 ? manifest.routes[0] : item) },
    { ...manifest, routes: manifest.routes.map((item, i) => i === 0 ? null : item) },
  ];
  for (const candidate of changed) {
    await assert.rejects(createStockAppRoutes({ manifest: candidate, connection: allow }), { code: 'stock-apps:invalid-manifest' });
  }
});

test('stock manifest rejects escapes, unknown files, route remapping and wrong MIME', async () => {
  const changes = [
    { relative: '../auma.css' }, { relative: '/etc/passwd' },
    { relative: 'auma-lingwa/runtime/app/auma/../auma.css' },
    { relative: 'auma-lingwa\\runtime\\app\\auma\\auma.css' },
    { relative: 'auma-lingwa/runtime/app/auma%2fauma.css' },
    { relative: 'auma-lingwa/runtime/app//auma/auma.css' },
    { relative: 'auma-lingwa/runtime/app/auma/./auma.css' },
    { relative: 'unknown.js', path: undefined, contentType: 'text/javascript; charset=utf-8' },
    { path: '/stock-apps/auma.css' }, { contentType: 'text/html; charset=utf-8' },
    { relative: 'zeta-harp/index.html', path: '/stock-apps/zeta-harp/index.html' },
  ];
  for (const change of changes) {
    const candidate = structuredClone(manifest);
    Object.assign(candidate.routes[0], change);
    await assert.rejects(createStockAppRoutes({ manifest: candidate, connection: allow }), { code: 'stock-apps:invalid-manifest' });
  }
});

test('stock manifest rejects malformed byte lengths and digest pins', async () => {
  for (const change of [{ bytes: 0 }, { bytes: -1 }, { bytes: 1.5 }, { bytes: '21749' },
    { bytes: Number.MAX_SAFE_INTEGER + 1 }, { sha256: null }, { sha256: 'x'.repeat(64) },
    { sha256: 'f'.repeat(63) }, { sha256: 'F'.repeat(64) }]) {
    const candidate = structuredClone(manifest);
    Object.assign(candidate.routes[0], change);
    await assert.rejects(createStockAppRoutes({ manifest: candidate, connection: allow }), { code: 'stock-apps:invalid-manifest' });
  }
});

test('stock vendor root refuses symlinks, ancestor aliases and regular files', async t => {
  const fixtureRoot = await fixture(t);
  const link = join(fixtureRoot.root, 'root-link');
  await symlink(fixtureRoot.vendor, link);
  await assert.rejects(createStockAppRoutes({ vendorRoot: link, connection: allow }), { code: 'stock-apps:root-refused' });
  const alias = join(fixtureRoot.root, 'ancestor-link');
  await symlink(fixtureRoot.root, alias);
  await assert.rejects(createStockAppRoutes({ vendorRoot: join(alias, 'vendor'), connection: allow }), { code: 'stock-apps:root-refused' });
  const regular = join(fixtureRoot.root, 'root-file');
  await writeFile(regular, 'not a directory');
  await assert.rejects(createStockAppRoutes({ vendorRoot: regular, connection: allow }), { code: 'stock-apps:root-refused' });
});

test('stock file and directory symlinks are refused even when their bytes match', async t => {
  const fixtureRoot = await fixture(t);
  const body = await readFile(fixtureRoot.file);
  const outside = join(fixtureRoot.root, 'outside.css');
  const inside = join(fixtureRoot.vendor, 'inside.css');
  await writeFile(outside, body);
  await writeFile(inside, body);
  for (const target of [outside, inside]) {
    await rm(fixtureRoot.file);
    await symlink(target, fixtureRoot.file);
    await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:symlink-refused' });
  }
  await rm(fixtureRoot.file);
  await writeFile(fixtureRoot.file, body);
  const parent = dirname(fixtureRoot.file);
  for (const moved of [join(fixtureRoot.root, 'outside-directory'), join(fixtureRoot.vendor, 'internal-directory')]) {
    await rename(parent, moved);
    await symlink(moved, parent);
    await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:symlink-refused' });
    await rm(parent);
    await rename(moved, parent);
  }
});

test('stock nonregular files and non-directory parents are refused', async t => {
  const fixtureRoot = await fixture(t);
  await rm(fixtureRoot.file);
  await mkdir(fixtureRoot.file);
  await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:file-refused' });
  const parent = dirname(fixtureRoot.file);
  await rm(parent, { recursive: true });
  await writeFile(parent, 'not a directory');
  await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:file-refused' });
});

test('stock resolved file paths must remain inside the vendor root', async t => {
  const fixtureRoot = await fixture(t);
  await patchFs('realpath', original => async path => path === fixtureRoot.file
    ? join(fixtureRoot.root, 'outside.css') : original(path), async () => {
    await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:file-refused' });
  });
});

test('stock late symlinks are refused by the no-follow file open', async t => {
  const fixtureRoot = await fixture(t);
  let changed = false;
  await patchFs('open', original => async (path, flags, ...rest) => {
    if (path === fixtureRoot.file && !changed) {
      changed = true;
      const moved = join(fixtureRoot.root, 'original.css');
      await rename(path, moved);
      await symlink(moved, path);
    }
    return original(path, flags, ...rest);
  }, async () => {
    await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'ELOOP' });
  });
  assert.equal(changed, true);
  assert.ok(constants.O_NOFOLLOW > 0);
});

test('stock replacement between stat and open is refused even for identical bytes', async t => {
  const fixtureRoot = await fixture(t);
  let changed = false;
  await patchFs('open', original => async (path, flags, ...rest) => {
    if (path === fixtureRoot.file && !changed) {
      changed = true;
      const body = await readFile(path);
      await rename(path, join(fixtureRoot.root, 'old.css'));
      await writeFile(path, body);
    }
    return original(path, flags, ...rest);
  }, async () => {
    await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:file-replaced' });
  });
  assert.equal(changed, true);
});

test('stock changed hashes and changed byte lengths each prevent mounting', async t => {
  const fixtureRoot = await fixture(t);
  const original = await readFile(fixtureRoot.file);
  const changed = Buffer.from(original);
  changed[0] ^= 1;
  await writeFile(fixtureRoot.file, changed);
  await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:baseline-changed' });
  await writeFile(fixtureRoot.file, original.subarray(1));
  await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow }), { code: 'stock-apps:baseline-changed' });
  await writeFile(fixtureRoot.file, original);
  const candidate = structuredClone(manifest);
  candidate.routes[0].bytes += 1;
  await assert.rejects(createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, manifest: candidate, connection: allow }), { code: 'stock-apps:baseline-changed' });
});

test('stock handlers keep the verified snapshot after vendor bytes change or disappear', async t => {
  const fixtureRoot = await fixture(t);
  const mounted = await createStockAppRoutes({ vendorRoot: fixtureRoot.vendor, connection: allow });
  await writeFile(fixtureRoot.file, 'changed after mounting');
  await rm(fixtureRoot.vendor, { recursive: true });
  for (const item of manifest.routes) {
    const res = await request(routeFor(item.path, mounted));
    assert.equal(res.status, 200, item.path);
    assert.equal(hash(res.body), item.sha256, item.path);
    assert.equal(res.body.length, item.bytes, item.path);
  }
});

test('stock dependency notices, content licence and attribution are retained byte for byte', async () => {
  const expected = [
    'DAKINI-BASE-UI-NOTICES.md', 'DAKINI-LUCIDE-THREE-NOTICES.md',
    'DAKINI-REACT-NOTICES.md', 'upstream/npm/@base-ui/react@1.7.0/LICENSE',
    'upstream/npm/lucide-react@1.31.0/LICENSE', 'upstream/npm/react@19.2.6/LICENSE',
    'upstream/npm/three@0.186.0/LICENSE',
  ];
  assert.deepEqual(manifest.licenses.map(item => item.path).sort(), expected.sort());
  assert.deepEqual(await filesUnder(licenseRoot), expected);
  const readme = await readFile(new URL('../faces/README.md', import.meta.url), 'utf8');
  for (const item of manifest.licenses) {
    const body = await readFile(join(licenseRoot, item.path));
    assert.deepEqual(body, await readFile(primeFile(`licenses/${item.path}`)), item.path);
    assert.equal(body.length, item.bytes, item.path);
    assert.equal(hash(body), item.sha256, item.path);
    assert.ok(readme.includes(`apps/LICENSES/${item.path}`), item.path);
  }
});

test('stock local HTML and module resource references have manifest routes', async () => {
  const referenced = new Set();
  const paths = new Set(manifest.routes.map(item => item.path));
  for (const item of manifest.routes) {
    if (!/\.(?:html|js)$/.test(item.relative)) continue;
    const source = await readFile(join(vendorRoot, item.relative), 'utf8');
    const resources = [...source.matchAll(/["']((?:\/app\/|\/assets\/)[^"']+)["']/g)].map(match => match[1]);
    if (item.relative.endsWith('.html')) {
      resources.push(...[...source.matchAll(/(?:src|href)=["']([^"']+)["']/g)].map(match => match[1]));
    }
    resources.push(...[...source.matchAll(/(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["'`]((?:\.\/|\.\.\/)[^"'`]+)["'`]/g)]
      .map(match => match[1]));
    for (const resource of resources) {
      const path = new URL(resource, 'http://stock.test' + item.path).pathname;
      assert.ok(paths.has(path), `${item.path} references missing ${path}`);
      referenced.add(path);
    }
  }
  for (const required of ['/stock-apps/dakini-code/assets/index-t74FFCZZ.js',
    '/stock-apps/dakini-code/assets/space-Bu4O81zr.js']) assert.ok(referenced.has(required), required);
});

test('stock guest plugin mounts beside unavailable services and disposes its routes', async () => {
  const overlay = JSON.parse(await readFile(new URL('../sovereign.patch.yml', import.meta.url), 'utf8'));
  const inserted = overlay.flatMap(row => row.insert ?? []);
  const services = inserted.findIndex(row => row.id === 'aukora-face-services');
  assert.deepEqual(inserted[services + 1], { id: 'aukora-face-stock-apps', name: './faces/stock-apps.mjs' });
  const mounted = [];
  const removed = [];
  const effects = [];
  apply({ inject(names, callback) {
    assert.deepEqual(names, ['webServer', 'connection']);
    callback({ connection: allow, webServer: { register(route) { mounted.push(route); return () => removed.push(route.path); } },
      effect(callback) { effects.push(callback()); } });
  } });
  const [dispose] = await Promise.all(effects);
  assert.deepEqual(mounted.map(route => [route.kind, route.path]), routes.map(route => [route.kind, route.path]));
  dispose();
  assert.deepEqual(removed, mounted.map(route => route.path));
});

test('stock guest plugin rolls back routes when registration fails', async () => {
  const collision = new Error('fixture route collision');
  const registered = [];
  const removed = [];
  await assert.rejects(Promise.resolve(apply({ inject(names, callback) {
    assert.deepEqual(names, ['webServer', 'connection']);
    return callback({ connection: allow, effect: callback => callback(), webServer: { register(route) {
      if (registered.length === 2) throw collision;
      registered.push(route.path);
      return () => removed.push(route.path);
    } } });
  } })), collision);
  assert.equal(registered.length, 2);
  assert.deepEqual(removed, registered);
});

test('stock guest plugin propagates effect startup errors to its injector', async () => {
  const startup = new Error('fixture effect failure');
  await assert.rejects(Promise.resolve(apply({ inject(names, callback) {
    assert.deepEqual(names, ['webServer', 'connection']);
    return callback({ effect: () => Promise.reject(startup) });
  } })), startup);
});
