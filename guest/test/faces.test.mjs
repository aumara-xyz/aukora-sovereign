// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { apply, UNAVAILABLE } from '../faces/unavailable.mjs';

const FACES = ['layout', 'sidebar', 'threads', 'apps', 'messages', 'documents', 'settings', 'memory', 'organs'];

function response() {
  return { status: 0, headers: {}, body: '', writeHead(status, headers = {}) { this.status = status; this.headers = headers; }, end(body = '') { this.body = body; } };
}

function mount(rejection) {
  const routes = [];
  const web = {
    webServer: { register(route) { routes.push(route); return () => {}; } },
    connection: { requestRejection: () => rejection },
    effect(callback) { callback(); },
  };
  apply({ inject(names, callback) { assert.deepEqual(names, ['webServer', 'connection']); callback(web); } });
  return routes;
}

test('every Prime service route the faces call answers 503 UNAVAILABLE, as Prime NEXT does', () => {
  const routes = mount(undefined);
  assert.deepEqual(routes.map(r => [r.kind, r.path]), UNAVAILABLE.map(([path]) => ['prefix', path]));
  for (const route of routes) {
    const res = response();
    route.handler({ headers: {} }, res);
    assert.equal(res.status, 503);
    const body = JSON.parse(res.body);
    assert.equal(body.ok, false);
    assert.equal(body.error_code, 'UNAVAILABLE');
    assert.ok(body.reason.length > 0);
  }
});

test('the harness browser-session check still runs first', () => {
  for (const rejection of [401, 403]) {
    for (const route of mount(rejection)) {
      const res = response();
      route.handler({ headers: {} }, res);
      assert.equal(res.status, rejection);
      assert.equal(res.body, '');
    }
  }
});

test('the identity face is not in the chat app: the phrase is never typed on the agent-served origin', () => {
  // The chat origin is served by the untrusted agent; Aumlok ceremonies live on the owner origin.
  assert.ok(!existsSync(new URL('../faces/aumlok', import.meta.url)));
  assert.ok(!readFileSync(new URL('../sovereign.patch.yml', import.meta.url), 'utf8').includes('aukora-face-aumlok'));
});

test('every face ships its client bundle, a no-op host half and a browser manifest', async () => {
  for (const face of FACES) {
    const dir = new URL(`../faces/${face}/`, import.meta.url);
    const pkg = JSON.parse(readFileSync(new URL('package.json', dir), 'utf8'));
    assert.equal(pkg.name, `@aukora/face-${face}`);
    assert.equal(pkg.exports['.'], './lib/host.mjs');
    assert.equal(pkg.exports['./client'], './lib/client.js');
    assert.equal(pkg.dsh.client.platform, 'web');
    assert.ok(existsSync(new URL('lib/client.js', dir)));
    const host = await import(new URL('lib/host.mjs', dir));
    assert.equal(host.apply(), undefined);
    // The Prime host half (which reaches services outside the sandbox) is not shipped.
    assert.ok(!existsSync(new URL('lib/index.js', dir)));
  }
});

test('the AUMARA mark is served as one exact file, after the session check', async () => {
  const { apply: applyBranding, ICON_PATH } = await import('../faces/branding.mjs');
  const routes = [];
  for (const rejection of [undefined, 401]) {
    routes.length = 0;
    applyBranding({ inject(names, callback) { callback({ webServer: { register(route) { routes.push(route); return () => {}; } }, connection: { requestRejection: () => rejection }, effect(cb) { cb(); } }); } });
    assert.deepEqual(routes.map(r => [r.kind, r.path]), [['exact', ICON_PATH]]);
    const res = response();
    routes[0].handler({ method: 'GET', headers: {} }, res);
    if (rejection) { assert.equal(res.status, 401); continue; }
    assert.equal(res.status, 200);
    assert.equal(res.headers['content-type'], 'image/png');
    assert.deepEqual(res.body.subarray(0, 8), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  }
});
