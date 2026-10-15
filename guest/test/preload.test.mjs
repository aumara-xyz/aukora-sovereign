// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const preload = new URL('../preload.mjs', import.meta.url).href;
const cwd = fileURLToPath(new URL('../../', import.meta.url));

function run(source, stdio = undefined) {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd,
    encoding: 'utf8',
    timeout: 5000,
    ...(stdio === undefined ? {} : { stdio }),
  });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  return result;
}

const sentinel = `
  import assert from 'node:assert/strict';
  import dns, { lookup as namedLookup } from 'node:dns';
  import dnsPromises, { lookup as namedPromiseLookup } from 'node:dns/promises';
  import net, { connect as namedConnect, createConnection as namedCreateConnection } from 'node:net';
  import { syncBuiltinESMExports } from 'node:module';
  const attempted = (...args) => { attempted.args = args; return 'unconfined-attempt'; };
  globalThis.fetch = attempted;
  dns.lookup = attempted;
  dnsPromises.lookup = attempted;
  net.connect = attempted;
  net.createConnection = attempted;
  net.Socket.prototype.connect = attempted;
  syncBuiltinESMExports();
  await import(${JSON.stringify(preload)});
  const refused = fn => assert.throws(fn, error =>
    error.code === 'guest:network-forbidden'
    && error.message === 'guest:network-forbidden'
    && error.retryable === false);
`;

test('preload refuses global fetch without dispatching', () => {
  run(`${sentinel} refused(() => fetch('https://invalid.example'));`);
});

test('preload refuses callback DNS through default and named exports', () => {
  run(`${sentinel}
    refused(() => dns.lookup('invalid.example', () => {}));
    refused(() => namedLookup('invalid.example', () => {}));
  `);
});

test('preload refuses promise DNS through default, property, and named exports', () => {
  run(`${sentinel}
    refused(() => dnsPromises.lookup('invalid.example'));
    refused(() => dns.promises.lookup('invalid.example'));
    refused(() => namedPromiseLookup('invalid.example'));
  `);
});

test('preload refuses TCP factories and Socket.connect without dispatching', () => {
  run(`${sentinel}
    for (const factory of [net.connect, net.createConnection, namedConnect, namedCreateConnection]) {
      refused(() => factory({ port: 80, host: '127.0.0.1' }));
      refused(() => factory(80, '127.0.0.1'));
      refused(() => factory('80'));
      refused(() => factory({ path: '' }));
      refused(() => factory({ path: '\\0abstract' }));
    }
    const socket = new net.Socket();
    refused(() => socket.connect({ port: 80, host: '127.0.0.1' }));
    socket.destroy();
  `);
});

test('preload passes Unix paths with a stable path value', () => {
  run(`${sentinel}
    assert.equal(net.connect('./local.sock'), 'unconfined-attempt');
    assert.equal(net.createConnection({ path: '/local.sock' }), 'unconfined-attempt');
    let reads = 0;
    assert.equal(net.connect({ get path() { return ++reads === 1 ? '/local.sock' : undefined; } }), 'unconfined-attempt');
    assert.equal(attempted.args[0].path, '/local.sock');
    const socket = new net.Socket();
    assert.equal(socket.connect({ path: '/local.sock' }), 'unconfined-attempt');
    assert.equal(socket.connect([{ path: '/local.sock' }]), 'unconfined-attempt');
    socket.destroy();
  `);
});

test('preload preserves the factory to Socket normalized Unix path', () => {
  run(`
    import assert from 'node:assert/strict';
    import net from 'node:net';
    net.Socket.prototype.connect = options => options.path;
    net.connect = options => {
      const socket = new net.Socket();
      const path = socket.connect([options]);
      socket.destroy();
      return path;
    };
    await import(${JSON.stringify(preload)});
    assert.equal(net.connect({ path: '/local.sock' }), '/local.sock');
  `);
});

test('preload preserves inherited FD 3 stream writes', () => {
  const result = run(`
    import assert from 'node:assert/strict';
    import net from 'node:net';
    await import(${JSON.stringify(preload)});
    const socket = new net.Socket({ fd: 3, readable: true, writable: true });
    assert.equal(socket.destroyed, false);
    await new Promise((resolve, reject) => {
      socket.once('error', reject);
      socket.end('fd-channel', () => { socket.destroy(); resolve(); });
    });
  `, ['ignore', 'pipe', 'pipe', 'pipe']);
  assert.equal(result.output[3], 'fd-channel');
});

test('preload serves a TCP listen on the inherited FD 4 listener and refuses any second listener', async () => {
  const { spawn } = await import('node:child_process');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const net = (await import('node:net')).default;
  const dir = mkdtempSync(join(tmpdir(), 'preload-listen-'));
  const path = join(dir, 'ui.sock');
  const inherited = net.createServer();
  await new Promise(resolve => inherited.listen(path, resolve));
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import http from 'node:http';
    import net from 'node:net';
    await import(${JSON.stringify(preload)});
    const server = http.createServer((req, res) => res.end('served:' + req.url));
    await new Promise(resolve => server.listen(3080, '127.0.0.1', resolve));
    assert.deepEqual(server.address(), { address: '127.0.0.1', family: 'IPv4', port: 3080 });
    for (const attempt of [() => net.createServer().listen(3081), () => net.createServer().listen({ fd: 4 }), () => net.createServer().listen('/tmp/other.sock')]) {
      assert.throws(attempt, error => error.code === 'guest:network-forbidden');
    }
    process.stdout.write('ready');
  `], { cwd, stdio: ['ignore', 'pipe', 'pipe', 'ignore', inherited._handle.fd] });
  // Closing the parent's handle unlinks its path; a hard link keeps the socket reachable.
  const { linkSync } = await import('node:fs');
  linkSync(path, join(dir, 'ui-link.sock'));
  inherited.close();
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  let errors = '';
  child.stderr.on('data', chunk => { errors += chunk; });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('guest never listened: ' + errors)), 5000);
      child.stdout.on('data', () => { if (output === 'ready') { clearTimeout(timer); resolve(); } });
      child.once('exit', code => { clearTimeout(timer); reject(new Error(`guest exited ${code}: ${errors}`)); });
    });
    const reply = await new Promise((resolve, reject) => {
      const socket = net.connect(join(dir, 'ui-link.sock'), () => socket.write('GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'));
      let data = '';
      socket.on('data', chunk => { data += chunk; });
      socket.on('end', () => resolve(data));
      socket.on('error', reject);
      socket.setTimeout(3000, () => { socket.destroy(); reject(new Error('the inherited listener never answered')); });
    });
    assert.match(reply, /served:\/probe$/);
  } finally {
    child.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});
