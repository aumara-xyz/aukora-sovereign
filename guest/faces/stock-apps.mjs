// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const donor = '645d3213b8aede3b544269b4224ae09df06b0a42';
const defaultRoot = fileURLToPath(new URL('./apps/vendor/', import.meta.url));
const manifestUrl = new URL('./apps/stock-manifest.json', import.meta.url);
const mime = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.svg': 'image/svg+xml',
};
const allowed = new Map();
for (const name of ['index.html', 'favicon.svg', 'assets/index-C2MMIvhO.css',
  'assets/index-t74FFCZZ.js', 'assets/space-Bu4O81zr.js']) {
  allowed.set('dakini-code/' + name, '/stock-apps/dakini-code/' + name);
}

function refuse(reason) {
  const error = new Error('stock-apps:' + reason);
  error.code = error.message;
  throw error;
}

function validateManifest(manifest) {
  if (manifest?.schema !== 'aukora-stock-apps-v1' || manifest.donorCommit !== donor
    || !Array.isArray(manifest.routes) || manifest.routes.length !== allowed.size) refuse('invalid-manifest');
  const paths = new Set();
  for (const item of manifest.routes) {
    if (!item || !allowed.has(item.relative) || allowed.get(item.relative) !== item.path
      || item.contentType !== mime[extname(item.relative)]
      || !Number.isSafeInteger(item.bytes) || item.bytes < 1
      || typeof item.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(item.sha256)
      || paths.has(item.path)) refuse('invalid-manifest');
    paths.add(item.path);
  }
}

async function verifiedBytes(root, item) {
  const segments = item.relative.split('/');
  const file = resolve(root, ...segments);
  for (let i = 1; i <= segments.length; i += 1) {
    const stat = await lstat(resolve(root, ...segments.slice(0, i)));
    if (stat.isSymbolicLink()) refuse('symlink-refused');
    if (i < segments.length && !stat.isDirectory()) refuse('file-refused');
  }
  const before = await lstat(file);
  if (!before.isFile() || !(await realpath(file)).startsWith(root + sep)) refuse('file-refused');
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  let body;
  try {
    const after = await handle.stat();
    if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino) refuse('file-replaced');
    body = await handle.readFile();
  } finally {
    await handle.close();
  }
  if (body.length !== item.bytes
    || createHash('sha256').update(body).digest('hex') !== item.sha256) refuse('baseline-changed');
  return body;
}

function requestPath(url) {
  if (typeof url !== 'string' || !url.startsWith('/')) return undefined;
  const path = url.split('?', 1)[0];
  // Check the raw target before a URL parser can erase traversal segments.
  if (/[\\%#\u0000-\u0020\u007f]/.test(path) || path.includes('..')
    || path.includes('//') || path.split('/').includes('.')) return undefined;
  return path;
}

function handler(connection, entry) {
  return (req, res) => {
    const rejection = typeof connection?.requestRejection === 'function'
      ? connection.requestRejection(req) : 403;
    if (rejection !== undefined) {
      res.writeHead(rejection);
      res.end();
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end();
      return;
    }
    const path = requestPath(req.url);
    if (path === undefined) {
      res.writeHead(400);
      res.end();
      return;
    }
    if (!entry || path !== entry.path) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, {
      'content-type': entry.contentType,
      'content-length': String(entry.body.length),
      'x-content-type-options': 'nosniff',
    });
    res.end(req.method === 'HEAD' ? undefined : entry.body);
  };
}

export async function createStockAppRoutes({ vendorRoot = defaultRoot, manifest, connection } = {}) {
  manifest ??= JSON.parse(await readFile(manifestUrl, 'utf8'));
  validateManifest(manifest);
  const root = resolve(vendorRoot);
  const stat = await lstat(root);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(root) !== root) refuse('root-refused');
  // Serve a verified snapshot; requests never resolve filesystem paths.
  const entries = [];
  for (const item of manifest.routes) {
    entries.push({ path: item.path, contentType: item.contentType, body: await verifiedBytes(root, item) });
  }
  return Object.freeze([
    ...entries.map(entry => Object.freeze({ kind: 'exact', path: entry.path, handler: handler(connection, entry) })),
    Object.freeze({ kind: 'prefix', path: '/stock-apps', handler: handler(connection) }),
  ]);
}

export function apply(ctx) {
  return ctx.inject(['webServer', 'connection'], async web => {
    await web.effect(async () => {
      const routes = await createStockAppRoutes({ connection: web.connection });
      const disposers = [];
      try {
        for (const route of routes) disposers.push(web.webServer.register(route));
      } catch (error) {
        for (const dispose of disposers) dispose();
        throw error;
      }
      return () => { for (const dispose of disposers) dispose(); };
    }, 'aukora-face stock apps');
  });
}
