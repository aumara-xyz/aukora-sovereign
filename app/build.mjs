// SPDX-License-Identifier: AGPL-3.0-or-later
import { stripTypeScriptTypes } from 'node:module';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';
import { isDeepStrictEqual } from 'node:util';

const app = dirname(fileURLToPath(import.meta.url));
const repository = dirname(app);
const staging = join(app, '.release-build');
const destination = join(app, 'release');
const sourceTrees = ['app/core', 'app/shell', 'app/design', 'app/faces', 'app/store', 'app/theme', 'ui/owner', 'portal'];
const extension = /\.(ts|js|mjs|html|css|json|svg|png|webp|jpg|jpeg|woff2?|wasm)$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const portable = path => path.split(sep).join('/');

async function present(path) {
  try { return await lstat(path); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

async function collect(folder) {
  const info = await present(join(repository, folder));
  if (!info) return [];
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('app:asset-directory');
  const files = [];
  for (const entry of (await readdir(join(repository, folder), { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
    const name = `${folder}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error('app:asset-link');
    if (entry.isDirectory()) files.push(...await collect(name));
    else if (entry.isFile() && extension.test(entry.name) && !entry.name.endsWith('.d.ts')) files.push(name);
  }
  return files;
}

function emitModule(source) {
  return stripTypeScriptTypes(source, { mode: 'strip' });
}

function checkImports(modules, outputs) {
  const syntax = /(?:^|\n)\s*(?:import|export)\s+(?:[^'";]*?\s+from\s+)?['"]([^'"\r\n]+)['"]/g;
  for (const [path, source] of modules) {
    if (/\bimport\s*\(/.test(source)) throw new Error('app:dynamic-import');
    for (const match of source.matchAll(syntax)) {
      const specifier = match[1];
      if (!/^\.{1,2}\/[^?#]+\.js$/.test(specifier)) throw new Error('app:module-specifier');
      const target = portable(relative(staging, join(staging, dirname(path), specifier)));
      if (!outputs.has(target)) throw new Error('app:module-missing');
    }
  }
}

async function verifyAppLock() {
  const lock = JSON.parse(await readFile(join(app, 'APP-LOCK.json'), 'utf8'));
  if (lock.schema !== 'aukora-app-lock-v1' || lock.aukora_apps?.length !== 8 || lock.system?.length !== 8) {
    throw new Error('app:lock-format');
  }
  const manifests = [];
  for (const folder of await readdir(join(app, 'faces'), { withFileTypes: true })) {
    if (!folder.isDirectory()) continue;
    const path = join(app, 'faces', folder.name, 'manifest.json');
    const info = await present(path);
    if (!info || !info.isFile() || info.isSymbolicLink()) throw new Error('app:manifest-missing');
    const manifest = JSON.parse(await readFile(path, 'utf8'));
    if (manifest.id !== folder.name || !/^[a-z][a-z0-9-]*$/.test(manifest.id)
      || manifest.surface !== `./faces/${manifest.id}/index.html`
      || !Array.isArray(manifest.requires) || !manifest.requires.includes(manifest.organ)
      || manifest.requires.some(name => typeof name !== 'string' || !/^[a-z][a-z0-9._:-]{0,127}$/.test(name))
      || !manifest.menu || !Number.isInteger(manifest.menu.order)
      || !['workspace', 'aukora_apps', 'system'].includes(manifest.menu.section)) throw new Error('app:manifest-format');
    if (!(await present(join(app, 'faces', folder.name, 'index.html')))?.isFile()) throw new Error('app:surface-missing');
    manifests.push(manifest);
  }
  const workspace = manifests.filter(value => value.menu.section === 'workspace').map(value => value.id).sort();
  if (!isDeepStrictEqual(workspace, ['sidebar', 'threads']) || manifests.length !== 18) throw new Error('app:lock-mismatch');
  for (const section of ['aukora_apps', 'system']) {
    const titles = manifests.filter(value => value.menu.section === section)
      .sort((a, b) => a.menu.order - b.menu.order).map(value => value.title);
    if (!isDeepStrictEqual(titles, lock[section])) throw new Error('app:lock-mismatch');
  }
  const catalogSource = await readFile(join(app, 'faces', 'catalog.ts'), 'utf8');
  const literal = /export const FACE_CATALOG[^=]*=\s*(\[[\s\S]*\]);\s*$/.exec(catalogSource);
  if (!literal) throw new Error('app:catalog-format');
  const catalog = JSON.parse(literal[1]);
  const sorted = values => [...values].sort((a, b) => a.id.localeCompare(b.id, 'en'));
  if (!isDeepStrictEqual(sorted(catalog), sorted(manifests))) throw new Error('app:catalog-mismatch');
}

async function verifyDesign() {
  const lock = JSON.parse(await readFile(join(app, 'design', 'design-lock.json'), 'utf8'));
  if (lock.schema !== 'aukora-design-lock-v1' || !Array.isArray(lock.assets)) throw new Error('app:design-lock');
  const seen = new Set();
  for (const asset of lock.assets) {
    if (!/^[a-z][a-z0-9-]*\.json$/.test(asset.path) || !/^[0-9a-f]{64}$/.test(asset.sha256)
      || seen.has(asset.path)) throw new Error('app:design-lock');
    seen.add(asset.path);
    const bytes = await readFile(join(app, 'design', asset.path));
    if (sha256(bytes) !== asset.sha256) throw new Error('app:design-digest');
  }
  for (const required of ['tokens.json', 'fonts.json', 'icons.json', 'copy.json', 'captures.json']) {
    if (!seen.has(required)) throw new Error('app:design-unpinned');
  }
}

async function build() {
  if (process.argv.length !== 2) throw new Error('app:build-arguments');
  await verifyDesign();
  await verifyAppLock();
  for (const path of [staging, destination]) {
    const info = await present(path);
    if (info?.isSymbolicLink() || (info && !info.isDirectory())) throw new Error('app:release-directory');
  }
  const sourceFiles = ['app/APP-LOCK.json'];
  for (const tree of sourceTrees) sourceFiles.push(...await collect(tree));
  await rm(staging, { recursive: true, force: true });
  await mkdir(staging);
  try {
    const assets = [];
    const outputs = new Set();
    const modules = new Map();
    for (const source of sourceFiles.sort()) {
      const sourcePath = join(repository, source);
      const info = await lstat(sourcePath);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error('app:asset-link');
      const bytes = await readFile(sourcePath);
      const path = source.endsWith('.ts') ? source.slice(0, -3) + '.js' : source;
      if (outputs.has(path)) throw new Error('app:asset-collision');
      outputs.add(path);
      const result = source.endsWith('.ts') ? Buffer.from(emitModule(bytes.toString('utf8'))) : bytes;
      if (path.endsWith('.js') || path.endsWith('.mjs')) modules.set(path, result.toString('utf8'));
      const target = join(staging, path);
      if (portable(relative(staging, target)) !== path) throw new Error('app:asset-path');
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, result, { flag: 'wx' });
      assets.push({ path, bytes: result.length, sha256: sha256(result) });
    }
    checkImports(modules, outputs);
    const entries = { shell: 'app/shell/index.html', owner: 'ui/owner/index.html' };
    for (const path of Object.values(entries)) {
      if (!outputs.has(path)) throw new Error('app:entry-missing');
    }
    if (outputs.has('portal/index.html')) entries.portal = 'portal/index.html';
    const manifest = {
      schema: 'aukora-browser-release-v1',
      entries,
      assets,
    };
    const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
    await writeFile(join(staging, 'release-manifest.json'), manifestBytes, { flag: 'wx' });
    await rm(destination, { recursive: true, force: true });
    await rename(staging, destination);
    process.stdout.write(`app:compiled ${assets.length} assets; release-manifest sha256 ${sha256(manifestBytes)}\n`);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

await build();
