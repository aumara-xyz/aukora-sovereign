// SPDX-License-Identifier: AGPL-3.0-or-later
// The app build: erasable TypeScript turned into ES modules, the design data checked against its pins, the face
// catalog checked against the face manifests, the two WebAssembly modules built from crates/pentora and crates/canon,
// and a release manifest listing every byte. `node app/build.mjs --pin-design` rewrites design-lock.json instead.
// `--pin-captures 3673b98` indexes a supplied complete capture directory and updates only its two pins.
import { execFileSync } from 'node:child_process';
import { stripTypeScriptTypes } from 'node:module';
import { createHash } from 'node:crypto';
import { lstat, mkdir, open, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { crc32 } from 'node:zlib';

const app = dirname(fileURLToPath(import.meta.url));
const repository = dirname(app);
const staging = join(app, '.release-build');
const destination = join(app, 'release');
// portal is read for syntax and left out of the release: the frontdoor refuses every portal path.
const sourceTrees = [
  ['app/core', true], ['app/shell', true], ['app/design', true], ['app/faces', true], ['app/store', true],
  ['app/theme', true], ['ui/owner', true], ['portal', false],
];
const extension = /\.(ts|js|mjs|html|css|json|svg|png|webp|jpg|jpeg|woff2?)$/;
const dataFile = /\.(json|png|webp|woff2?)$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const portable = path => path.split(sep).join('/');
const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const WASM_MODULES = {
  pentora: ['memory', 'pentora_allocate_root32', 'pentora_expand', 'pentora_release_root32', 'pentora_release_result'],
  canon: ['memory', 'allocate_input', 'canonicalize', 'health_decode_snapshot', 'release_input', 'release_result'],
};
const MAX_WASM_BYTES = 16 * 1024 * 1024;

async function present(path) {
  try { return await lstat(path); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function collect(folder, files = []) {
  const info = await present(join(repository, folder));
  if (!info) return files;
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('app:asset-directory');
  for (const entry of (await readdir(join(repository, folder), { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
    const name = `${folder}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error('app:asset-link');
    if (entry.isDirectory()) await collect(name, files);
    else if (entry.name.endsWith('.wasm')) throw new Error(`app:wasm-in-source ${name}`);
    else if (entry.isFile() && extension.test(entry.name) && !entry.name.endsWith('.d.ts')) files.push(name);
  }
  return files;
}

function emitModule(source) {
  return stripTypeScriptTypes(source, { mode: 'strip' });
}

// Every import names a built module by a relative .js path; the one other form is a JSON data file with its
// `with { type: 'json' }` attribute, so the bytes the page reads are the bytes that were pinned.
function checkImports(modules, outputs) {
  const syntax = /(?:^|\n)\s*(?:import|export)\s+(?:[^'";]*?\s+from\s+)?['"]([^'"\r\n]+)['"]([^;\n]*)/g;
  for (const [path, source] of modules) {
    if (/\bimport\s*\(/.test(source)) throw new Error(`app:dynamic-import ${path}`);
    for (const match of source.matchAll(syntax)) {
      const specifier = match[1];
      const data = /^\.{1,2}\/[^?#]+\.json$/.test(specifier) && /^\s*with\s*\{\s*type\s*:\s*['"]json['"]\s*\}/.test(match[2]);
      if (!data && !/^\.{1,2}\/[^?#]+\.js$/.test(specifier)) throw new Error(`app:module-specifier ${path}`);
      const target = portable(relative(staging, join(staging, dirname(path), specifier)));
      if (!outputs.has(target)) throw new Error(`app:module-missing ${path} -> ${specifier}`);
    }
  }
}

async function readManifests() {
  const manifests = [];
  for (const folder of await readdir(join(app, 'faces'), { withFileTypes: true })) {
    if (!folder.isDirectory()) continue;
    const path = join(app, 'faces', folder.name, 'manifest.json');
    const info = await present(path);
    if (!info || !info.isFile() || info.isSymbolicLink()) throw new Error('app:manifest-missing');
    const manifest = await readJson(path);
    if (manifest.id !== folder.name || !/^[a-z][a-z0-9-]*$/.test(manifest.id)
      || manifest.surface !== `./faces/${manifest.id}/index.html`
      || !Array.isArray(manifest.requires) || !manifest.requires.includes(manifest.organ)
      || manifest.requires.some(name => typeof name !== 'string' || !/^[a-z][a-z0-9._:-]{0,127}$/.test(name))
      || !manifest.menu || !Number.isInteger(manifest.menu.order)
      || !['workspace', 'aukora_apps', 'system'].includes(manifest.menu.section)) throw new Error('app:manifest-format');
    if (!(await present(join(app, 'faces', folder.name, 'index.html')))?.isFile()) throw new Error('app:surface-missing');
    manifests.push(manifest);
  }
  return manifests;
}

async function verifyAppLock(manifests) {
  const lock = await readJson(join(app, 'APP-LOCK.json'));
  if (lock.schema !== 'aukora-app-lock-v1' || lock.aukora_apps?.length !== 8 || lock.system?.length !== 8) {
    throw new Error('app:lock-format');
  }
  const workspace = manifests.filter(value => value.menu.section === 'workspace').map(value => value.id).sort();
  if (!isDeepStrictEqual(workspace, ['sidebar', 'threads']) || manifests.length !== 18) throw new Error('app:lock-mismatch');
  for (const section of ['aukora_apps', 'system']) {
    const titles = manifests.filter(value => value.menu.section === section)
      .sort((a, b) => a.menu.order - b.menu.order).map(value => value.title);
    if (!isDeepStrictEqual(titles, lock[section])) throw new Error('app:lock-mismatch');
  }
}

// A release uses the committed catalog only when it agrees with every face manifest.
async function verifiedCatalog(manifests) {
  const source = await readFile(join(app, 'faces', 'catalog.ts'), 'utf8');
  const literal = /export const FACE_CATALOG[^=]*=\s*(\[[\s\S]*\]);\s*$/.exec(source);
  if (!literal) throw new Error('app:catalog-format');
  const committed = JSON.parse(literal[1]);
  const sorted = values => [...values].sort((a, b) => (a.id < b.id ? -1 : 1));
  if (!isDeepStrictEqual(sorted(committed), sorted(manifests))) {
    throw new Error('app:catalog-mismatch');
  }
  return source;
}

const hexColour = /^#(?:[0-9a-f]{6}|[0-9a-f]{8})$/;
const tokenName = /^[a-z][A-Za-z0-9]*$/;
const kebab = name => name.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`);
const number = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;

// The token colours, sizes and durations as the custom properties the stylesheets read.
function tokensCss(tokens, fonts) {
  const rows = [];
  for (const [name, value] of Object.entries(tokens.colors ?? {})) {
    if (!tokenName.test(name) || !hexColour.test(value)) throw new Error(`app:design-tokens colour ${name}`);
    rows.push(`--${kebab(name)}: ${value};`);
  }
  const metrics = tokens.metrics ?? {};
  for (const [name, value] of Object.entries(metrics)) {
    if (!tokenName.test(name)) throw new Error(`app:design-tokens metric ${name}`);
    if (name === 'focusedMeasure') {
      if (!Array.isArray(value) || value.length !== 2 || !value.every(part => Number.isInteger(part) && part > 0) || value[0] > value[1]) {
        throw new Error('app:design-tokens focusedMeasure');
      }
      rows.push(`--focused-measure: ${Math.round(value[0] / value[1] * 1e6) / 1e4}%;`);
    } else if (number(value)) rows.push(`--${kebab(name)}: ${value}px;`);
    else throw new Error(`app:design-tokens metric ${name}`);
  }
  for (const [name, value] of Object.entries(tokens.type ?? {})) {
    if (!tokenName.test(name) || !number(value)) throw new Error(`app:design-tokens type ${name}`);
    rows.push(name.startsWith('tracking') ? `--${kebab(name)}: ${value}em;` : `--type-${kebab(name)}: ${value}px;`);
  }
  const motion = tokens.motion ?? {};
  for (const name of ['fast', 'slow']) {
    if (!number(motion[name])) throw new Error(`app:design-tokens motion ${name}`);
    rows.push(`--motion-${name}: ${motion[name]}ms;`);
  }
  if (!/^cubic-bezier\(\s*[0-9.]+(?:\s*,\s*[0-9.]+){3}\s*\)$/.test(motion.ease ?? '')) throw new Error('app:design-tokens motion ease');
  rows.push(`--motion-ease: ${motion.ease};`);
  for (const group of ['interface', 'monospace']) {
    const names = fonts[group];
    if (!Array.isArray(names) || !names.length || !names.every(name => /^[A-Za-z0-9 _-]+$/.test(name))) throw new Error(`app:design-fonts ${group}`);
    rows.push(`--font-${group}: ${names.map(name => (name.includes(' ') ? `"${name}"` : name)).join(', ')};`);
  }
  return '/* SPDX-License-Identifier: AGPL-3.0-or-later */\n'
    + '/* Written by app/build.mjs from the pinned tokens.json and fonts.json. Do not edit. */\n'
    + `:root {\n  color-scheme: dark;\n${rows.map(row => `  ${row}`).join('\n')}\n}\n`;
}

async function designFiles(folder = 'app/design', files = []) {
  for (const entry of (await readdir(join(repository, folder), { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
    const name = `${folder}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error('app:asset-link');
    if (entry.isDirectory() && entry.name !== 'captures') await designFiles(name, files);
    else if (entry.isFile() && dataFile.test(entry.name) && entry.name !== 'design-lock.json') files.push(name.slice('app/design/'.length));
  }
  return files;
}

async function pinDesign() {
  const assets = [];
  for (const path of await designFiles()) assets.push({ path, sha256: sha256(await readFile(join(app, 'design', path))) });
  const lock = { schema: 'aukora-design-lock-v1', assets };
  await writeFile(join(app, 'design', 'design-lock.json'), JSON.stringify(lock, null, 2) + '\n');
  process.stdout.write(`app:design-pinned ${assets.length} files\n`);
}

function captureRequirements(captures, manifests) {
  const states = captures?.requiredStates;
  const faces = captures?.requiredFaces;
  const weights = captures?.requiredLaneWeights;
  if (captures?.schema !== 'aukora-design-captures-v1' || captures.referenceBuild !== '3673b98'
    || !isDeepStrictEqual(captures.statuses, ['unavailable', 'partial', 'complete'])
    || !captures.statuses.includes(captures.status) || !Array.isArray(captures.files)
    || !isDeepStrictEqual(states, ['initial', 'loading', 'empty', 'ready', 'refusal', 'service-unavailable', 'phone'])
    || !Array.isArray(faces) || !Array.isArray(weights)
    || !isDeepStrictEqual([...faces].sort(), manifests.map(value => value.id).sort())
    || weights.length !== 10
    || weights.some(value => !Array.isArray(value) || value.length !== 3
      || value.some(part => !Number.isInteger(part) || part < 0 || part > 3) || value[0] + value[1] + value[2] !== 3)
    || new Set(weights.map(value => value.join('-'))).size !== 10) {
    throw new Error('app:design-captures');
  }
  return [...faces.flatMap(subject => states.map(state => ({ subject, state }))),
    ...weights.map(weights => ({ subject: 'shell', state: 'ready', weights }))];
}

const captureKey = file => `${file.subject}/${file.state}/${file.weights ? file.weights.join('-') : ''}`;
const captureName = file => `${file.subject}-${file.state}${file.weights ? `-${file.weights.join('-')}` : ''}`;

// Check container boundaries and image headers. These checks do not establish which application was captured.
function verifyCaptureImage(bytes, path) {
  const refuse = () => { throw new Error(`app:design-captures image ${path}`); };
  if (path.endsWith('.png')) {
    if (bytes.length < 57 || !bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))
      || bytes.readUInt32BE(8) !== 13 || bytes.toString('latin1', 12, 16) !== 'IHDR') refuse();
    const width = bytes.readUInt32BE(16), height = bytes.readUInt32BE(20);
    const depths = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
    if (!width || !height || width > 0x7fffffff || height > 0x7fffffff
      || !depths[bytes[25]]?.includes(bytes[24]) || bytes[26] !== 0 || bytes[27] !== 0 || bytes[28] > 1) refuse();
    let imageBytes = 0;
    for (let offset = 8; offset < bytes.length;) {
      if (offset + 12 > bytes.length) refuse();
      const length = bytes.readUInt32BE(offset), end = offset + 12 + length;
      if (length > 0x7fffffff || end > bytes.length) refuse();
      const kind = bytes.toString('latin1', offset + 4, offset + 8);
      if (!/^[A-Za-z]{4}$/.test(kind) || (kind === 'IHDR' && offset !== 8)
        || crc32(bytes.subarray(offset + 4, end - 4)) !== bytes.readUInt32BE(end - 4)) refuse();
      if (kind === 'IDAT') imageBytes += length;
      if (kind === 'IEND') {
        if (length !== 0 || end !== bytes.length || imageBytes === 0) refuse();
        return;
      }
      offset = end;
    }
    refuse();
  }
  if (!path.endsWith('.webp') || bytes.length < 26 || bytes.toString('latin1', 0, 4) !== 'RIFF'
    || bytes.toString('latin1', 8, 12) !== 'WEBP' || bytes.readUInt32LE(4) + 8 !== bytes.length) refuse();
  let image = false;
  let canvas = null;
  for (let offset = 12; offset < bytes.length;) {
    if (offset + 8 > bytes.length) refuse();
    const length = bytes.readUInt32LE(offset + 4), data = offset + 8, end = data + length;
    const next = end + (length % 2);
    if (next > bytes.length || (length % 2 && bytes[end] !== 0)) refuse();
    const kind = bytes.toString('latin1', offset, offset + 4);
    if (kind === 'VP8X') {
      if (offset !== 12 || length !== 10 || (bytes[data] & 0xc3) !== 0
        || bytes.readUIntBE(data + 1, 3) !== 0) refuse();
      canvas = [bytes.readUIntLE(data + 4, 3) + 1, bytes.readUIntLE(data + 7, 3) + 1];
    } else if (kind === 'ANIM' || kind === 'ANMF') refuse();
    else if (kind === 'VP8 ' || kind === 'VP8L') {
      if (image) refuse();
      let dimensions;
      if (kind === 'VP8 ') {
        if (length <= 10 || (bytes[data] & 1) !== 0 || bytes.toString('hex', data + 3, data + 6) !== '9d012a') refuse();
        dimensions = [bytes.readUInt16LE(data + 6) & 0x3fff, bytes.readUInt16LE(data + 8) & 0x3fff];
      } else {
        if (length <= 5 || bytes[data] !== 0x2f || (bytes[data + 4] & 0xe0) !== 0) refuse();
        const bits = bytes.readUInt32LE(data + 1);
        dimensions = [(bits & 0x3fff) + 1, ((bits >>> 14) & 0x3fff) + 1];
      }
      if (dimensions.some(value => value === 0) || (canvas && !isDeepStrictEqual(canvas, dimensions))) refuse();
      image = true;
    }
    offset = next;
  }
  if (!image) refuse();
}

async function captureBytes(path) {
  const file = join(app, 'design', path);
  const info = await present(file);
  if (!info || !info.isFile() || info.isSymbolicLink()) throw new Error(`app:design-captures file ${path}`);
  if (info.size === 0 || info.size > 64 * 1024 * 1024) throw new Error(`app:design-captures size ${path}`);
  const bytes = await readFile(file);
  if (bytes.length !== info.size) throw new Error(`app:design-captures changed ${path}`);
  verifyCaptureImage(bytes, path);
  return bytes;
}

async function verifyCaptures(captures, manifests) {
  const required = captureRequirements(captures, manifests);
  const { requiredFaces: faces, requiredStates: states, requiredLaneWeights: weights } = captures;
  const folder = join(app, 'design', 'captures');
  const directory = await present(folder);
  if (directory && (!directory.isDirectory() || directory.isSymbolicLink())) throw new Error('app:design-captures directory');
  const listed = new Set();
  const covered = new Set();
  for (const file of captures.files) {
    if (!file || typeof file !== 'object' || Array.isArray(file)) throw new Error('app:design-captures file');
    const subject = file.subject === 'shell' ? 'shell' : faces.includes(file.subject) ? file.subject : null;
    const shellWeights = subject === 'shell' && weights.some(value => isDeepStrictEqual(value, file.weights));
    if (!subject || !states.includes(file.state) || (subject === 'shell') !== (file.weights !== undefined)
      || (subject === 'shell' && !shellWeights) || !/^captures\/[a-z0-9][a-z0-9-]*\.(png|webp)$/.test(file.path)
      || !/^[0-9a-f]{64}$/.test(file.sha256) || listed.has(file.path)) throw new Error(`app:design-captures ${file.path}`);
    const key = captureKey(file);
    if (covered.has(key)) throw new Error(`app:design-captures duplicate ${key}`);
    listed.add(file.path);
    covered.add(key);
    const bytes = await captureBytes(file.path);
    if (sha256(bytes) !== file.sha256) throw new Error(`app:design-captures digest ${file.path}`);
  }
  if (directory) {
    for (const entry of await readdir(folder)) if (!listed.has(`captures/${entry}`)) throw new Error(`app:design-captures unpinned ${entry}`);
  }
  const missing = required.map(captureKey).filter(key => !covered.has(key));
  if (captures.status === 'unavailable' && listed.size === 0) return 'pending';
  if (captures.status !== 'complete' || missing.length) {
    throw new Error(`app:design-captures-incomplete build ${captures.referenceBuild}: ${captures.status}; `
      + `missing ${missing.length}/${required.length}${missing.length ? `\n  ${missing.join('\n  ')}` : ''}`);
  }
  return 'complete';
}

async function verifyDesign(manifests, captureCandidate) {
  const lock = await readJson(join(app, 'design', 'design-lock.json'));
  if (lock.schema !== 'aukora-design-lock-v1' || !Array.isArray(lock.assets)) throw new Error('app:design-lock');
  const seen = new Set();
  for (const asset of lock.assets) {
    if (!/^[a-z][a-z0-9-]*(?:\/[a-z][a-z0-9-]*)*\.(json|png|webp|woff2?)$/.test(asset.path) || !/^[0-9a-f]{64}$/.test(asset.sha256)
      || seen.has(asset.path)) throw new Error('app:design-lock');
    seen.add(asset.path);
    const info = await present(join(app, 'design', asset.path));
    if (!info || !info.isFile() || info.isSymbolicLink()) throw new Error(`app:design-unpinned ${asset.path}`);
    if (sha256(await readFile(join(app, 'design', asset.path))) !== asset.sha256) throw new Error(`app:design-digest ${asset.path}`);
  }
  for (const required of ['tokens.json', 'fonts.json', 'icons.json', 'copy.json', 'captures.json']) {
    if (!seen.has(required)) throw new Error('app:design-unpinned');
  }
  for (const path of await designFiles()) if (!seen.has(path)) throw new Error(`app:design-unpinned ${path}`);
  const design = {};
  for (const name of ['tokens', 'fonts', 'icons', 'copy', 'captures']) design[name] = await readJson(join(app, 'design', `${name}.json`));
  const wanted = [...manifests.map(value => value.id), 'threads', 'surface', 'apps', 'system', 'close', 'owner'];
  const paths = design.icons.paths ?? {};
  if (design.icons.schema !== 'aukora-design-icons-v1' || !seen.has(design.icons.brand?.mark)
    || wanted.some(name => typeof paths[name] !== 'string')
    || Object.values(paths).some(path => !/^[MmLlHhVvCcSsAaZz0-9eE.,\s-]+$/.test(path))) throw new Error('app:design-icons');
  // Every copy key the shell reads must exist, so a missing string fails here and not on a person's screen.
  const missing = [];
  for (const name of ['shell/main.ts', 'shell/layout.ts', 'shell/owner-frame.ts', 'design/index.ts']) {
    const text = await readFile(join(app, name), 'utf8');
    for (const match of text.matchAll(/\bCOPY\.([A-Za-z]+)/g)) if (!(match[1] in design.copy)) missing.push(match[1]);
  }
  if (design.copy.schema !== 'aukora-design-copy-v1' || missing.length) throw new Error(`app:design-copy ${missing.join(',')}`);
  const captures = await verifyCaptures(captureCandidate ?? design.captures, manifests);
  return { css: tokensCss(design.tokens, design.fonts), captures };
}

// The operator supplies the build attribution; image bytes alone cannot prove it.
async function pinCaptures(referenceBuild) {
  if (referenceBuild !== '3673b98') throw new Error('app:design-captures reference-build');
  const directory = join(app, 'design');
  const rootInfo = await present(directory);
  if (!rootInfo || !rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('app:design-captures directory');
  for (const name of ['captures.json', 'design-lock.json']) {
    const info = await present(join(directory, name));
    if (!info || !info.isFile() || info.isSymbolicLink()) throw new Error('app:design-captures pin');
  }
  const manifests = await readManifests();
  await verifyAppLock(manifests);
  const captures = await readJson(join(directory, 'captures.json'));
  const required = captureRequirements(captures, manifests);
  // Existing capture hashes cannot be replaced by rescanning changed image bytes.
  if (captures.files.length !== 0) throw new Error('app:design-captures already-pinned');
  const expected = new Map(required.flatMap(file => ['png', 'webp'].map(type => [`${captureName(file)}.${type}`, file])));
  const found = new Map();
  const files = [];
  const folder = join(directory, 'captures');
  const info = await present(folder);
  if (info && (!info.isDirectory() || info.isSymbolicLink())) throw new Error('app:design-captures directory');
  const entries = info ? await readdir(folder, { withFileTypes: true }) : [];
  for (const entry of entries.sort((a, b) => a.name < b.name ? -1 : 1)) {
    const file = expected.get(entry.name);
    if (!file || !entry.isFile() || entry.isSymbolicLink()) throw new Error(`app:design-captures unpinned ${entry.name}`);
    const key = captureKey(file);
    if (found.has(key)) throw new Error(`app:design-captures duplicate ${key}`);
    found.set(key, entry.name);
  }
  const missing = required.filter(file => !found.has(captureKey(file))).map(captureName);
  if (missing.length) {
    throw new Error(`app:design-captures-incomplete build ${referenceBuild}: missing ${missing.length}/${required.length}`
      + `\n  ${missing.join('\n  ')}`);
  }
  for (const file of required) {
    const path = `captures/${found.get(captureKey(file))}`;
    files.push({ ...file, path, sha256: sha256(await captureBytes(path)) });
  }
  const candidate = { ...captures, status: 'complete', files };
  // Verify the current design pins and the complete candidate before changing either pin.
  await verifyDesign(manifests, candidate);
  const bytes = JSON.stringify(candidate, null, 2) + '\n';
  const lock = await readJson(join(directory, 'design-lock.json'));
  lock.assets = lock.assets.map(asset => asset.path === 'captures.json' ? { ...asset, sha256: sha256(bytes) } : asset);
  const pending = [];
  try {
    for (const [name, text] of [['captures.json', bytes], ['design-lock.json', JSON.stringify(lock, null, 2) + '\n']]) {
      const path = join(directory, `${name}.pinning`);
      const handle = await open(path, 'wx');
      pending.push([path, join(directory, name)]);
      try { await handle.writeFile(text); }
      finally { await handle.close(); }
    }
    for (const [source, target] of pending) await rename(source, target);
  } finally {
    for (const [source] of pending) await rm(source, { force: true });
  }
  process.stdout.write(`app:design-captures-pinned build ${referenceBuild}: ${files.length} files\n`);
}

// Requires the wasm32-unknown-unknown Rust target installed before this offline build; modules must import nothing.
function buildWasm() {
  const output = execFileSync('cargo', ['build', '--release', '--offline', '--locked', '--target', 'wasm32-unknown-unknown',
    '--message-format', 'json-render-diagnostics', ...Object.keys(WASM_MODULES).flatMap(name => ['-p', name])],
  { cwd: repository, encoding: 'utf8', maxBuffer: 1 << 26, stdio: ['ignore', 'pipe', 'inherit'] });
  const found = new Map();
  for (const line of output.split('\n')) {
    if (!line.startsWith('{')) continue;
    const message = JSON.parse(line);
    if (message.reason !== 'compiler-artifact' || !message.target?.kind?.includes('cdylib')) continue;
    const wasm = (message.filenames ?? []).filter(name => name.endsWith('.wasm'));
    if (wasm.length === 1 && message.target.name in WASM_MODULES) found.set(message.target.name, wasm[0]);
  }
  return found;
}

async function wasmModules() {
  const built = buildWasm();
  const modules = [];
  for (const [name, exported] of Object.entries(WASM_MODULES)) {
    if (!built.has(name)) throw new Error(`app:wasm-missing ${name}`);
    const bytes = await readFile(built.get(name));
    if (bytes.length > MAX_WASM_BYTES) throw new Error(`app:wasm-size ${name}`);
    const compiled = await WebAssembly.compile(bytes);
    const names = WebAssembly.Module.exports(compiled).map(value => value.name);
    if (WebAssembly.Module.imports(compiled).length !== 0) throw new Error(`app:wasm-imports ${name}`);
    if (exported.some(value => !names.includes(value))) throw new Error(`app:wasm-exports ${name}`);
    modules.push({ path: `app/core/${name}.wasm`, bytes });
  }
  return modules;
}

async function build() {
  const args = process.argv.slice(2);
  if (args.length === 2 && args[0] === '--pin-captures') return pinCaptures(args[1]);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--pin-design')) throw new Error('app:build-arguments');
  if (args[0] === '--pin-design') return pinDesign();
  const manifests = await readManifests();
  await verifyAppLock(manifests);
  const design = await verifyDesign(manifests);
  if (design.captures === 'pending') {
    process.stderr.write('Warning: design captures are pending; this release is not design-complete.\n');
  }
  const catalog = await verifiedCatalog(manifests);
  for (const path of [staging, destination]) {
    const info = await present(path);
    if (info?.isSymbolicLink() || (info && !info.isDirectory())) throw new Error('app:release-directory');
  }
  const sourceFiles = new Map([['app/APP-LOCK.json', true]]);
  for (const [tree, ship] of sourceTrees) for (const file of await collect(tree)) sourceFiles.set(file, ship);
  const syntax = [];
  const outputs = new Set();
  const modules = new Map();
  const files = [];
  for (const source of [...sourceFiles.keys()].sort()) {
    const sourcePath = join(repository, source);
    const info = await lstat(sourcePath);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error('app:asset-link');
    const path = source.endsWith('.ts') ? source.slice(0, -3) + '.js' : source;
    let result = await readFile(sourcePath);
    if (source.endsWith('.ts')) {
      try { result = Buffer.from(emitModule(source === 'app/faces/catalog.ts' ? catalog : result.toString('utf8'))); }
      catch (error) { syntax.push(`${source}: ${String(error.message).split('\n')[0]}`); continue; }
    }
    if (!sourceFiles.get(source)) continue;
    if (outputs.has(path)) throw new Error('app:asset-collision');
    outputs.add(path);
    if (path.endsWith('.js') || path.endsWith('.mjs')) modules.set(path, result.toString('utf8'));
    files.push({ path, bytes: result });
  }
  if (syntax.length) throw new Error(`app:syntax\n  ${syntax.join('\n  ')}`);
  if (outputs.has('app/design/tokens.css')) throw new Error('app:asset-collision');
  outputs.add('app/design/tokens.css');
  files.push({ path: 'app/design/tokens.css', bytes: Buffer.from(design.css) });
  for (const module of await wasmModules()) {
    if (outputs.has(module.path)) throw new Error('app:asset-collision');
    outputs.add(module.path);
    files.push(module);
  }
  checkImports(modules, outputs);
  const entries = { shell: 'app/shell/index.html', owner: 'ui/owner/index.html' };
  for (const path of Object.values(entries)) {
    if (!outputs.has(path)) throw new Error('app:entry-missing');
  }
  await rm(staging, { recursive: true, force: true });
  await mkdir(staging);
  try {
    const assets = [];
    for (const file of files) {
      const target = join(staging, file.path);
      if (portable(relative(staging, target)) !== file.path) throw new Error('app:asset-path');
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, file.bytes, { flag: 'wx' });
      assets.push({ path: file.path, bytes: file.bytes.length, sha256: sha256(file.bytes) });
    }
    const manifest = { schema: 'aukora-browser-release-v2', captures: design.captures, entries, assets: assets.sort(byPath) };
    const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');
    await writeFile(join(staging, 'release-manifest.json'), manifestBytes, { flag: 'wx' });
    await rm(destination, { recursive: true, force: true });
    await rename(staging, destination);
    process.stdout.write(`app:compiled ${assets.length} assets; release-manifest sha256 ${sha256(manifestBytes)}; design captures ${design.captures}\n`);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

try { await build(); }
catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
