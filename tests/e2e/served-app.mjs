// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { strictJSON } from './codec.mjs';

const APPS = ['Auma Lingwa', 'Auma Live', 'Zeta Harp', 'Human Graph', 'Media', 'Memory', 'Messages', 'Documents'];
const SYSTEM = ['AUMLOK', 'Identity', 'Aura Coherence', 'General', 'Models', 'Plugins', 'Agent presets', 'Archived sessions'];
const IDS = ['threads', 'sidebar', 'lingwa', 'live', 'zetaharp', 'humangraph', 'media', 'memory',
  'messages', 'documents', 'aumlok', 'identity', 'coherence', 'general', 'models', 'plugins', 'presets', 'archived'];
const TITLES = ['Threads', 'Sidebar', ...APPS, ...SYSTEM];
const opaqueHeaders = { origin: 'null', 'sec-fetch-site': 'cross-site' };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function sameList(c, id, actual, expected) {
  c.require(id, Array.isArray(actual) && actual.length === expected.length);
  expected.forEach((value, index) => c.same(`${id}-${index}`, actual[index], value));
}

function keys(c, id, value, expected) {
  c.require(`${id}-object`, object(value));
  sameList(c, `${id}-keys`, Object.keys(value).sort(), [...expected].sort());
}

function decode(c, id, bytes) {
  try { return strictJSON(bytes); }
  catch { c.require(`${id}-json`, false); }
}

async function asset(c, path, mime, opaque = false) {
  const id = `m1-served-${path.slice(1).replaceAll('/', '-')}`;
  const response = await c.http(c.shell, path, opaque ? { headers: opaqueHeaders } : {});
  c.same(`${id}-status`, response.status, 200);
  c.require(`${id}-mime`, mime.test(response.headers.get('content-type') ?? ''));
  c.require(`${id}-nonempty`, response.body.length > 0);
  if (opaque) {
    c.require(`${id}-cors`, ['*', 'null'].includes(response.headers.get('access-control-allow-origin')));
    c.same(`${id}-resource-policy`, response.headers.get('cross-origin-resource-policy'), 'cross-origin');
  }
  return response;
}

function attributes(c, id, source) {
  const values = Object.create(null);
  const pair = /\s+([a-zA-Z][a-zA-Z0-9:-]*)\s*=\s*(["'])(.*?)\2/g;
  let end = 0;
  for (const match of source.matchAll(pair)) {
    c.same(`${id}-attribute-gap`, source.slice(end, match.index).trim(), '');
    const name = match[1].toLowerCase();
    c.require(`${id}-attribute-unique`, !Object.hasOwn(values, name));
    values[name] = match[3];
    end = match.index + match[0].length;
  }
  c.same(`${id}-attribute-tail`, source.slice(end).trim(), '');
  return values;
}

async function faceHTML(c, manifest) {
  const id = `m1-face-${manifest.id}`;
  const path = `/app/faces/${manifest.id}/index.html`;
  const response = await asset(c, path, /^text\/html(?:;|$)/i, true);
  let source;
  try { source = new TextDecoder('utf-8', { fatal: true }).decode(response.body); }
  catch { c.require(`${id}-utf8`, false); }
  const titles = [...source.matchAll(/<title\s*>([^<]*)<\/title\s*>/gi)];
  c.same(`${id}-title-count`, titles.length, 1);
  c.same(`${id}-title`, titles[0][1], manifest.title);
  const mounts = [...source.matchAll(/<main\b([^>]*)>/gi)];
  c.same(`${id}-mount-count`, mounts.length, 1);
  const mount = attributes(c, `${id}-mount`, mounts[0][1]);
  c.same(`${id}-mount-id`, mount.id, 'face');
  c.same(`${id}-mount-label`, mount['aria-label'], manifest.title);
  const scripts = [...source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  c.same(`${id}-script-count`, scripts.length, 1);
  const script = attributes(c, `${id}-script`, scripts[0][1]);
  c.same(`${id}-script-type`, script.type, 'module');
  c.same(`${id}-script-source`, script.src, './main.js');
  c.same(`${id}-script-cors`, script.crossorigin, 'anonymous');
  c.same(`${id}-script-body`, scripts[0][2].trim(), '');
  await asset(c, `/app/faces/${manifest.id}/main.js`, /^(?:text|application)\/javascript(?:;|$)/i, true);
}

function manifestShape(c, value, index) {
  const id = `m1-manifest-${IDS[index]}`;
  c.require(`${id}-object`, object(value));
  keys(c, id, value, ['id', 'title', 'organ', 'requires', 'menu', 'surface', 'capabilities',
    ...(Object.hasOwn(value, 'wasm') ? ['wasm'] : [])]);
  c.same(`${id}-id`, value.id, IDS[index]);
  c.same(`${id}-title`, value.title, TITLES[index]);
  c.same(`${id}-surface`, value.surface, `./faces/${IDS[index]}/index.html`);
  keys(c, `${id}-menu`, value.menu, ['section', 'order']);
  c.same(`${id}-section`, value.menu.section, index < 2 ? 'workspace' : index < 10 ? 'aukora_apps' : 'system');
  c.same(`${id}-order`, value.menu.order, index);
  c.require(`${id}-organ`, typeof value.organ === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(value.organ));
  c.require(`${id}-requirements`, Array.isArray(value.requires) && value.requires.includes(value.organ)
    && value.requires.every(name => typeof name === 'string' && /^[a-z][a-z0-9._:-]{0,127}$/.test(name))
    && new Set(value.requires).size === value.requires.length);
  c.require(`${id}-capabilities`, object(value.capabilities));
  for (const [service, grant] of Object.entries(value.capabilities)) {
    c.require(`${id}-service`, value.requires.includes(service));
    keys(c, `${id}-grant`, grant, ['methods', 'topics']);
    for (const name of ['methods', 'topics']) {
      c.require(`${id}-${name}`, Array.isArray(grant[name]) && grant[name].every(method =>
        typeof method === 'string' && /^[a-z][a-zA-Z0-9._:-]{0,127}$/.test(method))
        && new Set(grant[name]).size === grant[name].length);
    }
  }
  if (Object.hasOwn(value, 'wasm')) c.require(`${id}-wasm`, typeof value.wasm === 'boolean');
}

export async function servedApp(c, shellResponse) {
  const shell = await asset(c, '/app/shell/index.html', /^text\/html(?:;|$)/i);
  c.require('m1-shell-root-alias', shell.body.equals(shellResponse.body));
  const lockResponse = await asset(c, '/app/APP-LOCK.json', /^application\/json(?:;|$)/i);
  const lock = decode(c, 'm1-app-lock', lockResponse.body);
  keys(c, 'm1-app-lock', lock, ['schema', 'aukora_apps', 'system']);
  c.same('m1-app-lock-schema', lock.schema, 'aukora-app-lock-v1');
  sameList(c, 'm1-app-lock-apps', lock.aukora_apps, APPS);
  sameList(c, 'm1-app-lock-system', lock.system, SYSTEM);
  const copyResponse = await asset(c, '/app/design/copy.json', /^application\/json(?:;|$)/i);
  const copy = decode(c, 'm1-design-copy', copyResponse.body);
  const expected = decode(c, 'm1-design-copy-reference', await readFile(new URL('../../app/design/copy.json', import.meta.url)));
  c.require('m1-design-copy-matches-reference', isDeepStrictEqual(copy, expected));
  c.same('m1-design-copy-schema', copy.schema, 'aukora-design-copy-v1');
  const manifests = [];
  for (const [index, id] of IDS.entries()) {
    const response = await asset(c, `/app/faces/${id}/manifest.json`, /^application\/json(?:;|$)/i, true);
    const manifest = decode(c, `m1-manifest-${id}`, response.body);
    manifestShape(c, manifest, index);
    await faceHTML(c, manifest);
    manifests.push(manifest);
  }
  for (const section of ['aukora_apps', 'system']) {
    sameList(c, `m1-served-${section}-inventory`, manifests.filter(value => value.menu.section === section)
      .sort((a, b) => a.menu.order - b.menu.order).map(value => value.title), lock[section]);
  }
  return { copy, manifests };
}
