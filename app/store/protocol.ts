// SPDX-License-Identifier: AGPL-3.0-or-later
import { decodeData, encodeData, exactKeys, objectData } from '../core/data.js';
import type { JsonValue } from '../core/data.js';

export const MANIFEST_SCHEMA = 'aukora-app-manifest-v1';
export const INSTALL_SCHEMA = 'aukora-app-install-v1';
export const MAX_MANIFEST_BYTES = 16_384;
export const MAX_PACKAGE_BYTES = 8_388_608;
export const GRANTS = Object.freeze(['app.clock', 'app.random', 'app.storage.read', 'app.storage.write'] as const);
export type AppGrant = typeof GRANTS[number];
export interface ManifestBody {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly package_sha256: string;
  readonly grants: readonly AppGrant[];
  readonly runtime: { readonly kind: 'user-app'; readonly entry: string; readonly network: false; readonly exec: false; readonly wasi: false };
  readonly face: { readonly entry: string };
}
export interface AppManifest {
  readonly schema: typeof MANIFEST_SCHEMA;
  readonly body: ManifestBody;
  readonly signature: { readonly v: 1; readonly algorithm: 'secp256k1-schnorr'; readonly public_key: string; readonly signature: string };
}
export interface InstallRequest {
  readonly app: string;
  readonly package_digest: string;
  readonly manifest_bytes: Uint8Array;
}
export interface PreparedInstall {
  readonly manifest: AppManifest;
  readonly request: InstallRequest;
  readonly packageBytes: Uint8Array;
}

export function fail(reason: string): never { throw new Error(`store:${reason}`); }

export function stringValue(value: unknown, maximum: number): string {
  if (typeof value !== 'string' || !value.length || new TextEncoder().encode(value).length > maximum
    || /[\u0000-\u001f\u007f-\u009f]/.test(value)) fail('invalid-text');
  return value;
}

export function hex(value: unknown, length = 64): string {
  if (typeof value !== 'string' || value.length !== length || !/^[0-9a-f]+$/.test(value)) fail('invalid-digest');
  return value;
}

export function relativeEntry(value: unknown): string {
  const path = stringValue(value, 128);
  if (!/^[A-Za-z0-9._/-]+$/.test(path)
    || path.split('/').some(part => !part || part === '.' || part === '..')) fail('invalid-entry');
  return path;
}

export function canonicalBytes(bytes: Uint8Array, maximum = MAX_MANIFEST_BYTES): { text: string; value: JsonValue } {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > maximum) fail('invalid-bytes');
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { return fail('invalid-utf8'); }
  try { return { text, value: decodeData(text) }; }
  catch { return fail('noncanonical-data'); }
}

function fields(value: JsonValue, expected: readonly string[]): { [key: string]: JsonValue } {
  try { const object = objectData(value); exactKeys(object, expected); return object; }
  catch { return fail('invalid-fields'); }
}

/** Parse claims only. Author signatures are verified by the Nostr organ and gate. */
export function parseManifest(bytes: Uint8Array): AppManifest {
  const outer = fields(canonicalBytes(bytes).value, ['schema', 'body', 'signature']);
  if (outer.schema !== MANIFEST_SCHEMA) fail('manifest-version');
  const body = fields(outer.body, ['id', 'name', 'version', 'package_sha256', 'grants', 'runtime', 'face']);
  const id = hex(body.id, 32);
  const name = stringValue(body.name, 128);
  const version = stringValue(body.version, 64);
  if (!/^[A-Za-z0-9._-]+$/.test(version)) fail('invalid-version');
  const package_sha256 = hex(body.package_sha256);
  if (!Array.isArray(body.grants) || body.grants.length > GRANTS.length) fail('invalid-grants');
  const grants = body.grants.map(value => {
    if (typeof value !== 'string' || !GRANTS.includes(value as AppGrant)) return fail('forbidden-grant');
    return value as AppGrant;
  });
  if (grants.some((value, index) => index > 0 && grants[index - 1] >= value)) fail('invalid-grants');
  const runtime = fields(body.runtime, ['kind', 'entry', 'network', 'exec', 'wasi']);
  if (runtime.kind !== 'user-app' || runtime.network !== false || runtime.exec !== false || runtime.wasi !== false) {
    fail('runtime-policy');
  }
  const entry = relativeEntry(runtime.entry);
  if (!entry.endsWith('.wasm')) fail('invalid-runtime');
  const face = fields(body.face, ['entry']);
  const faceEntry = relativeEntry(face.entry);
  if (!faceEntry.endsWith('.html')) fail('invalid-face');
  const signature = fields(outer.signature, ['v', 'algorithm', 'public_key', 'signature']);
  if (signature.v !== 1 || signature.algorithm !== 'secp256k1-schnorr') fail('signature-algorithm');
  return Object.freeze({
    schema: MANIFEST_SCHEMA,
    body: Object.freeze({ id, name, version, package_sha256, grants: Object.freeze(grants),
      runtime: Object.freeze({ kind: 'user-app', entry, network: false, exec: false, wasi: false }),
      face: Object.freeze({ entry: faceEntry }) }),
    signature: Object.freeze({ v: 1, algorithm: 'secp256k1-schnorr',
      public_key: hex(signature.public_key), signature: hex(signature.signature, 128) }),
  });
}

export function base64(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_PACKAGE_BYTES) fail('invalid-bytes');
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8_192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8_192));
  }
  return btoa(binary);
}

export function unbase64(value: unknown, maximum = MAX_MANIFEST_BYTES): Uint8Array {
  if (typeof value !== 'string' || !value.length || value.length > 4 * Math.ceil(maximum / 3)
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('invalid-base64');
  let binary: string;
  try { binary = atob(value); } catch { return fail('invalid-base64'); }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (bytes.length > maximum || base64(bytes) !== value) fail('invalid-base64');
  return bytes;
}

export async function sha256(bytes: Uint8Array): Promise<string> {
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.slice()));
    return Array.from(digest, value => value.toString(16).padStart(2, '0')).join('');
  } catch { return fail('digest-unavailable'); }
}

/** Snapshot and compare the actual package, never a catalog assertion of its hash. */
export async function prepareInstall(manifestBytes: Uint8Array, packageBytes: Uint8Array, author: string,
  packageDigest: string): Promise<PreparedInstall> {
  const exactManifest = manifestBytes.slice();
  const exactPackage = packageBytes.slice();
  if (!exactPackage.length || exactPackage.length > MAX_PACKAGE_BYTES) fail('package-limit');
  const manifest = parseManifest(exactManifest);
  if (manifest.signature.public_key !== hex(author)) fail('author-mismatch');
  if (manifest.body.package_sha256 !== hex(packageDigest) || await sha256(exactPackage) !== packageDigest) {
    fail('package-mismatch');
  }
  return Object.freeze({ manifest, packageBytes: exactPackage,
    request: Object.freeze({ app: manifest.body.id, package_digest: packageDigest, manifest_bytes: exactManifest }) });
}

export function installEffect(request: InstallRequest): Uint8Array {
  const manifest = parseManifest(request.manifest_bytes);
  if (request.app !== manifest.body.id || request.package_digest !== manifest.body.package_sha256) fail('install-mismatch');
  return new TextEncoder().encode(encodeData({ schema: INSTALL_SCHEMA,
    body: { app: request.app, manifest_b64: base64(request.manifest_bytes), package_sha256: request.package_digest } }));
}

export function refusalText(error: unknown): string {
  const value = error instanceof Error ? error.message : '';
  return /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/.test(value) ? value : 'store:unavailable';
}
