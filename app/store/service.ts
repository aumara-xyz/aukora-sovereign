// SPDX-License-Identifier: AGPL-3.0-or-later
import { decodeData, encodeData, exactKeys, objectData } from '../core/data.js';
import type { JsonValue } from '../core/data.js';
import type { RpcCallContext, RpcService } from '../core/rpc.js';
import { base64, fail, hex, parseManifest, prepareInstall } from './protocol.js';
import type { AppManifest, InstallRequest } from './protocol.js';

export interface RatingEvidence {
  readonly event_id: string;
  readonly author: string;
  readonly rating: number;
  readonly text: string;
}
export interface CatalogEvidence {
  readonly event_id: string;
  readonly author: string;
  readonly package_sha256: string;
  readonly manifest_bytes: Uint8Array;
  readonly ratings: readonly RatingEvidence[];
}
export interface InstalledRecord {
  readonly app: string;
  readonly package_sha256: string;
  readonly manifest_bytes: Uint8Array;
  readonly receipt_sequence: number;
}
export interface PendingInstall {
  readonly proposal_id: string;
  readonly app: string;
  readonly package_sha256: string;
}

/** Implemented by trusted services. Catalog reads verify Nostr events; gate writes reverify manifest signatures. */
export interface StoreBackend {
  search(query: string, signal: AbortSignal): Promise<readonly CatalogEvidence[]>;
  readPackage(packageDigest: string, signal: AbortSignal): Promise<Uint8Array>;
  proposeInstall(request: InstallRequest, packageBytes: Uint8Array, signal: AbortSignal): Promise<PendingInstall>;
  installed(signal: AbortSignal): Promise<readonly InstalledRecord[]>;
}
export interface StoreActions {
  openInstalled(record: InstalledRecord, signal: AbortSignal): Promise<void>;
}
interface Publication {
  readonly event: string;
  readonly author: string;
  readonly digest: string;
  readonly bytes: Uint8Array;
  readonly manifest: AppManifest;
  readonly ratings: readonly RatingEvidence[];
}

function positive(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) fail('invalid-receipt');
  return value as number;
}

function ratingSnapshot(value: RatingEvidence): RatingEvidence {
  const text = typeof value.text === 'string' ? value.text : fail('invalid-rating');
  if (new TextEncoder().encode(text).length > 1_024 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(text)
    || !Number.isInteger(value.rating) || value.rating < 1 || value.rating > 5) fail('invalid-rating');
  return Object.freeze({ event_id: hex(value.event_id), author: hex(value.author), rating: value.rating, text });
}

function publicationSnapshot(record: CatalogEvidence): Publication {
  const bytes = record.manifest_bytes.slice();
  const manifest = parseManifest(bytes);
  const author = hex(record.author);
  const digest = hex(record.package_sha256);
  if (author !== manifest.signature.public_key || digest !== manifest.body.package_sha256) fail('catalog-mismatch');
  if (!Array.isArray(record.ratings) || record.ratings.length > 100) fail('rating-limit');
  const ratings = record.ratings.map(ratingSnapshot);
  if (new Set(ratings.map(rating => rating.event_id)).size !== ratings.length) fail('duplicate-rating');
  return Object.freeze({ event: hex(record.event_id), author, digest, bytes, manifest, ratings: Object.freeze(ratings) });
}

export function installedSnapshot(record: InstalledRecord): InstalledRecord {
  const bytes = record.manifest_bytes.slice();
  const manifest = parseManifest(bytes);
  if (manifest.body.id !== hex(record.app, 32) || manifest.body.package_sha256 !== hex(record.package_sha256)) {
    fail('installed-mismatch');
  }
  return Object.freeze({ app: record.app, package_sha256: record.package_sha256,
    manifest_bytes: bytes, receipt_sequence: positive(record.receipt_sequence) });
}

function publicationData(item: Publication): JsonValue {
  return { event_id: item.event, author: item.author, package_sha256: item.digest,
    manifest_b64: base64(item.bytes), ratings: item.ratings.map(rating => ({ ...rating })) };
}

function installedData(item: InstalledRecord): JsonValue {
  return { app: item.app, package_sha256: item.package_sha256, manifest_b64: base64(item.manifest_bytes),
    receipt_sequence: item.receipt_sequence };
}

/** Per-store service; its candidate cache is evidence and cannot authorize an effect. */
export class StoreService implements RpcService {
  #backend: StoreBackend;
  #actions: StoreActions;
  #publications = new Map<string, Publication>();
  #busy = new Set<string>();
  #closed = false;

  constructor(backend: StoreBackend, actions: StoreActions) { this.#backend = backend; this.#actions = actions; }

  dispose(): void { this.#closed = true; this.#publications.clear(); }

  async call(method: string, params: JsonValue, context: RpcCallContext): Promise<JsonValue> {
    if (this.#closed || context.signal.aborted) fail('disposed');
    const value = objectData(decodeData(encodeData(params)));
    switch (method) {
      case 'catalog.search': {
        exactKeys(value, ['query']);
        if (typeof value.query !== 'string' || new TextEncoder().encode(value.query).length > 128
          || /[\u0000-\u001f\u007f-\u009f]/.test(value.query)) fail('invalid-query');
        const result = await this.#backend.search(value.query, context.signal);
        if (!Array.isArray(result) || result.length > 25) fail('catalog-limit');
        const rows = result.map(publicationSnapshot);
        if (new Set(rows.map(row => row.event)).size !== rows.length) fail('duplicate-publication');
        this.#assertOpen(context.signal);
        const next = new Map(rows.map(row => [row.event, row]));
        // Bound the complete reply before replacing the last usable candidate cache.
        const reply: JsonValue = { publications: rows.map(publicationData) };
        encodeData(reply);
        this.#publications = next;
        return reply;
      }
      case 'install.propose': {
        exactKeys(value, ['event_id']);
        const eventId = hex(value.event_id);
        const candidate = this.#publications.get(eventId);
        if (!candidate) fail('unknown-publication');
        const key = `${candidate.manifest.body.id}:${candidate.digest}`;
        if (this.#busy.has(key)) fail('install-pending');
        this.#busy.add(key);
        try {
          const supplied = await this.#backend.readPackage(candidate.digest, context.signal);
          this.#assertOpen(context.signal);
          const prepared = await prepareInstall(candidate.bytes, supplied, candidate.author, candidate.digest);
          this.#assertOpen(context.signal);
          const result = await this.#backend.proposeInstall(prepared.request, prepared.packageBytes, context.signal);
          if (result.app !== candidate.manifest.body.id || result.package_sha256 !== candidate.digest) fail('proposal-mismatch');
          const accepted = Object.freeze({ proposal_id: hex(result.proposal_id, 32), app: result.app,
            package_sha256: result.package_sha256 });
          this.#assertOpen(context.signal);
          return { ...accepted, state: 'pending-owner' };
        } finally { this.#busy.delete(key); }
      }
      case 'installed.list': {
        exactKeys(value, []);
        const installed = await this.#installed(context.signal);
        return { installed: installed.map(installedData) };
      }
      case 'installed.open': {
        exactKeys(value, ['app', 'package_sha256']);
        const app = hex(value.app, 32);
        const digest = hex(value.package_sha256);
        const records = await this.#installed(context.signal);
        const record = records.find(item => item.app === app && item.package_sha256 === digest);
        if (!record) fail('not-installed');
        await this.#actions.openInstalled(record, context.signal);
        this.#assertOpen(context.signal);
        return { app, package_sha256: digest, state: 'opened' };
      }
      default: return fail('unknown-operation');
    }
  }

  #assertOpen(signal: AbortSignal): void { if (this.#closed || signal.aborted) fail('disposed'); }

  async #installed(signal: AbortSignal): Promise<readonly InstalledRecord[]> {
    const result = await this.#backend.installed(signal);
    if (!Array.isArray(result) || result.length > 100) fail('installed-limit');
    const records = result.map(installedSnapshot);
    if (new Set(records.map(item => item.app)).size !== records.length) fail('duplicate-app');
    this.#assertOpen(signal);
    return records;
  }
}
