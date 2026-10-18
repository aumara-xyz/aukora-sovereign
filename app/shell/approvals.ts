// SPDX-License-Identifier: AGPL-3.0-or-later
import { decodeData, exactKeys, MAX_RPC_BYTES, objectData } from '../core/data.js';

type Route = `/approval/${string}`;
interface Options {
  signal: AbortSignal;
  ownerBusy(): boolean;
  openOwner(route: Route): Promise<void>;
  pending(count: number): void;
  /** Proposals the owner explicitly declined and may ask for again; never opened automatically. */
  declined(ids: readonly string[]): void;
  session(bound: boolean): void;
  refusal(error: unknown): void;
}

const INTERVAL_MS = 1_200;
const MAX_NOTIFICATIONS = 10_000;
const MAX_DECLINED = 16;
/** The node has no bound shell session for this browser: the owner signs in, nothing is wrong. */
export const SESSION_REFUSALS: ReadonlySet<string> = new Set([
  'frontdoor:session-required', 'frontdoor:session-expired', 'frontdoor:session-revoked',
  'frontdoor:cookie-host-refused', 'aumlok:binding-required',
]);

async function pending(signal: AbortSignal): Promise<{ sequence: number; ids: string[]; declined: string[]; engineRefusal: string | null }> {
  const response = await fetch('/api/approvals', {
    method: 'GET', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store',
    headers: { accept: 'application/json' }, signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
  });
  if (response.headers.get('content-type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
    throw new Error('shell:approval-response-invalid');
  }
  const reader = response.body.getReader();
  const bytes = new Uint8Array(MAX_RPC_BYTES);
  let length = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (chunk.value.byteLength > bytes.length - length) throw new Error('shell:approval-response-invalid');
      bytes.set(chunk.value, length);
      length += chunk.value.byteLength;
    }
  } finally { await reader.cancel(); reader.releaseLock(); }
  const data = objectData(decodeData(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length))));
  if (!response.ok) {
    const code = typeof data.error === 'string' && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(data.error)
      ? data.error : 'shell:approval-unavailable';
    throw new Error(code);
  }
  exactKeys(data, Object.hasOwn(data, 'engine_refusal')
    ? ['sequence', 'proposals', 'declined', 'engine_refusal'] : ['sequence', 'proposals', 'declined']);
  const engineRefusal = data.engine_refusal ?? null;
  if (engineRefusal !== null && (typeof engineRefusal !== 'string'
    || !/^supervisor:(?:authority-[a-z0-9-]+|profile-plugin-disabled)$/.test(engineRefusal))) {
    throw new Error('shell:approval-response-invalid');
  }
  if (typeof data.sequence !== 'number' || !Number.isSafeInteger(data.sequence) || data.sequence < 0
    || !Array.isArray(data.proposals) || data.proposals.length > MAX_NOTIFICATIONS) {
    throw new Error('shell:approval-response-invalid');
  }
  const ids = new Set<string>();
  for (const value of data.proposals) {
    const row = objectData(value);
    exactKeys(row, ['proposal', 'expires_at_ms']);
    if (typeof row.proposal !== 'string' || !/^[0-9a-f]{32}$/.test(row.proposal) || ids.has(row.proposal)
      || typeof row.expires_at_ms !== 'number' || !Number.isSafeInteger(row.expires_at_ms) || row.expires_at_ms < 0) {
      throw new Error('shell:approval-response-invalid');
    }
    ids.add(row.proposal);
  }
  if (!Array.isArray(data.declined) || data.declined.length > MAX_DECLINED) throw new Error('shell:approval-response-invalid');
  const declined = new Set<string>();
  for (const id of data.declined) {
    if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id) || declined.has(id)) throw new Error('shell:approval-response-invalid');
    declined.add(id);
  }
  return { sequence: data.sequence, ids: [...ids], declined: [...declined], engineRefusal };
}

/** Server-filtered notifications select a pane; they carry no approval material. */
export class ApprovalWatch {
  #options: Options;
  #abort = new AbortController();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #inFlight = false;
  #requested = false;
  #disposed = false;
  #shown = new Set<string>();
  #sequence: number | null = null;

  constructor(options: Options) {
    if (window.top !== window.self) throw new Error('shell:framed-shell');
    this.#options = options;
    options.signal.addEventListener('abort', () => this.dispose(), { once: true });
    if (options.signal.aborted) this.dispose();
  }

  refresh(): void {
    if (this.#disposed) return;
    this.#requested = true;
    if (!this.#inFlight && this.#timer === undefined) void this.#poll();
  }

  forget(id: string): void { this.#shown.delete(id); }

  reopen(): void {
    if (this.#disposed) return;
    this.#shown.clear();
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    this.refresh();
  }

  async #poll(): Promise<void> {
    if (this.#disposed || this.#inFlight) return;
    this.#inFlight = true;
    this.#requested = false;
    let sessionMissing = false;
    try {
      const next = await pending(this.#abort.signal);
      if (this.#disposed) return;
      if (this.#sequence !== null && next.sequence < this.#sequence) throw new Error('shell:approval-sequence-rollback');
      this.#options.session(true);
      if (next.engineRefusal !== null) this.#options.refusal(new Error(next.engineRefusal));
      this.#sequence = next.sequence;
      this.#options.pending(next.ids.length);
      this.#options.declined(next.declined);
      const present = new Set(next.ids);
      for (const id of this.#shown) if (!present.has(id)) this.#shown.delete(id);
      if (!this.#options.ownerBusy()) {
        const id = next.ids.find(value => !this.#shown.has(value));
        if (id) {
          await this.#options.openOwner(`/approval/${id}`);
          if (!this.#disposed) this.#shown.add(id);
        }
      }
    } catch (error) {
      if (this.#disposed) return;
      sessionMissing = error instanceof Error && SESSION_REFUSALS.has(error.message);
      if (sessionMissing) {
        this.#shown.clear();
        this.#sequence = null;
        this.#options.pending(0);
        this.#options.declined([]);
        this.#options.session(false);
      } else if (!(error instanceof Error) || error.message !== 'supervisor:approval-poll-not-due') {
        this.#options.refusal(error);
      }
    } finally {
      this.#inFlight = false;
      if (!this.#disposed && (!sessionMissing || this.#requested)) {
        this.#timer = setTimeout(() => { this.#timer = undefined; void this.#poll(); }, INTERVAL_MS);
      }
    }
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#abort.abort();
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    this.#shown.clear();
    this.#sequence = null;
  }
}
