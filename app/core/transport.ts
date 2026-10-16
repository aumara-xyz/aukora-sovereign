// SPDX-License-Identifier: AGPL-3.0-or-later
import { decodeData, encodeData, exactKeys, objectData } from './data.js';
import type { JsonValue } from './data.js';
import { FD4_LIMITS } from './fd4.js';
import { commandFrame, readFrame, eventFrame } from './wire.js';
import type { Dispose } from './organism.js';

export interface DataTransport {
  call(kind: string, body: JsonValue, signal: AbortSignal): Promise<JsonValue>;
  read(face: string, service: string, method: string, params: JsonValue, signal: AbortSignal): Promise<JsonValue>;
  subscribe(topic: string, emit: (value: JsonValue) => void, signal: AbortSignal): Dispose;
}
interface Pending {
  kind: string;
  resolve(value: JsonValue): void;
  reject(error: Error): void;
  cleanup(): void;
}
const DEADLINE = 25_000;
const CODE = /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/;

function errorCode(value: JsonValue): string {
  const row = objectData(value);
  return typeof row.error === 'string' && CODE.test(row.error) ? row.error : 'app:transport-failed';
}

/** One receiver owns the session queue; every face shares its bounded, correlated replies. */
export class ShellTransport implements DataTransport {
  #pending = new Map<string, Pending>();
  #listeners = new Map<string, Set<(value: JsonValue) => void>>();
  #controller = new AbortController();
  #polling = false;
  #wakePoll: (() => void) | undefined;
  #writes: Promise<void> = Promise.resolve();
  #queuedBytes = 0;

  async request(path: string, body: JsonValue, signal = this.#controller.signal): Promise<JsonValue> {
    return this.#http(path, 'POST', encodeData(body), signal);
  }

  call(kind: string, body: JsonValue, signal: AbortSignal): Promise<JsonValue> {
    const id = crypto.randomUUID().replaceAll('-', '');
    return this.#submit(id, kind, commandFrame(id, kind, body), signal);
  }

  read(face: string, service: string, method: string, params: JsonValue, signal: AbortSignal): Promise<JsonValue> {
    const id = crypto.randomUUID().replaceAll('-', '');
    return this.#submit(id, 'service.reply', readFrame(id, face, service, method, params), signal);
  }

  subscribe(topic: string, emit: (value: JsonValue) => void, signal: AbortSignal): Dispose {
    if (!['session.event', 'health.snapshot'].includes(topic)) throw new Error('app:unknown-topic');
    if (signal.aborted || this.#controller.signal.aborted) throw new Error('app:cancelled');
    const listeners = this.#listeners.get(topic) ?? new Set();
    if (listeners.size >= FD4_LIMITS.pendingChunks) throw new Error('app:backpressure');
    listeners.add(emit);
    this.#listeners.set(topic, listeners);
    const dispose = () => {
      listeners.delete(emit);
      if (!listeners.size) this.#listeners.delete(topic);
      signal.removeEventListener('abort', dispose);
      if (!this.#pending.size && !this.#listeners.size) this.#wakePoll?.();
    };
    signal.addEventListener('abort', dispose, { once: true });
    void this.#poll();
    return dispose;
  }

  dispose(): void {
    this.#controller.abort();
    for (const [id] of this.#pending) this.#reject(id, new Error('app:cancelled'));
    this.#listeners.clear();
  }

  #submit(id: string, kind: string, bytes: string, signal: AbortSignal): Promise<JsonValue> {
    if (signal.aborted || this.#controller.signal.aborted) return Promise.reject(new Error('app:cancelled'));
    if (this.#pending.size >= 32) return Promise.reject(new Error('app:backpressure'));
    const byteLength = new TextEncoder().encode(bytes).byteLength;
    if (this.#queuedBytes + byteLength > 4 * FD4_LIMITS.frameBytes) return Promise.reject(new Error('app:backpressure'));
    this.#queuedBytes += byteLength;
    let settled!: () => void;
    const completion = new Promise<void>(resolve => { settled = resolve; });
    return new Promise((resolve, reject) => {
      const abort = () => this.#reject(id, new Error('app:cancelled'));
      const timer = setTimeout(() => this.#reject(id, new Error('app:deadline')), DEADLINE);
      this.#pending.set(id, { kind, resolve, reject, cleanup: () => {
        clearTimeout(timer);
        signal.removeEventListener('abort', abort);
        this.#queuedBytes -= byteLength;
        settled();
      } });
      signal.addEventListener('abort', abort, { once: true });
      this.#writes = this.#writes.then(async () => {
        if (!this.#pending.has(id)) return;
        try {
          const reply = objectData(await this.#http('/api/data', 'POST', bytes,
            AbortSignal.any([signal, this.#controller.signal])));
          exactKeys(reply, ['ok']);
          if (reply.ok !== true) throw new Error('app:invalid-message');
          this.#wakePoll?.();
          void this.#poll();
          await completion;
        } catch (error) {
          this.#reject(id, error instanceof Error ? error : new Error('app:transport-failed'));
        }
      });
    });
  }

  #resolve(id: string, value: JsonValue): void {
    const pending = this.#pending.get(id);
    if (!pending) return;
    this.#pending.delete(id);
    pending.cleanup();
    pending.resolve(value);
  }

  #reject(id: string, error: Error): void {
    const pending = this.#pending.get(id);
    if (!pending) return;
    this.#pending.delete(id);
    pending.cleanup();
    pending.reject(error);
    if (!this.#pending.size && !this.#listeners.size) this.#wakePoll?.();
  }

  #emit(topic: string, value: JsonValue): void {
    for (const emit of this.#listeners.get(topic) ?? []) {
      try { emit(value); } catch { this.#listeners.get(topic)?.delete(emit); }
    }
  }

  async #poll(): Promise<void> {
    if (this.#polling || this.#controller.signal.aborted) return;
    this.#polling = true;
    let idleDelay = 1_000;
    try {
      while (!this.#controller.signal.aborted && (this.#pending.size || this.#listeners.size)) {
        try {
          const event = eventFrame(await this.#http('/api/data', 'GET', undefined, this.#controller.signal));
          idleDelay = 1_000;
          const pending = this.#pending.get(event.id as string);
          if (event.kind === 'refusal') {
            const body = objectData(event.body);
            this.#reject(event.id as string, new Error(body.code as string));
          } else if (pending) {
            const turn = pending.kind === 'chat.turn'
              && ['session.entry', 'session.append', 'model.start'].includes(event.kind as string);
            if (pending.kind !== event.kind && !turn) throw new Error('app:unexpected-event');
            this.#resolve(event.id as string, event.kind === 'service.reply' ? objectData(event.body).value : event.body);
          }
          if (event.v === 2) this.#emit('session.event', event);
          if (event.kind === 'health.snapshot') this.#emit('health.snapshot', event.body);
        } catch (error) {
          if (this.#controller.signal.aborted) break;
          const code = error instanceof Error ? error.message : 'app:transport-failed';
          if (code === 'supervisor:not-ready') {
            await this.#pause(this.#pending.size ? 1_000 : idleDelay);
            idleDelay = Math.min(idleDelay * 2, 30_000);
            continue;
          }
          for (const [id] of this.#pending) this.#reject(id, new Error(code));
          this.#emit('session.event', { kind: 'refusal', body: { code: CODE.test(code) ? code : 'app:transport-failed', next: '' } });
          await this.#pause(2_000);
        }
      }
    } finally { this.#polling = false; }
  }

  #pause(ms: number): Promise<void> {
    return new Promise(resolve => {
      const signal = this.#controller.signal;
      const done = () => {
        clearTimeout(timer);
        signal.removeEventListener('abort', done);
        if (this.#wakePoll === done) this.#wakePoll = undefined;
        resolve();
      };
      const timer = setTimeout(done, ms);
      this.#wakePoll = done;
      signal.addEventListener('abort', done, { once: true });
      if (signal.aborted) done();
    });
  }

  async #http(path: string, method: 'GET' | 'POST', body: string | undefined, signal: AbortSignal): Promise<JsonValue> {
    const response = await fetch(path, {
      method, body, credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store',
      headers: body === undefined ? { accept: 'application/json' } : { accept: 'application/json', 'content-type': 'application/json' },
      signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
    });
    if (response.headers.get('content-type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
      throw new Error('app:invalid-message');
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > FD4_LIMITS.frameBytes) throw new Error('app:data-limit');
        chunks.push(value);
      }
    } finally { await reader.cancel(); reader.releaseLock(); }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value = decodeData(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!response.ok) throw new Error(errorCode(value));
    return value;
  }
}
