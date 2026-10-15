// SPDX-License-Identifier: AGPL-3.0-or-later

import { decodeData, encodeData, exactKeys, objectData } from './data.js';
import type { JsonValue } from './data.js';
import type { Dispose } from './organism.js';

export type CapabilityMap = Readonly<Record<string, { readonly methods: readonly string[]; readonly topics: readonly string[] }>>;
export interface RpcCallContext { signal: AbortSignal }
export interface RpcService {
  call?(method: string, params: JsonValue, context: RpcCallContext): JsonValue | Promise<JsonValue>;
  subscribe?(topic: string, params: JsonValue, emit: (value: JsonValue) => void, context: RpcCallContext): Dispose | Promise<Dispose>;
}
export interface HostFaceOptions {
  frame: HTMLIFrameElement;
  pluginId: string;
  capabilities: CapabilityMap;
  services: ReadonlyMap<string, RpcService>;
  signal?: AbortSignal;
}
export const RPC_CHANNEL = 'aukora.face-rpc.v1';
export const MAX_RPC_PENDING = 32;
export const MAX_RPC_EVENTS = 16;
export const RPC_DEADLINE_MS = 30_000;
const NAME = /^[a-z][a-z0-9._:-]{0,127}$/;
const ID = /^[A-Za-z0-9_-]{1,64}$/;

export function refusal(error: unknown): string {
  try {
    const code = error instanceof Error ? error.message : '';
    if (typeof code === 'string' && /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/.test(code)) return code;
  } catch { /* An unreadable error carries no refusal code. */ }
  return 'app:service-failed';
}

interface Work {
  id: string;
  settled: boolean;
  cleaning: boolean;
  controller: AbortController;
  cleanup: Dispose | null;
  timer: ReturnType<typeof setTimeout> | null;
  subscription: boolean;
  ready: boolean;
  nextEvent: number;
  sentEvent: number;
  nextAck: number;
  queued: string[];
}

function capabilitySnapshot(value: CapabilityMap): CapabilityMap {
  const source = objectData(decodeData(encodeData(value)));
  const result: Record<string, { readonly methods: readonly string[]; readonly topics: readonly string[] }> = Object.create(null);
  for (const [name, item] of Object.entries(source)) {
    if (!NAME.test(name)) throw new Error('app:invalid-capability');
    const grant = objectData(item);
    exactKeys(grant, ['methods', 'topics']);
    const names = (items: JsonValue): readonly string[] => {
      if (!Array.isArray(items) || items.some(entry => typeof entry !== 'string' || !NAME.test(entry))) {
        throw new Error('app:invalid-capability');
      }
      return Object.freeze([...new Set(items as string[])]);
    };
    result[name] = Object.freeze({ methods: names(grant.methods), topics: names(grant.topics) });
  }
  return Object.freeze(result);
}

function hostPort(port: MessagePort, grants: CapabilityMap, services: ReadonlyMap<string, RpcService>): Dispose {
  const active = new Map<string, Work>();
  const retained = new Map<string, Work>();
  const executing = new Set<Promise<void>>();
  const cleanups = new Set<Promise<void>>();
  let closed = false;
  let closing: Promise<void> | null = null;
  let cleanupFailed = false;

  const release = (work: Work) => {
    if (active.get(work.id) !== work && work.settled && !work.cleaning) retained.delete(work.id);
  };
  const runCleanup = (work: Work, cleanup: Dispose): Promise<void> => {
    work.cleaning = true;
    const task = Promise.resolve().then(cleanup).then(() => undefined, () => {
      cleanupFailed = true;
      void close().catch(() => undefined);
    }).then(() => {
      work.cleaning = false;
      release(work);
    });
    cleanups.add(task);
    void task.then(() => { cleanups.delete(task); });
    return task;
  };
  const clearTimer = (work: Work) => {
    if (work.timer !== null) clearTimeout(work.timer);
    work.timer = null;
  };
  const stop = (id: string): void => {
    const work = active.get(id);
    if (!work) return;
    active.delete(id);
    clearTimer(work);
    work.queued.length = 0;
    work.controller.abort();
    const cleanup = work.cleanup;
    work.cleanup = null;
    if (cleanup) void runCleanup(work, cleanup);
    release(work);
  };
  const close = (): Promise<void> => {
    if (closing) return closing;
    closing = Promise.resolve().then(async () => {
      await Promise.all([...executing, ...cleanups]);
      if (cleanupFailed) throw new Error('app:cleanup-failed');
    });
    closed = true;
    port.onmessage = null;
    port.onmessageerror = null;
    port.close();
    for (const id of [...active.keys()]) stop(id);
    return closing;
  };
  const deliver = (bytes: string): boolean => {
    if (closed) return false;
    try { port.postMessage(bytes); return true; }
    catch { void close().catch(() => undefined); return false; }
  };
  const send = (value: JsonValue): boolean => deliver(encodeData(value));
  const reject = (id: string, error: unknown) => send({ v: 1, type: 'refusal', id, code: refusal(error) });
  const deadline = (id: string, work: Work) => {
    clearTimer(work);
    work.timer = setTimeout(() => {
      if (active.get(id) !== work) return;
      reject(id, new Error('app:deadline'));
      stop(id);
    }, RPC_DEADLINE_MS);
  };
  const watchEvents = (id: string, work: Work) => {
    clearTimer(work);
    if (work.sentEvent > work.nextAck) deadline(id, work);
  };
  const emit = (id: string, work: Work, value: JsonValue) => {
    if (active.get(id) !== work) return;
    try {
      if (work.nextEvent - work.nextAck >= MAX_RPC_EVENTS || work.nextEvent >= Number.MAX_SAFE_INTEGER) {
        throw new Error('app:backpressure');
      }
      const bytes = encodeData({ v: 1, type: 'event', id, index: work.nextEvent, value });
      work.nextEvent++;
      if (!work.ready) work.queued.push(bytes);
      else if (deliver(bytes)) {
        work.sentEvent++;
        if (work.timer === null) watchEvents(id, work);
      }
    } catch (error) { reject(id, error); stop(id); }
  };

  const perform = async (id: string, work: Work, service: RpcService, operation: string, params: JsonValue) => {
    try {
      if (work.controller.signal.aborted) return;
      const context: RpcCallContext = Object.freeze({ signal: work.controller.signal });
      if (work.subscription) {
        const cleanup = await service.subscribe!(operation, params, value => emit(id, work, value), context);
        if (typeof cleanup !== 'function') throw new Error('app:invalid-service');
        if (active.get(id) !== work) { await runCleanup(work, cleanup); return; }
        work.cleanup = cleanup;
        work.ready = true;
        clearTimer(work);
        if (!send({ v: 1, type: 'subscribed', id })) return;
        for (const bytes of work.queued.splice(0)) {
          if (!deliver(bytes)) return;
          work.sentEvent++;
        }
        watchEvents(id, work);
      } else {
        const value = await service.call!(operation, params, context);
        if (active.get(id) !== work) return;
        send({ v: 1, type: 'reply', id, value });
        stop(id);
      }
    } catch (error) {
      if (active.get(id) !== work) return;
      reject(id, error);
      stop(id);
    } finally {
      work.settled = true;
      release(work);
    }
  };

  port.onmessage = event => {
    try {
      if (event.ports.length) throw new Error('app:invalid-message');
      const message = objectData(decodeData(event.data));
      if (message.v !== 1 || typeof message.id !== 'string' || !ID.test(message.id)) throw new Error('app:invalid-message');
      const id = message.id;
      if (message.type === 'ack') {
        exactKeys(message, ['v', 'type', 'id', 'index']);
        if (typeof message.index !== 'number' || !Number.isSafeInteger(message.index) || message.index < 0) {
          throw new Error('app:invalid-message');
        }
        const work = active.get(id);
        if (!work) return;
        if (!work.subscription || !work.ready || message.index !== work.nextAck || work.nextAck >= work.sentEvent) {
          throw new Error('app:invalid-message');
        }
        work.nextAck++;
        watchEvents(id, work);
        return;
      }
      if (message.type === 'cancel' || message.type === 'unsubscribe') {
        exactKeys(message, ['v', 'type', 'id']);
        const work = active.get(id);
        if (work && work.subscription !== (message.type === 'unsubscribe')) throw new Error('app:invalid-message');
        stop(id);
        return;
      }
      if (message.type !== 'call' && message.type !== 'subscribe') {
        reject(id, new Error('app:unknown-operation'));
        return;
      }
      exactKeys(message, ['v', 'type', 'id', 'service', 'operation', 'params']);
      if (typeof message.service !== 'string' || !NAME.test(message.service)
        || typeof message.operation !== 'string' || !NAME.test(message.operation)) throw new Error('app:invalid-message');
      if (retained.has(id)) throw new Error('app:invalid-message');
      const subscription = message.type === 'subscribe';
      const grant = Object.hasOwn(grants, message.service) ? grants[message.service] : undefined;
      if (!(subscription ? grant?.topics : grant?.methods)?.includes(message.operation)) {
        reject(id, new Error('app:capability-denied'));
        return;
      }
      const service = services.get(message.service);
      if (!service || typeof (subscription ? service.subscribe : service.call) !== 'function') {
        reject(id, new Error('app:service-unavailable'));
        return;
      }
      if (retained.size >= MAX_RPC_PENDING) { reject(id, new Error('app:busy')); return; }
      const work: Work = {
        id, settled: false, cleaning: false,
        controller: new AbortController(), cleanup: null, timer: null, subscription,
        ready: false, nextEvent: 0, sentEvent: 0, nextAck: 0, queued: [],
      };
      active.set(id, work);
      retained.set(id, work);
      deadline(id, work);
      const task = Promise.resolve().then(() => perform(id, work, service, message.operation as string, message.params));
      executing.add(task);
      void task.then(() => { executing.delete(task); });
    } catch {
      for (const transferred of event.ports) transferred.close();
      void close().catch(() => undefined);
    }
  };
  port.onmessageerror = () => { void close().catch(() => undefined); };
  port.start();
  return close;
}

export function hostFace(options: HostFaceOptions): Dispose {
  const { frame, pluginId, signal } = options;
  const sandboxed = () => frame.sandbox.length === 1 && frame.sandbox.contains('allow-scripts');
  if (typeof pluginId !== 'string' || !NAME.test(pluginId) || !sandboxed()) throw new Error('app:invalid-sandbox');
  let grants: CapabilityMap;
  try { grants = capabilitySnapshot(options.capabilities); }
  catch { throw new Error('app:invalid-capability'); }
  const services = new Map(options.services);
  const retiring = new Set<Promise<void>>();
  let cleanupFailed = false;
  let connection: Dispose | null = null;
  let offered = false;
  let loadedOnce = false;
  let closed = false;
  let closing: Promise<void> | null = null;
  const retire = () => {
    const dispose = connection;
    connection = null;
    if (!dispose) return;
    const task = Promise.resolve(dispose()).then(() => undefined, () => { cleanupFailed = true; });
    retiring.add(task);
    void task.then(() => { retiring.delete(task); });
  };
  const dispose = (): Promise<void> => {
    if (closing) return closing;
    closing = Promise.resolve().then(async () => {
      await Promise.all([...retiring]);
      if (cleanupFailed) throw new Error('app:cleanup-failed');
    });
    closed = true;
    window.removeEventListener('message', hello);
    window.removeEventListener('pagehide', aborted);
    frame.removeEventListener('load', loaded);
    signal?.removeEventListener('abort', aborted);
    sandboxObserver.disconnect();
    retire();
    return closing;
  };
  const aborted = () => { void dispose().catch(() => undefined); };
  const offer = () => {
    if (closed || !loadedOnce || offered || !frame.contentWindow) return;
    if (!sandboxed()) { aborted(); return; }
    const channel = new MessageChannel();
    offered = true;
    connection = hostPort(channel.port1, grants, services);
    try {
      frame.contentWindow.postMessage({ channel: RPC_CHANNEL, type: 'connect', pluginId }, '*', [channel.port2]);
    } catch { channel.port2.close(); aborted(); }
  };
  const hello = (event: MessageEvent) => {
    if (closed || event.source !== frame.contentWindow || event.origin !== 'null') return;
    try {
      const message = objectData(decodeData(encodeData(event.data)));
      if (message.channel !== RPC_CHANNEL || message.pluginId !== pluginId) return;
      exactKeys(message, ['channel', 'type', 'pluginId']);
      if (message.type !== 'hello' || event.ports.length) throw new Error('app:invalid-message');
      offer();
    } catch {
      for (const transferred of event.ports) transferred.close();
    }
  };
  const loaded = () => {
    if (closed) return;
    if (loadedOnce || !sandboxed()) { aborted(); return; }
    loadedOnce = true;
    try { frame.contentWindow?.postMessage({ channel: RPC_CHANNEL, type: 'hello-request', pluginId }, '*'); }
    catch { aborted(); }
  };
  const sandboxObserver = new MutationObserver(() => { if (!sandboxed()) aborted(); });
  if (signal?.aborted) { void dispose().catch(() => undefined); return dispose; }
  sandboxObserver.observe(frame, { attributes: true, attributeFilter: ['sandbox'] });
  window.addEventListener('message', hello);
  window.addEventListener('pagehide', aborted, { once: true });
  frame.addEventListener('load', loaded);
  signal?.addEventListener('abort', aborted, { once: true });
  return dispose;
}
