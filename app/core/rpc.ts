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
  const message = error instanceof Error ? error.message : '';
  return /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/.test(message) ? message : 'app:service-failed';
}

interface Work {
  controller: AbortController;
  cleanup: Dispose | null;
  timer: ReturnType<typeof setTimeout> | null;
  subscription: boolean;
  nextEvent: number;
  nextAck: number;
}

function hostPort(port: MessagePort, grants: CapabilityMap, services: ReadonlyMap<string, RpcService>): Dispose {
  const active = new Map<string, Work>();
  let closed = false;
  const send = (value: JsonValue) => {
    if (!closed) port.postMessage(encodeData(value));
  };
  const stop = async (id: string) => {
    const work = active.get(id);
    if (!work) return;
    active.delete(id);
    if (work.timer !== null) clearTimeout(work.timer);
    work.controller.abort();
    if (work.cleanup) { try { await work.cleanup(); } catch { /* The channel is already revoked. */ } }
  };
  const reject = (id: string, error: unknown) => send({ v: 1, type: 'refusal', id, code: refusal(error) });
  port.onmessage = event => {
    let message: ReturnType<typeof objectData>;
    try {
      message = objectData(decodeData(event.data));
      if (message.v !== 1 || typeof message.id !== 'string' || !ID.test(message.id)) throw new Error('app:invalid-message');
      if (message.type === 'ack') {
        exactKeys(message, ['v', 'type', 'id', 'index']);
        const work = active.get(message.id);
        if (!work) return;
        if (!work.subscription || message.index !== work.nextAck || work.nextAck >= work.nextEvent) {
          throw new Error('app:invalid-message');
        }
        work.nextAck++;
        return;
      }
      if (message.type === 'cancel' || message.type === 'unsubscribe') {
        exactKeys(message, ['v', 'type', 'id']);
        void stop(message.id);
        return;
      }
      if (message.type !== 'call' && message.type !== 'subscribe') {
        reject(message.id, new Error('app:unknown-operation'));
        return;
      }
      exactKeys(message, ['v', 'type', 'id', 'service', 'operation', 'params']);
      if (typeof message.service !== 'string' || !NAME.test(message.service)
        || typeof message.operation !== 'string' || !NAME.test(message.operation)) throw new Error('app:invalid-message');
    } catch { void close(); return; }
    const id = message.id as string;
    const serviceName = message.service as string;
    const operation = message.operation as string;
    const subscription = message.type === 'subscribe';
    const capability = Object.hasOwn(grants, serviceName) ? grants[serviceName] : undefined;
    if (!(subscription ? capability?.topics : capability?.methods)?.includes(operation)) {
      reject(id, new Error('app:capability-denied'));
      return;
    }
    const service = services.get(serviceName);
    if (!service || (subscription ? !service.subscribe : !service.call)) {
      reject(id, new Error('app:service-unavailable'));
      return;
    }
    if (active.has(id) || active.size >= MAX_RPC_PENDING) {
      reject(id, new Error('app:busy'));
      return;
    }
    const work: Work = { controller: new AbortController(), cleanup: null, timer: null, subscription, nextEvent: 0, nextAck: 0 };
    active.set(id, work);
    work.timer = setTimeout(() => {
      reject(id, new Error('app:deadline'));
      void stop(id);
    }, RPC_DEADLINE_MS);
    const context = { signal: work.controller.signal };
    Promise.resolve().then(async () => {
      if (work.controller.signal.aborted) return;
      if (subscription) {
        const cleanup = await service.subscribe!(operation, message.params, value => {
          if (active.get(id) !== work) return;
          try {
            if (work.nextEvent - work.nextAck >= MAX_RPC_EVENTS || work.nextEvent >= Number.MAX_SAFE_INTEGER) {
              throw new Error('app:backpressure');
            }
            send({ v: 1, type: 'event', id, index: work.nextEvent++, value });
          }
          catch (error) { reject(id, error); void stop(id); }
        }, context);
        if (typeof cleanup !== 'function') throw new Error('app:invalid-service');
        if (active.get(id) !== work) { await cleanup(); return; }
        work.cleanup = cleanup;
        if (work.timer !== null) clearTimeout(work.timer);
        work.timer = null;
        send({ v: 1, type: 'subscribed', id });
      } else {
        const value = await service.call!(operation, message.params, context);
        if (active.get(id) === work) {
          send({ v: 1, type: 'reply', id, value });
          await stop(id);
        }
      }
    }).catch(error => {
      if (active.get(id) !== work) return;
      reject(id, error);
      void stop(id);
    });
  };
  port.onmessageerror = () => { void close(); };
  port.start();
  const close = async () => {
    if (closed) return;
    closed = true;
    port.onmessage = null;
    port.onmessageerror = null;
    port.close();
    await Promise.all([...active.keys()].map(stop));
  };
  return close;
}

export function hostFace(options: HostFaceOptions): Dispose {
  const { frame, pluginId, services, signal } = options;
  if (!NAME.test(pluginId) || frame.sandbox.length !== 1 || !frame.sandbox.contains('allow-scripts')) {
    throw new Error('app:invalid-sandbox');
  }
  const grants: CapabilityMap = Object.freeze(Object.fromEntries(Object.entries(options.capabilities).map(([name, grant]) => {
    if (!NAME.test(name) || [...grant.methods, ...grant.topics].some(item => !NAME.test(item))) throw new Error('app:invalid-capability');
    return [name, Object.freeze({ methods: Object.freeze([...grant.methods]), topics: Object.freeze([...grant.topics]) })];
  })));
  let closed = false;
  let offered = false;
  let loadedOnce = false;
  let disconnect: Dispose | null = null;
  const offer = () => {
    if (closed || !loadedOnce || offered || !frame.contentWindow) return;
    offered = true;
    const channel = new MessageChannel();
    disconnect = hostPort(channel.port1, grants, services);
    frame.contentWindow.postMessage({ channel: RPC_CHANNEL, type: 'connect', pluginId }, '*', [channel.port2]);
  };
  const hello = (event: MessageEvent) => {
    if (event.source !== frame.contentWindow || event.origin !== 'null') return;
    const data = event.data;
    if (!data || data.channel !== RPC_CHANNEL || data.type !== 'hello' || data.pluginId !== pluginId) return;
    offer();
  };
  const loaded = () => {
    loadedOnce = true;
    if (disconnect) void disconnect();
    disconnect = null;
    offered = false;
    frame.contentWindow?.postMessage({ channel: RPC_CHANNEL, type: 'hello-request', pluginId }, '*');
  };
  const dispose = async () => {
    if (closed) return;
    closed = true;
    window.removeEventListener('message', hello);
    frame.removeEventListener('load', loaded);
    signal?.removeEventListener('abort', aborted);
    if (disconnect) await disconnect();
  };
  const aborted = () => { void dispose(); };
  if (signal?.aborted) { closed = true; return dispose; }
  window.addEventListener('message', hello);
  frame.addEventListener('load', loaded);
  signal?.addEventListener('abort', aborted, { once: true });
  return dispose;
}
