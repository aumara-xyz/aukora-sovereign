// SPDX-License-Identifier: AGPL-3.0-or-later

import { decodeData, encodeData, exactKeys, objectData } from './data.js';
import type { JsonValue } from './data.js';
import { MAX_RPC_PENDING, RPC_CHANNEL, RPC_DEADLINE_MS } from './rpc.js';
import type { Dispose } from './organism.js';

export interface FaceClientOptions { shellOrigin: string; pluginId: string; signal?: AbortSignal }
export interface CallOptions { signal?: AbortSignal }
export interface SubscriptionOptions extends CallOptions { onError?: (code: string) => void }
export interface FaceClient {
  call(service: string, method: string, params: JsonValue, options?: CallOptions): Promise<JsonValue>;
  subscribe(service: string, topic: string, params: JsonValue, onValue: (value: JsonValue) => void,
    options?: SubscriptionOptions): Promise<Dispose>;
  dispose(): void;
}
interface Pending {
  resolve(value: JsonValue): void;
  reject(error: Error): void;
  onValue: ((value: JsonValue) => void) | null;
  onError: ((code: string) => void) | null;
  timer: ReturnType<typeof setTimeout> | null;
  removeAbort: () => void;
  subscribed: boolean;
  sent: boolean;
  message: string;
  nextEvent: number;
}

export function connectFace(options: FaceClientOptions): FaceClient {
  const { shellOrigin, pluginId } = options;
  if (new URL(shellOrigin).origin !== shellOrigin || !/^https?:\/\//.test(shellOrigin)
    || !/^[a-z][a-z0-9._:-]{0,127}$/.test(pluginId) || window.parent === window) {
    throw new Error('app:invalid-shell');
  }
  let port: MessagePort | null = null;
  let serial = 0;
  let closed = false;
  const pending = new Map<string, Pending>();
  const send = (value: JsonValue) => port?.postMessage(encodeData(value));
  const remove = (id: string) => {
    const request = pending.get(id);
    if (!request) return null;
    pending.delete(id);
    if (request.timer !== null) clearTimeout(request.timer);
    request.removeAbort();
    return request;
  };
  const fail = (id: string, code: string) => {
    const request = remove(id);
    if (!request) return;
    if (request.subscribed) {
      try { request.onError?.(code); } catch { /* One consumer cannot retain a revoked subscription. */ }
    } else request.reject(new Error(code));
  };
  const disconnect = (code: string) => {
    port?.close();
    port = null;
    for (const id of [...pending.keys()]) fail(id, code);
  };
  const read = (event: MessageEvent) => {
    try {
      const message = objectData(decodeData(event.data));
      if (message.v !== 1 || typeof message.id !== 'string') throw new Error('app:invalid-message');
      const request = pending.get(message.id);
      if (!request) return;
      if (message.type === 'refusal') {
        exactKeys(message, ['v', 'type', 'id', 'code']);
        if (typeof message.code !== 'string' || !/^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/.test(message.code)) {
          throw new Error('app:invalid-message');
        }
        fail(message.id, message.code);
      } else if (message.type === 'reply' && !request.onValue) {
        exactKeys(message, ['v', 'type', 'id', 'value']);
        remove(message.id)?.resolve(message.value);
      } else if (message.type === 'subscribed' && request.onValue && !request.subscribed) {
        exactKeys(message, ['v', 'type', 'id']);
        request.subscribed = true;
        if (request.timer !== null) clearTimeout(request.timer);
        request.timer = null;
        request.resolve(null);
      } else if (message.type === 'event' && request.onValue) {
        exactKeys(message, ['v', 'type', 'id', 'index', 'value']);
        if (message.index !== request.nextEvent) throw new Error('app:invalid-message');
        request.nextEvent++;
        try { request.onValue(message.value); } catch { /* Consumer errors do not change RPC authority. */ }
        send({ v: 1, type: 'ack', id: message.id, index: message.index });
      } else throw new Error('app:unknown-operation');
    } catch { disconnect('app:invalid-message'); }
  };
  const hello = () => {
    if (!closed) window.parent.postMessage({ channel: RPC_CHANNEL, type: 'hello', pluginId }, shellOrigin);
  };
  const connect = (event: MessageEvent) => {
    if (closed || event.source !== window.parent || event.origin !== shellOrigin) return;
    const message = event.data;
    if (!message || message.channel !== RPC_CHANNEL || message.pluginId !== pluginId) return;
    if (message.type === 'hello-request') { hello(); return; }
    if (message.type !== 'connect' || event.ports.length !== 1) return;
    if (port) disconnect('app:reconnected');
    port = event.ports[0];
    port.onmessage = read;
    port.onmessageerror = () => disconnect('app:invalid-message');
    port.start();
    for (const request of pending.values()) {
      request.sent = true;
      port.postMessage(request.message);
    }
  };
  const request = (type: 'call' | 'subscribe', service: string, operation: string, params: JsonValue,
    onValue: ((value: JsonValue) => void) | null, callOptions: SubscriptionOptions = {}) => {
    const id = String(++serial);
    const promise = new Promise<JsonValue>((resolve, reject) => {
      if (closed) { reject(new Error('app:disposed')); return; }
      if (callOptions.signal?.aborted) { reject(new Error('app:aborted')); return; }
      if (pending.size >= MAX_RPC_PENDING) { reject(new Error('app:busy')); return; }
      let message: string;
      try { message = encodeData({ v: 1, id, type, service, operation, params }); }
      catch { reject(new Error('app:invalid-data')); return; }
      const aborted = () => {
        if (pending.get(id)?.sent) send({ v: 1, type: onValue ? 'unsubscribe' : 'cancel', id });
        fail(id, 'app:aborted');
      };
      const item: Pending = {
        resolve, reject, onValue, onError: callOptions.onError ?? null, timer: null, subscribed: false,
        sent: port !== null, message, nextEvent: 0,
        removeAbort: () => callOptions.signal?.removeEventListener('abort', aborted),
      };
      pending.set(id, item);
      item.timer = setTimeout(() => {
        if (item.sent) send({ v: 1, type: onValue ? 'unsubscribe' : 'cancel', id });
        fail(id, 'app:deadline');
      }, RPC_DEADLINE_MS);
      callOptions.signal?.addEventListener('abort', aborted, { once: true });
      port?.postMessage(message);
    });
    const dispose = () => {
      const item = pending.get(id);
      if (!item) return;
      if (item.sent) send({ v: 1, type: onValue ? 'unsubscribe' : 'cancel', id });
      fail(id, 'app:disposed');
    };
    return { promise, dispose };
  };
  const dispose = () => {
    if (closed) return;
    closed = true;
    for (const [id, item] of pending) {
      if (item.sent) send({ v: 1, type: item.onValue ? 'unsubscribe' : 'cancel', id });
    }
    disconnect('app:disposed');
    window.removeEventListener('message', connect);
    options.signal?.removeEventListener('abort', dispose);
  };
  window.addEventListener('message', connect);
  options.signal?.addEventListener('abort', dispose, { once: true });
  if (options.signal?.aborted) dispose();
  else hello();
  return Object.freeze({
    call: (service: string, method: string, params: JsonValue, callOptions?: CallOptions) =>
      request('call', service, method, params, null, callOptions).promise,
    subscribe: async (service: string, topic: string, params: JsonValue, onValue: (value: JsonValue) => void,
      callOptions?: SubscriptionOptions): Promise<Dispose> => {
      const pendingRequest = request('subscribe', service, topic, params, onValue, callOptions);
      await pendingRequest.promise;
      return pendingRequest.dispose;
    },
    dispose,
  });
}
