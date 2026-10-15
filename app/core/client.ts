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
const NAME = /^[a-z][a-z0-9._:-]{0,127}$/;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const CODE = /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/;

export function connectFace(options: FaceClientOptions): FaceClient {
  const { shellOrigin, pluginId } = options;
  try {
    const origin = new URL(shellOrigin);
    if (origin.origin !== shellOrigin || !['https:', 'http:'].includes(origin.protocol)
      || typeof pluginId !== 'string' || !NAME.test(pluginId) || window.parent === window) throw new Error();
  } catch { throw new Error('app:invalid-shell'); }

  const pending = new Map<string, Pending>();
  let port: MessagePort | null = null;
  let closed = false;
  let serial = 0;
  const remove = (id: string): Pending | null => {
    const work = pending.get(id);
    if (!work) return null;
    pending.delete(id);
    if (work.timer !== null) clearTimeout(work.timer);
    work.timer = null;
    work.removeAbort();
    return work;
  };
  const fail = (id: string, code: string) => {
    const work = remove(id);
    if (!work) return;
    if (!work.subscribed) work.reject(new Error(code));
    else {
      try { work.onError?.(code); } catch { /* Error callbacks cannot retain a subscription. */ }
    }
  };
  const disconnect = (code: string) => {
    const previous = port;
    port = null;
    if (previous) {
      previous.onmessage = null;
      previous.onmessageerror = null;
      previous.close();
    }
    for (const id of [...pending.keys()]) fail(id, code);
  };
  const send = (value: JsonValue): boolean => {
    if (!port) return false;
    try { port.postMessage(encodeData(value)); return true; }
    catch { disconnect('app:disconnected'); return false; }
  };
  const cancel = (id: string, code: string) => {
    const work = pending.get(id);
    if (!work) return;
    if (work.sent) send({ v: 1, type: work.onValue ? 'unsubscribe' : 'cancel', id });
    fail(id, code);
  };
  const read = (event: MessageEvent, source: MessagePort) => {
    if (closed || source !== port) return;
    try {
      if (event.ports.length) throw new Error('app:invalid-message');
      const message = objectData(decodeData(event.data));
      if (message.v !== 1 || typeof message.id !== 'string' || !ID.test(message.id)) throw new Error('app:invalid-message');
      if (message.type === 'reply') exactKeys(message, ['v', 'type', 'id', 'value']);
      else if (message.type === 'subscribed') exactKeys(message, ['v', 'type', 'id']);
      else if (message.type === 'refusal') {
        exactKeys(message, ['v', 'type', 'id', 'code']);
        if (typeof message.code !== 'string' || !CODE.test(message.code)) throw new Error('app:invalid-message');
      } else if (message.type === 'event') {
        exactKeys(message, ['v', 'type', 'id', 'index', 'value']);
        if (typeof message.index !== 'number' || !Number.isSafeInteger(message.index) || message.index < 0) {
          throw new Error('app:invalid-message');
        }
      } else throw new Error('app:unknown-operation');
      const work = pending.get(message.id);
      if (!work) return;
      if (!work.sent) throw new Error('app:invalid-message');
      if (message.type === 'refusal') {
        fail(message.id, message.code as string);
      } else if (message.type === 'reply') {
        if (work.onValue) throw new Error('app:invalid-message');
        remove(message.id)?.resolve(message.value);
      } else if (message.type === 'subscribed') {
        if (!work.onValue || work.subscribed) throw new Error('app:invalid-message');
        work.subscribed = true;
        if (work.timer !== null) clearTimeout(work.timer);
        work.timer = null;
        work.resolve(null);
      } else {
        if (!work.onValue || !work.subscribed || message.index !== work.nextEvent || work.nextEvent >= Number.MAX_SAFE_INTEGER) {
          throw new Error('app:invalid-message');
        }
        work.nextEvent++;
        try { work.onValue(message.value); }
        catch { cancel(message.id, 'app:consumer-failed'); return; }
        if (pending.get(message.id) === work) send({ v: 1, type: 'ack', id: message.id, index: message.index });
      }
    } catch {
      for (const transferred of event.ports) transferred.close();
      disconnect('app:invalid-message');
    }
  };
  const hello = () => {
    if (closed) return;
    try { window.parent.postMessage({ channel: RPC_CHANNEL, type: 'hello', pluginId }, shellOrigin); }
    catch { disconnect('app:disconnected'); }
  };
  const connect = (event: MessageEvent) => {
    if (closed || event.source !== window.parent || event.origin !== shellOrigin) return;
    try {
      const message = objectData(decodeData(encodeData(event.data)));
      if (message.channel !== RPC_CHANNEL || message.pluginId !== pluginId) return;
      exactKeys(message, ['channel', 'type', 'pluginId']);
      if (message.type === 'hello-request' && event.ports.length === 0) { hello(); return; }
      if (message.type !== 'connect' || event.ports.length !== 1) throw new Error('app:invalid-message');
      if (port) disconnect('app:reconnected');
      const connected = event.ports[0];
      port = connected;
      connected.onmessage = incoming => read(incoming, connected);
      connected.onmessageerror = () => {
        if (port === connected) disconnect('app:invalid-message');
      };
      connected.start();
      for (const work of pending.values()) {
        if (work.sent) throw new Error('app:invalid-message');
        work.sent = true;
        connected.postMessage(work.message);
      }
    } catch {
      for (const transferred of event.ports) transferred.close();
      disconnect('app:invalid-message');
    }
  };

  const request = (type: 'call' | 'subscribe', service: string, operation: string, params: JsonValue,
    onValue: ((value: JsonValue) => void) | null, callOptions: SubscriptionOptions = {}) => {
    const id = serial < Number.MAX_SAFE_INTEGER ? String(++serial) : '';
    const promise = new Promise<JsonValue>((resolve, reject) => {
      if (closed) { reject(new Error('app:disposed')); return; }
      if (!id) { reject(new Error('app:id-exhausted')); return; }
      if (callOptions.signal?.aborted) { reject(new Error('app:aborted')); return; }
      if (pending.size >= MAX_RPC_PENDING) { reject(new Error('app:busy')); return; }
      if (typeof service !== 'string' || !NAME.test(service) || typeof operation !== 'string' || !NAME.test(operation)
        || (type === 'subscribe' && typeof onValue !== 'function')
        || (callOptions.onError !== undefined && typeof callOptions.onError !== 'function')) {
        reject(new Error('app:invalid-message'));
        return;
      }
      let message: string;
      try { message = encodeData({ v: 1, type, id, service, operation, params }); }
      catch { reject(new Error('app:invalid-data')); return; }
      const aborted = () => cancel(id, 'app:aborted');
      const work: Pending = {
        resolve, reject, onValue, onError: callOptions.onError ?? null, timer: null,
        removeAbort: () => callOptions.signal?.removeEventListener('abort', aborted),
        subscribed: false, sent: false, message, nextEvent: 0,
      };
      pending.set(id, work);
      work.timer = setTimeout(() => cancel(id, 'app:deadline'), RPC_DEADLINE_MS);
      callOptions.signal?.addEventListener('abort', aborted, { once: true });
      if (callOptions.signal?.aborted) { aborted(); return; }
      if (port) {
        work.sent = true;
        try { port.postMessage(message); }
        catch { disconnect('app:disconnected'); }
      }
    });
    const dispose = () => cancel(id, 'app:disposed');
    return { promise, dispose };
  };
  const dispose = () => {
    if (closed) return;
    closed = true;
    for (const [id, work] of pending) {
      if (work.sent) send({ v: 1, type: work.onValue ? 'unsubscribe' : 'cancel', id });
    }
    disconnect('app:disposed');
    window.removeEventListener('message', connect);
    window.removeEventListener('pagehide', dispose);
    options.signal?.removeEventListener('abort', dispose);
  };
  window.addEventListener('message', connect);
  window.addEventListener('pagehide', dispose, { once: true });
  options.signal?.addEventListener('abort', dispose, { once: true });
  if (options.signal?.aborted) dispose();
  else hello();
  return Object.freeze({
    call: (service: string, method: string, params: JsonValue, callOptions?: CallOptions) =>
      request('call', service, method, params, null, callOptions).promise,
    subscribe: async (service: string, topic: string, params: JsonValue, onValue: (value: JsonValue) => void,
      callOptions?: SubscriptionOptions): Promise<Dispose> => {
      const work = request('subscribe', service, topic, params, onValue, callOptions);
      await work.promise;
      return work.dispose;
    },
    dispose,
  });
}
