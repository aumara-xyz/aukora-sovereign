// SPDX-License-Identifier: AGPL-3.0-or-later

import { exactKeys, objectData } from './data.js';
import type { JsonValue } from './data.js';
import type { Dispose, PluginStatus } from './organism.js';
import { refusal } from './rpc.js';
import type { RpcService } from './rpc.js';
import type { DataTransport } from './transport.js';

const COMMANDS = new Set(['session.create', 'session.open', 'session.list', 'chat.turn', 'model.cancel']);
const READS: Readonly<Record<string, Readonly<Record<string, string>>>> = Object.freeze({
  body: Object.freeze({
    'settings.general': 'general', 'settings.presets': 'presets',
  }),
  broker: Object.freeze({ 'model.report': 'models' }),
  network: Object.freeze({
    'contacts.list': 'messages', 'messages.list': 'messages', 'refusals.counts': 'messages',
  }),
  kira: Object.freeze({
    'memory.list': 'memory', 'memory.recall': 'memory',
    'documents.list': 'documents', 'documents.read': 'documents',
  }),
  aumlok: Object.freeze({ status: 'aumlok', identity: 'identity' }),
  'gate-aura': Object.freeze({ head: 'coherence' }),
});

function empty(params: JsonValue): void { exactKeys(objectData(params), []); }
function live(signal: AbortSignal): void {
  if (signal.aborted) throw new Error('app:disposed');
}

function poll(
  read: (signal: AbortSignal) => Promise<JsonValue>,
  emit: (value: JsonValue) => void,
  signal: AbortSignal,
): Dispose {
  live(signal);
  const controller = new AbortController();
  const pending = AbortSignal.any([signal, controller.signal]);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const run = async () => {
    try {
      const value = await read(pending);
      if (!pending.aborted) emit(value);
    } catch (error) {
      if (!pending.aborted) emit({ code: refusal(error) });
    } finally {
      if (!pending.aborted) timer = setTimeout(() => { void run(); }, 30_000);
    }
  };
  const stop = () => {
    controller.abort();
    if (timer !== undefined) clearTimeout(timer);
    signal.removeEventListener('abort', stop);
  };
  signal.addEventListener('abort', stop, { once: true });
  void run();
  return stop;
}

/** Each face's RPC grant is checked before these shared organ services are reached. */
export function createServices(
  transport: DataTransport,
  pluginStatuses: () => readonly PluginStatus[],
): ReadonlyMap<string, RpcService> {
  const services = new Map<string, RpcService>();
  for (const [service, methods] of Object.entries(READS)) {
    services.set(service, {
      async call(method, params, context) {
        live(context.signal);
        objectData(params);
        if (service === 'body') {
          if (COMMANDS.has(method) || method === 'health.snapshot') {
            return transport.call(method, params, context.signal);
          }
          if (method === 'settings.plugins') {
            empty(params);
            return { plugins: pluginStatuses().map(status => ({
              id: status.id, state: status.state, missing: [...status.missing], error: status.error,
            })) };
          }
        }
        const face = Object.hasOwn(methods, method) ? methods[method] : undefined;
        if (!face) throw new Error('app:capability-denied');
        // The frozen face-read route dispatches this legacy name to the broker's model report.
        if (service === 'broker' && method === 'model.report') {
          return transport.read(face, 'body', 'settings.models', params, context.signal);
        }
        return transport.read(face, service, method, params, context.signal);
      },
      subscribe(topic, params, emit, context) {
        live(context.signal);
        empty(params);
        if (service === 'body' && topic === 'session.event') {
          return transport.subscribe(topic, emit, context.signal);
        }
        if (service === 'body' && topic === 'health.snapshot') {
          return poll(signal => transport.call('health.snapshot', {}, signal), emit, context.signal);
        }
        if (service === 'gate-aura' && topic === 'head') {
          return poll(signal => transport.read('coherence', service, 'head', {}, signal), emit, context.signal);
        }
        throw new Error('app:capability-denied');
      },
    });
  }
  return services;
}
