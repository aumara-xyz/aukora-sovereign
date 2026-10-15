// SPDX-License-Identifier: AGPL-3.0-or-later

export type Dispose = () => void | Promise<void>;
export type PluginState = 'waiting' | 'starting' | 'active' | 'stopping' | 'failed' | 'disposed';
export interface PluginMenu { title: string; section: string; order: number }
export interface PluginSurface { kind: 'frame'; entry: string }
export interface PluginDescriptor {
  id: string;
  requires: readonly string[];
  menu: PluginMenu | null;
  surface: PluginSurface | null;
  setup(context: PluginContext): void | Dispose | Promise<void | Dispose>;
}
export interface PluginContext {
  readonly id: string;
  readonly signal: AbortSignal;
  service<T>(name: string): T;
  provide<T>(name: string, value: T): Dispose;
  effect(cleanup: Dispose): Dispose;
  listen(target: EventTarget, type: string, listener: EventListener, options?: AddEventListenerOptions): Dispose;
  mount(parent: Node, child: Node): Dispose;
}
export interface PluginStatus { id: string; state: PluginState; missing: readonly string[]; error: string | null }
export interface PluginHandle { readonly id: string; dispose(): Promise<void> }

interface ServiceSlot { value: unknown; owner: Scope | null }
interface PluginRecord {
  descriptor: PluginDescriptor;
  state: PluginState;
  error: string | null;
  scope: Scope | null;
  stopping: Promise<void> | null;
  removed: boolean;
}
const namePattern = /^[a-z][a-z0-9._:-]{0,127}$/;
function requireName(name: string): void {
  if (!namePattern.test(name)) throw new Error('app:invalid-name');
}

class Scope {
  controller = new AbortController();
  effects: Dispose[] = [];
  closed = false;
  released = false;
  ready: Promise<void>;
  complete: () => void = () => undefined;

  constructor() {
    this.ready = new Promise(resolve => { this.complete = resolve; });
  }

  add(cleanup: Dispose): Dispose {
    let pending: Promise<void> | null = null;
    const once = () => {
      if (!pending) pending = Promise.resolve().then(cleanup).then(() => undefined);
      return pending;
    };
    if (!this.released) this.effects.push(once);
    else void once().catch(() => undefined);
    return once;
  }

  async release(): Promise<void> {
    await this.ready;
    while (this.effects.length) {
      const cleanup = this.effects.pop()!;
      try { await cleanup(); } catch { /* Remaining owned effects still release. */ }
    }
    this.released = true;
  }
}

export class Organism {
  #services = new Map<string, ServiceSlot>();
  #plugins = new Map<string, PluginRecord>();
  #observers = new Set<(status: PluginStatus) => void>();
  #reconciling = false;
  #changed = false;
  #closed = false;

  provide<T>(name: string, value: T): Dispose {
    return this.#provide(name, value, null);
  }

  has(name: string): boolean { return this.#services.has(name); }

  install(descriptor: PluginDescriptor): PluginHandle {
    if (this.#closed) throw new Error('app:disposed');
    requireName(descriptor.id);
    descriptor.requires.forEach(requireName);
    if (this.#plugins.has(descriptor.id)) throw new Error('app:duplicate-plugin');
    const record: PluginRecord = {
      descriptor: Object.freeze({ ...descriptor, requires: Object.freeze([...new Set(descriptor.requires)]) }),
      state: 'waiting', error: null, scope: null, stopping: null, removed: false,
    };
    this.#plugins.set(descriptor.id, record);
    this.#reconcile();
    return { id: descriptor.id, dispose: () => this.#remove(record) };
  }

  status(id: string): PluginStatus | null {
    const record = this.#plugins.get(id);
    return record ? this.#status(record) : null;
  }

  descriptors(): readonly PluginDescriptor[] {
    return [...this.#plugins.values()].map(record => record.descriptor);
  }

  observe(listener: (status: PluginStatus) => void): Dispose {
    this.#observers.add(listener);
    return () => { this.#observers.delete(listener); };
  }

  async dispose(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await Promise.all([...this.#plugins.values()].map(record => this.#remove(record)));
    this.#services.clear();
    this.#observers.clear();
  }

  #status(record: PluginRecord): PluginStatus {
    return Object.freeze({
      id: record.descriptor.id, state: record.state, error: record.error,
      missing: record.descriptor.requires.filter(name => !this.#services.has(name)),
    });
  }

  #notify(record: PluginRecord): void {
    const status = this.#status(record);
    for (const observer of this.#observers) {
      try { observer(status); } catch { /* Observers cannot stop lifecycle cleanup. */ }
    }
  }

  #provide(name: string, value: unknown, owner: Scope | null): Dispose {
    requireName(name);
    if (this.#closed || owner?.closed) throw new Error('app:disposed');
    if (this.#services.has(name)) throw new Error('app:duplicate-service');
    const slot = { value, owner };
    this.#services.set(name, slot);
    this.#reconcile();
    const remove = async () => {
      if (this.#services.get(name) !== slot) return;
      this.#services.delete(name);
      const stops = this.#invalidate();
      await Promise.all(stops);
      this.#reconcile();
    };
    return owner ? owner.add(remove) : remove;
  }

  #invalidate(): Promise<void>[] {
    const stopped: Promise<void>[] = [];
    for (const record of this.#plugins.values()) {
      if (record.scope && record.descriptor.requires.some(name => !this.#services.has(name))) {
        stopped.push(this.#stop(record, 'waiting'));
      }
    }
    return stopped;
  }

  #stop(record: PluginRecord, next: 'waiting' | 'failed' | 'disposed'): Promise<void> {
    const scope = record.scope;
    if (!scope) return record.stopping ?? Promise.resolve();
    record.scope = null;
    scope.closed = true;
    scope.controller.abort();
    record.state = 'stopping';
    for (const [name, slot] of this.#services) {
      if (slot.owner === scope) this.#services.delete(name);
    }
    const dependencies = this.#invalidate();
    const stopping = Promise.all(dependencies).then(() => scope.release()).then(() => {
      record.stopping = null;
      record.state = record.removed ? 'disposed' : next;
      this.#notify(record);
      this.#reconcile();
    });
    record.stopping = stopping;
    this.#notify(record);
    return stopping;
  }

  async #remove(record: PluginRecord): Promise<void> {
    if (record.removed) { await record.stopping; return; }
    record.removed = true;
    this.#plugins.delete(record.descriptor.id);
    await this.#stop(record, 'disposed');
    record.state = 'disposed';
    this.#notify(record);
  }

  #reconcile(): void {
    if (this.#closed) return;
    if (this.#reconciling) { this.#changed = true; return; }
    this.#reconciling = true;
    do {
      this.#changed = false;
      for (const record of this.#plugins.values()) {
        if (record.state !== 'waiting' || record.stopping || record.removed) continue;
        if (record.descriptor.requires.every(name => this.#services.has(name))) this.#start(record);
      }
    } while (this.#changed);
    this.#reconciling = false;
  }

  #start(record: PluginRecord): void {
    const scope = new Scope();
    record.scope = scope;
    record.state = 'starting';
    this.#notify(record);
    const assertLive = () => { if (scope.closed) throw new Error('app:disposed'); };
    const context: PluginContext = Object.freeze({
      id: record.descriptor.id, signal: scope.controller.signal,
      service: <T>(name: string): T => {
        assertLive();
        if (!record.descriptor.requires.includes(name)) throw new Error('app:capability-denied');
        const slot = this.#services.get(name);
        if (!slot) throw new Error('app:service-unavailable');
        return slot.value as T;
      },
      provide: <T>(name: string, value: T) => this.#provide(name, value, scope),
      effect: (cleanup: Dispose) => scope.add(cleanup),
      listen: (target: EventTarget, type: string, listener: EventListener, options?: AddEventListenerOptions) => {
        assertLive();
        target.addEventListener(type, listener, options);
        return scope.add(() => target.removeEventListener(type, listener, options));
      },
      mount: (parent: Node, child: Node) => {
        assertLive();
        parent.appendChild(child);
        return scope.add(() => { child.parentNode?.removeChild(child); });
      },
    });
    const failed = () => {
      if (record.scope !== scope) return;
      record.error = 'app:setup-failed';
      void this.#stop(record, 'failed');
    };
    try {
      Promise.resolve(record.descriptor.setup(context)).then(cleanup => {
        if (typeof cleanup === 'function') scope.add(cleanup);
        if (record.scope !== scope) return;
        record.state = 'active';
        this.#notify(record);
      }, failed).finally(scope.complete);
    } catch { failed(); scope.complete(); }
  }
}
