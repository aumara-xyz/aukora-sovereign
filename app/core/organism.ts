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

const NAME = /^[a-z][a-z0-9._:-]{0,127}$/;
function checkName(name: string): void {
  if (typeof name !== 'string' || !NAME.test(name)) throw new Error('app:invalid-name');
}
interface ServiceSlot { value: unknown; owner: Lifetime | null }
interface PluginRecord {
  descriptor: PluginDescriptor;
  state: PluginState;
  error: string | null;
  lifetime: Lifetime | null;
  stopping: Promise<void> | null;
  removed: boolean;
}

class Lifetime {
  readonly controller = new AbortController();
  readonly bindings: ReadonlyMap<string, ServiceSlot>;
  closed = false;
  #effects: Dispose[] = [];
  #failed = false;
  #setup: Promise<void>;
  #settle!: () => void;

  constructor(bindings: ReadonlyMap<string, ServiceSlot>) {
    this.bindings = bindings;
    this.#setup = new Promise(resolve => { this.#settle = resolve; });
  }

  own(cleanup: Dispose): Dispose {
    if (typeof cleanup !== 'function') throw new Error('app:invalid-effect');
    let result: Promise<void> | null = null;
    const release = () => {
      if (!result) {
        result = Promise.resolve().then(cleanup).then(() => undefined);
        void result.catch(() => { this.#failed = true; });
      }
      return result;
    };
    this.#effects.push(release);
    if (this.closed) void release();
    return release;
  }

  setupFinished(): void { this.#settle(); }

  async release(): Promise<void> {
    const drain = async () => {
      while (this.#effects.length) {
        const effects = this.#effects.splice(0).reverse();
        const results = await Promise.allSettled(effects.map(effect => effect()));
        if (results.some(result => result.status === 'rejected')) this.#failed = true;
      }
    };
    // Release existing effects before joining asynchronous setup and late cleanup.
    await drain();
    await this.#setup;
    await drain();
    if (this.#failed) throw new Error('app:cleanup-failed');
  }
}

function freezeDescriptor(input: PluginDescriptor): PluginDescriptor {
  checkName(input.id);
  if (!Array.isArray(input.requires) || typeof input.setup !== 'function') throw new Error('app:invalid-plugin');
  for (const name of input.requires) checkName(name);
  const menu = input.menu;
  if (menu !== null && (!menu || typeof menu.title !== 'string' || !menu.title
    || typeof menu.section !== 'string' || !menu.section || !Number.isSafeInteger(menu.order))) {
    throw new Error('app:invalid-menu');
  }
  const surface = input.surface;
  if (surface !== null && (!surface || surface.kind !== 'frame' || typeof surface.entry !== 'string'
    || !surface.entry || /[\u0000-\u0020\u007f]/.test(surface.entry))) throw new Error('app:invalid-surface');
  return Object.freeze({
    id: input.id, requires: Object.freeze([...new Set(input.requires)]), setup: input.setup,
    menu: menu === null ? null : Object.freeze({ title: menu.title, section: menu.section, order: menu.order }),
    surface: surface === null ? null : Object.freeze({ kind: 'frame' as const, entry: surface.entry }),
  });
}

export class Organism {
  #services = new Map<string, ServiceSlot>();
  #plugins = new Map<string, PluginRecord>();
  #observers = new Set<(status: PluginStatus) => void>();
  #stops = new Set<Promise<void>>();
  #reconciling = false;
  #again = false;
  #closed = false;
  #disposal: Promise<void> | null = null;

  provide<T>(name: string, value: T): Dispose { return this.#register(name, value, null); }
  has(name: string): boolean { return this.#services.has(name); }

  install(descriptor: PluginDescriptor): PluginHandle {
    if (this.#closed) throw new Error('app:disposed');
    const frozen = freezeDescriptor(descriptor);
    if (this.#plugins.has(frozen.id)) throw new Error('app:duplicate-plugin');
    const record: PluginRecord = {
      descriptor: frozen, state: 'waiting', error: null, lifetime: null, stopping: null, removed: false,
    };
    this.#plugins.set(frozen.id, record);
    this.#notify(record);
    this.#reconcile();
    let removal: Promise<void> | null = null;
    return Object.freeze({ id: frozen.id, dispose: () => removal ??= this.#remove(record) });
  }

  status(id: string): PluginStatus | null {
    const record = this.#plugins.get(id);
    return record ? this.#snapshot(record) : null;
  }

  descriptors(): readonly PluginDescriptor[] {
    return Object.freeze([...this.#plugins.values()].map(record => record.descriptor));
  }

  observe(listener: (status: PluginStatus) => void): Dispose {
    if (this.#closed) throw new Error('app:disposed');
    if (typeof listener !== 'function') throw new Error('app:invalid-observer');
    this.#observers.add(listener);
    return () => { this.#observers.delete(listener); };
  }

  dispose(): Promise<void> {
    if (this.#disposal) return this.#disposal;
    this.#closed = true;
    this.#services.clear();
    const records = [...this.#plugins.values()];
    this.#disposal = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        ...records.map(record => this.#remove(record)), ...this.#stops,
      ]);
      this.#services.clear();
      this.#observers.clear();
      if (results.some(result => result.status === 'rejected')) throw new Error('app:cleanup-failed');
    });
    for (const record of records) record.removed = true;
    void this.#stop(records, 'disposed');
    return this.#disposal;
  }

  #snapshot(record: PluginRecord): PluginStatus {
    return Object.freeze({
      id: record.descriptor.id, state: record.state, error: record.error,
      missing: Object.freeze(record.descriptor.requires.filter(name => !this.#services.has(name))),
    });
  }

  #notify(record: PluginRecord): void {
    const snapshot = this.#snapshot(record);
    for (const observer of [...this.#observers]) {
      try { observer(snapshot); } catch { /* Observer failures do not interrupt resource release. */ }
    }
  }

  #register(name: string, value: unknown, owner: Lifetime | null): Dispose {
    checkName(name);
    if (this.#closed || owner?.closed) throw new Error('app:disposed');
    if (this.#services.has(name)) throw new Error('app:duplicate-service');
    const slot: ServiceSlot = { value, owner };
    this.#services.set(name, slot);
    const withdraw = async () => {
      if (this.#services.get(name) !== slot) return;
      this.#services.delete(name);
      const stopping = this.#stop([], 'waiting');
      this.#reconcile();
      await stopping;
    };
    const cleanup = owner ? owner.own(withdraw) : this.#once(withdraw);
    this.#reconcile();
    return cleanup;
  }

  #once(cleanup: Dispose): Dispose {
    let result: Promise<void> | null = null;
    return () => result ??= Promise.resolve().then(cleanup);
  }

  #invalid(record: PluginRecord): boolean {
    const lifetime = record.lifetime;
    return lifetime !== null && [...lifetime.bindings].some(([name, slot]) => this.#services.get(name) !== slot);
  }

  #stop(roots: readonly PluginRecord[], next: 'waiting' | 'failed' | 'disposed'): Promise<void> {
    const batch: { record: PluginRecord; lifetime: Lifetime; next: PluginState }[] = [];
    const joining = new Set<Promise<void>>();
    let complete!: () => void;
    let fail!: (error: Error) => void;
    const task = new Promise<void>((resolve, reject) => { complete = resolve; fail = reject; });
    const detach = (record: PluginRecord, target: PluginState) => {
      if (record.stopping) { joining.add(record.stopping); return; }
      const lifetime = record.lifetime;
      if (!lifetime) {
        if (target === 'disposed') { record.state = 'disposed'; this.#notify(record); }
        return;
      }
      record.lifetime = null;
      record.stopping = task;
      record.state = 'stopping';
      lifetime.closed = true;
      batch.push({ record, lifetime, next: target });
      for (const [name, slot] of this.#services) if (slot.owner === lifetime) this.#services.delete(name);
    };
    for (const record of roots) detach(record, next);
    let changed: boolean;
    do {
      changed = false;
      for (const record of this.#plugins.values()) {
        if (this.#invalid(record)) { detach(record, 'waiting'); changed = true; }
      }
    } while (changed);
    if (!batch.length) { complete(); return Promise.all(joining).then(() => undefined); }
    this.#stops.add(task);
    void task.catch(() => undefined);
    for (const item of batch) item.lifetime.controller.abort();
    for (const item of batch) this.#notify(item.record);
    void Promise.allSettled(batch.map(item => item.lifetime.release())).then(async results => {
      let failed = false;
      for (let i = 0; i < batch.length; i++) {
        const { record, next: target } = batch[i];
        const cleanupFailed = results[i].status === 'rejected';
        failed ||= cleanupFailed;
        record.stopping = null;
        if (cleanupFailed) record.error = 'app:cleanup-failed';
        record.state = record.removed ? 'disposed' : cleanupFailed ? 'failed' : target;
        this.#notify(record);
      }
      const joined = await Promise.allSettled(joining);
      failed ||= joined.some(result => result.status === 'rejected');
      this.#stops.delete(task);
      this.#reconcile();
      if (failed) fail(new Error('app:cleanup-failed')); else complete();
    });
    return task;
  }

  #remove(record: PluginRecord): Promise<void> {
    record.removed = true;
    return this.#stop([record], 'disposed').finally(() => {
      if (this.#plugins.get(record.descriptor.id) === record) this.#plugins.delete(record.descriptor.id);
    });
  }

  #reconcile(): void {
    if (this.#closed) return;
    if (this.#reconciling) { this.#again = true; return; }
    this.#reconciling = true;
    try {
      do {
        this.#again = false;
        for (const record of this.#plugins.values()) {
          if (record.state === 'waiting' && !record.removed && !record.stopping
            && record.descriptor.requires.every(name => this.#services.has(name))) this.#start(record);
        }
      } while (this.#again);
    } finally { this.#reconciling = false; }
  }

  #start(record: PluginRecord): void {
    const bindings = new Map(record.descriptor.requires.map(name => [name, this.#services.get(name)!]));
    const lifetime = new Lifetime(bindings);
    record.lifetime = lifetime;
    record.state = 'starting';
    record.error = null;
    const live = () => { if (lifetime.closed || this.#closed) throw new Error('app:disposed'); };
    const context: PluginContext = Object.freeze({
      id: record.descriptor.id, signal: lifetime.controller.signal,
      service: <T>(name: string): T => {
        live();
        if (!bindings.has(name)) throw new Error('app:capability-denied');
        const slot = bindings.get(name)!;
        if (this.#services.get(name) !== slot) throw new Error('app:service-unavailable');
        return slot.value as T;
      },
      provide: <T>(name: string, value: T) => { live(); return this.#register(name, value, lifetime); },
      effect: (cleanup: Dispose) => lifetime.own(cleanup),
      listen: (target: EventTarget, type: string, listener: EventListener, options?: AddEventListenerOptions) => {
        live();
        const capture = options?.capture === true;
        const guarded: EventListener = event => { if (!lifetime.closed) listener.call(target, event); };
        target.addEventListener(type, guarded, options ? { ...options } : undefined);
        return lifetime.own(() => target.removeEventListener(type, guarded, capture));
      },
      mount: (parent: Node, child: Node) => {
        live();
        if (child.parentNode !== null) throw new Error('app:already-mounted');
        parent.appendChild(child);
        return lifetime.own(() => { child.parentNode?.removeChild(child); });
      },
    });
    this.#notify(record);
    void Promise.resolve().then(async () => {
      if (lifetime.closed) return;
      const cleanup = await record.descriptor.setup(context);
      if (cleanup !== undefined) lifetime.own(cleanup);
      if (record.lifetime === lifetime) { record.state = 'active'; this.#notify(record); }
    }).catch(() => {
      if (record.lifetime === lifetime) {
        record.error = 'app:setup-failed';
        void this.#stop([record], 'failed');
      }
    }).finally(() => lifetime.setupFinished());
  }
}
