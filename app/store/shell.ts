// SPDX-License-Identifier: AGPL-3.0-or-later
import { hostFace } from '../core/rpc.js';
import type { RpcService } from '../core/rpc.js';
import type { JsonValue } from '../core/data.js';
import type { Dispose, Organism, PluginHandle } from '../core/organism.js';
import type { TriPane } from '../shell/layout.js';
import { APP_OPEN } from '../shell/weights.js';
import { fail, parseManifest, sha256 } from './protocol.js';
import type { AppGrant } from './protocol.js';
import { installedSnapshot, StoreService } from './service.js';
import type { InstalledRecord, StoreBackend } from './service.js';

export interface StoreNavigation {
  /** Register one dynamic surface in the shell's normal selection and menu routing. */
  register(id: string, title: string, surface: HTMLElement, open: () => void): Dispose;
  select(id: string): void;
}
export interface AppCageLease {
  readonly app: string;
  readonly package_sha256: string;
  readonly receipt_sequence: number;
  readonly principal: string;
  readonly profile: 'user-app';
  readonly grants: readonly AppGrant[];
  /** Digest-addressed face response; the server enforces its no-network policy. */
  readonly face_url: string;
  call(operation: AppServiceOperation, params: JsonValue, signal: AbortSignal): Promise<JsonValue>;
  dispose(): void | Promise<void>;
}
/** A trusted launcher adapter. The signal cancels startup; the returned lease owns the app lifetime. */
export interface UserAppRuntime {
  openInstalled(record: InstalledRecord, signal: AbortSignal): Promise<AppCageLease>;
}
export interface StoreShellOptions {
  readonly organism: Organism;
  readonly layout: TriPane;
  readonly navigation: StoreNavigation;
  readonly backend: StoreBackend;
  readonly runtime?: UserAppRuntime;
}
export interface StoreAttachment {
  open(): void;
  dispose(): Promise<void>;
}
interface AppSlot { readonly digest: string; readonly manifestDigest: string; readonly receipt: number; readonly handle: PluginHandle }
export type AppServiceOperation = 'storage.read' | 'storage.write' | 'clock.now' | 'random.bytes';
const OPERATIONS: Readonly<Record<AppGrant, AppServiceOperation>> = Object.freeze({
  'app.clock': 'clock.now', 'app.random': 'random.bytes',
  'app.storage.read': 'storage.read', 'app.storage.write': 'storage.write',
});

function activePlugin(organism: Organism, id: string, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    let unobserve: Dispose | null = null;
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', aborted);
      void unobserve?.();
      if (error) reject(error); else resolve();
    };
    const aborted = () => finish(new Error('store:disposed'));
    const inspect = () => {
      const state = organism.status(id)?.state;
      if (state === 'active') finish();
      else if (!state || state === 'failed' || state === 'disposed') finish(new Error('store:app-start-failed'));
    };
    const timer = setTimeout(() => finish(new Error('store:app-start-deadline')), 30_000);
    unobserve = organism.observe(status => { if (status.id === id) inspect(); });
    signal.addEventListener('abort', aborted, { once: true });
    if (signal.aborted) aborted(); else inspect();
  });
}

function frame(title: string): HTMLIFrameElement {
  const result = document.createElement('iframe');
  result.className = 'face-frame';
  result.title = title;
  result.setAttribute('sandbox', 'allow-scripts');
  result.referrerPolicy = 'origin';
  result.setAttribute('allow', "camera 'none'; microphone 'none'; geolocation 'none'; payment 'none'; usb 'none'; serial 'none'; bluetooth 'none'; clipboard-read 'none'; clipboard-write 'none'; display-capture 'none'; publickey-credentials-get 'none'; publickey-credentials-create 'none'");
  result.setAttribute('credentialless', '');
  return result;
}

function faceEntry(lease: AppCageLease, expected: InstalledRecord, path: string): URL {
  let entry: URL;
  try { entry = new URL(lease.face_url, location.href); } catch { return fail('invalid-face-url'); }
  const prefix = `/apps/${expected.app}/${expected.package_sha256}/`;
  if (entry.origin !== location.origin || !['http:', 'https:'].includes(entry.protocol)
    || entry.pathname !== prefix + path || entry.search || entry.hash || entry.username || entry.password) fail('invalid-face-url');
  return entry;
}

/** Attach trusted controllers; the store and installed app code execute only in opaque-origin frames. */
export function attachStore(options: StoreShellOptions): StoreAttachment {
  if (window.top !== window.self) fail('shell-required');
  const { organism, layout, navigation, backend, runtime } = options;
  const life = new AbortController();
  const apps = new Map<string, AppSlot>();
  const opening = new Map<string, Promise<void>>();
  const handles = new Set<PluginHandle>();
  const surface = document.createElement('section');
  surface.className = 'face-slot';
  surface.setAttribute('aria-label', 'App store');
  let closed = false;
  const reveal = (id: string): void => {
    if (closed) fail('disposed');
    navigation.select(id);
    if (!layout.phone && layout.weights[1] === 0) layout.setWeights(APP_OPEN);
    layout.showPhoneLane('surface');
  };

  const openInstalled = async (source: InstalledRecord, callerSignal: AbortSignal): Promise<void> => {
    const signal = AbortSignal.any([callerSignal, life.signal]);
    if (closed || signal.aborted) fail('disposed');
    if (!runtime) fail('runtime-unavailable');
    const record = installedSnapshot(source);
    const manifest = parseManifest(record.manifest_bytes);
    const manifestDigest = await sha256(record.manifest_bytes);
    if (closed || signal.aborted) fail('disposed');
    const id = `user-app:${record.app}`;
    const active = apps.get(id);
    if (active?.digest === record.package_sha256 && active.manifestDigest === manifestDigest
      && active.receipt === record.receipt_sequence && organism.status(id)?.state === 'active') { reveal(id); return; }
    if (opening.has(id)) fail('app-opening');
    const task = (async () => {
      if (active) { await active.handle.dispose(); apps.delete(id); handles.delete(active.handle); }
      const lease = await runtime.openInstalled(record, signal);
      let transferred = false;
      try {
        if (closed || signal.aborted || lease.app !== record.app || lease.package_sha256 !== record.package_sha256
          || lease.receipt_sequence !== record.receipt_sequence || lease.principal !== `app:${record.app}`
          || lease.profile !== 'user-app' || !Array.isArray(lease.grants)
          || lease.grants.length !== manifest.body.grants.length
          || lease.grants.some((grant, index) => grant !== manifest.body.grants[index])) fail('cage-mismatch');
        const entry = faceEntry(lease, record, manifest.body.face.entry);
        const methods = manifest.body.grants.map(grant => OPERATIONS[grant]);
        const appSurface = document.createElement('section');
        appSurface.className = 'face-slot';
        appSurface.setAttribute('aria-label', manifest.body.name);
        const handle = organism.install({
          id, requires: [], menu: { title: manifest.body.name, section: 'aukora_apps', order: 1_000 },
          surface: null,
          setup(context) {
            context.effect(() => lease.dispose());
            context.effect(navigation.register(id, manifest.body.name, appSurface, () => reveal(id)));
            const appFrame = frame(manifest.body.name);
            const scoped: RpcService = {
              async call(method, params, callContext) {
                if (!methods.includes(method as AppServiceOperation)) fail('forbidden-grant');
                return lease.call(method as AppServiceOperation, params, callContext.signal);
              },
            };
            context.effect(hostFace({ frame: appFrame, pluginId: id, capabilities: {
              app: { methods, topics: [] },
            }, services: new Map([['app', scoped]]), signal: context.signal }));
            appFrame.src = entry.href;
            appSurface.append(appFrame);
            context.effect(() => appFrame.remove());
          },
        });
        transferred = true;
        handles.add(handle);
        apps.set(id, { digest: record.package_sha256, manifestDigest, receipt: record.receipt_sequence, handle });
        try {
          await activePlugin(organism, id, signal);
          if (closed || signal.aborted) fail('disposed');
          reveal(id);
        } catch (error) {
          await handle.dispose(); handles.delete(handle); apps.delete(id); throw error;
        }
      } finally { if (!transferred) await lease.dispose(); }
    })();
    opening.set(id, task);
    try { await task; } finally { opening.delete(id); }
  };

  const storeService = new StoreService(backend, { openInstalled });
  const storeEntry = new URL('./index.html', import.meta.url);
  if (storeEntry.origin !== location.origin || storeEntry.search || storeEntry.hash) fail('invalid-store-entry');
  const storeHandle = organism.install({
    id: 'store', requires: [], menu: { title: 'App store', section: 'system', order: 1_000 },
    surface: null,
    setup(context) {
      context.effect(() => storeService.dispose());
      context.effect(navigation.register('store', 'App store', surface, () => reveal('store')));
      const storeFrame = frame('App store');
      context.effect(hostFace({ frame: storeFrame, pluginId: 'store', capabilities: {
        store: { methods: ['catalog.search', 'install.propose', 'installed.list', 'installed.open'], topics: [] },
      }, services: new Map([['store', storeService]]), signal: context.signal }));
      storeFrame.src = storeEntry.href;
      surface.append(storeFrame);
      context.effect(() => storeFrame.remove());
    },
  });
  handles.add(storeHandle);
  let disposal: Promise<void> | null = null;
  const dispose = (): Promise<void> => disposal ??= (async () => {
    closed = true;
    life.abort();
    storeService.dispose();
    await Promise.allSettled([...opening.values()]);
    const results = await Promise.allSettled([...handles].map(handle => handle.dispose()));
    handles.clear(); apps.clear();
    if (results.some(result => result.status === 'rejected')) fail('cleanup-failed');
  })();
  window.addEventListener('pagehide', () => { void dispose().catch(() => undefined); }, { once: true, signal: life.signal });
  return Object.freeze({ open: () => reveal('store'), dispose });
}
