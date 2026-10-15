// SPDX-License-Identifier: AGPL-3.0-or-later
import type { JsonValue } from '../core/data.js';
import { decodeThemeRead } from './bytes.js';
import { THEME_TARGET } from './protocol.js';

export interface ThemeReader {
  read(body: { target: string }, signal: AbortSignal): Promise<JsonValue>;
}
export interface ThemeProjection {
  readonly state: ThemeState;
  refresh(): Promise<void>;
  dispose(): void;
}
export interface ThemeState {
  readonly state: 'loading' | 'available' | 'unavailable' | 'disposed';
  readonly accent: string | null;
  readonly sha256: string | null;
  readonly reason: string | null;
}
export interface ThemeProjectionOptions {
  readonly root: HTMLElement;
  readonly reader: ThemeReader;
  readonly signal?: AbortSignal;
  readonly onState?: (state: Readonly<ThemeState>) => void;
}
export const THEME_POLL_MS = 2_000;
export const THEME_READ_DEADLINE_MS = 5_000;

// These properties colour shell controls and decoration, never health or fingerprint data.
const PROPERTIES = ['--control-active', '--corner-left', '--corner-centre', '--corner-right'] as const;
const roots = new WeakSet<HTMLElement>();

/** Follows target reads. Neither proposal acceptance nor an outcome changes its CSS. */
export function projectTheme(options: ThemeProjectionOptions): ThemeProjection {
  const { root, reader } = options;
  if (roots.has(root)) throw new Error('theme:root-in-use');
  const saved = PROPERTIES.map(name => ({
    name, value: root.style.getPropertyValue(name), priority: root.style.getPropertyPriority(name),
  }));
  const savedAccent = root.getAttribute('data-auma-accent');
  const savedState = root.getAttribute('data-auma-theme-state');
  roots.add(root);
  let state: Readonly<ThemeState> = Object.freeze({ state: 'loading', accent: null, sha256: null, reason: null });
  let stopped = false;
  let controller: AbortController | null = null;
  let work: Promise<void> | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const publish = (next: ThemeState): void => {
    state = Object.freeze(next);
    root.setAttribute('data-auma-theme-state', next.state);
    if (next.accent === null) root.removeAttribute('data-auma-accent');
    else root.setAttribute('data-auma-accent', next.accent);
    try { options.onState?.(state); } catch { /* Observation does not control projection. */ }
  };
  const restore = (): void => {
    for (const item of saved) {
      if (item.value) root.style.setProperty(item.name, item.value, item.priority);
      else root.style.removeProperty(item.name);
    }
  };
  const read = async (): Promise<void> => {
    const pending = new AbortController();
    controller = pending;
    let deadline: ReturnType<typeof setTimeout> | null = null;
    const aborted = new Promise<never>((_resolve, reject) => {
      pending.signal.addEventListener('abort', () => reject(new Error('theme:read-cancelled')), { once: true });
    });
    const timeout = new Promise<never>((_resolve, reject) => {
      deadline = setTimeout(() => {
        reject(new Error('theme:read-deadline'));
        pending.abort();
      }, THEME_READ_DEADLINE_MS);
    });
    try {
      const current = await Promise.race([
        Promise.resolve().then(() => {
          if (pending.signal.aborted) throw new Error('theme:read-cancelled');
          return reader.read({ target: THEME_TARGET }, pending.signal);
        }).then(decodeThemeRead),
        timeout, aborted,
      ]);
      if (stopped || pending.signal.aborted) return;
      restore();
      if (current.theme.accent !== 'default') {
        for (const name of PROPERTIES) {
          root.style.setProperty(name, `${current.theme.accent}${name === '--control-active' ? '1F' : '66'}`);
        }
      }
      publish({ state: 'available', accent: current.theme.accent, sha256: current.sha256, reason: null });
    } catch (error) {
      if (stopped) return;
      restore();
      const message = error instanceof Error ? error.message : '';
      const reason = /^theme:[a-z-]+$/.test(message) ? message : 'theme:read-unavailable';
      publish({ state: 'unavailable', accent: null, sha256: null, reason });
    } finally {
      if (deadline !== null) clearTimeout(deadline);
      pending.abort();
      if (controller === pending) controller = null;
    }
  };
  const refresh = (): Promise<void> => {
    if (stopped) return Promise.reject(new Error('theme:disposed'));
    if (work) return work;
    if (timer !== null) clearTimeout(timer);
    timer = null;
    work = read().finally(() => {
      work = null;
      if (!stopped) timer = setTimeout(() => { void refresh(); }, THEME_POLL_MS);
    });
    return work;
  };
  const dispose = (): void => {
    if (stopped) return;
    stopped = true;
    if (timer !== null) clearTimeout(timer);
    controller?.abort();
    options.signal?.removeEventListener('abort', dispose);
    restore();
    publish({ state: 'disposed', accent: null, sha256: null, reason: null });
    for (const [name, value] of [['data-auma-accent', savedAccent], ['data-auma-theme-state', savedState]] as const) {
      if (value === null) root.removeAttribute(name);
      else root.setAttribute(name, value);
    }
    roots.delete(root);
  };
  const projection = { get state() { return state; }, refresh, dispose };
  if (options.signal?.aborted) dispose();
  else {
    options.signal?.addEventListener('abort', dispose, { once: true });
    publish({ state: 'loading', accent: null, sha256: null, reason: null });
    if (!stopped) void refresh();
  }
  return projection;
}
