// SPDX-License-Identifier: AGPL-3.0-or-later
import { Organism, hostFace } from '../core/index.js';
import type { Dispose, PluginHandle, PluginStatus, RpcService } from '../core/index.js';
import { COPY, brandMarkUrl, fill, icon, ICONS } from '../design/index.js';
import { FACE_CATALOG } from '../faces/catalog.js';
import type { FaceManifest } from '../faces/catalog.js';
import { TriPane } from './layout.js';
import type { PaneState } from './layout.js';
import { APP_OPEN } from './weights.js';
import { OwnerFrame } from './owner-frame.js';
import type { OwnerNotice, OwnerRoute } from './owner-frame.js';

export interface ShellOptions {
  root: HTMLElement;
  services?: ReadonlyMap<string, RpcService>;
  ownerOrigin?: string;
  onOwnerNotice?: (notice: OwnerNotice) => void;
  prepareOwner?: () => Promise<string | void>;
  servicesPendingText?: string;
  phraseRoute?: () => '/phrase' | '/phrase/refresh';
  openApprovals?: () => void;
}
export interface ShellController {
  readonly organism: Organism;
  readonly layout: TriPane;
  openFace(id: string): void;
  openOwner(route: OwnerRoute, claim?: string): Promise<void>;
  readonly ownerBusy: boolean;
  setApprovalsPending(count: number): void;
  provideService(name: string, service: RpcService): Dispose;
  removeFace(id: string): Promise<void>;
  dispose(): Promise<void>;
}
interface FaceSlot {
  manifest: FaceManifest;
  element: HTMLElement;
  status: HTMLElement;
  button: HTMLButtonElement;
  handle: PluginHandle | null;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', text = ''): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text) element.textContent = text;
  return element;
}

/** A button that carries a line icon beside its text. */
function iconButton(iconName: string, text: string, click: () => void, className: string): HTMLButtonElement {
  const element = el('button', className);
  element.type = 'button';
  element.append(icon(iconName), el('span', 'entry-title', text));
  element.addEventListener('click', click);
  return element;
}

function laneHeading(iconName: string, title: string): HTMLElement {
  const heading = el('header', 'lane-heading');
  heading.append(icon(iconName), el('h2', '', title));
  return heading;
}

function setActive(element: HTMLElement, active: boolean): void {
  element.dataset.active = String(active);
  element.inert = !active;
  element.setAttribute('aria-hidden', String(!active));
}

export function mountShell(options: ShellOptions): ShellController {
  if (window.top !== window.self) throw new Error('shell:framed-shell');
  if (options.root.childNodes.length !== 0) throw new Error('shell:occupied-root');
  const organism = new Organism();
  const root = el('div', 'shell');
  const bar = el('header', 'shell-bar');
  const brand = el('span', 'shell-brand');
  const mark = el('img', 'brand-mark');
  mark.alt = '';
  mark.width = ICONS.brand.size;
  mark.height = ICONS.brand.size;
  mark.src = brandMarkUrl();
  brand.append(mark, el('strong', 'brand-name', COPY.brand as string));
  bar.append(brand);
  root.append(bar);
  options.root.append(root);
  const layout = new TriPane(root);
  const owner = options.ownerOrigin ? new OwnerFrame(options.ownerOrigin, options.onOwnerNotice, options.prepareOwner) : null;
  const openOwner = async (route: OwnerRoute, claim?: string): Promise<void> => {
    if (!owner || disposed) throw new Error('shell:owner-unavailable');
    try { await owner.open(route, claim); }
    catch (error) {
      options.onOwnerNotice?.({ kind: 'refusal', code: error instanceof Error ? error.message : 'shell:owner-unavailable' });
      throw error;
    }
  };
  const faceSlots = new Map<string, FaceSlot>();
  let selected = '';
  let selectedWorkspace = 'threads';
  let disposed = false;

  const syncControls = (state: PaneState): void => {
    root.dataset.phone = String(state.phone);
  };
  syncControls(layout.state);
  const unobserveLayout = layout.observe(syncControls);
  const workspaceHeading = laneHeading('threads', COPY.threadsHeading as string);
  const threadStack = el('div', 'face-stack');
  layout.lanes.threads.append(workspaceHeading, threadStack);
  const surfaceHeading = laneHeading('surface', COPY.laneTabs.surface);
  const surfacePrompt = el('p', 'surface-status', COPY.emptySurface as string);
  const surfaceStack = el('div', 'face-stack');
  layout.lanes.surface.append(surfaceHeading, surfacePrompt, surfaceStack);
  const menuContent = el('div', 'menu-content');
  layout.lanes.menu.append(laneHeading('apps', COPY.laneTabs.menu), menuContent);
  const menuGroups = new Map<string, HTMLElement>();
  for (const [section, title] of [
    ['workspace', COPY.threadsHeading], ['aukora_apps', COPY.appsHeading], ['system', COPY.systemHeading],
  ] as const) {
    const group = el('nav', 'menu-group');
    group.setAttribute('aria-label', title as string);
    group.append(el('h2', '', title as string));
    menuGroups.set(section, group);
    menuContent.append(group);
  }

  const openFace = (id: string): void => {
    const chosen = faceSlots.get(id);
    if (!chosen || disposed) throw new Error('shell:unknown-face');
    const workspace = chosen.manifest.menu.section === 'workspace';
    if (workspace) selectedWorkspace = id;
    else selected = id;
    for (const [key, slot] of faceSlots) {
      const active = slot.manifest.menu.section === 'workspace' ? key === selectedWorkspace : key === selected;
      setActive(slot.element, active);
      slot.button.setAttribute('aria-pressed', String(active));
    }
    surfacePrompt.hidden = selected !== '';
    if (!workspace) surfaceHeading.querySelector('h2')!.textContent = chosen.manifest.title;
    if (workspace) layout.reveal('threads');
    else {
      // Reveal a hidden desktop surface without replacing a visible lane's chosen width.
      if (!layout.phone && layout.weights[1] === 0) layout.setWeights(APP_OPEN);
      layout.showPhoneLane('surface');
    }
  };

  const refresh = (state: PluginStatus) => {
    const slot = faceSlots.get(state.id);
    if (!slot) return;
    slot.status.hidden = state.state === 'active';
    slot.status.textContent = state.state === 'waiting' ? options.servicesPendingText ?? fill(COPY.waitingFor as string, { names: state.missing.join(', ') })
      : state.state === 'failed' ? 'Unavailable' : state.state;
  };
  const unobserve = organism.observe(refresh);
  for (const [name, service] of options.services ?? []) organism.provide(name, service);
  const appRoot = new URL('../', import.meta.url);
  for (const manifest of [...FACE_CATALOG].sort((a, b) => a.menu.order - b.menu.order)) {
    const element = el('section', 'face-slot');
    element.setAttribute('aria-label', manifest.title);
    setActive(element, false);
    const status = el('p', 'surface-status');
    status.setAttribute('role', 'status');
    element.append(status);
    const item = iconButton(manifest.id, manifest.title, () => openFace(manifest.id), 'menu-entry');
    menuGroups.get(manifest.menu.section)!.append(item);
    if (manifest.menu.section === 'workspace') {
      threadStack.append(element);
    } else {
      surfaceStack.append(element);
    }
    const slot: FaceSlot = { manifest, element, status, button: item, handle: null };
    faceSlots.set(manifest.id, slot);
    const entry = new URL(manifest.surface, appRoot);
    if (manifest.surface !== `./faces/${manifest.id}/index.html` || entry.origin !== location.origin
      || entry.pathname !== appRoot.pathname + `faces/${manifest.id}/index.html`
      || entry.search || entry.hash) throw new Error('shell:face-entry');
    slot.handle = organism.install({
      id: manifest.id,
      requires: manifest.requires,
      menu: { title: manifest.title, ...manifest.menu },
      surface: { kind: 'frame', entry: `./faces/${manifest.id}/index.html` },
      setup(context) {
        const frame = el('iframe', 'face-frame');
        frame.title = manifest.title;
        frame.setAttribute('sandbox', 'allow-scripts');
        frame.referrerPolicy = 'origin';
        const services = new Map<string, RpcService>();
        for (const name of manifest.requires) services.set(name, context.service<RpcService>(name));
        context.effect(hostFace({ frame, pluginId: manifest.id, capabilities: manifest.capabilities, services, signal: context.signal }));
        frame.src = entry.href;
        element.append(frame);
        context.effect(() => frame.remove());
      },
    });
    const state = organism.status(manifest.id);
    if (state) refresh(state);
  }
  for (const [iconName, label, route] of [
    ['owner', 'Sign in', '/passkey'],
    ['aumlok', COPY.ownerPasskey, '/passkey'],
    ['identity', COPY.ownerPhrase, '/phrase'],
  ] as const) {
    const control = iconButton(iconName, label as string, () => {
      if (!owner) throw new Error('shell:owner-unavailable');
      void openOwner(route === '/phrase' ? options.phraseRoute?.() ?? route : route).catch(() => {});
    }, 'menu-entry owner-entry');
    control.disabled = !owner;
    if (!owner) control.title = COPY.ownerUnavailable as string;
    menuGroups.get('system')!.append(control);
  }
  const approvalsEntry = iconButton('owner', 'Approvals (0)', () => options.openApprovals?.(), 'menu-entry approvals-entry');
  approvalsEntry.disabled = true;
  menuGroups.get('system')!.append(approvalsEntry);
  const setApprovalsPending = (count: number): void => {
    if (!Number.isSafeInteger(count) || count < 0 || count > 10_000) throw new Error('shell:approval-response-invalid');
    approvalsEntry.querySelector('.entry-title')!.textContent = `Approvals (${count})`;
    approvalsEntry.disabled = !owner || !options.openApprovals || count === 0;
    approvalsEntry.dataset.pending = String(count > 0);
  };
  openFace('threads');
  return {
    organism, layout, openFace,
    openOwner,
    get ownerBusy() { return owner?.busy ?? false; },
    setApprovalsPending,
    provideService(name, service) { return organism.provide(name, service); },
    async removeFace(id) {
      const slot = faceSlots.get(id);
      if (!slot) throw new Error('shell:unknown-face');
      throw new Error('shell:locked-face');
    },
    async dispose() {
      if (disposed) return;
      disposed = true;
      owner?.dispose();
      unobserveLayout();
      await unobserve();
      await organism.dispose();
      layout.dispose();
      root.remove();
    },
  };
}
