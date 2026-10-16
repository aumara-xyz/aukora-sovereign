// SPDX-License-Identifier: AGPL-3.0-or-later
import { Organism, hostFace } from '../core/index.js';
import type { Dispose, PluginHandle, PluginStatus, RpcService } from '../core/index.js';
import { COPY, brandMarkUrl, fill, icon, ICONS } from '../design/index.js';
import { FACE_CATALOG } from '../faces/catalog.js';
import type { FaceManifest } from '../faces/catalog.js';
import { TriPane } from './layout.js';
import type { PaneState } from './layout.js';
import { APP_OPEN, LANES, PANE_WEIGHTS } from './weights.js';
import type { LaneId } from './weights.js';
import { OwnerFrame } from './owner-frame.js';
import type { OwnerNotice, OwnerRoute } from './owner-frame.js';

export interface ShellOptions {
  root: HTMLElement;
  services?: ReadonlyMap<string, RpcService>;
  ownerOrigin?: string;
  onOwnerNotice?: (notice: OwnerNotice) => void;
}
export interface ShellController {
  readonly organism: Organism;
  readonly layout: TriPane;
  openFace(id: string): void;
  openOwner(route: OwnerRoute, claim?: string): void;
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

const PHONE_ICONS: Readonly<Record<LaneId, string>> = { threads: 'threads', surface: 'surface', menu: 'apps' };

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', text = ''): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text) element.textContent = text;
  return element;
}

function button(text: string, click: () => void, className = ''): HTMLButtonElement {
  const element = el('button', className, text);
  element.type = 'button';
  element.addEventListener('click', click);
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
  const owner = options.ownerOrigin ? new OwnerFrame(options.ownerOrigin, options.onOwnerNotice) : null;
  const faceSlots = new Map<string, FaceSlot>();
  const phoneButtons = new Map<LaneId, HTMLButtonElement>();
  let selected = '';
  let selectedWorkspace = 'threads';
  let disposed = false;

  const phone = el('nav', 'phone-tabs');
  phone.setAttribute('aria-label', COPY.phoneTabs as string);
  for (const lane of LANES) {
    const item = iconButton(PHONE_ICONS[lane], COPY.laneTabs[lane], () => layout.showPhoneLane(lane), 'phone-tab');
    phoneButtons.set(lane, item);
    phone.append(item);
  }
  const layoutLabel = el('label', 'layout-label', COPY.lanes as string);
  layoutLabel.htmlFor = 'pane-composition';
  const picker = el('select', 'layout-picker');
  picker.id = 'pane-composition';
  picker.setAttribute('aria-label', COPY.lanesPicker as string);
  for (const weights of PANE_WEIGHTS) {
    const option = el('option', '', weights.join(' · '));
    option.value = weights.join('-');
    picker.append(option);
  }
  picker.addEventListener('change', () => {
    const weights = PANE_WEIGHTS.find(value => value.join('-') === picker.value);
    if (weights) layout.setWeights(weights);
  });
  const syncControls = (state: PaneState): void => {
    root.dataset.phone = String(state.phone);
    picker.value = state.weights.join('-');
    for (const [lane, item] of phoneButtons) item.setAttribute('aria-pressed', String(lane === state.phoneLane));
  };
  syncControls(layout.state);
  const unobserveLayout = layout.observe(syncControls);
  bar.append(layoutLabel, picker, phone);

  const workspaceHeading = el('h2', 'lane-heading', COPY.threadsHeading as string);
  const workspaceTabs = el('nav', 'workspace-tabs');
  workspaceTabs.setAttribute('aria-label', COPY.threadsHeading as string);
  const threadStack = el('div', 'face-stack');
  layout.lanes.threads.append(workspaceHeading, workspaceTabs, threadStack);
  const surfacePrompt = el('p', 'surface-status', COPY.emptySurface as string);
  const surfaceStack = el('div', 'face-stack');
  layout.lanes.surface.append(surfacePrompt, surfaceStack);
  const menuGroups = new Map<string, HTMLElement>();
  for (const [section, title] of [['aukora_apps', COPY.appsHeading], ['system', COPY.systemHeading]] as const) {
    const group = el('nav', 'menu-group');
    group.setAttribute('aria-label', title as string);
    group.append(el('h2', '', title as string));
    menuGroups.set(section, group);
    layout.lanes.menu.append(group);
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
    slot.status.textContent = state.state === 'waiting' ? fill(COPY.waitingFor as string, { names: state.missing.join(', ') })
      : state.state === 'failed' ? fill(COPY.unavailable as string, { code: state.error ?? 'app:setup-failed' }) : state.state;
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
    if (manifest.menu.section === 'workspace') {
      workspaceTabs.append(item);
      threadStack.append(element);
    } else {
      menuGroups.get(manifest.menu.section)!.append(item);
      surfaceStack.append(element);
    }
    const slot: FaceSlot = { manifest, element, status, button: item, handle: null };
    faceSlots.set(manifest.id, slot);
    const entry = new URL(manifest.surface, appRoot);
    if (entry.origin !== location.origin || !entry.pathname.startsWith(appRoot.pathname + 'faces/')
      || entry.search || entry.hash) throw new Error('shell:face-entry');
    slot.handle = organism.install({
      id: manifest.id,
      requires: manifest.requires,
      menu: { title: manifest.title, ...manifest.menu },
      surface: { kind: 'frame', entry: manifest.surface },
      setup(context) {
        const frame = el('iframe', 'face-frame');
        frame.title = manifest.title;
        frame.setAttribute('sandbox', 'allow-scripts');
        frame.referrerPolicy = 'origin';
        const services = new Map<string, RpcService>();
        for (const name of manifest.requires) services.set(name, context.service<RpcService>(name));
        context.effect(hostFace({ frame, pluginId: manifest.id, capabilities: manifest.capabilities, services, signal: context.signal }));
        frame.src = entry.href;
        context.mount(element, frame);
      },
    });
    const state = organism.status(manifest.id);
    if (state) refresh(state);
  }
  for (const [label, route] of [[COPY.ownerPasskey, '/passkey'], [COPY.ownerPhrase, '/phrase']] as const) {
    const control = button(label as string, () => {
      if (!owner) throw new Error('shell:owner-unavailable');
      owner.open(route);
    }, 'owner-entry');
    control.disabled = !owner;
    if (!owner) control.title = COPY.ownerUnavailable as string;
    bar.append(control);
  }
  openFace('threads');
  return {
    organism, layout, openFace,
    openOwner(route, claim) {
      if (!owner || disposed) throw new Error('shell:owner-unavailable');
      owner.open(route, claim);
    },
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
