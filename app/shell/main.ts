// SPDX-License-Identifier: AGPL-3.0-or-later
import { Organism, hostFace } from '../core/index.js';
import type { Dispose, PluginHandle, PluginStatus, RpcService } from '../core/index.js';
import { FACE_CATALOG } from '../faces/catalog.js';
import type { FaceManifest } from '../faces/catalog.js';
import { LANES, PANE_WEIGHTS, TriPane } from './layout.js';
import type { LaneId } from './layout.js';
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
  openOwner(route: OwnerRoute): void;
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

function button(text: string, click: () => void): HTMLButtonElement {
  const element = document.createElement('button');
  element.type = 'button';
  element.textContent = text;
  element.addEventListener('click', click);
  return element;
}

export function mountShell(options: ShellOptions): ShellController {
  if (window.top !== window.self) throw new Error('shell:framed-shell');
  if (options.root.childNodes.length !== 0) throw new Error('shell:occupied-root');
  const organism = new Organism();
  const root = document.createElement('div');
  root.className = 'shell';
  const bar = document.createElement('header');
  bar.className = 'shell-bar';
  const brand = document.createElement('strong');
  brand.className = 'shell-brand';
  brand.textContent = 'AUKORA SOVEREIGN';
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

  const choosePhone = (lane: LaneId) => {
    layout.showPhoneLane(lane);
    for (const [id, item] of phoneButtons) item.setAttribute('aria-pressed', String(id === lane));
  };
  const phone = document.createElement('nav');
  phone.className = 'phone-tabs';
  phone.setAttribute('aria-label', 'Workspace lanes');
  for (const lane of LANES) {
    const item = button(lane === 'surface' ? 'App' : lane === 'menu' ? 'Apps · System' : 'Threads', () => choosePhone(lane));
    phoneButtons.set(lane, item);
    phone.append(item);
  }
  const layoutLabel = document.createElement('label');
  layoutLabel.className = 'layout-label';
  layoutLabel.htmlFor = 'pane-composition';
  layoutLabel.textContent = 'Lanes';
  const picker = document.createElement('select');
  picker.className = 'layout-picker';
  picker.id = 'pane-composition';
  picker.setAttribute('aria-label', 'Lane thirds: Threads, App, Apps and System');
  for (const weights of PANE_WEIGHTS) {
    const option = document.createElement('option');
    option.value = weights.join('-');
    option.textContent = weights.join(' · ');
    picker.append(option);
  }
  picker.value = '1-1-1';
  picker.addEventListener('change', () => {
    const weights = PANE_WEIGHTS.find(value => value.join('-') === picker.value);
    if (weights) layout.setWeights(weights);
  });
  bar.append(layoutLabel, picker, phone);
  const leftHeading = document.createElement('nav');
  leftHeading.className = 'lane-heading';
  leftHeading.setAttribute('aria-label', 'Threads and sidebar');
  layout.lanes.threads.append(leftHeading);
  const surfacePrompt = document.createElement('p');
  surfacePrompt.className = 'surface-status';
  surfacePrompt.textContent = 'Choose an app or a System entry.';
  layout.lanes.surface.append(surfacePrompt);
  const menuGroups = new Map<string, HTMLElement>();
  for (const [section, title] of [['aukora_apps', 'AUKORA APPS'], ['system', 'SYSTEM']]) {
    const group = document.createElement('nav');
    group.className = 'menu-group';
    group.setAttribute('aria-label', title);
    const heading = document.createElement('h2');
    heading.textContent = title;
    group.append(heading);
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
      slot.element.hidden = !active;
      slot.element.inert = !active;
      slot.button.setAttribute('aria-pressed', String(active));
    }
    surfacePrompt.hidden = selected !== '';
    layout.reveal(workspace ? 'threads' : 'surface');
    picker.value = layout.weights.join('-');
    choosePhone(workspace ? 'threads' : 'surface');
  };

  const refresh = (state: PluginStatus) => {
    const slot = faceSlots.get(state.id);
    if (!slot) return;
    slot.status.hidden = state.state === 'active';
    slot.status.textContent = state.state === 'waiting' ? `Waiting for required services: ${state.missing.join(', ')}`
      : state.state === 'failed' ? `Unavailable · ${state.error ?? 'app:setup-failed'}` : state.state;
  };
  const unobserve = organism.observe(refresh);
  for (const [name, service] of options.services ?? []) organism.provide(name, service);
  const appRoot = new URL('../', import.meta.url);
  for (const manifest of [...FACE_CATALOG].sort((a, b) => a.menu.order - b.menu.order)) {
    const element = document.createElement('section');
    element.className = 'face-slot';
    element.setAttribute('aria-label', manifest.title);
    element.hidden = manifest.id !== selectedWorkspace;
    element.inert = element.hidden;
    const status = document.createElement('p');
    status.className = 'surface-status';
    status.setAttribute('role', 'status');
    element.append(status);
    const item = button(manifest.title, () => openFace(manifest.id));
    item.className = 'menu-entry';
    if (manifest.menu.section === 'workspace') {
      leftHeading.append(item);
      layout.lanes.threads.append(element);
    } else {
      menuGroups.get(manifest.menu.section)!.append(item);
      layout.lanes.surface.append(element);
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
        const frame = document.createElement('iframe');
        frame.className = 'face-frame';
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
  for (const [label, route] of [['Passkey', '/passkey'], ['Phrase', '/phrase']] as const) {
    const control = button(label, () => {
      if (!owner) throw new Error('shell:owner-unavailable');
      owner.open(route);
    });
    control.disabled = !owner;
    if (!owner) control.title = 'Owner origin is not configured in this release';
    bar.append(control);
  }
  openFace('threads');
  return {
    organism, layout, openFace,
    openOwner(route) {
      if (!owner || disposed) throw new Error('shell:owner-unavailable');
      owner.open(route);
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
      await unobserve();
      await organism.dispose();
      layout.dispose();
      root.remove();
    },
  };
}

