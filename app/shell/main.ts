// SPDX-License-Identifier: AGPL-3.0-or-later
import { Organism, hostFace } from '../core/index.js';
import type { Dispose, PluginHandle, PluginStatus, RpcService } from '../core/index.js';
import { COPY, fill } from '../design/index.js';
import { FACE_CATALOG } from '../faces/catalog.js';
import type { FaceManifest } from '../faces/catalog.js';
import { TriPane } from './layout.js';
import menuData from '../design/spatial/menu.json' with { type: 'json' };
import { revealCentre } from './weights.js';
import { OwnerFrame } from './owner-frame.js';
import type { OwnerNotice, OwnerRoute } from './owner-frame.js';
import { createMenu, element, menuCard } from './menu.js';
import { ownerNavigation, threadNavigation } from './navigation.js';
import type { ThreadNavigation } from './navigation.js';

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
  button: HTMLButtonElement | null;
  frame: HTMLIFrameElement | null;
  handle: PluginHandle | null;
}

function active(element: HTMLElement, shown: boolean): void {
  element.dataset.active = String(shown);
  element.inert = !shown;
  element.setAttribute('aria-hidden', String(!shown));
}

export function mountShell(options: ShellOptions): ShellController {
  if (window.top !== window.self) throw new Error('shell:framed-shell');
  if (options.root.childNodes.length) throw new Error('shell:occupied-root');
  const life = new AbortController();
  const organism = new Organism();
  const root = element('div', 'shell');
  options.root.append(root);
  let disposed = false;
  let selected = '';
  let workspace = 'sidebar';
  let threadReady = false;
  let pendingThread: ThreadNavigation | null = null;
  const slots = new Map<string, FaceSlot>();
  const layout = new TriPane(root, () => openFace('sidebar'));
  const owner = options.ownerOrigin
    ? new OwnerFrame(options.ownerOrigin, options.onOwnerNotice, options.prepareOwner) : null;
  const openOwner = async (route: OwnerRoute, claim?: string): Promise<void> => {
    try {
      if (!owner || disposed) throw new Error('shell:owner-unavailable');
      await owner.open(route, claim);
    }
    catch (error) {
      options.onOwnerNotice?.({ kind: 'refusal', code: error instanceof Error ? error.message : 'shell:owner-unavailable' });
      throw error;
    }
  };

  const threadStack = element('div', 'threadStack');
  const listLayer = element('div', 'threadLayer');
  listLayer.dataset.threadLayer = 'list';
  const sidebarSlot = element('div');
  sidebarSlot.dataset.slot = 'sidebar';
  listLayer.append(sidebarSlot);
  const conversationLayer = element('div', 'threadLayer');
  conversationLayer.dataset.threadLayer = 'conversation';
  const conversationBody = element('div', 'threadConversationBody');
  const conversationSlot = element('div');
  conversationSlot.dataset.slot = 'main';
  conversationBody.append(conversationSlot);
  conversationLayer.append(conversationBody);
  threadStack.append(listLayer, conversationLayer);
  layout.lanes.threads.append(threadStack);

  const surfaceStack = element('div', 'surfaceStack');
  const surfaceEmpty = element('div', 'surfaceEmpty');
  surfaceEmpty.dataset.surfaceEmpty = '';
  surfaceEmpty.append(element('span', '', menuData.empty));
  const surfaceLayer = element('div', 'surfaceLayer');
  surfaceLayer.dataset.surfaceLayer = 'extension';
  surfaceStack.append(surfaceEmpty, surfaceLayer);
  layout.lanes.surface.append(surfaceStack);
  const menu = createMenu(life.signal);
  layout.lanes.menu.append(menu.element);

  function openFace(id: string): void {
    const slot = slots.get(id);
    if (!slot || disposed) throw new Error('shell:unknown-face');
    const isWorkspace = slot.manifest.menu.section === 'workspace';
    if (isWorkspace) workspace = id;
    else selected = id;
    const conversation = workspace === 'threads';
    threadStack.dataset.threadView = conversation ? 'conversation' : 'list';
    listLayer.hidden = conversation;
    listLayer.inert = conversation;
    conversationLayer.hidden = !conversation;
    conversationLayer.inert = !conversation;
    layout.conversation(conversation);
    surfaceStack.dataset.surfaceActive = selected;
    surfaceEmpty.hidden = selected !== '';
    for (const [key, value] of slots) {
      const shown = value.manifest.menu.section === 'workspace' ? key === workspace : key === selected;
      active(value.element, shown);
      value.button?.classList.toggle('menuItemActive', shown);
      value.button?.setAttribute('aria-pressed', String(shown));
      if (shown) value.button?.setAttribute('aria-current', 'page');
      else value.button?.removeAttribute('aria-current');
    }
    if (isWorkspace) layout.reveal('threads');
    else {
      if (!layout.phone && layout.weights[1] === 0) layout.setWeights(revealCentre(layout.weights));
      layout.showPhoneLane('surface');
    }
  }

  const deliverThread = () => {
    const target = slots.get('threads')?.frame?.contentWindow;
    if (!threadReady || !pendingThread || !target) return;
    // This frame has an opaque origin; the destination is the exact installed frame window.
    target.postMessage(pendingThread, '*');
    pendingThread = null;
  };

  const refresh = (status: PluginStatus) => {
    const slot = slots.get(status.id);
    if (!slot) return;
    slot.status.hidden = status.state === 'active';
    slot.status.textContent = status.state === 'waiting'
      ? options.servicesPendingText ?? fill(COPY.waitingFor as string, { names: status.missing.join(', ') })
      : status.state === 'failed' ? 'Unavailable' : status.state;
  };
  const unobserve = organism.observe(refresh);
  for (const [name, service] of options.services ?? []) organism.provide(name, service);
  const appRoot = new URL('../', import.meta.url);
  for (const manifest of [...FACE_CATALOG].sort((a, b) => a.menu.order - b.menu.order)) {
    const container = element('section', 'face-slot');
    container.setAttribute('aria-label', manifest.title);
    active(container, false);
    const status = element('p', 'surface-status');
    status.setAttribute('role', 'status');
    container.append(status);
    const card = manifest.menu.section === 'workspace' ? null
      : menu.add(manifest, () => openFace(manifest.id));
    if (manifest.id === 'sidebar') sidebarSlot.append(container);
    else if (manifest.id === 'threads') conversationSlot.append(container);
    else if (manifest.menu.section === 'workspace') throw new Error('shell:unknown-face');
    else surfaceLayer.append(container);
    const slot: FaceSlot = { manifest, element: container, status, button: card, frame: null, handle: null };
    slots.set(manifest.id, slot);
    const entry = new URL(manifest.surface, appRoot);
    if (manifest.surface !== `./faces/${manifest.id}/index.html` || entry.origin !== location.origin
      || entry.pathname !== `${appRoot.pathname}faces/${manifest.id}/index.html` || entry.search || entry.hash) {
      throw new Error('shell:face-entry');
    }
    slot.handle = organism.install({
      id: manifest.id, requires: manifest.requires,
      menu: { title: manifest.title, ...manifest.menu },
      surface: { kind: 'frame', entry: `./faces/${manifest.id}/index.html` },
      setup(context) {
        const frame = element('iframe', 'face-frame');
        frame.title = manifest.title;
        frame.setAttribute('sandbox', 'allow-scripts');
        frame.referrerPolicy = 'origin';
        slot.frame = frame;
        const services = new Map<string, RpcService>();
        for (const name of manifest.requires) services.set(name, context.service<RpcService>(name));
        context.effect(hostFace({ frame, pluginId: manifest.id, capabilities: manifest.capabilities, services, signal: context.signal }));
        const rejectNavigation = (error: unknown) => {
          const message = error instanceof Error ? error.message : '';
          const code = /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(message) ? message : 'app:invalid-message';
          status.textContent = `Navigation refused · ${code}`;
          status.hidden = false;
        };
        const navigate = (event: MessageEvent) => {
          if (disposed || context.signal.aborted || event.source !== frame.contentWindow || event.origin !== 'null') return;
          try {
            if (event.ports.length) throw new Error('app:invalid-message');
            if (manifest.id === 'aumlok') {
              const route = ownerNavigation(event.data);
              if (route) void openOwner(route === '/phrase' ? options.phraseRoute?.() ?? route : route).catch(rejectNavigation);
            } else if (manifest.id === 'sidebar' || manifest.id === 'threads') {
              const request = threadNavigation(event.data);
              if (!request) return;
              if (request.action === 'ready') {
                if (manifest.id !== 'threads') throw new Error('app:capability-denied');
                threadReady = true;
                deliverThread();
              } else if (manifest.id === 'sidebar') {
                pendingThread = request;
                openFace('threads');
                deliverThread();
              } else throw new Error('app:capability-denied');
            }
          } catch (error) {
            for (const port of event.ports) port.close();
            rejectNavigation(error);
          }
        };
        context.listen(window, 'message', navigate as EventListener);
        frame.src = entry.href;
        container.append(frame);
        context.effect(() => {
          if (slot.frame === frame) slot.frame = null;
          if (manifest.id === 'threads') { threadReady = false; pendingThread = null; }
          frame.remove();
        });
      },
    });
    const statusNow = organism.status(manifest.id);
    if (statusNow) refresh(statusNow);
  }

  const approvals = menuCard('Approvals', 'Waiting for approval status', () => options.openApprovals?.(), life.signal);
  approvals.button.classList.add('approvals-entry');
  approvals.button.disabled = true;
  menu.system.append(approvals.button);
  const setApprovalsPending = (count: number) => {
    if (!Number.isSafeInteger(count) || count < 0 || count > 10_000) throw new Error('shell:approval-response-invalid');
    approvals.subtitle.textContent = count === 1 ? '1 waiting for you' : `${count} waiting for you`;
    approvals.button.disabled = !owner || !options.openApprovals || count === 0;
    approvals.button.dataset.pending = String(count > 0);
  };
  openFace('sidebar');
  return {
    organism, layout, openFace, openOwner,
    get ownerBusy() { return owner?.busy ?? false; },
    setApprovalsPending,
    provideService(name, service) { return organism.provide(name, service); },
    async removeFace(id) {
      if (!slots.has(id)) throw new Error('shell:unknown-face');
      throw new Error('shell:locked-face');
    },
    async dispose() {
      if (disposed) return;
      disposed = true;
      life.abort();
      owner?.dispose();
      await unobserve();
      try { await organism.dispose(); }
      finally { layout.dispose(); slots.clear(); root.remove(); }
    },
  };
}
