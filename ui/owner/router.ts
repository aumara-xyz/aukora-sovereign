// SPDX-License-Identifier: AGPL-3.0-or-later
import { OWNER_PROTOCOL, ownerRoute, shellOwnerMessage } from "./contracts.js";
import type { OwnerDisposer, OwnerModules, OwnerRoute, OwnerShellMessage, WitnessObservation } from "./contracts.js";

const mounted = new WeakMap<HTMLElement, OwnerDisposer>();

function configuredOrigin(value: string): string {
  const url = new URL(value);
  if (url.origin !== value || url.protocol !== "https:" || value === location.origin) {
    throw new Error("owner:invalid-shell-origin");
  }
  return value;
}

function channelId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
}

function witnessText(observation: WitnessObservation): string {
  if (observation.state === "first") return `First head retained in this browser (tree ${observation.treeSize}). Earlier history is unchecked.`;
  if (observation.state === "extension") return `History extends this browser's retained head (tree ${observation.treeSize}).`;
  const reasons = {
    rollback: "The presented head is older than this browser's retained head.",
    fork: "The presented history conflicts with this browser's retained head.",
    unavailable: "The browser witness could not inspect the retained or presented head.",
    undetermined: "An extension of this browser's retained head has not been established.",
  };
  return `${reasons[observation.reason]} This alarm is evidence; owner actions remain available.`;
}

export function mountOwner(root: HTMLElement, modules: OwnerModules): OwnerDisposer {
  mounted.get(root)?.();
  if (window.parent === window || window.top !== window.parent) {
    root.textContent = "Owner panes open only inside the app.";
    throw new Error("owner:frame-required");
  }
  const shellOrigin = configuredOrigin(modules.shellOrigin);
  const channel = channelId();
  const lifetime = new AbortController();
  let paneLifetime = new AbortController();
  let witnessLifetime = new AbortController();
  let paneDispose: OwnerDisposer | undefined;
  let initialized = false;
  let currentRoute: OwnerRoute | undefined;
  const header = document.createElement("header");
  const title = document.createElement("h1");
  title.textContent = "Owner ceremony";
  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "Close";
  header.append(title, close);
  const witness = document.createElement("aside");
  witness.className = "owner-witness";
  witness.setAttribute("aria-label", "Browser head witness");
  witness.setAttribute("role", "status");
  witness.textContent = "Browser head witness is waiting for the app.";
  const pane = document.createElement("section");
  pane.className = "owner-pane";
  pane.setAttribute("aria-live", "polite");
  pane.textContent = "Waiting for the app's owner pane request.";
  root.replaceChildren(header, witness, pane);

  function post(message: OwnerShellMessage): void {
    if (!lifetime.signal.aborted) window.parent.postMessage(message, shellOrigin);
  }

  function refuse(code: string): void {
    post({ protocol: OWNER_PROTOCOL, kind: "refusal", channel, code });
  }

  function stopPane(): void {
    paneLifetime.abort();
    try { paneDispose?.(); } catch { refuse("owner:dispose-failed"); }
    paneDispose = undefined;
    pane.replaceChildren();
  }

  function observeVisit(): void {
    witnessLifetime.abort();
    witnessLifetime = new AbortController();
    const signal = witnessLifetime.signal;
    witness.dataset.state = "checking";
    witness.setAttribute("role", "status");
    witness.textContent = "Checking this browser's retained Aura head.";
    Promise.resolve().then(() => modules.witness.observeVisit(signal)).catch((): WitnessObservation => ({
      state: "alarm", reason: "unavailable",
    })).then(observation => {
      if (signal.aborted || lifetime.signal.aborted) return;
      witness.dataset.state = observation.state;
      witness.setAttribute("role", observation.state === "alarm" ? "alert" : "status");
      witness.textContent = witnessText(observation);
    });
  }

  async function show(route: OwnerRoute): Promise<void> {
    stopPane();
    paneLifetime = new AbortController();
    const signal = paneLifetime.signal;
    const routeHost = document.createElement("div");
    pane.replaceChildren(routeHost);
    title.textContent = route.pane === "approval" ? "Review proposal" : `${route.pane[0].toUpperCase()}${route.pane.slice(1)}`;
    const mount = modules.panes[route.pane];
    if (!mount) {
      routeHost.textContent = "This owner service is unavailable.";
      refuse("owner:pane-unavailable");
      return;
    }
    try {
      const cleanup = await mount({
        host: routeHost, route, signal, shellOrigin,
        complete() { if (!signal.aborted) post({ protocol: OWNER_PROTOCOL, kind: "complete", channel }); },
      });
      if (signal.aborted) cleanup();
      else paneDispose = cleanup;
    } catch {
      if (signal.aborted) return;
      routeHost.textContent = "The owner service could not complete this request.";
      refuse("owner:pane-unavailable");
    }
  }

  const receive = (event: MessageEvent): void => {
    if (event.source !== window.parent || event.origin !== shellOrigin) return;
    const message = shellOwnerMessage(event.data);
    if (!message || message.channel !== channel) { refuse("owner:invalid-message"); return; }
    if ((message.kind === "init") === initialized) { refuse("owner:invalid-phase"); return; }
    let route: OwnerRoute;
    try { route = ownerRoute(message.route); } catch { refuse("owner:unknown-route"); return; }
    if (!initialized) observeVisit();
    initialized = true;
    currentRoute = route;
    void show(route);
  };

  function dispose(): void {
    if (lifetime.signal.aborted) return;
    lifetime.abort();
    witnessLifetime.abort();
    stopPane();
    mounted.delete(root);
    root.replaceChildren();
  }

  close.addEventListener("click", () => {
    post({ protocol: OWNER_PROTOCOL, kind: "closed", channel });
    dispose();
  }, { signal: lifetime.signal });
  window.addEventListener("message", receive, { signal: lifetime.signal });
  window.addEventListener("pageshow", event => {
    if (event.persisted && initialized) {
      observeVisit();
      if (currentRoute) void show(currentRoute);
    }
  }, { signal: lifetime.signal });
  window.addEventListener("pagehide", () => { witnessLifetime.abort(); stopPane(); }, { signal: lifetime.signal });
  mounted.set(root, dispose);
  post({ protocol: OWNER_PROTOCOL, kind: "ready", channel });
  return dispose;
}
