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
    unavailable: "Browser witness not enabled",
    undetermined: "An extension of this browser's retained head has not been established.",
  };
  return reasons[observation.reason];
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
  const witness = document.createElement("aside");
  witness.className = "owner-witness";
  witness.setAttribute("aria-label", "Browser head witness");
  witness.setAttribute("role", "status");
  witness.title = "Browser witness not enabled";
  witness.setAttribute("aria-label", witness.title);
  const pane = document.createElement("section");
  pane.className = "owner-pane";
  pane.setAttribute("aria-live", "polite");
  root.replaceChildren(witness, pane);

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
    witness.title = "Checking browser witness";
    witness.setAttribute("aria-label", witness.title);
    Promise.resolve().then(() => modules.witness.observeVisit(signal)).catch((): WitnessObservation => ({
      state: "alarm", reason: "unavailable",
    })).then(observation => {
      if (signal.aborted || lifetime.signal.aborted) return;
      witness.dataset.state = observation.state === "alarm" && observation.reason === "unavailable"
        ? "disabled" : observation.state;
      witness.setAttribute("role", observation.state === "alarm" && observation.reason !== "unavailable" ? "alert" : "status");
      witness.title = witnessText(observation);
      witness.setAttribute("aria-label", witness.title);
    });
  }

  async function show(route: OwnerRoute): Promise<void> {
    stopPane();
    paneLifetime = new AbortController();
    const signal = paneLifetime.signal;
    const routeHost = document.createElement("div");
    pane.replaceChildren(routeHost);
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

  window.addEventListener("message", receive, { signal: lifetime.signal });
  window.addEventListener("pageshow", event => {
    if (event.persisted && initialized) {
      observeVisit();
      // Sign-out is an action, not a view: a restored page never repeats it on whatever owner session the browser
      // holds now (one signed in after it). The shell is told the pane closed.
      if (currentRoute?.pane === "signout") post({ protocol: OWNER_PROTOCOL, kind: "closed", channel });
      else if (currentRoute) void show(currentRoute);
    }
  }, { signal: lifetime.signal });
  window.addEventListener("pagehide", () => { witnessLifetime.abort(); stopPane(); }, { signal: lifetime.signal });
  mounted.set(root, dispose);
  post({ protocol: OWNER_PROTOCOL, kind: "ready", channel });
  return dispose;
}
