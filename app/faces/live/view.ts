// SPDX-License-Identifier: AGPL-3.0-or-later
import { showServiceState } from "../../core/service-state.js";
import { icon } from "../../design/index.js";

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K, className: string, text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** The M1 face has no voice service or browser audio fallback. */
export function mountLive(root: HTMLElement, signal: AbortSignal): void {
  if (signal.aborted) throw new Error("live:disposed");

  const surface = element("div", "live-surface");
  const header = element("header", "live-header");
  const identity = element("div", "live-identity");
  identity.append(icon("live"), element("h1", "live-title", "Auma Live"));
  const badge = element("span", "live-badge", "Not yet");
  header.append(identity, badge);

  const stage = element("section", "live-stage");
  stage.setAttribute("aria-labelledby", "live-heading");
  const heading = element("h2", "live-heading", "A space for voice with Auma");
  heading.id = "live-heading";
  const status = element("p", "live-status");
  showServiceState(status, "live:voice-status-unavailable");
  status.id = "live-status";
  status.setAttribute("role", "status");
  const start = element("button", "live-start");
  start.type = "button";
  start.disabled = true;
  start.setAttribute("aria-describedby", "live-status");
  const orb = element("span", "live-orb");
  orb.setAttribute("aria-hidden", "true");
  orb.append(icon("live", "live-wave"));
  start.append(orb, element("span", "live-start-label", "Start Voice"));
  stage.append(heading, status, start);

  const footer = element("footer", "live-footer");
  const facts = element("dl", "live-facts");
  for (const [label, value] of [
    ["Voice", "Not installed in this release"],
    ["Microphone", "Not requested"],
    ["Conversation", "No voice session"],
  ]) {
    const row = element("div", "live-fact");
    row.append(element("dt", "", label), element("dd", "", value));
    facts.append(row);
  }
  footer.append(facts, element("p", "live-privacy", "This app does not record or send audio."));
  surface.append(header, stage, footer);
  root.replaceChildren(surface);
  signal.addEventListener("abort", () => surface.remove(), { once: true });
}
