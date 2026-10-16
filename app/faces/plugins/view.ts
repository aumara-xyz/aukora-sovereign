// SPDX-License-Identifier: AGPL-3.0-or-later
// The Plugins screen. The registry card lists every plugin this release registers, grouped as the shell groups them, from
// the registry shipped with the release, so it is printed whether or not the shell answers. Only each plugin's state comes
// from the shell, and a failed read clears every running state. Nothing here installs, removes,
// starts, stops or updates a plugin.
import type { FaceManifest } from "../catalog.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { card, make, mark, note, plural } from "../general/kit.js";
import type { Tone } from "../general/kit.js";
import { join } from "./registry.js";
import type { PluginState, PluginStatus } from "./registry.js";

export interface PluginsView {
  show(live: readonly PluginStatus[]): void;
  unavailable(reason: unknown): void;
}

const SECTIONS = [
  { id: "workspace", title: "Workspace" },
  { id: "aukora_apps", title: "AUKORA APPS" },
  { id: "system", title: "SYSTEM" },
] as const;
const STATES: Record<PluginState, readonly [Tone, string]> = {
  active: ["ok", "Running"],
  starting: ["attention", "Starting"],
  waiting: ["attention", "Waiting"],
  stopping: ["attention", "Stopping"],
  failed: ["failed", "Failed to start"],
  disposed: ["attention", "Removed"],
};

interface RowParts {
  readonly state: HTMLElement;
  readonly detail: HTMLElement;
}

function setState(parts: RowParts, tone: Tone, label: string, detail: string): void {
  clearServiceState(parts.state);
  parts.state.dataset.tone = tone;
  parts.state.textContent = label;
  parts.detail.textContent = detail;
  parts.detail.hidden = detail === "";
}

/** "a", "a and b", "a, b and c". */
function andList(names: readonly string[]): string {
  return names.length < 2 ? names.join("") : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** What a plugin may ask for, read straight from its registered capability lists. */
function grants(manifest: FaceManifest): string {
  const sentences: string[] = [];
  for (const [organ, grant] of Object.entries(manifest.capabilities)) {
    const asks: string[] = [];
    if (grant.methods.length > 0) asks.push(`call ${andList(grant.methods)}`);
    if (grant.topics.length > 0) asks.push(`listen to ${andList(grant.topics)}`);
    if (asks.length > 0) sentences.push(`On ${organ} it may ${asks.join(" and ")}.`);
  }
  return sentences.length > 0 ? sentences.join(" ")
    : "It asks its organ for nothing yet: its service is not connected in this release.";
}

function entry(list: HTMLElement, manifest: FaceManifest): RowParts {
  const item = make("li", "entry");
  const head = make("div", "entry-head");
  const state = make("span", "state");
  head.append(make("strong", undefined, manifest.title), make("code", "mono", manifest.id), state);
  const detail = make("p", "entry-detail");
  const more = make("details", "entry-more");
  more.append(make("summary", undefined, "What it may ask for"), make("p", undefined, grants(manifest)));
  item.append(head, detail, more);
  list.append(item);
  return { state, detail };
}

export function createPluginsView(root: HTMLElement, catalog: readonly FaceManifest[]): PluginsView {
  const registry = card(root, "registry", "Registered in this release");
  const lead = note(registry.body, "", "lead");
  const parts = new Map<string, RowParts>();
  for (const section of SECTIONS) {
    const members = catalog.filter(manifest => manifest.menu.section === section.id)
      .sort((a, b) => a.menu.order - b.menu.order);
    if (members.length === 0) continue;
    const heading = make("h3", undefined, `${section.title} · ${members.length}`);
    const list = make("ul", "entries");
    registry.body.append(heading, list);
    for (const manifest of members) parts.set(manifest.id, entry(list, manifest));
  }
  note(registry.body, "Each plugin runs in its own sandboxed frame. The shell lets it make only the calls listed under it.");

  const strangers = card(root, "strangers", "Not in this release's registry");
  strangers.section.hidden = true;
  const store = card(root, "store", "App store");
  showServiceState(store.badge, "app:service-unavailable");

  const total = plural(catalog.length, "plugin is", "plugins are");
  mark(registry.badge, "unknown", "CHECKING");
  lead.textContent = `${total} registered in this release. Reading which of them the shell has started.`;
  for (const part of parts.values()) setState(part, "unknown", "Checking", "");

  return {
    show(live) {
      const joined = join(catalog, live);
      let running = 0;
      const broken = live.filter(plugin => plugin.state === "failed").length;
      for (const placed of joined.placed) {
        const part = parts.get(placed.manifest.id);
        if (!part) continue;
        if (placed.live === null) {
          setState(part, "unknown", "Not reported", "The shell did not report this plugin.");
          continue;
        }
        const [tone, label] = STATES[placed.live.state];
        if (placed.live.state === "active") running++;
        setState(part, tone, label, "");
        if (placed.live.state === "waiting") showServiceState(part.state, "app:service-unavailable");
      }
      const all = running === catalog.length;
      const extra = joined.strangers.length;
      const summary = all ? "ALL RUNNING" : `${running} OF ${catalog.length} RUNNING`;
      mark(registry.badge, broken > 0 ? "failed" : all && extra === 0 ? "ok" : "attention", extra > 0 ? `${summary} · ${extra} UNEXPECTED` : summary);
      lead.textContent = `${total} registered in this release. The shell reports ${running} running.${extra > 0
        ? ` It also reports ${plural(extra, "plugin", "plugins")} this release does not register.` : ""}`;
      strangers.body.replaceChildren();
      strangers.section.hidden = joined.strangers.length === 0;
      if (joined.strangers.length > 0) {
        mark(strangers.badge, joined.strangers.some(plugin => plugin.state === "failed") ? "failed" : "attention", "UNEXPECTED");
        note(strangers.body, "The shell reports these, but this release does not register them.", "lead");
        const list = make("ul", "entries");
        for (const stranger of joined.strangers) {
          const item = make("li", "entry");
          const head = make("div", "entry-head");
          const state = make("span", "state");
          const [tone, label] = STATES[stranger.state];
          state.dataset.tone = tone;
          state.textContent = label;
          if (stranger.state === "waiting") showServiceState(state, "app:service-unavailable");
          head.append(make("code", "mono", stranger.id), state);
          item.append(head);
          list.append(item);
        }
        strangers.body.append(list);
      }
    },
    unavailable(reason) {
      showServiceState(registry.badge, reason);
      lead.textContent = "";
      for (const part of parts.values()) {
        setState(part, "unknown", "", "");
        showServiceState(part.state, reason);
      }
      strangers.section.hidden = true;
      strangers.body.replaceChildren();
    },
  };
}
