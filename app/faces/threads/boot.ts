// SPDX-License-Identifier: AGPL-3.0-or-later
// The one connection a face of this brick makes to the shell. The shell's origin is the referrer its frame was given, the
// face id selects the capability set the shell granted, and everything is released when the page goes away. A page
// opened outside the shell has no parent and refuses.
import { connectFace } from "../../core/index.js";
import type { FaceClient } from "../../core/index.js";
import { showServiceState } from "../../core/service-state.js";
import { FACE_CATALOG } from "../catalog.js";
import { COPY } from "./copy.js";
import { h } from "./dom.js";

export type Mount = (root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>) => void;

function shellOrigin(): string {
  try {
    if (window.parent !== window && document.referrer) {
      const origin = new URL(document.referrer).origin;
      if (origin !== "null") return origin;
    }
  } catch { /* An unreadable referrer is the same refusal as none. */ }
  throw new Error("app:shell-required");
}

export function boot(id: string, mount: Mount): void {
  const manifest = FACE_CATALOG.find(face => face.id === id);
  const root = document.getElementById("face");
  if (!manifest || !root) return;
  // The face asks only for what its manifest grants; the shell enforces the same list on every call.
  const grant = manifest.capabilities[manifest.organ];
  const granted: ReadonlySet<string> = new Set(grant ? grant.methods : []);
  const life = new AbortController();
  const status = h("p", { role: "status" }, COPY.connecting);
  root.append(h("h1", { class: "sr" }, manifest.title), status);
  let client: FaceClient | undefined;
  window.addEventListener("pagehide", () => {
    life.abort();
    client?.dispose();
    root.replaceChildren();
  }, { once: true, signal: life.signal });
  try {
    client = connectFace({ shellOrigin: shellOrigin(), pluginId: id, signal: life.signal });
    mount(root, client, life.signal, granted);
    status.remove();
  } catch (error) {
    showServiceState(status, error);
  }
}
