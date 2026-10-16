// SPDX-License-Identifier: AGPL-3.0-or-later
import { connectFace } from "../../core/index.js";
import type { FaceClient } from "../../core/index.js";
import { FACE_CATALOG } from "../catalog.js";
import { showServiceState } from "../../core/service-state.js";
import { h } from "./dom.js";
import { mountMemory } from "./view.js";

const ID = "memory";

// The shell's origin is the referrer its frame was given; a page opened outside the shell has none.
function shellOrigin(): string {
  try {
    if (window.parent !== window && document.referrer) {
      const origin = new URL(document.referrer).origin;
      if (origin !== "null") return origin;
    }
  } catch { /* An unreadable referrer is the same refusal as none. */ }
  throw new Error("app:shell-required");
}

function start(): void {
  const manifest = FACE_CATALOG.find(face => face.id === ID);
  const root = document.getElementById("face");
  if (!manifest || !root) return;
  const life = new AbortController();
  const status = h("p", { role: "status" }, "Connecting");
  root.append(h("h1", {}, manifest.title), status);
  let client: FaceClient | undefined;
  window.addEventListener("pagehide", () => {
    life.abort();
    client?.dispose();
    root.replaceChildren();
  }, { once: true, signal: life.signal });
  try {
    client = connectFace({ shellOrigin: shellOrigin(), pluginId: ID, signal: life.signal });
    mountMemory(root, client, life.signal);
    status.remove();
  } catch (error) {
    showServiceState(status, error);
  }
}

start();
