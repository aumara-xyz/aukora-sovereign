// SPDX-License-Identifier: AGPL-3.0-or-later
import { connectFace } from "../../core/index.js";
import type { FaceClient } from "../../core/index.js";
import { showServiceState } from "../../core/service-state.js";
import { FACE_CATALOG } from "../catalog.js";
import { mountHumanGraph } from "./view.js";

const ID = "humangraph";

const root = document.getElementById("face");
const manifest = FACE_CATALOG.find(face => face.id === ID);
if (root) {
  const heading = document.createElement("h1");
  heading.textContent = manifest?.title ?? "Human Graph";
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  root.append(heading, status);
  const life = new AbortController();
  let client: FaceClient | undefined;
  window.addEventListener("pagehide", () => {
    life.abort();
    client?.dispose();
    root.replaceChildren();
  }, { once: true });
  try {
    if (!manifest) throw new Error("app:unknown-face");
    // Only the shell may host a face: a face opened on its own, or from an opaque origin, does nothing.
    if (window.parent === window || !document.referrer) throw new Error("app:shell-required");
    const shellOrigin = new URL(document.referrer).origin;
    if (shellOrigin === "null") throw new Error("app:shell-required");
    client = connectFace({ shellOrigin, pluginId: ID, signal: life.signal });
    mountHumanGraph(root, client, life.signal);
  } catch (error) {
    showServiceState(status, error);
  }
}
