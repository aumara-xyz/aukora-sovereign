// SPDX-License-Identifier: AGPL-3.0-or-later
import { FACE_CATALOG } from "../catalog.js";
import { mountLive } from "./view.js";

const root = document.getElementById("face");
if (!root) throw new Error("live:missing-root");

const life = new AbortController();
window.addEventListener("pagehide", () => {
  life.abort();
  root.replaceChildren();
}, { once: true, signal: life.signal });

try {
  const face = FACE_CATALOG.find(item => item.id === "live");
  if (!face || face.organ !== "body") throw new Error("live:invalid-manifest");
  const grants = face.capabilities.body;
  // No voice operation is granted in this release; a changed grant needs a status reader.
  if (!grants || grants.methods.length !== 0 || grants.topics.length !== 0 ||
      Object.keys(face.capabilities).length !== 1) throw new Error("live:voice-status-unavailable");
  if (window.parent === window || !document.referrer) throw new Error("app:shell-required");
  const shell = new URL(document.referrer);
  if (shell.origin === "null" || !["http:", "https:"].includes(shell.protocol)) {
    throw new Error("app:shell-required");
  }
  mountLive(root, life.signal);
} catch (error) {
  root.replaceChildren();
  const title = document.createElement("h1");
  title.textContent = "Auma Live";
  const status = document.createElement("p");
  status.setAttribute("role", "alert");
  const code = error instanceof Error && /^[a-z][a-z0-9-]*:[a-z0-9-]+$/.test(error.message)
    ? error.message : "live:unavailable";
  status.textContent = `Unavailable · ${code}`;
  root.append(title, status);
}
