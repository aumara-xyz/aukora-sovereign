// SPDX-License-Identifier: AGPL-3.0-or-later
// Media has no granted service, so it opens no channel: it only checks that the shell is its parent.
import { FACE_CATALOG } from "../catalog.js";
import { mountMedia } from "./view.js";

const ID = "media";

const root = document.getElementById("face");
const manifest = FACE_CATALOG.find(face => face.id === ID);
if (root) {
  const heading = document.createElement("h1");
  heading.textContent = manifest?.title ?? "Media";
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  root.append(heading, status);
  const life = new AbortController();
  window.addEventListener("pagehide", () => {
    life.abort();
    root.replaceChildren();
  }, { once: true });
  try {
    if (!manifest) throw new Error("app:unknown-face");
    // Only the shell may host a face: a face opened on its own, or from an opaque origin, does nothing.
    if (window.parent === window || !document.referrer) throw new Error("app:shell-required");
    if (new URL(document.referrer).origin === "null") throw new Error("app:shell-required");
    mountMedia(root, life.signal);
  } catch (error) {
    const code = error instanceof Error && /^[a-z][a-z0-9-]*:[a-z0-9-]+$/.test(error.message) ? error.message : "app:service-unavailable";
    status.textContent = `Unavailable · ${code}`;
  }
}
