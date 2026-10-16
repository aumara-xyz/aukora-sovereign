// SPDX-License-Identifier: AGPL-3.0-or-later
import { showServiceState } from "../../core/service-state.js";
import { mountHarp } from "./view.js";

const root = document.getElementById("face");
if (!root) throw new Error("zetaharp:missing-root");
const lifetime = new AbortController();
window.addEventListener("pagehide", () => {
  lifetime.abort();
  root.replaceChildren();
}, { once: true });

try {
  if (window.parent === window || !document.referrer) throw new Error("zetaharp:shell-required");
  const parent = new URL(document.referrer);
  if (parent.origin === "null" || !["https:", "http:"].includes(parent.protocol)) {
    throw new Error("zetaharp:shell-required");
  }
  mountHarp(root, lifetime.signal);
} catch (error) {
  lifetime.abort();
  const message = document.createElement("p");
  message.setAttribute("role", "alert");
  showServiceState(message, error);
  root.replaceChildren(message);
}
