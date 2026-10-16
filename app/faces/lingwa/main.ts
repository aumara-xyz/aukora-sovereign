// SPDX-License-Identifier: AGPL-3.0-or-later
import { showServiceState } from "../../core/service-state.js";
import { mountLingwa } from "./view.js";

const root = document.getElementById("face");
if (root) {
  const life = new AbortController();
  window.addEventListener("pagehide", () => { life.abort(); root.replaceChildren(); }, { once: true });
  try {
    if (window.parent === window || !document.referrer) throw new Error("lingwa:shell-required");
    const parent = new URL(document.referrer);
    if (parent.origin === "null" || !["https:", "http:"].includes(parent.protocol)) throw new Error("lingwa:shell-required");
    mountLingwa(root, life.signal);
  } catch (error) {
    life.abort();
    const message = document.createElement("p");
    message.setAttribute("role", "alert");
    showServiceState(message, error);
    root.replaceChildren(message);
  }
}
