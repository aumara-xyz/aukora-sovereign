// SPDX-License-Identifier: AGPL-3.0-or-later
// Reads the public binding status on load, on request and every half minute while the page is visible. A failed or
// malformed read replaces the picture with an explicit unavailable state; the last good status is never kept on screen
// behind a failure, so a stale "bound" cannot outlive the service that said it.
import { refusalText } from "./link.js";
import type { FaceHost } from "./link.js";
import { parseStatusReply } from "./status.js";
import { createAumlokView } from "./view.js";

export const REFRESH_MS = 30_000;

export function mountAumlok(host: FaceHost): void {
  const { root, client, signal } = host;
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.textContent = "Refresh";
  root.append(refresh);
  const view = createAumlokView(root);
  signal.addEventListener("abort", () => view.dispose(), { once: true });
  let reading = 0;
  const load = async () => {
    const mine = ++reading;
    refresh.disabled = true;
    try {
      const status = parseStatusReply(await client.call("aumlok", "status", {}, { signal }));
      if (!signal.aborted && mine === reading) view.show(status);
    } catch (error) {
      if (!signal.aborted && mine === reading) view.unavailable(refusalText(error));
    } finally {
      if (mine === reading) refresh.disabled = signal.aborted;
    }
  };
  refresh.addEventListener("click", () => void load(), { signal });
  const timer = setInterval(() => { if (document.visibilityState === "visible") void load(); }, REFRESH_MS);
  signal.addEventListener("abort", () => clearInterval(timer), { once: true });
  void load();
}
