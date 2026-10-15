// SPDX-License-Identifier: AGPL-3.0-or-later
// Reads the public card on load, on request, once a minute while visible, and when a contact code is about to lapse or has.
// A failed or malformed read replaces the card with an explicit unavailable state; the last good card is never kept on
// screen behind a failure.
import { refusalText } from "../aumlok/link.js";
import type { FaceHost } from "../aumlok/link.js";
import { parseCard } from "./card.js";
import { createIdentityView } from "./view.js";

export const RENEW_SECONDS = 5;
export const MIN_GAP_MS = 5_000;
export const REFRESH_MS = 60_000;

export function mountIdentity(host: FaceHost): void {
  const { root, client, signal } = host;
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.textContent = "Refresh";
  root.append(refresh);
  const view = createIdentityView(root);
  signal.addEventListener("abort", () => view.dispose(), { once: true });
  let reading = 0;
  let lastRead = 0;
  const load = async () => {
    const mine = ++reading;
    lastRead = Date.now();
    refresh.disabled = true;
    try {
      const card = parseCard(await client.call("aumlok", "identity", {}, { signal }));
      if (!signal.aborted && mine === reading) view.show(card, Date.now());
    } catch (error) {
      if (!signal.aborted && mine === reading) view.unavailable(refusalText(error));
    } finally {
      if (mine === reading) refresh.disabled = signal.aborted;
    }
  };
  refresh.addEventListener("click", () => void load(), { signal });
  const timer = setInterval(() => {
    const now = Date.now();
    const left = view.tick(now);
    const lapsing = left !== null && left <= RENEW_SECONDS;
    const idle = document.visibilityState === "visible" && now - lastRead >= REFRESH_MS;
    if ((lapsing || idle) && now - lastRead >= MIN_GAP_MS) void load();
  }, 1_000);
  signal.addEventListener("abort", () => clearInterval(timer), { once: true });
  void load();
}
