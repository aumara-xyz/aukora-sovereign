// SPDX-License-Identifier: AGPL-3.0-or-later
import { refusalText } from './link.js';
import type { FaceHost } from './link.js';
import { parseStatusReply } from './status.js';
import { createAumlokView } from './view.js';

export const REFRESH_MS = 30_000;

export function mountAumlok(host: FaceHost): void {
  const { root, client, signal } = host;
  let sequence = 0;
  let pending = false;
  const view = createAumlokView(root, { openOwner: host.openOwner, refresh: () => void load() });
  async function load(): Promise<void> {
    if (pending || signal.aborted) return;
    pending = true;
    const current = ++sequence;
    view.refreshing(true);
    try {
      const reply = await client.call('aumlok', 'status', {}, { signal });
      const status = parseStatusReply(reply);
      if (!signal.aborted && current === sequence) view.show(status);
    } catch (error) {
      if (!signal.aborted && current === sequence) view.unavailable(refusalText(error));
    } finally {
      pending = false;
      if (!signal.aborted && current === sequence) view.refreshing(false);
    }
  }
  const timer = setInterval(() => { if (document.visibilityState === 'visible') void load(); }, REFRESH_MS);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') void load(); }, { signal });
  signal.addEventListener('abort', () => { clearInterval(timer); view.dispose(); }, { once: true });
  void load();
}
