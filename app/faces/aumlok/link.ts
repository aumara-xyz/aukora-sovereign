// SPDX-License-Identifier: AGPL-3.0-or-later
import { connectFace } from '../../core/index.js';
import type { FaceClient } from '../../core/index.js';

export type OwnerDestination = '/passkey' | '/phrase' | '/phrase/refresh';
export interface FaceHost {
  readonly root: HTMLElement;
  readonly client: FaceClient;
  readonly signal: AbortSignal;
  openOwner(route: OwnerDestination): void;
}

export function refusalText(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/(?:session-required|binding-required|session-expired|signin-required)/.test(message)) {
    return 'Sign in to view your binding.';
  }
  if (/(?:shell-required|frame-required|origin-mismatch)/.test(message)) return 'Open AUMLOK inside the app.';
  return 'Binding status unavailable. Try again shortly.';
}

export function openFace(id: string, title: string, mount: (host: FaceHost) => void | Promise<void>): () => void {
  const root = document.getElementById('face');
  if (!root || id !== 'aumlok') throw new Error('aumlok:unknown-face');
  const life = new AbortController();
  const status = document.createElement('p');
  status.className = 'connectionStatus';
  status.setAttribute('role', 'status');
  status.textContent = 'Connecting';
  root.setAttribute('aria-label', title);
  root.replaceChildren(status);
  let client: FaceClient | undefined;
  const dispose = () => {
    life.abort();
    client?.dispose();
    root.replaceChildren();
  };
  window.addEventListener('pagehide', dispose, { once: true, signal: life.signal });
  void (async () => {
    try {
      if (window.parent === window || !document.referrer) throw new Error('aumlok:shell-required');
      const shellOrigin = new URL(document.referrer).origin;
      if (shellOrigin === 'null') throw new Error('aumlok:shell-required');
      client = connectFace({ shellOrigin, pluginId: id, signal: life.signal });
      if (life.signal.aborted) { client.dispose(); return; }
      const openOwner = (route: OwnerDestination) => {
        if (life.signal.aborted || !['/passkey', '/phrase', '/phrase/refresh'].includes(route)) {
          throw new Error('aumlok:owner-route');
        }
        window.parent.postMessage({ protocol: 'aukora.aumlok-navigation.v1', route }, shellOrigin);
      };
      await mount({ root, client, signal: life.signal, openOwner });
    } catch (error) {
      if (!life.signal.aborted) {
        status.textContent = refusalText(error);
        root.replaceChildren(status);
      }
    }
  })();
  return dispose;
}
