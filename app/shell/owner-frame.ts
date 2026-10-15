// SPDX-License-Identifier: AGPL-3.0-or-later
export type OwnerRoute = '/passkey' | '/phrase' | '/claim' | `/approval/${string}`;
export type OwnerNotice = { kind: 'closed' | 'complete' } | { kind: 'refusal'; code: string };
const protocol = 'aukora.owner.v1';

export function validOwnerRoute(route: string): route is OwnerRoute {
  return ['/passkey', '/phrase', '/claim'].includes(route) || /^\/approval\/[0-9a-f]{32}$/.test(route);
}

function trustedOrigin(value: string): string {
  const url = new URL(value);
  const local = url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !local) || url.origin === location.origin || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash) throw new Error('shell:owner-origin');
  return url.origin;
}

export class OwnerFrame {
  #origin: string;
  #dialog: HTMLDialogElement | null = null;
  #close: (() => void) | null = null;
  #notice: (notice: OwnerNotice) => void;

  constructor(origin: string, notice: (notice: OwnerNotice) => void = () => {}) {
    if (window.top !== window.self) throw new Error('shell:framed-shell');
    this.#origin = trustedOrigin(origin);
    this.#notice = notice;
  }

  open(route: OwnerRoute): void {
    if (!validOwnerRoute(route)) throw new Error('shell:unknown-owner-route');
    this.close();
    const dialog = document.createElement('dialog');
    dialog.className = 'owner-dialog';
    dialog.setAttribute('aria-label', 'Owner ceremony');
    const bar = document.createElement('div');
    bar.className = 'owner-toolbar';
    const title = document.createElement('strong');
    title.textContent = 'Owner ceremony';
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = 'Close';
    const frame = document.createElement('iframe');
    frame.className = 'owner-frame';
    frame.title = 'Owner ceremony · trusted origin';
    frame.referrerPolicy = 'origin';
    frame.allow = `publickey-credentials-get ${this.#origin}; publickey-credentials-create ${this.#origin}`;
    frame.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-forms');
    const url = new URL('index.html', `${this.#origin}/`);
    url.hash = route;
    frame.src = url.href;
    let channel: string | null = null;
    const onMessage = (event: MessageEvent) => {
      if (event.source !== frame.contentWindow || event.origin !== this.#origin) return;
      const data = event.data;
      if (!data || typeof data !== 'object' || Array.isArray(data) || data.protocol !== protocol) return;
      if (data.kind === 'ready') {
        if (channel !== null || typeof data.channel !== 'string' || !/^[0-9a-f]{32}$/.test(data.channel)
          || Object.keys(data).sort().join(',') !== 'channel,kind,protocol') return;
        channel = data.channel;
        frame.contentWindow?.postMessage({ protocol, kind: 'init', channel, route }, this.#origin);
      } else if (data.channel === channel && channel !== null) {
        if ((data.kind === 'complete' || data.kind === 'closed')
          && Object.keys(data).sort().join(',') === 'channel,kind,protocol') {
          this.close();
          this.#notice({ kind: data.kind });
        } else if (data.kind === 'refusal' && typeof data.code === 'string'
          && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(data.code)
          && Object.keys(data).sort().join(',') === 'channel,code,kind,protocol') {
          this.#notice({ kind: 'refusal', code: data.code });
        }
      }
    };
    const dismiss = () => { this.close(); this.#notice({ kind: 'closed' }); };
    close.addEventListener('click', dismiss);
    dialog.addEventListener('cancel', dismiss);
    window.addEventListener('message', onMessage);
    bar.append(title, close);
    dialog.append(bar, frame);
    document.body.append(dialog);
    this.#dialog = dialog;
    this.#close = () => {
      window.removeEventListener('message', onMessage);
      close.removeEventListener('click', dismiss);
      dialog.removeEventListener('cancel', dismiss);
      dialog.close();
      dialog.remove();
    };
    dialog.showModal();
  }

  close(): void {
    const close = this.#close;
    this.#close = null;
    this.#dialog = null;
    close?.();
  }

  dispose(): void { this.close(); }
}
