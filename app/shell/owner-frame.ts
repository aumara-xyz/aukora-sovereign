// SPDX-License-Identifier: AGPL-3.0-or-later
import { COPY } from '../design/index.js';

export type OwnerRoute = '/passkey' | '/phrase' | '/phrase/refresh' | '/claim' | '/witness' | `/approval/${string}`;
export type OwnerNotice = { kind: 'closed' | 'complete'; route?: OwnerRoute } | { kind: 'refusal'; code: string };
const protocol = 'aukora.owner.v1';

export function validOwnerRoute(route: string): route is OwnerRoute {
  return ['/passkey', '/phrase', '/phrase/refresh', '/claim', '/witness'].includes(route) || /^\/approval\/[0-9a-f]{32}$/.test(route);
}

function trustedOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin === location.origin || url.username || url.password
    || url.pathname !== '/' || url.search || url.hash) throw new Error('shell:owner-origin');
  return url.origin;
}

export class OwnerFrame {
  #origin: string;
  #dialog: HTMLDialogElement | null = null;
  #close: (() => void) | null = null;
  #notice: (notice: OwnerNotice) => void;
  #prepare: () => Promise<string | void>;
  #generation = 0;
  #preparing: Promise<void> = Promise.resolve();
  #route: OwnerRoute | null = null;

  constructor(origin: string, notice: (notice: OwnerNotice) => void = () => {}, prepare: () => Promise<string | void> = async () => {}) {
    if (window.top !== window.self) throw new Error('shell:framed-shell');
    this.#origin = trustedOrigin(origin);
    this.#notice = notice;
    this.#prepare = prepare;
  }

  /** A claim token rides in the frame's fragment, which never reaches a server; only `/claim` carries one. */
  async open(route: OwnerRoute, claim = ''): Promise<void> {
    if (!validOwnerRoute(route)) throw new Error('shell:unknown-owner-route');
    if (claim && (route !== '/claim' || !/^[A-Za-z0-9_-]{43}$/.test(claim))) throw new Error('shell:claim-invalid');
    this.close();
    this.#route = route;
    const generation = this.#generation;
    const prepared = this.#preparing.then(() => {
      if (generation !== this.#generation) return;
      return this.#prepare();
    });
    this.#preparing = prepared.then(() => {}, () => {});
    let reference: string | void;
    try {
      reference = await prepared;
      if (reference !== undefined && !/^[0-9a-f]{64}$/.test(reference)) throw new Error('shell:handoff-refused');
    } catch (error) {
      if (generation === this.#generation) this.close();
      throw error;
    }
    if (generation !== this.#generation) return;
    const dialog = document.createElement('dialog');
    dialog.className = 'owner-dialog';
    dialog.setAttribute('aria-labelledby', 'owner-ceremony-title');
    const bar = document.createElement('div');
    bar.className = 'owner-toolbar';
    const title = document.createElement('strong');
    title.id = 'owner-ceremony-title';
    title.textContent = COPY.ownerTitle as string;
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = COPY.ownerClose as string;
    const frame = document.createElement('iframe');
    frame.className = 'owner-frame';
    frame.title = COPY.ownerFrame as string;
    frame.referrerPolicy = 'origin';
    frame.allow = `publickey-credentials-get ${this.#origin}; publickey-credentials-create ${this.#origin}`;
    frame.setAttribute('sandbox', 'allow-scripts allow-same-origin');
    // The public reference selects a rendezvous; only HttpOnly cookies and the verified passkey can complete it.
    const url = new URL(reference ? `/handoff-v1-${reference}` : '/', `${this.#origin}/`);
    if (claim) url.hash = `claim=${claim}`;
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
          this.#notice({ kind: data.kind, route });
        } else if (data.kind === 'refusal' && typeof data.code === 'string'
          && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(data.code)
          && Object.keys(data).sort().join(',') === 'channel,code,kind,protocol') {
          this.#notice({ kind: 'refusal', code: data.code });
        }
      }
    };
    const dismiss = () => { this.close(); this.#notice({ kind: 'closed', route }); };
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
    try { dialog.showModal(); frame.focus({ preventScroll: true }); }
    catch (error) { this.close(); throw error; }
  }

  close(): void {
    this.#generation++;
    this.#route = null;
    const close = this.#close;
    this.#close = null;
    this.#dialog = null;
    close?.();
  }

  get busy(): boolean { return this.#route !== null; }

  dispose(): void { this.close(); }
}
