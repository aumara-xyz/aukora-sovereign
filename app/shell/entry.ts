// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountShell } from './main.js';
import { ShellTransport } from '../core/transport.js';
import { createServices } from '../core/services.js';
import type { Dispose } from '../core/organism.js';
import { exactKeys, objectData } from '../core/data.js';

// The installer always serves the owner pages at `owner.` plus the shell's host (deploy/spawn/node_install.py).
function ownerOrigin(): string {
  return `${location.protocol}//owner.${location.host}`;
}

// A claim link opens the shell at `#claim=<token>`. The token leaves the address bar at once and goes only to the
// owner frame.
function takeClaim(): string {
  const fragment = location.hash;
  if (!fragment.startsWith('#claim=')) return '';
  history.replaceState(null, '', `${location.pathname}${location.search}`);
  return /^#claim=[A-Za-z0-9_-]{43}$/.test(fragment) ? fragment.slice(7) : '';
}

const root = document.getElementById('aukora-shell');
if (root) {
  try {
    const claim = takeClaim();
    const lifetime = new AbortController();
    const handoff = new ShellTransport();
    let transport: ShellTransport | null = null;
    let services: Dispose[] = [];
    let connecting: Promise<void> | null = null;
    const notice = document.createElement('p');
    notice.className = 'shell-connection';
    notice.setAttribute('role', 'status');
    notice.hidden = true;
    const show = (error: unknown) => {
      notice.textContent = error instanceof Error ? error.message : 'shell:connection-failed';
      notice.hidden = false;
    };
    const exchange = async (step: 'prepare' | 'complete') => {
      const reply = objectData(await handoff.request(`/api/data/handoff/${step}`, {}, lifetime.signal));
      if (step === 'prepare') {
        exactKeys(reply, ['reference']);
        if (typeof reply.reference !== 'string' || !/^[0-9a-f]{64}$/.test(reply.reference)) throw new Error('shell:handoff-refused');
        return reply.reference;
      }
      exactKeys(reply, ['ok']);
      if (reply.ok !== true) throw new Error('shell:handoff-refused');
    };
    const activate = (): Promise<void> => {
      if (connecting) return connecting;
      connecting = (async () => {
        const next = new ShellTransport();
        try {
          await next.call('session.list', { thread_id: null, include_archived: false, before: null, limit: 1 }, lifetime.signal);
          transport?.dispose();
          await Promise.all(services.map(dispose => dispose()));
          services = [];
          transport = next;
          const current = () => shell.organism.descriptors().flatMap(plugin => {
            const status = shell.organism.status(plugin.id);
            return status ? [status] : [];
          });
          for (const [name, service] of createServices(next, current)) services.push(shell.provideService(name, service));
          notice.hidden = true;
        } catch (error) { next.dispose(); throw error; }
      })().finally(() => { connecting = null; });
      return connecting;
    };
    const shell = mountShell({
      root, ownerOrigin: ownerOrigin(), servicesPendingText: 'Sign in',
      prepareOwner: () => exchange('prepare'),
      onOwnerNotice: notice => {
        if (notice.kind === 'complete') {
          if (notice.route?.startsWith('/approval/')) return;
          void exchange('complete').then(async () => {
            if (connecting) await connecting.catch(() => {});
            await activate();
          }).catch(show);
        } else if (notice.kind === 'refusal') show(new Error(notice.code));
      },
    });
    root.append(notice);
    window.addEventListener('pagehide', () => {
      lifetime.abort(); handoff.dispose(); transport?.dispose();
      void shell.dispose();
    }, { once: true });
    if (!claim) void activate().catch(error => {
      if (!(error instanceof Error) || error.message !== 'frontdoor:session-required') show(error);
    });
    if (claim) shell.openOwner('/claim', claim);
  }
  catch (error) {
    const refusal = document.createElement('p');
    refusal.className = 'startup-refusal';
    refusal.textContent = error instanceof Error ? error.message : 'shell:startup-failed';
    root.replaceChildren(refusal);
  }
}
