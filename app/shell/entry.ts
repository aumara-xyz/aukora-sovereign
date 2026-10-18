// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountShell } from './main.js';
import { ShellTransport } from '../core/transport.js';
import { createServices } from '../core/services.js';
import type { Dispose } from '../core/organism.js';
import { exactKeys, objectData } from '../core/data.js';
import { ApprovalWatch, SESSION_REFUSALS } from './approvals.js';

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
    // A claim link opens on the stage, not on the app behind it: the app stays out of sight until the ceremony ends.
    if (claim) document.body.dataset.claiming = '';
    const lifetime = new AbortController();
    const handoff = new ShellTransport();
    const transport = new ShellTransport();
    const services: Dispose[] = [];
    let connecting: Promise<void> | null = null;
    let bound = false;
    let approvals: ApprovalWatch | null = null;
    let ownerEnding: { resolve(): void; reject(error: Error): void } | null = null;
    const notice = document.createElement('p');
    notice.className = 'shell-connection';
    notice.setAttribute('role', 'status');
    notice.hidden = true;
    const show = (error: unknown) => {
      const code = error instanceof Error ? error.message : '';
      notice.textContent = code === 'frontdoor:session-required' || code === 'aumlok:binding-required'
        ? 'Sign in to continue.' : code.startsWith('shell:approval-')
          ? 'Approvals are unavailable. Try again shortly.' : 'Connection unavailable. Try again shortly.';
      notice.hidden = false;
      notice.dataset.source = 'connection';
    };
    // Without a session the menu's base offers Sign in; that is a calm state, not a notice.
    const showSessionError = (error: unknown) => {
      if (error instanceof Error && SESSION_REFUSALS.has(error.message)) {
        if (notice.dataset.source === 'connection') notice.hidden = true;
        shell.setSignedIn(false);
        return;
      }
      show(error);
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
      connecting = transport.call('session.list', {
        thread_id: null, include_archived: false, before: null, limit: 1,
      }, lifetime.signal).then(async () => {
        await Promise.all(services.splice(0).map(dispose => dispose()));
        if (lifetime.signal.aborted) return;
        provideServices();
        notice.hidden = true;
        shell.setSignedIn(true);
      }).finally(() => { connecting = null; });
      return connecting;
    };
    // The server revokes the whole family first. Then the owner host clears its own HttpOnly cookie.
    const endSession = async () => {
      try {
        const reply = objectData(await handoff.request('/api/session/end', {}, lifetime.signal));
        exactKeys(reply, ['ended']);
        if (reply.ended !== true) throw new Error('shell:session-end-refused');
      } catch (error) {
        if (!(error instanceof Error && SESSION_REFUSALS.has(error.message))) throw error;
      }
      bound = false;
      shell.setSignedIn(false);
      // Remove signed-in content as soon as revocation succeeds, even if owner-cookie cleanup later fails.
      await Promise.all(services.splice(0).map(dispose => dispose()));
      if (!lifetime.signal.aborted) provideServices();
      approvals?.refresh();
      let timeout: ReturnType<typeof setTimeout> | undefined;
      try {
        await new Promise<void>((resolve, reject) => {
          ownerEnding = { resolve, reject };
          timeout = setTimeout(() => reject(new Error('shell:session-end-timeout')), 15_000);
          void shell.openOwner('/signout').catch(reject);
        });
      } finally {
        clearTimeout(timeout);
        ownerEnding = null;
      }
    };
    const shell = mountShell({
      root, ownerOrigin: ownerOrigin(), servicesPendingText: 'Sign in',
      prepareOwner: () => exchange('prepare'),
      phraseRoute: () => bound ? '/phrase/refresh' : '/phrase',
      openApprovals: () => approvals?.reopen(),
      endSession,
      onOwnerNotice: notice => {
        delete document.body.dataset.claiming;
        if (ownerEnding) {
          if (notice.kind === 'complete' && notice.route === '/signout') ownerEnding.resolve();
          else ownerEnding.reject(new Error('shell:session-end-refused'));
          return;
        }
        if ('route' in notice && notice.route === '/signout') return;
        if (notice.kind === 'closed' && notice.route?.startsWith('/approval/')) {
          approvals?.forget(notice.route.slice('/approval/'.length));
        }
        if (notice.kind === 'closed' || notice.kind === 'complete') approvals?.refresh();
        if (notice.kind === 'complete') {
          if (notice.route?.startsWith('/approval/') || notice.route === '/phrase/refresh' || notice.route === '/witness') return;
          void exchange('complete').then(async () => {
            bound = true;
            approvals?.refresh();
            if (connecting) await connecting.catch(() => {});
            await activate();
          }).catch(showSessionError);
        } else if (notice.kind === 'refusal') show(new Error(notice.code));
      },
    });
    const current = () => shell.organism.descriptors().flatMap(plugin => {
      const status = shell.organism.status(plugin.id);
      return status ? [status] : [];
    });
    // Faces may render before sign-in. Every service request still passes the node's session check.
    const provideServices = () => {
      for (const [name, service] of createServices(transport, current)) services.push(shell.provideService(name, service));
    };
    provideServices();
    approvals = new ApprovalWatch({
      signal: lifetime.signal,
      ownerBusy: () => shell.ownerBusy,
      openOwner: route => shell.openOwner(route),
      pending: count => shell.setApprovalsPending(count),
      declined: ids => shell.setApprovalsDeclined(ids),
      session: signedIn => {
        bound = signedIn;
        shell.setSignedIn(signedIn);
        if (signedIn && notice.dataset.source === 'approvals') notice.hidden = true;
      },
      refusal: error => { show(error); notice.dataset.source = 'approvals'; },
    });
    approvals.refresh();
    root.append(notice);
    window.addEventListener('pagehide', () => {
      lifetime.abort(); handoff.dispose(); transport.dispose();
      void shell.dispose().finally(() => Promise.all(services.map(dispose => dispose())));
    }, { once: true });
    if (!claim) void activate().catch(showSessionError);
    if (claim) void shell.openOwner('/claim', claim).catch(error => { delete document.body.dataset.claiming; show(error); });
  }
  catch (error) {
    const refusal = document.createElement('p');
    refusal.className = 'startup-refusal';
    refusal.textContent = 'The app could not open. Reload to try again.';
    root.replaceChildren(refusal);
  }
}
