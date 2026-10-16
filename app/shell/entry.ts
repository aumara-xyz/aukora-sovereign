// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountShell } from './main.js';

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
    const shell = mountShell({ root, ownerOrigin: ownerOrigin() });
    if (claim) shell.openOwner('/claim', claim);
  }
  catch (error) {
    const refusal = document.createElement('p');
    refusal.className = 'startup-refusal';
    refusal.textContent = error instanceof Error ? error.message : 'shell:startup-failed';
    root.replaceChildren(refusal);
  }
}
