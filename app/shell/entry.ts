// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountShell } from './main.js';

const root = document.getElementById('aukora-shell');
if (root) {
  try { mountShell({ root }); }
  catch (error) {
    const refusal = document.createElement('p');
    refusal.className = 'startup-refusal';
    refusal.textContent = error instanceof Error ? error.message : 'shell:startup-failed';
    root.replaceChildren(refusal);
  }
}
