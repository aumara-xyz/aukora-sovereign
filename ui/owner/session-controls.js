// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from './api.js';
import { mountCard } from './card.js';
import { checkPermissionChallenge, permissionAssertion } from './owner-permission.js';

export function addSignOut(container, { onDone = () => location.reload() } = {}) {
  const signout = document.createElement('button');
  signout.textContent = 'Sign out';
  signout.onclick = async () => {
    signout.disabled = true;
    try {
      await api.logout();
      await onDone();
    } catch (ex) {
      signout.disabled = false;
      signout.title = ex.code ?? String(ex);
    }
  };
  container.appendChild(signout);
}

export function addSignOutEverywhere(container, state, { onDone = () => location.reload() } = {}) {
  const section = document.createElement('section');
  section.className = 'session-controls';
  const start = document.createElement('button');
  start.textContent = 'Sign out everywhere';
  const err = document.createElement('p');
  err.className = 'instruct warn';
  err.hidden = true;
  section.append(start, err);
  container.appendChild(section);
  start.onclick = async () => {
    start.disabled = true;
    err.hidden = true;
    try {
      const ch = await api.logoutEverywhere();
      await checkPermissionChallenge(ch, state, 'aumlok/session/revoke-all', 'aumlok:session-challenge-mismatch');
      const review = document.createElement('div');
      mountCard(review, ch.card);
      const approve = document.createElement('button');
      approve.className = 'primary';
      approve.textContent = 'Touch ID — sign out everywhere';
      const cancel = document.createElement('button');
      cancel.textContent = 'Keep sessions';
      const actions = document.createElement('div');
      actions.className = 'row-actions';
      actions.append(cancel, approve);
      review.appendChild(actions);
      section.replaceChildren(review, err);
      cancel.onclick = () => section.replaceChildren(start, err);
      start.disabled = false;
      approve.onclick = async () => {
        approve.disabled = true;
        err.hidden = true;
        try {
          const proof = await permissionAssertion(ch);
          await api.logoutEverywhereConfirm(ch.ceremony_id, proof);
          await onDone();
        } catch (ex) {
          approve.disabled = false;
          err.textContent = ex.code ?? String(ex);
          err.hidden = false;
        }
      };
    } catch (ex) {
      start.disabled = false;
      err.textContent = ex.code ?? String(ex);
      err.hidden = false;
    }
  };
}
