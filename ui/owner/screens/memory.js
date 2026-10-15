/* Memory screen: recall with citations, tier labels, and demote (forget —
   never delete; recall simply never returns the note again). */

import { ownerRoute } from '../embed.js';
import { api } from '../api.js';
import { ICONS, iconButton } from '../icons.js';

export async function showMemory(app) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage wide';
  app.appendChild(panel);

  const h = document.createElement('h1');
  h.className = 'wordless';
  h.innerHTML = ICONS.memory;
  // Memory permission (OWNER-API §10): one action proposes disclose-to-context;
  // the decision itself happens on the approval card.
  const permit = iconButton('share', 'let recall enter the hosted model’s context');
  permit.classList.add('head-action');
  permit.onclick = async () => {
    permit.disabled = true;
    try {
      await api.memoryPermissionPropose();
      location.hash = ownerRoute(location.hash).embedded ? '#/embed/approvals' : '#/approvals';
    } catch (ex) {
      status.textContent = ex.code ?? String(ex);
      status.hidden = false;
      permit.disabled = false;
    }
  };
  h.appendChild(permit);
  panel.appendChild(h);

  const form = document.createElement('form');
  form.className = 'recall-form';
  const input = document.createElement('input');
  input.type = 'text';
  input.setAttribute('aria-label', 'recall');
  const go = iconButton('search', 'recall');
  go.type = 'submit';
  form.append(input, go);
  panel.appendChild(form);

  const status = document.createElement('p');
  status.className = 'instruct';
  status.hidden = true;
  const list = document.createElement('div');
  panel.append(status, list);

  async function recall(query) {
    list.replaceChildren();
    status.hidden = true;
    let result;
    try {
      result = await api.memoryRecall(query, 20);
    } catch (ex) {
      status.textContent = ex.code ?? String(ex);
      status.hidden = false;
      return;
    }
    if (result.result === 'undetermined') {
      status.textContent = 'recall undetermined — the index did not answer';
      status.hidden = false;
      return;
    }
    if (result.result === 'empty' || result.items.length === 0) {
      status.textContent = 'nothing recalled';
      status.hidden = false;
      return;
    }
    for (const item of result.items) {
      const note = document.createElement('div');
      note.className = 'note';
      const text = document.createElement('div');
      text.className = 'text';
      text.textContent = item.text;
      const meta = document.createElement('div');
      meta.className = 'meta';
      const tier = document.createElement('span');
      tier.className = 'tier';
      tier.dataset.tier = item.tier;
      tier.textContent = item.tier;
      const cite = document.createElement('span');
      cite.className = 'cite';
      cite.textContent = `record ${item.cite_seq}`;
      const spacer = document.createElement('span');
      spacer.className = 'spacer';
      const demote = iconButton('demote', 'forget (demote)', 'icon icon-btn');
      demote.onclick = async () => {
        demote.disabled = true;
        try {
          await api.memoryDemote(item.note_id, 'owner-request');
          note.remove();
        } catch (ex) {
          status.textContent = ex.code ?? String(ex);
          status.hidden = false;
          demote.disabled = false;
        }
      };
      meta.append(tier, cite, spacer, demote);
      note.append(text, meta);
      list.appendChild(note);
    }
  }

  form.onsubmit = e => {
    e.preventDefault();
    void recall(input.value.trim());
  };
  void recall('');
}
