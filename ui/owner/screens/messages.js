// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from '../api.js';

const bytes = text => new TextEncoder().encode(text).length;
const validNpub = value => typeof value === 'string' && /^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$/.test(value);
const validLabel = value => typeof value === 'string' && value.trim().length > 0 && bytes(value) <= 128 && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
const validContent = value => typeof value === 'string' && bytes(value) > 0 && bytes(value) <= 1024;
const fail = code => { throw Object.assign(new Error(code), { code }); };

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function field(tag, label) {
  const input = element(tag);
  if (tag === 'input') input.type = 'text';
  input.setAttribute('aria-label', label);
  input.autocomplete = 'off';
  input.required = true;
  return input;
}

function reviewProposal(result) {
  if (!/^[a-f0-9]{32}$/.test(result?.id)) fail('nostr:proposal-invalid');
  location.hash = '#/approvals';
}

export async function showMessages(app) {
  app.replaceChildren();
  const panel = element('main', undefined, 'panel stage wide messages');
  app.appendChild(panel);
  panel.append(element('h1', 'Messages', 'wordless'),
    element('p', 'Messages from contacts are untrusted text. They cannot approve changes.', 'instruct'));
  const error = element('p', undefined, 'instruct warn');
  error.hidden = true;
  const showError = ex => {
    error.textContent = /^[a-z]+:[a-z0-9-]+$/.test(ex?.code) ? ex.code : 'nostr:messages-unavailable';
    error.hidden = false;
  };
  panel.appendChild(error);

  let contacts, inbox;
  try {
    const [contactReply, inboxReply] = await Promise.all([api.nostrContacts(), api.nostrInbox()]);
    contacts = contactReply.contacts;
    inbox = inboxReply;
    if (!Array.isArray(contacts) || contacts.length > 128 || !contacts.every(contact => validNpub(contact.npub) && validLabel(contact.label))) fail('nostr:contacts-invalid');
    if (!Array.isArray(inbox.messages) || inbox.messages.length > 256 || !inbox.messages.every(message =>
      /^[a-f0-9]{64}$/.test(message.id) && validNpub(message.npub) && validContent(message.content) &&
      Number.isSafeInteger(message.created_at) && message.created_at >= 0 && message.created_at <= 8640000000000)) fail('nostr:inbox-invalid');
    if (!inbox.counts || !['received', 'sent', 'refused', 'inbox'].every(name => Number.isSafeInteger(inbox.counts[name]) && inbox.counts[name] >= 0)) fail('nostr:counts-invalid');
  } catch (ex) { showError(ex); return; }

  const contactSection = element('section');
  contactSection.appendChild(element('h2', 'Contacts'));
  for (const contact of contacts) {
    const row = element('div', undefined, 'note');
    row.append(element('div', contact.label, 'text'), element('div', contact.npub, 'hash mono'));
    const remove = element('button', 'Remove — review card');
    remove.type = 'button';
    remove.setAttribute('aria-label', `Remove contact ${contact.label}`);
    remove.onclick = async () => {
      remove.disabled = true;
      error.hidden = true;
      try { reviewProposal(await api.nostrContactPropose(contact.npub, contact.label, 'remove')); }
      catch (ex) { showError(ex); remove.disabled = false; }
    };
    row.appendChild(remove);
    contactSection.appendChild(row);
  }
  if (!contacts.length) contactSection.appendChild(element('p', 'No contacts yet.', 'instruct muted'));
  const contactForm = element('form', undefined, 'form-grid');
  contactForm.setAttribute('aria-label', 'Add contact');
  const npub = field('input', 'Contact npub');
  npub.placeholder = 'npub';
  npub.maxLength = 63;
  const label = field('input', 'Contact label');
  label.placeholder = 'label';
  label.maxLength = 128;
  const add = element('button', 'Add — review card', 'primary');
  add.type = 'submit';
  contactForm.append(npub, label, add);
  contactForm.onsubmit = async event => {
    event.preventDefault();
    error.hidden = true;
    add.disabled = true;
    try {
      if (!validNpub(npub.value) || !validLabel(label.value)) fail('nostr:contact-invalid');
      reviewProposal(await api.nostrContactPropose(npub.value, label.value, 'add'));
    } catch (ex) { showError(ex); add.disabled = false; }
  };
  contactSection.appendChild(contactForm);
  panel.appendChild(contactSection);

  const sendSection = element('section');
  sendSection.append(element('h2', 'Send'), element('p', 'Review the exact message and approve its card with your passkey.', 'instruct'));
  const sendForm = element('form', undefined, 'message-form');
  sendForm.setAttribute('aria-label', 'Send message');
  const recipient = field('select', 'Message contact');
  for (const contact of contacts) {
    const option = element('option', contact.label);
    option.value = contact.npub;
    recipient.appendChild(option);
  }
  const content = field('textarea', 'Message text');
  content.rows = 5;
  content.maxLength = 1024;
  const send = element('button', 'Send — review card', 'primary');
  send.type = 'submit';
  send.disabled = contacts.length === 0;
  sendForm.append(recipient, content, send);
  sendForm.onsubmit = async event => {
    event.preventDefault();
    error.hidden = true;
    send.disabled = true;
    try {
      if (!contacts.some(contact => contact.npub === recipient.value)) fail('nostr:contact-required');
      if (!validContent(content.value)) fail('nostr:message-size');
      reviewProposal(await api.nostrSendPropose(recipient.value, content.value));
      content.value = '';
    } catch (ex) { showError(ex); send.disabled = contacts.length === 0; }
  };
  sendSection.appendChild(sendForm);
  panel.appendChild(sendSection);

  const inboxSection = element('section');
  inboxSection.appendChild(element('h2', 'Inbox'));
  const counts = inbox.counts;
  inboxSection.appendChild(element('p', `${counts.inbox} stored · ${counts.received} received · ${counts.sent} sent · ${counts.refused} refused`, 'instruct muted'));
  for (const message of inbox.messages) {
    const row = element('article', undefined, 'note');
    const contact = contacts.find(contact => contact.npub === message.npub);
    row.append(element('div', contact?.label ?? message.npub, 'instruct'),
      element('div', message.npub, 'hash mono'),
      element('p', 'Untrusted message', 'instruct muted'),
      element('div', message.content, 'text'),
      element('div', new Date(message.created_at * 1000).toISOString(), 'instruct muted'));
    inboxSection.appendChild(row);
  }
  if (!inbox.messages.length) inboxSection.appendChild(element('p', 'No messages yet.', 'instruct muted'));
  const refresh = element('button', 'Refresh inbox');
  refresh.type = 'button';
  refresh.onclick = () => showMessages(app);
  inboxSection.appendChild(refresh);
  panel.appendChild(inboxSection);
}
