// SPDX-License-Identifier: AGPL-3.0-or-later
import { api } from './api.js';
import { browserSha256 } from './pentora.js';

const fail = () => { throw Object.assign(new Error('nostr:preview-refused'), { code: 'nostr:preview-refused' }); };

export async function mountNostrSendPreview(parent, item) {
  const digests = item.card.facts.filter(row => row[0] === 'Message sha256');
  if (digests.length !== 1 || typeof digests[0][1] !== 'string' || !/^[a-f0-9]{64}$/.test(digests[0][1])) fail();
  const preview = await api.nostrSendPreview(item.id);
  if (preview?.id !== item.id || typeof preview.content !== 'string' || preview.content_sha256 !== digests[0][1]) fail();
  if (typeof preview.content_blind !== 'string' || !/^[a-f0-9]{32}$/.test(preview.content_blind)) fail();
  const bytes = new TextEncoder().encode(preview.content);
  if (bytes.length === 0 || bytes.length > 1024) fail();
  const domain = new TextEncoder().encode('nostr:message:v1\0');
  const blind = Uint8Array.from(preview.content_blind.match(/../g), pair => Number.parseInt(pair, 16));
  const commitment = new Uint8Array(domain.length + blind.length + bytes.length);
  commitment.set(domain);
  commitment.set(blind, domain.length);
  commitment.set(bytes, domain.length + blind.length);
  const actual = [...new Uint8Array(await browserSha256(commitment))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  if (actual !== digests[0][1]) fail();
  const block = document.createElement('section');
  block.className = 'nostr-send-preview';
  const label = document.createElement('p');
  label.className = 'instruct';
  label.textContent = 'Exact message to send';
  const content = document.createElement('pre');
  content.textContent = preview.content;
  block.append(label, content);
  parent.appendChild(block);
}
