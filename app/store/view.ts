// SPDX-License-Identifier: AGPL-3.0-or-later
import { exactKeys, objectData } from '../core/data.js';
import type { JsonValue } from '../core/data.js';
import type { FaceClient } from '../core/client.js';
import { fail, hex, parseManifest, refusalText, unbase64 } from './protocol.js';
import type { AppManifest } from './protocol.js';

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text = ''): HTMLElementTagNameMap[K] {
  const item = document.createElement(tag);
  item.textContent = text;
  return item;
}
interface PublicationView { event: string; author: string; digest: string; manifest: AppManifest; ratings: readonly JsonValue[] }

function publications(value: JsonValue): PublicationView[] {
  const reply = objectData(value);
  exactKeys(reply, ['publications']);
  if (!Array.isArray(reply.publications) || reply.publications.length > 25) fail('invalid-catalog');
  return reply.publications.map(raw => {
    const item = objectData(raw);
    exactKeys(item, ['event_id', 'author', 'package_sha256', 'manifest_b64', 'ratings']);
    const manifest = parseManifest(unbase64(item.manifest_b64));
    if (manifest.signature.public_key !== hex(item.author) || manifest.body.package_sha256 !== hex(item.package_sha256)
      || !Array.isArray(item.ratings) || item.ratings.length > 100) fail('catalog-mismatch');
    return { event: hex(item.event_id), author: item.author as string, digest: item.package_sha256 as string,
      manifest, ratings: item.ratings };
  });
}

function describe(parent: HTMLElement, manifest: AppManifest, author: string, digest: string): void {
  parent.append(el('h3', `${manifest.body.name} · ${manifest.body.version}`));
  const facts = el('dl');
  for (const [label, text] of [['Author key', author], ['Package SHA-256', digest], ['App id', manifest.body.id],
    ['Requested grants', manifest.body.grants.length ? manifest.body.grants.join(', ') : 'None']]) {
    const row = el('div');
    row.append(el('dt', label), el('dd', text));
    facts.append(row);
  }
  parent.append(facts);
}

export function mountStore(root: HTMLElement, client: FaceClient, signal: AbortSignal): void {
  const content = el('section');
  const notice = el('p', 'Author publications and ratings are evidence. Each install requires the owner’s passkey approval of the exact package bytes and its listed grants.');
  const wall = el('p', 'Apps receive only their listed storage, clock and random services. Passkey, gate, broker, Aura append and network access cannot be granted.');
  const form = el('form');
  const label = el('label', 'Find apps');
  const query = el('input');
  query.type = 'search';
  query.maxLength = 128;
  query.id = 'store-query';
  label.htmlFor = query.id;
  const search = el('button', 'Search catalog');
  search.type = 'submit';
  form.append(label, query, search);
  const status = el('p', 'Catalog not loaded.');
  status.setAttribute('role', 'status');
  const results = el('section');
  results.setAttribute('aria-label', 'Catalog results');
  const installed = el('section');
  installed.setAttribute('aria-label', 'Installed apps');
  const refresh = el('button', 'Refresh installed apps');
  refresh.type = 'button';
  content.append(notice, wall, form, status, results, el('h2', 'Installed apps'), refresh, installed);
  root.append(content);
  signal.addEventListener('abort', () => content.remove(), { once: true });
  let searchSerial = 0;
  let installedSerial = 0;

  const action = async (button: HTMLButtonElement, task: () => Promise<void>) => {
    button.disabled = true;
    try { await task(); }
    catch (error) { if (!signal.aborted) status.textContent = `Unavailable · ${refusalText(error)}`; }
    finally { if (!signal.aborted) button.disabled = false; }
  };

  const showCatalog = async () => {
    const serial = ++searchSerial;
    search.disabled = true;
    results.replaceChildren();
    status.textContent = 'Reading author-signed publications from the catalog…';
    try {
      const entries = publications(await client.call('store', 'catalog.search', { query: query.value }, { signal }));
      if (signal.aborted || serial !== searchSerial) return;
      status.textContent = entries.length ? `${entries.length} publication${entries.length === 1 ? '' : 's'}. Ratings carry no installation authority.` : 'No matching publications.';
      for (const entry of entries) {
        const card = el('article');
        describe(card, entry.manifest, entry.author, entry.digest);
        const ratings = el('details');
        ratings.append(el('summary', `${entry.ratings.length} rating${entry.ratings.length === 1 ? '' : 's'} · evidence only`));
        for (const raw of entry.ratings) {
          const rating = objectData(raw);
          exactKeys(rating, ['event_id', 'author', 'rating', 'text']);
          hex(rating.event_id); hex(rating.author);
          if (typeof rating.rating !== 'number' || !Number.isInteger(rating.rating) || rating.rating < 1 || rating.rating > 5
            || typeof rating.text !== 'string' || new TextEncoder().encode(rating.text).length > 1_024) fail('invalid-rating');
          const review = el('article');
          review.append(el('p', `${rating.rating}/5 · ${rating.author}`), el('p', rating.text));
          ratings.append(review);
        }
        const review = el('button', 'Review installation');
        review.type = 'button';
        review.addEventListener('click', () => { void action(review, async () => {
          status.textContent = 'Checking the exact package bytes and preparing owner review…';
          const reply = objectData(await client.call('store', 'install.propose', { event_id: entry.event }, { signal }));
          exactKeys(reply, ['app', 'package_sha256', 'proposal_id', 'state']);
          if (reply.app !== entry.manifest.body.id || reply.package_sha256 !== entry.digest || reply.state !== 'pending-owner') {
            fail('proposal-mismatch');
          }
          const proposal = hex(reply.proposal_id, 32);
          if (signal.aborted) return;
          review.textContent = 'Owner review pending';
          status.textContent = `Proposal ${proposal} is pending the owner’s passkey. Refresh installed apps after the owner completes review.`;
        }); }, { signal });
        card.append(ratings, review);
        results.append(card);
      }
    } catch (error) {
      if (!signal.aborted && serial === searchSerial) { results.replaceChildren(); status.textContent = `Unavailable · ${refusalText(error)}`; }
    } finally { if (!signal.aborted && serial === searchSerial) search.disabled = false; }
  };

  const showInstalled = async () => {
    const serial = ++installedSerial;
    installed.replaceChildren();
    try {
      const reply = objectData(await client.call('store', 'installed.list', {}, { signal }));
      exactKeys(reply, ['installed']);
      if (!Array.isArray(reply.installed) || reply.installed.length > 100) fail('invalid-installed');
      if (signal.aborted || serial !== installedSerial) return;
      if (!reply.installed.length) installed.append(el('p', 'No approved installed apps reported.'));
      for (const raw of reply.installed) {
        const item = objectData(raw);
        exactKeys(item, ['app', 'package_sha256', 'manifest_b64', 'receipt_sequence']);
        const manifest = parseManifest(unbase64(item.manifest_b64));
        const app = hex(item.app, 32);
        const digest = hex(item.package_sha256);
        if (manifest.body.id !== app || manifest.body.package_sha256 !== digest
          || !Number.isSafeInteger(item.receipt_sequence) || (item.receipt_sequence as number) < 1) fail('installed-mismatch');
        const card = el('article');
        describe(card, manifest, manifest.signature.public_key, digest);
        card.append(el('p', `Install receipt ${item.receipt_sequence}`));
        const open = el('button', 'Open in tri-pane');
        open.type = 'button';
        open.addEventListener('click', () => { void action(open, async () => {
          const opened = objectData(await client.call('store', 'installed.open', { app, package_sha256: digest }, { signal }));
          exactKeys(opened, ['app', 'package_sha256', 'state']);
          if (opened.app !== app || opened.package_sha256 !== digest || opened.state !== 'opened') fail('open-mismatch');
          if (!signal.aborted) status.textContent = 'App face opened in the tri-pane.';
        }); }, { signal });
        card.append(open);
        installed.append(card);
      }
    } catch (error) {
      if (!signal.aborted && serial === installedSerial) { installed.replaceChildren(); installed.append(el('p', `Installed state unavailable · ${refusalText(error)}`)); }
    }
  };
  form.addEventListener('submit', event => { event.preventDefault(); void showCatalog(); }, { signal });
  refresh.addEventListener('click', () => { void action(refresh, showInstalled); }, { signal });
  void showInstalled();
}
