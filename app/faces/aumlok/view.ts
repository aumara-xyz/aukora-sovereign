// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AumlokStatus } from './status.js';
import type { OwnerDestination } from './link.js';
import { brandMarkUrl, icon } from '../../design/index.js';

export interface AumlokView {
  show(status: AumlokStatus): void;
  unavailable(reason: string): void;
  refreshing(active: boolean): void;
  dispose(): void;
}
interface ViewActions { openOwner(route: OwnerDestination): void; refresh(): void; }
const BANDS = [
  { id: 'root', title: 'ROOT', tone: 'green', first: 1 },
  { id: 'unite', title: 'UNITE', tone: 'blue', first: 3 },
  { id: 'rise', title: 'RISE', tone: 'purple', first: 5 },
] as const;

function node<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', text = ''): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  element.className = className;
  element.textContent = text;
  return element;
}
function action(text: string, signal: AbortSignal, activate: () => void, className = ''): HTMLButtonElement {
  const button = node('button', className, text);
  button.type = 'button';
  button.addEventListener('click', activate, { signal });
  return button;
}
function maskedWord(bound: boolean): HTMLElement {
  const word = node('span', bound ? 'wordMask' : 'tileEmpty', bound ? '' : '—');
  word.dataset.aumlokTileFace = bound ? 'dots' : 'empty';
  word.setAttribute('aria-hidden', 'true');
  if (bound) for (let position = 0; position < 5; position++) word.append(node('i'));
  return word;
}

export function createAumlokView(root: HTMLElement, actions: ViewActions): AumlokView {
  const life = new AbortController();
  const { signal } = life;
  const surface = node('section', 'surface');
  surface.dataset.aumlokSurface = '';
  surface.setAttribute('aria-labelledby', 'aumlok-title');
  const canvas = node('div', 'canvas');
  const hero = node('header', 'hero');
  const heroCopy = node('div', 'heroCopy');
  const title = node('h2', '', 'AUMLOK');
  title.id = 'aumlok-title';
  heroCopy.append(node('p', '', 'SEVEN-WORD BINDING PHRASE'), title);
  const badge = node('span', 'statusBadge');
  badge.setAttribute('role', 'status');
  hero.append(heroCopy, badge);
  const composition = node('div', 'composition');
  const stage = node('section', 'phraseStage');
  stage.setAttribute('aria-label', 'Seven-word phrase');

  const languageLabel = node('label', 'handleLabel', 'Phrase language');
  const language = node('select');
  language.dataset.aumlokPhraseLanguage = '';
  language.setAttribute('aria-label', 'Phrase language');
  language.disabled = true;
  language.title = 'Phrase language is not available from this node.';
  const option = node('option', '', 'Unavailable');
  option.value = 'unavailable';
  language.append(option);
  languageLabel.append(language);
  const strength = node('p', 'handleHint', 'Generated phrase: 41.5 bits minimum, 43.1 bits average.');
  strength.dataset.aumlokPhraseStrength = '';
  const handleField = node('div', 'handleField');
  handleField.dataset.aumlokHandle = '';
  const handleLabel = node('label', 'handleLabel', 'YOUR HANDLE');
  handleLabel.htmlFor = 'aumlok-handle';
  const handle = node('input', 'handleInput');
  handle.id = 'aumlok-handle';
  handle.readOnly = true;
  handle.setAttribute('aria-describedby', 'aumlok-handle-hint');
  handle.dataset.aumlokHandleInput = '';
  const handleHint = node('p', 'handleHint', 'Your public handle is not available from this node.');
  handleHint.id = 'aumlok-handle-hint';
  handleHint.dataset.aumlokHandleHint = '';
  handleField.append(handleLabel, handle, handleHint);

  const anchor = node('div', 'anchorToken');
  anchor.dataset.aumlokToken = '0';
  anchor.dataset.aumlokAnchorCard = '';
  const anchorMeta = node('span', 'anchorMeta');
  anchorMeta.append(node('strong', '', 'WORD 1'), node('span', '', 'first independent random word'));
  const boxes = node('span', 'anchorBoxes');
  for (let position = 0; position < 6; position++) {
    const box = node('span', 'anchorBox');
    box.dataset.aumlokAnchorBox = String(position);
    boxes.append(box);
  }
  anchor.append(anchorMeta, boxes);
  const bands = node('div', 'bands');
  const rows: HTMLElement[] = [];
  for (const band of BANDS) {
    const group = node('section', 'phraseBand');
    group.dataset.aumlokBand = band.id;
    group.dataset.aumlokTone = band.tone;
    const heading = node('header', 'bandHeader');
    heading.append(node('strong', '', band.title), node('span', '', `words ${band.first + 1} and ${band.first + 2}`));
    const bandRows = node('div', 'bandRows');
    for (let at = band.first; at < band.first + 2; at++) {
      const row = node('div', 'phraseRow');
      row.dataset.aumlokToken = String(at);
      const position = node('span', 'position', String(at + 1));
      position.setAttribute('aria-hidden', 'true');
      const initial = node('span', 'initialBox');
      initial.dataset.aumlokInitialBox = String(at);
      initial.setAttribute('aria-hidden', 'true');
      row.append(position, initial, maskedWord(false));
      bandRows.append(row);
      rows.push(row);
    }
    group.append(heading, bandRows);
    bands.append(group);
  }

  let phraseRoute: OwnerDestination = '/phrase';
  const ceremony = node('div', 'ceremonyAction');
  ceremony.dataset.aumlokCeremonyBeat = 'none';
  const bind = action('Give me my phrase', signal, () => actions.openOwner(phraseRoute));
  bind.dataset.aumlokBindButton = '';
  const notice = node('p', 'handleHint', 'Your seven words are shown and entered only in the trusted owner pane.');
  ceremony.append(bind, notice);
  const ownerControls = node('div', 'ownerControls');
  const signin = action('Sign in', signal, () => actions.openOwner('/passkey'), 'action blue');
  signin.dataset.aumlokSignin = '';
  const refresh = action('Refresh status', signal, actions.refresh, 'action blue');
  const status = node('p', 'handleHint');
  status.setAttribute('role', 'status');
  ownerControls.append(signin, refresh);
  stage.append(languageLabel, strength, handleField, anchor, bands, ceremony, ownerControls, status);

  const flow = node('div', 'panel flow');
  flow.setAttribute('aria-labelledby', 'aumlok-flow-label');
  const explanation = node('div', 'flowBody');
  explanation.id = 'aumlok-flow-body';
  explanation.dataset.collapsed = 'true';
  const summary = action('What is this?', signal, () => {
    const expanded = summary.getAttribute('aria-expanded') !== 'true';
    summary.setAttribute('aria-expanded', String(expanded));
    if (expanded) delete explanation.dataset.collapsed;
    else explanation.dataset.collapsed = 'true';
  }, 'flowSummary');
  summary.setAttribute('aria-controls', explanation.id);
  summary.setAttribute('aria-expanded', 'false');
  const explanationHeader = node('header', 'sectionHeader explanationHeader');
  const mark = node('img');
  mark.alt = '';
  mark.width = 36;
  mark.height = 36;
  mark.src = brandMarkUrl();
  const explanationTitle = node('h3', '', 'What Aumlok is');
  explanationTitle.id = 'aumlok-flow-label';
  explanationHeader.append(mark, explanationTitle);
  const body = node('div', 'explanation');
  body.dataset.aumlokExplanation = '';
  for (const paragraph of [
    'Aumlok binds this node to your identity. Your seven-word phrase seals a random identity root; your passkey authorizes the exact action you approve.',
    'The first binding follows a claim and passkey enrolment. Before binding, the node holds the enrolled credential without inventing an identity.',
    'Your phrase belongs in the trusted owner pane. This screen receives only the public binding status and never receives the words or the identity root.',
    'Only the shell opens the owner pane. A binding status, receipt or picture cannot approve an operation.',
    'When an action needs your authority, the owner pane presents it for your passkey. The app cannot turn its own request into your approval.',
  ]) body.append(node('p', '', paragraph));
  explanation.append(explanationHeader, body, node('p', 'boundaryClosing', 'Your boundary. Your sovereignty.'));
  flow.append(summary, explanation);
  composition.append(stage, flow);
  canvas.append(hero, composition);
  surface.append(canvas);
  root.replaceChildren(surface);

  function setState(state: 'checking' | 'bound' | 'unbound' | 'unavailable', message: string): void {
    const bound = state === 'bound';
    surface.dataset.state = state;
    ceremony.dataset.aumlokCeremonyState = state;
    badge.dataset.aumlokBadge = state;
    badge.replaceChildren();
    if (bound) badge.append(icon('aumlok'));
    badge.append(document.createTextNode(state.toUpperCase()));
    anchor.dataset.aumlokTileFace = bound ? 'dots' : 'empty';
    anchor.setAttribute('aria-label', bound ? 'Masked first word' : 'First word unavailable');
    for (const box of boxes.children) {
      (box as HTMLElement).dataset.aumlokAnchorBoxKind = bound ? 'dot' : 'empty';
      box.replaceChildren(...(bound ? [node('i', 'anchorDot')] : []));
    }
    for (const row of rows) {
      row.children[2].replaceWith(maskedWord(bound));
      row.setAttribute('aria-label', bound ? 'Masked word' : 'Word unavailable');
    }
    bind.disabled = state === 'checking' || state === 'unavailable';
    status.textContent = message;
  }
  setState('checking', 'Reading binding status…');

  return {
    show(value) {
      phraseRoute = value.bound ? '/phrase/refresh' : '/phrase';
      bind.textContent = value.bound ? 'Rotate my phrase' : 'Give me my phrase';
      bind.dataset.aumlokAction = value.bound ? 'refresh' : 'bind';
      languageLabel.hidden = value.bound;
      const passkeys = `${value.passkeys} ${value.passkeys === 1 ? 'passkey' : 'passkeys'}`;
      setState(value.bound ? 'bound' : 'unbound', value.refreshDue
        ? `${passkeys} · Phrase refresh due.` : `${passkeys} · ${value.bound ? 'Your identity root is sealed.' : 'No binding yet.'}`);
    },
    unavailable(reason) {
      phraseRoute = '/phrase';
      languageLabel.hidden = false;
      setState('unavailable', reason);
    },
    refreshing(active) { refresh.disabled = active; },
    dispose() { life.abort(); surface.remove(); },
  };
}
