/* Phrase binding screen (SPEC §5). The six-letter anchor is laid ACROSS in gold
   boxes; words 2–7 are laid DOWN from each anchor letter, grouped ROOT (green) /
   UNITE (blue) / RISE (violet). The screen instructs: two short memory-palace
   lines, the honest server-computed entropy number, then a no-paste type-back.
   The same reveal and type-back layout is used by phrase replacement. */

import { api } from '../api.js';
import { layoutPhrase, firstMismatch, BANDS } from '../phrase-layout.js';

export async function showBinding(app, { onDone }) {
  app.replaceChildren();
  const panel = document.createElement('main');
  panel.className = 'panel stage wide';
  app.appendChild(panel);

  const err = document.createElement('p');
  err.className = 'instruct warn';

  let draw;
  try {
    draw = await api.bindingPrepare();
  } catch (ex) {
    err.textContent = ex.code ?? String(ex);
    panel.appendChild(err);
    return;
  }
  mountPhraseCeremony(panel, draw, {
    confirm: words => api.bindingConfirm(draw.ceremony_id, words),
    onDone,
    label: 'bind',
    doneText: 'Bound. This node now answers to your phrase and your passkey.',
  });
}

export function mountPhraseComplete(panel, { onDone, doneText, doneLink }) {
  panel.replaceChildren();
  const done = document.createElement('div');
  done.className = 'center-col';
  const ok = document.createElement('p');
  ok.className = 'instruct';
  ok.textContent = doneText;
  done.appendChild(ok);
  if (doneLink) {
    const backup = document.createElement('a');
    backup.href = doneLink.href;
    backup.download = doneLink.download;
    backup.textContent = doneLink.label;
    done.appendChild(backup);
  }
  const next = document.createElement('button');
  next.className = 'primary';
  next.textContent = 'continue';
  next.onclick = () => onDone();
  done.appendChild(next);
  panel.appendChild(done);
}

export function mountPhraseCeremony(panel, draw, { confirm, onDone, label, doneText, doneLink, cancel, exact = false, errorText = ex => ex.code ?? String(ex) }) {
  const err = document.createElement('p');
  err.className = 'instruct warn';
  err.hidden = true;
  const { words, entropy_bits } = draw;
  const laid = layoutPhrase(words);

  // -- reveal: anchor across in gold, themed words down each column ----------
  const reveal = document.createElement('section');

  const anchorWord = document.createElement('div');
  anchorWord.className = 'anchor-word';
  anchorWord.textContent = laid.anchor.word;
  reveal.appendChild(anchorWord);

  const row = document.createElement('div');
  row.className = 'anchor-row';
  for (const col of laid.columns) {
    const cell = document.createElement('div');
    cell.className = 'anchor-cell';
    const letter = document.createElement('div');
    letter.className = 'anchor-letter';
    letter.textContent = col.letter;
    const tile = document.createElement('div');
    tile.className = 'word-tile';
    tile.dataset.band = col.band;
    tile.textContent = col.word;
    cell.append(letter, tile);
    row.appendChild(cell);
  }
  reveal.appendChild(row);

  const key = document.createElement('div');
  key.className = 'band-key';
  for (const band of BANDS) {
    const span = document.createElement('span');
    span.dataset.band = band.id;
    span.innerHTML = `<i></i>${band.id.toUpperCase()}`;
    key.appendChild(span);
  }
  reveal.appendChild(key);

  const guide1 = document.createElement('p');
  guide1.className = 'instruct';
  guide1.textContent = 'Build a story in your own head that walks through these seven words, in order.';
  const guide2 = document.createElement('p');
  guide2.className = 'instruct warn';
  guide2.textContent = 'Never type these words into an AI.';

  const entropy = document.createElement('p');
  entropy.className = 'entropy';
  const bits = document.createElement('b');
  bits.textContent = `${entropy_bits} bits`;
  entropy.append('phrase entropy: ', bits, ' — measured over the real word lists');

  const hideBtn = document.createElement('button');
  hideBtn.className = 'primary';
  hideBtn.textContent = 'I have them — hide the words';

  const actions = document.createElement('div');
  actions.className = 'row-actions';

  actions.append(hideBtn);
  if (cancel) {
    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = 'Cancel replacement';
    cancelBtn.onclick = async () => {
      cancelBtn.disabled = true;
      err.hidden = true;
      try {
        const result = await cancel();
        if (result?.state === 'committed') mountPhraseComplete(panel, { onDone, doneText, doneLink });
      } catch (ex) {
        cancelBtn.disabled = false;
        err.textContent = errorText(ex);
        err.hidden = false;
      }
    };
    actions.appendChild(cancelBtn);
  }
  panel.append(reveal, guide1, guide2, entropy, actions, err);

  // -- type-back: words wiped from the DOM, seven no-paste inputs -------------
  hideBtn.onclick = () => {
    reveal.replaceChildren();
    guide1.remove();
    entropy.remove();
    hideBtn.remove();

    const typeNote = document.createElement('p');
    typeNote.className = 'instruct';
    typeNote.textContent = 'Type the seven words back, in order.';

    const grid = document.createElement('div');
    grid.className = 'typeback';
    const inputs = words.map((w, i) => {
      const input = document.createElement('input');
      input.type = 'text';
      input.setAttribute('autocomplete', 'off');
      input.setAttribute('spellcheck', 'false');
      input.setAttribute('autocorrect', 'off');
      input.setAttribute('autocapitalize', 'off');
      input.setAttribute('aria-label', `word ${i + 1}`);
      input.dataset.pos = String(i + 1);
      if (i > 0) input.dataset.band = laid.columns[i - 1].band;
      input.addEventListener('paste', e => e.preventDefault()); // no paste: the words live in the owner's head
      input.addEventListener('drop', e => e.preventDefault());
      grid.appendChild(input);
      return input;
    });
    inputs[0].focus();

    const confirmBtn = document.createElement('button');
    confirmBtn.className = 'primary';
    confirmBtn.textContent = label;
    actions.appendChild(confirmBtn);

    panel.insertBefore(typeNote, guide2);
    panel.insertBefore(grid, guide2);

    confirmBtn.onclick = async () => {
      err.hidden = true;
      const typed = inputs.map(i => i.value);
      const miss = exact ? words.findIndex((word, i) => word !== typed[i]) + 1 : firstMismatch(words, typed);
      if (miss !== 0) {
        err.textContent = miss > 0 ? `word ${miss} does not match` : 'all seven words are needed';
        err.hidden = false;
        if (miss > 0) inputs[miss - 1].focus();
        return;
      }
      confirmBtn.disabled = true;
      try {
        await confirm(exact ? typed : typed.map(t => t.trim().toLowerCase()));
        inputs.forEach(input => { input.value = ''; });
        mountPhraseComplete(panel, { onDone, doneText, doneLink });
      } catch (ex) {
        confirmBtn.disabled = false;
        err.textContent = ex.code === 'aumlok:word-mismatch' && ex.detail?.position
          ? `word ${ex.detail.position} does not match`
          : errorText(ex);
        err.hidden = false;
      }
    };
  };
}
