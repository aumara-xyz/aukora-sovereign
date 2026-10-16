// SPDX-License-Identifier: AGPL-3.0-or-later
import { CONTENT, type Word } from "./content.js";
import { LearningStore } from "./state.js";
import { el, button, shuffled } from "./dom.js";

type Choice = { label: string; right: boolean };
type Question =
  | { kind: "choice"; word: Word; prompt: string; choices: Choice[] }
  | { kind: "type"; word: Word; prompt: string }
  | { kind: "build"; word: Word; prompt: string; tiles: string[] };

const wordIndex = new Map(CONTENT.words.map(word => [word.token, word]));
const normalized = (text: string): string => text.normalize("NFC").trim().replace(/\s+/g, " ").toLowerCase();

function choicesFor(word: Word, pool: readonly Word[], reverse: boolean): Choice[] {
  const value = (item: Word) => reverse ? item.token : item.meaning;
  const seen = new Set([normalized(value(word))]);
  const wrong: Choice[] = [];
  for (const candidate of shuffled(pool)) {
    const label = value(candidate);
    const key = normalized(label);
    if (candidate.token === word.token || normalized(candidate.meaning) === normalized(word.meaning) || !key || seen.has(key)) continue;
    seen.add(key);
    wrong.push({ label, right: false });
    if (wrong.length === 2) break;
  }
  return [{ label: value(word), right: true }, ...wrong];
}

function questionFor(word: Word, store: LearningStore, learned: readonly Word[], at: number): Question {
  const review = store.review(word.token);
  const box = review?.box ?? 0;
  const exercise = ((review?.right ?? 0) % 3 + (review?.wrong ?? 0) % 3 + at) % 3;
  const tiles = word.sentence.trim().split(/\s+/).filter(Boolean);
  if (box >= 2 && exercise === 2 && word.translation && tiles.length >= 3 && tiles.length <= 12) {
    return { kind: "build", word, prompt: `Build the Auma sentence: ${word.translation}`, tiles };
  }
  if (box >= 2 && exercise === 1) {
    return { kind: "type", word, prompt: `Write the Auma word for “${word.meaning}”.` };
  }
  const reverse = at % 2 === 1;
  let choices = choicesFor(word, learned, reverse);
  if (choices.length < 3) choices = choicesFor(word, CONTENT.words, reverse);
  if (choices.length < 2) return { kind: "type", word, prompt: `Write the Auma word for “${word.meaning}”.` };
  return {
    kind: "choice", word,
    prompt: reverse ? `Which Auma word means “${word.meaning}”?` : `What does “${word.token}” mean?`,
    choices: shuffled(choices),
  };
}

function nextDue(store: LearningStore, tokens: readonly string[]): string {
  const dates = tokens.map(token => store.review(token)?.due).filter((due): due is number => due !== undefined);
  if (!dates.length) return "Finish a lesson to add its words here.";
  const remaining = Math.min(...dates) - Date.now();
  if (remaining <= 0) return "Words are ready for review now.";
  const hours = Math.max(1, Math.ceil(remaining / 3_600_000));
  if (hours < 24) return `The next review is in about ${hours} hour${hours === 1 ? "" : "s"}.`;
  const days = Math.ceil(hours / 24);
  return `The next review is in about ${days} day${days === 1 ? "" : "s"}.`;
}

export function mountPractice(
  host: HTMLElement,
  store: LearningStore,
  signal: AbortSignal,
  onChange: () => void,
  feedback?: (context: string, life: AbortSignal) => HTMLElement,
): void {
  let frame = new AbortController();
  let generation = 0;
  signal.addEventListener("abort", () => frame.abort(), { once: true });

  function screen(): { card: HTMLElement; current: () => boolean; events: AbortSignal } {
    frame.abort();
    frame = new AbortController();
    const ownGeneration = ++generation;
    const current = () => !signal.aborted && !frame.signal.aborted && generation === ownGeneration;
    const card = el("section", "lingwa-card");
    host.replaceChildren(card);
    if (signal.aborted) frame.abort();
    return { card, current, events: frame.signal };
  }

  function home(): void {
    if (signal.aborted) return;
    const { card, current, events } = screen();
    const learned = store.learned().filter(token => wordIndex.has(token));
    const due = store.due().filter(token => wordIndex.has(token));
    card.append(el("h2", "", "Practice"), el("p", "", `${learned.length} words learning · ${due.length} ready now`));
    card.append(el("p", "", "Review moves a word to a later interval after a correct answer. A missed word returns in about four hours."));
    card.append(el("p", "lingwa-muted", nextDue(store, learned)));
    if (!learned.length) {
      card.append(el("p", "lingwa-muted", "Complete a lesson on the journey to begin your practice deck."));
      return;
    }
    const actions = el("div", "lingwa-actions");
    const review = button(due.length ? `Review ${Math.min(20, due.length)} words` : "No reviews due", () => {
      if (current()) start(due.slice(0, 20), false);
    }, events, "lingwa-primary");
    review.disabled = due.length === 0;
    actions.append(review, button("Free practice", () => {
      if (current()) start(shuffled(learned).slice(0, 10), true);
    }, events));
    card.append(actions, el("p", "lingwa-muted", "Free practice leaves your review schedule unchanged."));
  }

  function start(tokens: readonly string[], free: boolean): void {
    if (signal.aborted) return;
    const learned = store.learned().map(token => wordIndex.get(token)).filter((word): word is Word => word !== undefined);
    const questions = tokens.map(token => wordIndex.get(token)).filter((word): word is Word => word !== undefined)
      .map((word, at) => questionFor(word, store, learned, at));
    if (!questions.length) { home(); return; }
    let position = 0;
    let right = 0;

    function summary(): void {
      if (signal.aborted) return;
      const { card, current, events } = screen();
      card.append(el("h2", "", "Practice complete"), el("p", "lingwa-word", `${right} / ${questions.length}`));
      card.append(el("p", "", free ? "Your review schedule is unchanged." : "Correct words rest longer. Missed words return sooner."));
      card.append(el("p", "lingwa-muted", store.notice));
      card.append(button("Practice home", () => { if (current()) home(); }, events, "lingwa-primary"));
    }

    function show(): void {
      if (signal.aborted) return;
      const { card, current, events } = screen();
      const question = questions[position];
      let submitted = false;
      let continued = false;
      let lockExtraControls = (): void => {};
      const controls: (HTMLButtonElement | HTMLInputElement)[] = [];
      card.append(el("h2", "", free ? "Free practice" : "Review"));
      card.append(el("p", "lingwa-muted", `Word ${position + 1} of ${questions.length}`));
      const progress = el("progress", "lingwa-progress");
      progress.max = questions.length;
      progress.value = position;
      progress.setAttribute("aria-label", "Practice progress");
      card.append(progress, el("h3", "", question.prompt));
      const result = el("p", "lingwa-feedback");
      result.setAttribute("role", "status");
      const actions = el("div", "lingwa-actions");
      const next = button("Continue", () => {
        if (!current() || !submitted || continued) return;
        continued = true;
        position++;
        if (position === questions.length) summary(); else show();
      }, events, "lingwa-primary");
      next.hidden = true;

      function submit(correct: boolean): void {
        if (!current() || submitted) return;
        submitted = true;
        controls.forEach(control => { control.disabled = true; });
        lockExtraControls();
        if (!free) {
          try { store.grade(question.word.token, correct); }
          catch {
            result.className = "lingwa-feedback lingwa-bad";
            result.textContent = "lingwa:review-invalid · This answer could not update its schedule. Return to practice.";
            return;
          }
        }
        if (correct) right++;
        result.className = `lingwa-feedback ${correct ? "lingwa-good" : "lingwa-bad"}`;
        result.textContent = `${correct ? "Correct." : "Review this answer."} ${question.word.token} — ${question.word.meaning}`;
        if (question.word.sentence) {
          card.insertBefore(el("p", "", question.word.sentence), result);
          if (question.word.translation) card.insertBefore(el("p", "lingwa-muted", question.word.translation), result);
        }
        next.hidden = false;
        next.focus();
        if (!free && current()) onChange();
      }

      if (question.kind === "choice") {
        const options = el("div", "lingwa-options");
        const rendered: { choice: Choice; control: HTMLButtonElement }[] = [];
        for (const choice of question.choices) {
          const control = button(choice.label, () => {
            if (!current() || submitted) return;
            submit(choice.right);
            if (!submitted || !current()) return;
            for (const item of rendered) {
              if (item.choice.right) item.control.classList.add("lingwa-good");
              else if (item.control === control) item.control.classList.add("lingwa-bad");
            }
          }, events);
          rendered.push({ choice, control });
          controls.push(control);
          options.append(control);
        }
        card.append(options);
      } else if (question.kind === "type") {
        const label = el("label", "", "Your Auma answer");
        const input = el("input");
        input.type = "text";
        input.maxLength = 128;
        input.autocomplete = "off";
        input.spellcheck = false;
        input.setAttribute("autocapitalize", "none");
        label.append(input);
        const check = button("Check answer", () => {
          if (current() && normalized(input.value)) submit(normalized(input.value) === normalized(question.word.token));
        }, events, "lingwa-primary");
        check.disabled = true;
        input.addEventListener("input", () => {
          if (current() && !submitted) check.disabled = !normalized(input.value);
        }, { signal: events });
        input.addEventListener("keydown", event => {
          if (event.key === "Enter" && !event.isComposing && current() && !submitted && normalized(input.value)) {
            event.preventDefault();
            submit(normalized(input.value) === normalized(question.word.token));
          }
        }, { signal: events });
        controls.push(input, check);
        card.append(label, check);
      } else {
        const answer = el("div", "lingwa-tiles");
        answer.setAttribute("aria-label", "Your sentence; choose a word to return it");
        const bank = el("div", "lingwa-tiles");
        bank.setAttribute("aria-label", "Available words");
        const chosen: number[] = [];
        let selectionEvents = new AbortController();
        events.addEventListener("abort", () => selectionEvents.abort(), { once: true });
        const ordered = shuffled(question.tiles.map((_, index) => index));
        if (ordered.every((index, at) => index === at)) [ordered[0], ordered[1]] = [ordered[1], ordered[0]];
        const tiles = new Map<number, HTMLButtonElement>();
        const check = button("Check sentence", () => {
          if (!current() || chosen.length !== question.tiles.length) return;
          submit(chosen.map(index => question.tiles[index]).join(" ") === question.tiles.join(" "));
        }, events, "lingwa-primary");
        check.disabled = true;
        controls.push(check);
        function update(): void {
          selectionEvents.abort();
          selectionEvents = new AbortController();
          answer.replaceChildren();
          if (!chosen.length) answer.append(el("span", "lingwa-muted", "Choose words in sentence order."));
          for (const index of chosen) {
            const tile = button(question.tiles[index], () => {
              if (!current() || submitted) return;
              const selected = chosen.indexOf(index);
              if (selected < 0) return;
              chosen.splice(selected, 1);
              const original = tiles.get(index);
              if (original) original.disabled = false;
              update();
            }, selectionEvents.signal, "lingwa-tile");
            answer.append(tile);
          }
          check.disabled = chosen.length !== question.tiles.length;
        }
        for (const index of ordered) {
          const tile = button(question.tiles[index], () => {
            if (!current() || submitted || tile.disabled) return;
            tile.disabled = true;
            chosen.push(index);
            update();
          }, events, "lingwa-tile");
          tiles.set(index, tile);
          controls.push(tile);
          bank.append(tile);
        }
        update();
        lockExtraControls = () => answer.querySelectorAll("button").forEach(tile => { tile.disabled = true; });
        card.append(answer, bank, check);
      }
      actions.append(next, button("Return to practice", () => { if (current()) home(); }, events));
      card.append(result);
      if (feedback) card.append(feedback(`practice:${question.word.token}:${question.kind}`, events));
      card.append(actions);
    }
    show();
  }
  home();
}
