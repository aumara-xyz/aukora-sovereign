// SPDX-License-Identifier: AGPL-3.0-or-later
import { checkAbort } from "./abort.js";

const BANDS = ["ROOT", "UNITE", "RISE"] as const;

function make<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", className = ""): HTMLElementTagNameMap[K] {
  const item = document.createElement(tag);
  item.textContent = text;
  item.className = className;
  return item;
}

function bandContainer(anchor: HTMLElement, rows: readonly HTMLElement[]): HTMLElement {
  const result = make("div", "", "phrase-composition");
  const bands = make("div", "", "phrase-bands");
  for (let index = 0; index < BANDS.length; index++) {
    const name = BANDS[index];
    const band = make("section", "", `phrase-band band-${name.toLowerCase()}`);
    const pair = make("div", "", "phrase-pair");
    pair.append(rows[index * 2], rows[index * 2 + 1]);
    band.append(make("h3", name, "word-label"), pair);
    bands.append(band);
  }
  result.append(anchor, bands);
  return result;
}

export function renderPhrase(words: readonly string[], signal: AbortSignal): HTMLElement {
  checkAbort(signal);
  if (words.length !== 7 || !/^[a-z]{6}$/.test(words[0])
    || words.slice(1).some((word, at) => !/^[a-z]+$/.test(word) || word[0] !== words[0][at])) {
    throw new Error("aumlok:phrase-invalid");
  }
  const anchor = make("section", "", "phrase-anchor band-anchor");
  const boxes = make("div", "", "anchor-boxes");
  boxes.setAttribute("aria-label", `Word 1: ${words[0]}`);
  for (const letter of words[0]) {
    const box = make("span", letter.toUpperCase(), "anchor-box");
    box.setAttribute("aria-hidden", "true");
    boxes.append(box);
  }
  anchor.append(make("h3", "WORD 1 · ANCHOR", "word-label"), boxes);
  const rows = words.slice(1).map((word, index) => {
    const row = make("div", "", "word-tile");
    const initial = make("span", word[0].toUpperCase(), "word-initial");
    initial.setAttribute("aria-hidden", "true");
    row.append(initial, make("strong", word));
    row.setAttribute("aria-label", `Word ${index + 2}: ${word}`);
    return row;
  });
  const result = bandContainer(anchor, rows);
  result.classList.add("phrase-display");
  for (const event of ["copy", "cut", "dragstart"] as const) {
    result.addEventListener(event, action => action.preventDefault(), { signal });
  }
  const fit = (): void => {
    if (signal.aborted || !result.isConnected) return;
    for (const row of rows) {
      const word = row.querySelector("strong");
      if (!word) continue;
      word.style.removeProperty("font-size");
      if (word.clientWidth === 0 || word.scrollWidth <= word.clientWidth) continue;
      const size = Number.parseFloat(getComputedStyle(word).fontSize);
      word.style.fontSize = `${size * word.clientWidth / word.scrollWidth}px`;
    }
  };
  const observer = new ResizeObserver(fit);
  rows.forEach(row => observer.observe(row));
  signal.addEventListener("abort", () => observer.disconnect(), { once: true });
  void document.fonts.ready.then(fit);
  return result;
}

export function phraseInputs(signal: AbortSignal): { element: HTMLElement; inputs: HTMLInputElement[] } {
  checkAbort(signal);
  const inputs: HTMLInputElement[] = [];
  const rows = Array.from({ length: 7 }, (_, index) => {
    const label = make("label", `Word ${index + 1}`, "owner-input");
    const field = make("input");
    field.type = "text";
    field.className = "phrase-secret";
    field.maxLength = 64;
    field.autocomplete = "off";
    field.spellcheck = false;
    field.setAttribute("autocapitalize", "off");
    field.setAttribute("autocorrect", "off");
    field.setAttribute("data-1p-ignore", "true");
    field.setAttribute("aria-label", `Word ${index + 1}`);
    for (const event of ["paste", "drop", "copy", "cut"] as const) {
      field.addEventListener(event, action => action.preventDefault(), { signal });
    }
    field.addEventListener("beforeinput", event => {
      if (["insertFromPaste", "insertFromDrop", "deleteByCut", "insertReplacementText"].includes(event.inputType)) {
        event.preventDefault();
      }
    }, { signal });
    field.addEventListener("input", () => { field.removeAttribute("aria-invalid"); }, { signal });
    const entry = make("span", "", "phrase-entry");
    const show = make("button", "Show", "phrase-show secondary");
    show.type = "button";
    show.setAttribute("aria-label", `Show word ${index + 1}`);
    show.setAttribute("aria-pressed", "false");
    show.addEventListener("click", () => {
      const visible = !field.classList.contains("phrase-visible");
      field.classList.toggle("phrase-visible", visible);
      show.textContent = visible ? "Hide" : "Show";
      show.setAttribute("aria-label", `${visible ? "Hide" : "Show"} word ${index + 1}`);
      show.setAttribute("aria-pressed", String(visible));
    }, { signal });
    entry.append(field, show);
    label.append(entry);
    inputs.push(field);
    return label;
  });
  const anchor = make("section", "", "phrase-anchor band-anchor");
  anchor.append(rows[0]);
  const element = bandContainer(anchor, rows.slice(1));
  element.classList.add("phrase-inputs");
  return { element, inputs };
}

/** What was typed is compared as letters only: case, spaces, punctuation and look-alike forms never decide it. */
export function normaliseWord(value: string): string {
  return value.normalize("NFKC").toLowerCase().replace(/[^a-z]/g, "");
}

export type PhraseForm = {
  element: HTMLElement;
  /** Every field, for clearing. */
  all(): HTMLInputElement[];
  /** The seven words as typed, normalised: the anchor from its six boxes, then the six words in order. */
  values(): string[];
  complete(): boolean;
  /** Mark the anchor row or one of the six word rows (0 to 5) as not matching. */
  flagAnchor(bad: boolean): void;
  flagWord(index: number, bad: boolean): void;
  focusAnchor(): void;
  focusWord(index: number): void;
  onChange(listener: () => void): void;
};

/** The words screen, blank: the anchor typed into its six gold boxes, and under them ROOT, UNITE and RISE with two rows each.
 *  Each row carries the gold letter badge of its anchor letter, filled in as the anchor is typed. Words are visible as typed. */
export function phraseForm(signal: AbortSignal): PhraseForm {
  checkAbort(signal);
  const listeners: Array<() => void> = [];
  const changed = (): void => listeners.forEach(listener => listener());
  const blockedInput = (field: HTMLInputElement, allowPaste: boolean): void => {
    for (const event of ["drop", "copy", "cut", ...(allowPaste ? [] : ["paste"])] as const) {
      field.addEventListener(event, action => action.preventDefault(), { signal });
    }
    field.addEventListener("beforeinput", event => {
      if (["insertFromDrop", "deleteByCut", "insertReplacementText", ...(allowPaste ? [] : ["insertFromPaste"])].includes(event.inputType)) {
        event.preventDefault();
      }
    }, { signal });
  };
  const plain = (field: HTMLInputElement, label: string): void => {
    field.type = "text";
    field.autocomplete = "off";
    field.spellcheck = false;
    field.setAttribute("autocapitalize", "off");
    field.setAttribute("autocorrect", "off");
    field.setAttribute("data-1p-ignore", "true");
    field.setAttribute("aria-label", label);
  };

  const element = make("div", "", "phrase-composition phrase-form");
  const anchor = make("section", "", "phrase-anchor band-anchor");
  const row = make("div", "", "anchor-boxes");
  const boxes = Array.from({ length: 6 }, (_, at) => {
    const box = make("input", "", "anchor-box");
    plain(box, `Letter ${at + 1} of the first word`);
    box.maxLength = 6;
    row.append(box);
    return box;
  });
  anchor.append(row);

  const badges: HTMLElement[] = [];
  const inputs: HTMLInputElement[] = [];
  const tiles: HTMLElement[] = [];
  const hints: HTMLElement[] = [];
  const bands = make("div", "", "phrase-bands");
  for (let band = 0; band < BANDS.length; band++) {
    const section = make("section", "", `phrase-band band-${BANDS[band].toLowerCase()}`);
    const pair = make("div", "", "phrase-pair");
    for (let side = 0; side < 2; side++) {
      const at = band * 2 + side;
      const tile = make("label", "", "word-tile entry-tile");
      const badge = make("span", "", "word-initial");
      badge.setAttribute("aria-hidden", "true");
      const field = make("input");
      plain(field, `Word ${at + 2}`);
      field.maxLength = 64;
      const hint = make("span", "", "word-hint");
      hint.setAttribute("aria-hidden", "true");
      tile.append(badge, field, hint);
      pair.append(tile);
      badges.push(badge);
      inputs.push(field);
      tiles.push(tile);
      hints.push(hint);
      blockedInput(field, false);
      field.addEventListener("input", () => { field.removeAttribute("aria-invalid"); refresh(); changed(); }, { signal });
    }
    section.append(make("h3", BANDS[band], "word-label"), pair);
    bands.append(section);
  }
  element.append(anchor, bands);

  const letter = (at: number): string => normaliseWord(boxes[at].value).charAt(0);
  function refresh(): void {
    inputs.forEach((field, at) => {
      const expected = letter(at);
      badges[at].textContent = expected.toUpperCase();
      const first = normaliseWord(field.value).charAt(0);
      const off = expected !== "" && first !== "" && first !== expected;
      tiles[at].toggleAttribute("data-off", off);
      hints[at].textContent = off ? `needs ${expected.toUpperCase()}` : "";
    });
  }

  boxes.forEach((box, at) => {
    blockedInput(box, true);
    box.addEventListener("input", () => {
      box.removeAttribute("aria-invalid");
      // Typing, or pasting the whole first word, fills the boxes from here on; each box keeps one letter.
      const typed = normaliseWord(box.value);
      let cursor = at;
      for (const character of typed) { if (cursor < 6) boxes[cursor++].value = character; }
      if (typed.length === 0) box.value = "";
      anchor.querySelectorAll("[aria-invalid]").forEach(node => node.removeAttribute("aria-invalid"));
      if (typed.length > 0) boxes[Math.min(cursor, 5)].focus();
      refresh();
      changed();
    }, { signal });
    box.addEventListener("keydown", event => {
      if (event.key === "Backspace" && box.value === "" && at > 0) {
        event.preventDefault();
        boxes[at - 1].value = "";
        boxes[at - 1].focus();
        refresh();
        changed();
      } else if (event.key === "ArrowLeft" && at > 0) boxes[at - 1].focus();
      else if (event.key === "ArrowRight" && at < 5) boxes[at + 1].focus();
    }, { signal });
    box.addEventListener("focus", () => box.select(), { signal });
  });
  refresh();

  return {
    element,
    all: () => [...boxes, ...inputs],
    values: () => [boxes.map((box, at) => letter(at)).join(""), ...inputs.map(field => normaliseWord(field.value))],
    complete: () => boxes.every((_, at) => letter(at) !== "") && inputs.every(field => normaliseWord(field.value) !== ""),
    flagAnchor(bad) { boxes.forEach(box => box.toggleAttribute("aria-invalid", bad)); if (bad) boxes.forEach(box => box.setAttribute("aria-invalid", "true")); },
    flagWord(index, bad) { inputs[index].toggleAttribute("aria-invalid", bad); if (bad) inputs[index].setAttribute("aria-invalid", "true"); },
    focusAnchor() { (boxes.find(box => box.value === "") ?? boxes[0]).focus(); },
    focusWord(index) { inputs[index].focus(); },
    onChange(listener) { listeners.push(listener); },
  };
}

export function recoveryInput(signal: AbortSignal): {
  element: HTMLElement; read(): Promise<string>; clear(): void;
} {
  checkAbort(signal);
  const maximum = 1_024;
  const result = make("div", "", "owner-input owner-recovery");
  const fileLabel = make("label", "Choose your recovery file", "owner-input");
  const file = make("input");
  file.type = "file";
  file.accept = ".json,application/json,text/plain";
  fileLabel.append(file);
  const pasteLabel = make("label", "Or paste the sealed envelope", "owner-input");
  const paste = make("textarea");
  paste.rows = 5;
  paste.maxLength = maximum;
  paste.autocomplete = "off";
  paste.spellcheck = false;
  paste.setAttribute("autocapitalize", "off");
  paste.setAttribute("autocorrect", "off");
  pasteLabel.append(paste);
  file.addEventListener("change", () => { paste.value = ""; }, { signal });
  paste.addEventListener("input", () => { file.value = ""; }, { signal });
  const clear = (): void => { file.value = ""; paste.value = ""; };
  signal.addEventListener("abort", clear, { once: true });
  result.append(fileLabel, pasteLabel);
  return { element: result, clear, async read() {
    checkAbort(signal);
    const chosen = file.files?.[0];
    let raw: string;
    if (chosen) {
      if (chosen.size === 0 || chosen.size > maximum) throw new Error("aumlok:envelope-too-large");
      const bytes = new Uint8Array(await chosen.arrayBuffer());
      try {
        checkAbort(signal);
        raw = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        checkAbort(signal);
        throw new Error("aumlok:envelope-json");
      } finally { bytes.fill(0); }
    } else raw = paste.value;
    if (!raw || new TextEncoder().encode(raw).length > maximum) throw new Error("aumlok:envelope-too-large");
    return raw;
  } };
}

export function phraseAcknowledgement(signal: AbortSignal, refresh = false): {
  element: HTMLElement; checked(): boolean; onChange(action: () => void): void;
} {
  const result = make("div", "", "phrase-acknowledgement");
  const warning = make("p", refresh
    ? "Keep these words. Without them or a retained recovery copy, you cannot open this identity."
    : "Keep these seven words and your recovery file. Restoring this identity needs both.", "phrase-warning");
  const label = make("label", "", "phrase-tick");
  const tick = make("input");
  tick.type = "checkbox";
  label.append(tick, make("span", "I have written them down"));
  result.append(warning, label);
  return { element: result, checked: () => tick.checked,
    onChange(action) { tick.addEventListener("change", action, { signal }); } };
}

export function explainOwnerError(error: unknown): string {
  if (error instanceof DOMException && ["NotAllowedError", "AbortError"].includes(error.name)) {
    return "Passkey cancelled. Try again when ready.";
  }
  const code = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  if (code === "aumlok:word-mismatch") return "Check the marked words.";
  if (code === "aumlok:phrase-invalid") return "Check all seven words, in order.";
  if (code === "aumlok:envelope-authentication") return "The words could not open this recovery file. Check both and enter the words again.";
  if (code.startsWith("aumlok:envelope-")) return "Choose or paste your original Light recovery file, then enter the seven words again.";
  if (code === "aumlok:enrolment-closed") return "A passkey is enrolled. Sign in to continue.";
  if (code === "aumlok:ceremony-expired") return "This request expired. Start the step again.";
  if (code.includes("handoff")) return "Close this pane and reopen Passkey to finish signing in.";
  if (code === "aumlok:already-bound" || code === "aumlok:binding-state") return "This identity is already bound. Sign in to continue.";
  if (code.includes("unavailable")) return "This step is unavailable. Try again shortly.";
  return "This step could not be confirmed. Try again.";
}
