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
    band.append(make("h3", name, "word-label"), rows[index * 2], rows[index * 2 + 1]);
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
  anchor.append(make("h3", "ANCHOR", "word-label"), boxes);
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
  return { element: bandContainer(anchor, rows.slice(1)), inputs };
}

export function recoveryInput(signal: AbortSignal): {
  element: HTMLElement; read(): Promise<string>; clear(): void;
} {
  checkAbort(signal);
  const maximum = 1_024;
  const result = make("div", "", "owner-input");
  const fileLabel = make("label", "Choose your Light recovery file", "owner-input");
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
  Object.assign(paste.style, { width: "100%", font: "inherit", color: "var(--text)",
    background: "var(--layer1)", border: "1px solid var(--border)", borderRadius: ".65rem",
    padding: ".7rem .85rem", resize: "vertical" });
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
  label.append(tick, make("span", "I know them by heart"));
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
