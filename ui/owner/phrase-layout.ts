// SPDX-License-Identifier: AGPL-3.0-or-later
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

export function renderPhrase(words: readonly string[]): HTMLElement {
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
    row.append(make("span", String(index + 2), "word-number"), make("strong", word));
    return row;
  });
  return bandContainer(anchor, rows);
}

export function phraseInputs(signal: AbortSignal): { element: HTMLElement; inputs: HTMLInputElement[] } {
  const inputs: HTMLInputElement[] = [];
  const rows = Array.from({ length: 7 }, (_, index) => {
    const label = make("label", `Word ${index + 1}`, "owner-input");
    const field = make("input");
    field.type = "password";
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
    label.append(field);
    inputs.push(field);
    return label;
  });
  const anchor = make("section", "", "phrase-anchor band-anchor");
  anchor.append(rows[0]);
  return { element: bandContainer(anchor, rows.slice(1)), inputs };
}

export function phraseAcknowledgement(signal: AbortSignal, refresh = false): {
  element: HTMLElement; checked(): boolean; onChange(action: () => void): void;
} {
  const result = make("div", "", "phrase-acknowledgement");
  const warning = make("p", refresh
    ? "Keep these words. Without them or a retained recovery copy, you cannot open this identity."
    : "If you lose these seven words, this identity is lost forever. A new phrase starts a new identity.", "phrase-warning");
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
  if (code === "aumlok:word-mismatch" || code === "aumlok:phrase-invalid") return "Check the marked words.";
  if (code === "aumlok:enrolment-closed") return "A passkey is enrolled. Sign in to continue.";
  if (code === "aumlok:ceremony-expired") return "This request expired. Start the step again.";
  if (code.includes("handoff")) return "Close this pane and reopen Passkey to finish signing in.";
  if (code === "aumlok:already-bound" || code === "aumlok:binding-state") return "This identity is already bound. Sign in to continue.";
  if (code.includes("unavailable")) return "This step is unavailable. Try again shortly.";
  return "This step could not be confirmed. Try again.";
}
