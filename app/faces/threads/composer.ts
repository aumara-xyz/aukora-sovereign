// SPDX-License-Identifier: AGPL-3.0-or-later
// The composer and the notices above it. The frame is sandboxed without allow-forms, so there is no form here: a
// message goes out from the send button's click or from Enter in the box. Send turns into Stop while Auma is replying.
import { COPY } from "./copy.js";
import { serviceState } from "../../core/service-state.js";
import { canSend } from "./conversation.js";
import type { Conversation, Notice } from "./conversation.js";
import { h, icon } from "./dom.js";
import { TEXT_BYTES, byteLength } from "./model.js";
import type { Mode } from "./model.js";

export interface ComposerOptions {
  readonly signal: AbortSignal;
  readonly conversation: Conversation;
  readonly granted: ReadonlySet<string>;
}

export interface Composer {
  readonly element: HTMLElement;
  sync(): void;
  focus(): void;
  setMode(mode: Mode): void;
}

const MAX_ROWS = 8;

export function createComposer(options: ComposerOptions): Composer {
  const { signal, conversation, granted } = options;
  const notices = h("div", { class: "notices" });
  const input = h("textarea", {
    id: "composer-input", class: "draft", rows: "1", maxlength: String(TEXT_BYTES), spellcheck: "true",
    placeholder: COPY.composer.placeholder, "aria-describedby": "composer-hint",
  });
  const mode = h("select", { id: "composer-mode", class: "mode" },
    h("option", { value: "chat" }, COPY.composer.chat), h("option", { value: "build" }, COPY.composer.build));
  const hint = h("p", { id: "composer-hint", class: "hint", role: "status" });
  const action = h("button", { type: "button", class: "send" });
  const card = h("div", { class: "composer-card" },
    h("label", { for: "composer-input", class: "sr" }, COPY.composer.label), input,
    h("div", { class: "composer-row" }, h("label", { for: "composer-mode", class: "sr" }, COPY.composer.mode), mode, action));
  const element = h("div", { class: "dock" }, notices, card, hint);

  let submitting = false;
  let shown = "";

  const length = () => byteLength(input.value);
  const draftOk = () => input.value.trim() !== "" && length() <= TEXT_BYTES;

  const syncNotices = (list: readonly Notice[]) => {
    const signature = list.map(item => `${item.key}\u0000${item.tone}\u0000${item.text}\u0000${item.code ?? ""}`).join("\u0001");
    if (signature === shown) return;
    shown = signature;
    notices.replaceChildren(...list.map(item => {
      const dismiss = h("button", { type: "button", class: "icon-button", "aria-label": COPY.notices.dismiss }, icon("close"));
      dismiss.addEventListener("click", () => conversation.dismiss(item.key), { signal });
      const text = h("span", { class: "notice-text" }, item.text);
      const state = item.code ? serviceState(item.code) : null;
      const calm = state !== null && state.kind !== "failure";
      const row = h("div", { class: "notice", "data-tone": calm ? "info" : item.tone }, text);
      if (state) {
        row.dataset.serviceState = state.kind;
        text.setAttribute("role", state.kind === "failure" ? "alert" : "status");
      }
      if (item.action && (state?.kind !== "unavailable" || state.retryable)) {
        const run = item.action.run;
        const button = h("button", { type: "button", class: "link" }, item.action.label);
        button.addEventListener("click", () => run(), { signal });
        row.append(" ", button);
      }
      row.append(dismiss);
      return row;
    }));
  };

  const sync = () => {
    const st = conversation.state;
    const granting = granted.has("chat.turn");
    const streaming = st.stream?.phase === "streaming";
    const waiting = st.turn !== null && st.turn.phase === "sent";
    const stopping = streaming || waiting;
    input.disabled = !granting;
    input.placeholder = st.phase === "draft" ? COPY.composer.placeholderNew : COPY.composer.placeholder;
    // A turn is in flight: Stop takes the button's place, and it works once the stream's identity is known.
    action.replaceChildren(icon(stopping ? "stop" : "send"));
    action.dataset.kind = stopping ? "stop" : "send";
    if (stopping) {
      action.setAttribute("aria-label", streaming ? COPY.composer.stop : COPY.composer.stopWait);
      action.title = streaming ? COPY.composer.stop : COPY.composer.stopWait;
      action.disabled = !streaming || st.stream?.stopping === true || !granted.has("model.cancel");
    } else {
      action.setAttribute("aria-label", COPY.composer.send);
      action.title = COPY.composer.send;
      action.disabled = !canSend(st, granted, false) || !draftOk() || submitting;
    }
    const bytes = length();
    if (!granting) hint.textContent = COPY.composer.unavailable;
    else if (bytes > TEXT_BYTES) hint.textContent = `${COPY.composer.tooLong} ${bytes.toLocaleString()} / ${TEXT_BYTES.toLocaleString()} bytes.`;
    else if (st.turn?.phase === "creating") hint.textContent = COPY.chat.creating;
    else if (st.turn?.phase === "sending") hint.textContent = COPY.chat.sending;
    else if (st.turn !== null || streaming) hint.textContent = COPY.composer.busy;
    else if (bytes > TEXT_BYTES * 0.9) hint.textContent = `${bytes.toLocaleString()} / ${TEXT_BYTES.toLocaleString()} bytes.`;
    else hint.textContent = mode.value === "build" ? COPY.hero.modeBuild : "";
    hint.hidden = hint.textContent === "";
    syncNotices(st.notices);
  };

  const resize = () => { input.rows = Math.min(MAX_ROWS, Math.max(1, input.value.split("\n").length)); };

  const submit = async () => {
    if (submitting || !draftOk() || !canSend(conversation.state, granted, false)) return;
    const text = input.value;
    submitting = true;
    input.value = "";
    resize();
    sync();
    const sent = await conversation.send(text, mode.value === "build" ? "build" : "chat");
    submitting = false;
    // A message that did not go is given back, ahead of anything typed since.
    if (!sent && !signal.aborted) {
      input.value = input.value === "" ? text : `${text}\n${input.value}`;
      resize();
    }
    sync();
    if (!signal.aborted) input.focus();
  };

  input.addEventListener("input", () => { resize(); sync(); }, { signal });
  input.addEventListener("keydown", event => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing || event.keyCode === 229) return;
    event.preventDefault();
    void submit();
  }, { signal });
  mode.addEventListener("change", () => sync(), { signal });
  action.addEventListener("click", () => {
    if (action.dataset.kind === "stop") void conversation.stop();
    else void submit();
  }, { signal });

  return {
    element,
    sync,
    focus: () => input.focus(),
    setMode(next) { mode.value = next; sync(); },
  };
}
