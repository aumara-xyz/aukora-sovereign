// SPDX-License-Identifier: AGPL-3.0-or-later
// The transcript: the node's saved entries, then whatever is still on its way (a message being sent, a reply being
// streamed), each marked as not yet saved. All text is shown as text. A function call Auma suggests is listed with its
// name and arguments and is never run, and tool and context entries are labelled as data.
import { COPY, explain, sourceText } from "./copy.js";
import type { Conversation, State, Stream } from "./conversation.js";
import { h, icon, mark, neutralize, untrusted, visible } from "./dom.js";
import { clip } from "./model.js";
import type { Entry, Receipt } from "./model.js";
import { render } from "./text.js";
import { clock, iso, stamp } from "./time.js";

export interface TranscriptOptions {
  readonly signal: AbortSignal;
  readonly conversation: Conversation;
}

export interface Transcript {
  readonly element: HTMLElement;
  sync(): void;
  scrollToEnd(): void;
}

interface LiveRow {
  readonly root: HTMLElement;
  readonly body: HTMLElement;
  readonly foot: HTMLElement;
  text: string;
  signature: string;
}

const NEAR_END = 64;
const ARGUMENT_CHARS = 4_000;
const money = new Intl.NumberFormat(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 4 });
const count = new Intl.NumberFormat();

function usage(receipt: Receipt): string {
  return `${visible(clip(receipt.model, 60))} · ${count.format(receipt.promptTokens)} in · ` +
    `${count.format(receipt.completionTokens)} out · ${money.format(receipt.costMicroUsd / 1_000_000)}`;
}

function when(entry: Entry): HTMLElement {
  const at = iso(entry.atMs);
  const title = `${stamp(entry.atMs)} · entry ${entry.sequence} · commitment ${entry.commitment.slice(0, 12)}…`;
  return at ? h("time", { datetime: at, title }, clock(entry.atMs)) : h("span", { title });
}

function suggestions(entry: Entry): HTMLElement | null {
  if (entry.calls.length === 0) return null;
  return h("details", { class: "calls" },
    h("summary", {}, `${COPY.chat.calls} (${entry.calls.length})`),
    h("ul", {}, ...entry.calls.map(call => h("li", {},
      h("p", { class: "call-name" }, `${COPY.chat.call}: `, untrusted("code", {}, call.name)),
      untrusted("pre", { class: "call-arguments" }, clip(call.arguments, ARGUMENT_CHARS))))));
}

function who(): HTMLElement {
  return h("div", { class: "who" }, mark(), h("span", {}, COPY.chat.auma));
}

function entryNode(entry: Entry): HTMLElement {
  const base = { class: `msg ${entry.role}`, "data-seq": String(entry.sequence) };
  if (entry.role === "owner") {
    return h("article", base,
      h("div", { class: "bubble" }, ...render(entry.content)), h("p", { class: "meta" }, when(entry)));
  }
  if (entry.role === "auma") {
    return h("article", base, who(), h("div", { class: "prose" }, ...render(entry.content)), suggestions(entry),
      h("p", { class: "meta" }, when(entry), h("span", { class: "usage" })));
  }
  if (entry.role === "tool") {
    return h("article", base, h("details", { class: "tool-result" },
      h("summary", {}, COPY.chat.tool, entry.callId !== null && h("span", {}, ` · ${visible(clip(entry.callId, 40))}`)),
      h("p", { class: "flag" }, COPY.chat.toolData),
      untrusted("pre", {}, entry.content)));
  }
  return h("article", base,
    h("p", { class: "flag" }, `${COPY.chat.context} · ${sourceText(entry.source.kind)}. ${COPY.chat.contextData}`),
    h("div", { class: "prose" }, ...render(entry.content)),
    h("p", { class: "meta" }, when(entry)));
}

function dots(): HTMLElement {
  return h("span", { class: "dots", "aria-hidden": "true" }, h("i"), h("i"), h("i"));
}

export function createTranscript(options: TranscriptOptions): Transcript {
  const { signal, conversation } = options;
  const earlierButton = h("button", { type: "button", class: "more", hidden: "" }, COPY.chat.earlier);
  const banner = h("p", { class: "banner", role: "status", hidden: "" });
  const entries = h("div", { class: "entries" });
  const tail = h("div", { class: "tail" });
  const scroller = h("div", {
    class: "transcript", role: "log", "aria-live": "polite", "aria-relevant": "additions", "aria-label": "Messages", tabindex: "0",
  }, h("div", { class: "earlier-row" }, earlierButton), banner, entries, tail);
  const jump = h("button", { type: "button", class: "jump", hidden: "" }, icon("down"), COPY.chat.jump);
  const element = h("div", { class: "stage-body" }, scroller, jump);

  let epoch = -1;
  let session: string | null = null;
  let last = 0;
  let stick = true;
  let grew = false;
  const nodes = new Map<number, HTMLElement>();
  const withReceipt = new Set<number>();
  // The tail's own elements, kept so a streaming reply updates in place instead of being rebuilt.
  let pending: HTMLElement | null = null;
  let pendingText = "";
  let live: LiveRow | null = null;
  let waiting: HTMLElement | null = null;

  const scrollToEnd = () => {
    scroller.scrollTop = scroller.scrollHeight;
    stick = true;
    jump.hidden = true;
  };
  scroller.addEventListener("scroll", () => {
    stick = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < NEAR_END;
    if (stick) jump.hidden = true;
  }, { signal });
  jump.addEventListener("click", scrollToEnd, { signal });
  earlierButton.addEventListener("click", () => { void conversation.earlier(); }, { signal });

  const syncEntries = (st: State) => {
    const id = st.summary?.sessionId ?? null;
    if (st.epoch !== epoch || id !== session) {
      const fromEnd = scroller.scrollHeight - scroller.scrollTop;
      const keep = st.keep && id === session;
      nodes.clear();
      withReceipt.clear();
      entries.replaceChildren(...st.entries.map(entry => {
        const node = entryNode(entry);
        nodes.set(entry.sequence, node);
        return node;
      }));
      epoch = st.epoch;
      session = id;
      last = st.entries.length > 0 ? st.entries[st.entries.length - 1].sequence : 0;
      // Older entries were added above the reader: put them back where they were.
      if (keep) {
        scroller.scrollTop = Math.max(0, scroller.scrollHeight - fromEnd);
        stick = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < NEAR_END;
      } else stick = true;
      return;
    }
    let at = st.entries.length;
    while (at > 0 && st.entries[at - 1].sequence > last) at--;
    for (; at < st.entries.length; at++) {
      const entry = st.entries[at];
      const node = entryNode(entry);
      nodes.set(entry.sequence, node);
      entries.append(node);
      last = entry.sequence;
      grew = true;
    }
  };

  const syncReceipts = (st: State) => {
    for (const [sequence, receipt] of st.receipts) {
      if (withReceipt.has(sequence)) continue;
      const slot = nodes.get(sequence)?.querySelector(".usage");
      if (!slot) continue;
      slot.textContent = ` · ${usage(receipt)}`;
      slot.setAttribute("title", `${COPY.chat.receipt} ${receipt.seq}`);
      withReceipt.add(sequence);
    }
  };

  const foot = (stream: Stream): Array<Node | string> => {
    if (stream.phase === "streaming") {
      const parts: Array<Node | string> = [dots(), stream.stopping ? COPY.chat.stopping : COPY.chat.replying];
      if (stream.calls > 0) parts.push(` ${COPY.chat.calls} (${stream.calls})`);
      return parts;
    }
    const parts: Array<Node | string> = [];
    if (stream.phase === "failed") {
      const code = stream.code ?? "app:service-failed";
      parts.push(h("strong", {}, COPY.chat.failed), " ", explain(code), " ", h("code", {}, code));
      if (stream.next) parts.push(" ", ...neutralize(clip(stream.next, 400)));
    } else parts.push(stream.phase === "cancelled" ? COPY.chat.stopped : COPY.chat.unsaved);
    if (stream.receipt) parts.push(" ", h("span", { class: "usage" }, `· ${usage(stream.receipt)}`));
    parts.push(" ", h("button", { type: "button", class: "link" }, COPY.chat.dismiss));
    return parts;
  };

  const syncStream = (stream: Stream) => {
    if (!live) {
      const row: LiveRow = {
        root: h("article", { class: "msg auma live", "aria-live": "off" }),
        body: h("div", { class: "prose" }),
        foot: h("p", { class: "meta live-foot", role: "status" }),
        text: "\u0000",
        signature: "",
      };
      row.root.append(who(), row.body, row.foot);
      tail.append(row.root);
      live = row;
    }
    if (live.text !== stream.text) {
      live.body.replaceChildren(...render(stream.text));
      live.text = stream.text;
      grew = true;
    }
    const signature = `${stream.phase}:${stream.stopping}:${stream.calls}:${stream.gap}:${stream.clipped}`;
    if (live.signature === signature) return;
    live.signature = signature;
    const parts = foot(stream);
    if (stream.gap) parts.push(" ", COPY.chat.partial);
    else if (stream.clipped) parts.push(" ", COPY.chat.clipped);
    live.foot.replaceChildren(...parts);
    live.foot.querySelector("button")?.addEventListener("click", () => conversation.clearStream(), { signal });
    live.root.dataset.phase = stream.phase;
    grew = true;
  };

  const syncTail = (st: State) => {
    const turn = st.turn;
    const id = st.summary?.sessionId ?? null;
    const mine = turn !== null && id !== null && turn.session === id;
    // The message is shown here until the node's saved entry for it exists.
    if (mine && st.last <= turn.base) {
      if (!pending) {
        pending = h("article", { class: "msg owner pending" }, h("div", { class: "bubble" }), h("p", { class: "meta" }));
        tail.prepend(pending);
        pendingText = "\u0000";
        grew = true;
      }
      if (pendingText !== turn.text) {
        pendingText = turn.text;
        pending.querySelector(".bubble")?.replaceChildren(...render(turn.text));
      }
      const meta = pending.querySelector(".meta");
      if (meta) meta.textContent = turn.phase === "creating" ? COPY.chat.creating : COPY.chat.sending;
    } else if (pending) { pending.remove(); pending = null; }

    const stream = st.stream;
    const shown = stream !== null && id !== null && stream.session === id && (stream.phase === "failed" || stream.persisted === null);
    if (stream && shown) syncStream(stream);
    else if (live) { live.root.remove(); live = null; }

    const streaming = shown && stream.phase === "streaming";
    if (mine && turn.phase === "sent" && !streaming) {
      if (!waiting) {
        waiting = h("p", { class: "msg waiting", role: "status" }, dots(), COPY.chat.waiting);
        tail.append(waiting);
        grew = true;
      }
    } else if (waiting) { waiting.remove(); waiting = null; }
  };

  const syncBanner = (st: State) => {
    let parts: Array<Node | string> | null = null;
    if (st.phase === "loading") parts = [COPY.chat.loading];
    else if (st.phase === "failed") {
      const code = st.failure ?? "app:service-failed";
      parts = [`${explain(code)} `, h("code", {}, code)];
    } else if (st.phase === "ready" && st.entries.length === 0 && tail.childElementCount === 0) parts = [COPY.chat.empty];
    if (parts) banner.replaceChildren(...parts);
    banner.hidden = parts === null;
  };

  const sync = () => {
    const st = conversation.state;
    grew = false;
    syncEntries(st);
    syncReceipts(st);
    syncTail(st);
    syncBanner(st);
    earlierButton.hidden = !(st.phase === "ready" && st.earlier);
    earlierButton.disabled = st.loadingEarlier;
    earlierButton.textContent = st.loadingEarlier ? COPY.chat.loadingEarlier : COPY.chat.earlier;
    scroller.setAttribute("aria-busy", String(st.phase === "loading"));
    if (stick) scrollToEnd();
    else if (grew) jump.hidden = false;
  };

  return { element, sync, scrollToEnd };
}
