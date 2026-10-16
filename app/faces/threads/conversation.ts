// SPDX-License-Identifier: AGPL-3.0-or-later
// One conversation at a time: reading a session from the node, keeping it current from the event topic, and sending
// turns. The node's saved entries are the only record. What is shown beyond them (a message on its way, a reply that is
// still streaming) is marked as such and is replaced by the saved entry. Nothing a reply says is acted on here, and a
// function-call suggestion is only ever shown.
import type { FaceClient } from "../../core/index.js";
import { visible } from "./dom.js";
import { COPY, explain, outcomeText, refusalCode } from "./copy.js";
import { PAGE, TEXT_BYTES, byteLength, clip, randomId, readOpened, readSummary, titleFrom } from "./model.js";
import type { Entry, Event, Mode, Opened, Receipt, Summary } from "./model.js";

export type Phase = "draft" | "loading" | "ready" | "failed";

export interface Turn {
  // Empty while a new chat is still being created.
  readonly session: string;
  readonly text: string;
  readonly mode: Mode;
  readonly phase: "creating" | "sending" | "sent";
  // The last saved sequence the turn was sent against.
  readonly base: number;
  readonly at: number;
}

export interface Stream {
  readonly request: string;
  readonly reservation: string;
  // The chat of the turn that admitted this stream.
  readonly session: string;
  // The turn's saved sequence in its own chat; a saved Auma entry after it is this reply.
  readonly since: number;
  readonly text: string;
  readonly index: number;
  readonly calls: number;
  readonly phase: "streaming" | "unconfirmed" | "ended" | "failed" | "cancelled";
  readonly gap: boolean;
  readonly clipped: boolean;
  readonly stopping: boolean;
  readonly finish: string | null;
  readonly receipt: Receipt | null;
  readonly code: string | null;
  readonly next: string | null;
  // The saved entry that now holds this reply.
  readonly persisted: number | null;
}

export interface Notice {
  readonly key: string;
  readonly tone: "info" | "warn" | "error";
  readonly text: string;
  readonly code: string | null;
  readonly action: { readonly label: string; readonly run: () => void } | null;
}

export interface State {
  readonly phase: Phase;
  readonly summary: Summary | null;
  readonly entries: readonly Entry[];
  // Saved entries exist before the first one shown.
  readonly earlier: boolean;
  readonly loadingEarlier: boolean;
  // The last saved sequence this face knows.
  readonly last: number;
  readonly failure: string | null;
  // Changes whenever the shown entries are replaced rather than extended at the end.
  readonly epoch: number;
  // On a replaced window: keep the reader where they were.
  readonly keep: boolean;
  readonly turn: Turn | null;
  readonly stream: Stream | null;
  readonly receipts: ReadonlyMap<number, Receipt>;
  readonly notices: readonly Notice[];
  readonly live: boolean;
}

export interface Options {
  readonly granted: ReadonlySet<string>;
  // A reader shows saved entries and nothing else: no sending, no streams, no proposals.
  readonly readOnly: boolean;
  readonly changed: () => void;
  readonly created?: (summary: Summary) => void;
}

export interface Conversation {
  readonly state: State;
  open(summary: Summary): Promise<void>;
  draft(): void;
  earlier(): Promise<void>;
  send(text: string, mode: Mode): Promise<boolean>;
  stop(): Promise<void>;
  event(event: Event): void;
  live(connected: boolean): void;
  resync(): void;
  notify(notice: Notice): void;
  dismiss(key: string): void;
  clearStream(): void;
}

type Writable<T> = { -readonly [K in keyof T]: T[K] };
type Inner = Omit<Writable<State>, "entries" | "turn" | "stream"> & {
  entries: Entry[];
  turn: Writable<Turn> | null;
  stream: Writable<Stream> | null;
};

const MAX_PAGES = 30;
const WINDOWS = [60, 10] as const;
const MAX_KEPT = 1_500;
const STREAM_CHARS = 32_768;
const QUIET_MS = 300_000;
const STREAM_QUIET_MS = 180_000;
const TICK_MS = 2_500;
const MAX_NOTICES = 4;
const MAX_RECEIPTS = 200;

export function busy(state: State): boolean {
  return state.turn !== null || state.stream?.phase === "streaming";
}

// Whether a message may be sent now: granted, not reading, not already waiting on a reply, and either a chat is open or
// a new one may be created.
export function canSend(state: State, granted: ReadonlySet<string>, readOnly: boolean): boolean {
  return !readOnly && granted.has("chat.turn") && !busy(state) && state.phase !== "loading" && state.phase !== "failed"
    && (state.phase === "ready" || granted.has("session.create"));
}

export function createConversation(client: FaceClient, signal: AbortSignal, options: Options): Conversation {
  let entries: Entry[] = [];
  const state: Inner = {
    phase: "draft", summary: null, entries, earlier: false, loadingEarlier: false, last: 0, failure: null, epoch: 0,
    keep: false, turn: null, stream: null, receipts: new Map<number, Receipt>(), notices: [], live: false,
  };
  const receipts = state.receipts as Map<number, Receipt>;
  const buffered: Entry[] = [];
  let overflow = false;
  let generation = 0;
  let catching: Promise<void> | null = null;
  let again = false;
  let watching: number | undefined;
  let activity = Date.now();
  let calls = new Set<string>();
  // Retain admitted identities after dismissal so late events cannot attach to a later turn.
  const seenRequests = new Set<string>();
  const timers = new Set<number>();
  const changed = () => { if (!signal.aborted) options.changed(); };
  const later = (ms: number, run: () => void) => {
    const id = window.setTimeout(() => { timers.delete(id); if (!signal.aborted) run(); }, ms);
    timers.add(id);
  };
  signal.addEventListener("abort", () => {
    for (const id of timers) window.clearTimeout(id);
    timers.clear();
    window.clearInterval(watching);
  }, { once: true });

  const notify = (notice: Notice) => {
    const kept = state.notices.filter(item => item.key !== notice.key);
    state.notices = [...kept, notice].slice(-MAX_NOTICES);
    changed();
  };
  const note = (key: string, tone: Notice["tone"], text: string, code: string | null = null) =>
    notify({ key, tone, text, code, action: null });
  const dismiss = (key: string) => {
    if (!state.notices.some(item => item.key === key)) return;
    state.notices = state.notices.filter(item => item.key !== key);
    changed();
  };

  const replace = (next: Entry[], earlier: boolean, keep: boolean) => {
    entries = next;
    state.entries = entries;
    state.earlier = earlier;
    state.epoch++;
    state.keep = keep;
  };

  const openPage = async (sessionId: string, after: number): Promise<Opened> => {
    const page = readOpened(await client.call("body", "session.open", {
      session_id: sessionId, after_sequence: after, limit: PAGE,
    }, { signal }));
    const first = page.entries[0];
    const last = page.entries[page.entries.length - 1];
    // The page continues exactly where it was asked to, and its end is the session's end whenever no cursor is given.
    if (page.summary.sessionId !== sessionId || (first && first.sequence !== after + 1)
      || (page.next === null && (last ? last.sequence : after) < page.summary.sequence)) {
      throw new Error("app:invalid-reply");
    }
    return page;
  };

  // The latest entries of a session. The first window starts near the end the list reported; if the pages do not
  // reach the end, a smaller window starts from the newest sequence a page reported.
  const fetchTail = async (target: Summary, token: number): Promise<Opened | null> => {
    let hint = target.sequence;
    for (const window of WINDOWS) {
      let after = Math.max(0, hint - window);
      const found: Entry[] = [];
      let summary = target;
      for (let pages = 0; pages < MAX_PAGES; pages++) {
        const page = await openPage(target.sessionId, after);
        if (token !== generation || signal.aborted) return null;
        summary = page.summary;
        found.push(...page.entries);
        if (page.next === null) return { summary, entries: found, next: null };
        after = page.next;
      }
      hint = summary.sequence;
    }
    throw new Error("app:session-too-long");
  };

  const forget = (stream: Writable<Stream>) => {
    if (stream.receipt && stream.persisted !== null) {
      receipts.set(stream.persisted, stream.receipt);
      if (receipts.size > MAX_RECEIPTS) receipts.delete(receipts.keys().next().value as number);
    }
  };

  // A saved Auma entry after a turn's base is its answer; after a stream began it is that stream's reply.
  const settle = (entry: Entry) => {
    const turn = state.turn;
    if (turn && turn.session === entry.sessionId && entry.role === "auma" && entry.sequence > turn.base) state.turn = null;
    const stream = state.stream;
    if (stream && stream.session === entry.sessionId && stream.persisted === null && entry.role === "auma"
      && entry.sequence > stream.since) {
      stream.persisted = entry.sequence;
      if (stream.receipt !== null) {
        forget(stream);
        if (stream.phase !== "failed") state.stream = null;
      }
    }
  };

  const saved = (entry: Entry): boolean => {
    const summary = state.summary;
    if (!summary || entry.sequence !== state.last + 1) return false;
    entries.push(entry);
    state.last = entry.sequence;
    state.summary = { ...summary, sequence: entry.sequence, updatedAtMs: Math.max(summary.updatedAtMs, entry.atMs) };
    if (entries.length > MAX_KEPT) replace(entries.slice(entries.length - MAX_KEPT), true, true);
    settle(entry);
    return true;
  };

  const pull = async () => {
    const summary = state.summary;
    if (state.phase !== "ready" || !summary) return;
    const token = generation;
    let after = state.last;
    for (let pages = 0; pages < MAX_PAGES; pages++) {
      const page = await openPage(summary.sessionId, after);
      if (token !== generation || signal.aborted) return;
      state.summary = page.summary.sequence >= state.last ? page.summary : state.summary;
      for (const entry of page.entries) saved(entry);
      changed();
      if (page.next === null) return;
      after = page.next;
    }
  };

  // Reads what the node saved after the last entry known. One read at a time; a request made meanwhile asks for one more.
  const catchUp = (): Promise<void> => {
    if (catching) { again = true; return catching; }
    catching = (async () => {
      do { again = false; await pull(); } while (again && !signal.aborted);
    })().catch((error: unknown) => {
      if (signal.aborted) return;
      const code = refusalCode(error);
      note("sync", "warn", explain(code), code);
    }).finally(() => { catching = null; });
    return catching;
  };

  const tick = () => {
    const streaming = state.stream?.phase === "streaming";
    if (!state.turn && !streaming) { window.clearInterval(watching); watching = undefined; return; }
    if (!state.live) void catchUp();
    const lost = state.stream;
    if (streaming && lost && Date.now() - activity > STREAM_QUIET_MS) {
      // Silence releases the composer, but only a receipt can settle this reply.
      lost.phase = "unconfirmed";
      lost.stopping = false;
      state.turn = null;
      changed();
      return;
    }
    if (state.turn && !streaming && Date.now() - activity > QUIET_MS) {
      state.turn = null;
      note("send", "warn", COPY.notices.noReply);
      changed();
    }
  };
  const watch = () => {
    activity = Date.now();
    if (watching === undefined) watching = window.setInterval(tick, TICK_MS);
  };

  const open = async (target: Summary): Promise<void> => {
    if (signal.aborted) return;
    const token = ++generation;
    buffered.length = 0;
    overflow = false;
    replace([], false, false);
    state.phase = "loading";
    state.summary = target;
    state.last = target.sequence;
    state.failure = null;
    state.loadingEarlier = false;
    changed();
    try {
      const tail = await fetchTail(target, token);
      if (!tail) return;
      replace(tail.entries.slice(), tail.entries.length > 0 && tail.entries[0].sequence > 1, false);
      state.summary = tail.summary;
      state.last = tail.summary.sequence;
      state.phase = "ready";
      for (const entry of buffered.splice(0)) {
        if (entry.sequence === state.last + 1) saved(entry);
        else if (entry.sequence > state.last + 1) overflow = true;
      }
      changed();
      if (overflow) void catchUp();
    } catch (error) {
      if (token !== generation || signal.aborted) return;
      state.phase = "failed";
      state.failure = refusalCode(error);
      changed();
    }
  };

  const draft = () => {
    generation++;
    replace([], false, false);
    state.phase = "draft";
    state.summary = null;
    state.last = 0;
    state.failure = null;
    state.loadingEarlier = false;
    changed();
  };

  const earlier = async (): Promise<void> => {
    const summary = state.summary;
    if (state.phase !== "ready" || !summary || !state.earlier || state.loadingEarlier || entries.length === 0) return;
    const token = generation;
    const first = entries[0].sequence;
    state.loadingEarlier = true;
    changed();
    try {
      const found: Entry[] = [];
      let after = Math.max(0, first - 1 - PAGE);
      while (after < first - 1) {
        const page = await openPage(summary.sessionId, after);
        if (token !== generation || signal.aborted) return;
        if (page.entries.length === 0) break;
        for (const entry of page.entries) if (entry.sequence < first) found.push(entry);
        after = page.entries[page.entries.length - 1].sequence;
      }
      // The older entries must meet the first shown one exactly, or nothing is added.
      if (found.length === 0 || found[found.length - 1].sequence !== first - 1) throw new Error("app:invalid-reply");
      replace([...found, ...entries], found[0].sequence > 1, true);
    } catch (error) {
      if (token !== generation || signal.aborted) return;
      const code = refusalCode(error);
      note("earlier", "warn", explain(code), code);
    } finally {
      if (token === generation) { state.loadingEarlier = false; changed(); }
    }
  };

  const entryEvent = (entry: Entry) => {
    const summary = state.summary;
    if (!summary || entry.sessionId !== summary.sessionId) return;
    if (state.phase === "loading") {
      if (buffered.length < 200) buffered.push(entry); else overflow = true;
      return;
    }
    if (state.phase !== "ready" || entry.sequence <= state.last) return;
    if (saved(entry)) changed();
    else void catchUp();
  };

  const fresh = (request: string, reservation: string, turn: Turn): Writable<Stream> => ({
    request, reservation, session: turn.session, since: turn.base, text: "", index: 0,
    calls: 0, phase: "streaming", gap: false, clipped: false, stopping: false, finish: null, receipt: null, code: null,
    next: null, persisted: null,
  });

  const streamFor = (request: string, reservation: string): Writable<Stream> | null => {
    let stream = state.stream;
    if (stream?.request === request) {
      if (stream.reservation !== reservation) return null;
    } else {
      if (stream || seenRequests.has(request)
        || !state.turn || state.turn.phase === "creating") return null;
      stream = fresh(request, reservation, state.turn);
      seenRequests.add(request);
      state.stream = stream;
      calls = new Set();
    }
    watch();
    return stream;
  };

  const settleStream = (stream: Writable<Stream>, phase: "ended" | "failed" | "cancelled", receipt: Receipt) => {
    stream.phase = phase;
    stream.receipt = receipt;
    stream.stopping = false;
    if (phase !== "ended") state.turn = null;
    if (stream.persisted !== null) {
      forget(stream);
      if (phase !== "failed") state.stream = null;
    } else {
      // The saved entry normally follows within moments; ask for it if the event does not bring it.
      later(900, () => { void catchUp(); });
      later(3_000, () => { void catchUp(); });
      // If it is still not saved by then, the reader may write again; the reply stays marked as not saved.
      later(8_000, () => {
        if (state.turn && state.stream === stream && stream.persisted === null) { state.turn = null; changed(); }
      });
    }
  };

  const handle = (event: Event) => {
    if (event.kind === "entry") { entryEvent(event.entry); return; }
    if (options.readOnly) return;
    switch (event.kind) {
      case "start":
        streamFor(event.request, event.reservation);
        break;
      case "delta": {
        const stream = streamFor(event.request, event.reservation);
        if (!stream || stream.receipt !== null) return;
        if (event.index >= stream.index) stream.phase = "streaming";
        if (event.index === stream.index) {
          stream.index++;
          if (event.text !== null && !stream.gap && !stream.clipped) {
            if (stream.text.length + event.text.length > STREAM_CHARS) stream.clipped = true;
            else stream.text += event.text;
          }
        } else if (event.index > stream.index) {
          stream.gap = true;
          stream.index = event.index + 1;
        }
        for (const call of event.calls) calls.add(call.id);
        stream.calls = calls.size;
        break;
      }
      case "end": {
        const stream = streamFor(event.request, event.reservation);
        if (!stream) return;
        stream.finish = event.finish;
        settleStream(stream, event.cancelled ? "cancelled" : "ended", event.receipt);
        break;
      }
      case "failed": {
        const stream = streamFor(event.request, event.reservation);
        if (!stream) return;
        stream.code = event.code;
        stream.next = event.next;
        settleStream(stream, "failed", event.receipt);
        break;
      }
      case "accepted":
        note(`proposal:${event.proposal}`, "info", `Proposal ${visible(clip(event.proposal, 12))}: ${COPY.notices.queued}`);
        break;
      case "outcome":
        note(`proposal:${event.proposal}`, event.state === "applied" ? "info" : "warn",
          `Proposal ${visible(clip(event.proposal, 12))}: ${outcomeText(event.state)}`);
        break;
      case "refused":
        note("refusal", "warn", explain(event.code), event.code);
        break;
      default:
        return;
    }
    changed();
  };

  const send = async (raw: string, mode: Mode): Promise<boolean> => {
    const text = raw.trim();
    if (text === "" || !canSend(state, options.granted, options.readOnly)) return false;
    if (byteLength(text) > TEXT_BYTES) { note("send", "warn", COPY.composer.tooLong); return false; }
    if (state.stream && state.stream.phase !== "streaming") state.stream = null;
    const known = state.phase === "ready" && state.summary !== null;
    const reading = generation;
    const turn: Writable<Turn> = {
      session: state.summary && known ? state.summary.sessionId : "", text, mode,
      phase: known ? "sending" : "creating", base: state.last, at: Date.now(),
    };
    state.turn = turn;
    dismiss("send");
    watch();
    changed();
    try {
      if (!known) {
        const summary = readSummary(await client.call("body", "session.create", {
          thread_id: randomId(), title: titleFrom(text, COPY.header.untitled), mode,
        }, { signal }));
        if (signal.aborted) return false;
        // The new chat becomes the open one, unless the reader has already moved elsewhere.
        if (state.phase === "draft" && generation === reading) {
          replace([], false, false);
          state.phase = "ready";
          state.summary = summary;
          state.last = summary.sequence;
        }
        turn.session = summary.sessionId;
        turn.base = summary.sequence;
        turn.phase = "sending";
        options.created?.(summary);
        changed();
      }
      await client.call("body", "chat.turn", {
        session_id: turn.session, expected_sequence: turn.base, text, mode,
      }, { signal });
      if (signal.aborted) return false;
      turn.phase = "sent";
      watch();
      changed();
      return true;
    } catch (error) {
      if (signal.aborted) return false;
      const code = refusalCode(error);
      if (code === "app:deadline") {
        // The node may still be working on it; the entries show what became of it.
        turn.phase = "sent";
        note("send", "warn", COPY.notices.unconfirmed, code);
        void catchUp();
        return true;
      }
      if (state.turn === turn) state.turn = null;
      if (code === "session:sequence") {
        note("send", "warn", COPY.notices.sequence, code);
        void catchUp();
      } else note("send", "error", `${COPY.notices.notSent} ${explain(code)}`, code);
      return false;
    }
  };

  const stop = async (): Promise<void> => {
    const stream = state.stream;
    if (options.readOnly || !stream || stream.phase !== "streaming" || stream.stopping) return;
    stream.stopping = true;
    changed();
    try {
      await client.call("body", "model.cancel", { request_id: stream.request, reservation_id: stream.reservation }, { signal });
      // Only the node's final receipt settles it; if that does not come, say so.
      later(6_000, () => {
        if (state.stream === stream && stream.phase === "streaming") {
          stream.stopping = false;
          note("stop", "warn", COPY.notices.stopUnconfirmed);
        }
      });
    } catch (error) {
      if (signal.aborted) return;
      stream.stopping = false;
      const code = refusalCode(error);
      note("stop", "error", explain(code), code);
    }
    changed();
  };

  return {
    state,
    open,
    draft,
    earlier,
    send,
    stop,
    event: handle,
    live(connected) { state.live = connected; changed(); },
    resync() { if (state.phase === "ready") void catchUp(); },
    notify,
    dismiss,
    clearStream() { if (state.stream && state.stream.phase !== "streaming") { state.stream = null; changed(); } },
  };
}
