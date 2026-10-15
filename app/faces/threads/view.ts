// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FaceClient, JsonValue } from "../../core/index.js";
import { record, refusalText } from "../runtime.js";

interface SessionSelection { session_id: string; sequence: number; mode: "chat" | "build" }

function selection(value: unknown): SessionSelection {
  const data = record(value);
  if (typeof data.session_id !== "string" || !/^[0-9a-f]{32}$/.test(data.session_id) ||
      !Number.isSafeInteger(data.sequence) || (data.sequence as number) < 0 ||
      (data.mode !== "chat" && data.mode !== "build")) throw new Error("app:session-reply");
  return { session_id: data.session_id, sequence: data.sequence as number, mode: data.mode };
}

export function mountThreads(root: HTMLElement, client: FaceClient, signal: AbortSignal, face: string) {
  const list = document.createElement("ul");
  const messages = document.createElement("div");
  messages.setAttribute("aria-live", "polite");
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  const refresh = document.createElement("button");
  refresh.textContent = "Refresh sessions";
  const form = document.createElement("form");
  const input = document.createElement("textarea");
  input.setAttribute("aria-label", "Message Auma");
  input.placeholder = "Message Auma";
  input.maxLength = 32_768;
  const send = document.createElement("button");
  send.type = "submit";
  send.textContent = "Send";
  send.disabled = true;
  let current: SessionSelection | undefined;
  let opening = 0;
  let busy = false;
  let needsRefresh = false;

  const showEntry = (value: unknown) => {
    const entry = record(value);
    if (typeof entry.content !== "string" || typeof entry.role !== "string") throw new Error("app:session-reply");
    const article = document.createElement("article");
    const author = document.createElement("strong");
    author.textContent = entry.role;
    const text = document.createElement("p");
    text.textContent = entry.content;
    article.append(author, text);
    messages.append(article);
  };
  const open = async (summary: JsonValue) => {
    const requested = ++opening;
    send.disabled = true;
    current = undefined;
    try {
      const session = selection(summary);
      const reply = record(await client.call("body", "session.open", {
        session_id: session.session_id, after_sequence: 0, limit: 100,
      }, { signal }));
      if (signal.aborted || requested !== opening) return;
      const selected = selection(reply.summary);
      if (selected.session_id !== session.session_id || !Array.isArray(reply.entries)) throw new Error("app:session-reply");
      current = selected;
      needsRefresh = false;
      messages.replaceChildren();
      for (const entry of reply.entries) showEntry(entry);
      status.textContent = reply.next_sequence === null ? "" : "Showing the first page of this session.";
      send.disabled = busy || face !== "threads";
    } catch (error) { if (!signal.aborted) status.textContent = `Unavailable · ${refusalText(error)}`; }
  };
  const load = async () => {
    refresh.disabled = true;
    try {
      const reply = record(await client.call("body", "session.list", {
        thread_id: null, include_archived: face === "archived", before: null, limit: 100,
      }, { signal }));
      if (signal.aborted) return;
      if (!Array.isArray(reply.items)) throw new Error("app:session-reply");
      list.replaceChildren();
      for (const value of reply.items) {
        const summary = record(value);
        if (face === "archived" && summary.archived !== true) continue;
        if (typeof summary.title !== "string") throw new Error("app:session-reply");
        const item = document.createElement("li");
        const button = document.createElement("button");
        button.textContent = summary.title || "Untitled session";
        button.addEventListener("click", () => void open(value), { signal });
        item.append(button);
        list.append(item);
      }
      if (!list.children.length) status.textContent = "No sessions yet.";
    } catch (error) { if (!signal.aborted) status.textContent = `Unavailable · ${refusalText(error)}`; }
    finally { refresh.disabled = signal.aborted; }
  };
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!current || busy || needsRefresh || signal.aborted) return;
    if (new TextEncoder().encode(input.value).length > 32_768) { status.textContent = "Message is too long."; return; }
    busy = true;
    send.disabled = true;
    const submitted = current;
    try {
      await client.call("body", "chat.turn", {
        session_id: submitted.session_id, expected_sequence: submitted.sequence, text: input.value, mode: submitted.mode,
      }, { signal });
      if (!signal.aborted) { input.value = ""; status.textContent = "Sent; awaiting persisted session data."; }
    } catch (error) { if (!signal.aborted) status.textContent = refusalText(error); }
    finally { busy = false; send.disabled = !current || needsRefresh || signal.aborted; }
  }, { signal });
  refresh.addEventListener("click", () => void load(), { signal });
  root.append(refresh, list, status, messages);
  if (face === "threads") {
    const create = document.createElement("button");
    create.textContent = "New chat";
    create.addEventListener("click", async () => {
      create.disabled = true;
      try {
        const thread = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
        const summary = await client.call("body", "session.create", {
          thread_id: thread, title: "New chat", mode: "chat",
        }, { signal });
        if (!signal.aborted) { await load(); await open(summary); }
      } catch (error) { if (!signal.aborted) status.textContent = refusalText(error); }
      finally { create.disabled = signal.aborted; }
    }, { signal });
    form.append(input, send);
    root.append(create, form);
  }
  void client.subscribe("body", "session.event", {}, value => {
    try {
      const event = record(value);
      if (event.kind === "session.entry" && current) {
        const entry = record(event.body);
        if (entry.session_id !== current.session_id) return;
        if (entry.sequence !== current.sequence + 1) {
          needsRefresh = true;
          status.textContent = "Session changed; reopen it to refresh.";
          send.disabled = true;
          return;
        }
        showEntry(entry);
        current.sequence = entry.sequence as number;
      } else if (event.kind === "accepted") status.textContent = "Proposal pending owner approval.";
      else if (event.kind === "outcome") {
        const outcome = record(event.body);
        status.textContent = typeof outcome.state === "string" ? `Proposal: ${outcome.state}` : "app:invalid-reply";
      }
    } catch (error) { status.textContent = refusalText(error); }
  }, {
    signal,
    onError: code => {
      if (signal.aborted) return;
      needsRefresh = true;
      send.disabled = true;
      status.textContent = `Session updates unavailable · ${code}`;
    },
  }).catch(error => {
    if (!signal.aborted) { needsRefresh = true; send.disabled = true; status.textContent = refusalText(error); }
  });
  void load();
}
