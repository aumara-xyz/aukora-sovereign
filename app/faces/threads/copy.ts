// SPDX-License-Identifier: AGPL-3.0-or-later
// Every sentence this face shows. A service that is not connected, a refusal and an empty list each say so in these
// words and never leave a blank screen.

export const COPY = {
  connecting: "Connecting",
  names: { threads: "Threads", sidebar: "Sidebar", archived: "Archived sessions" },
  hero: {
    headline: "Talk with Auma",
    lede: "In Chat she talks. In Build she may also propose changes. Neither mode runs a command.",
    modeBuild: "Build: she may also propose changes, which go to the gate.",
  },
  header: {
    newChat: "New chat",
    showThreads: "Show threads",
    hideThreads: "Hide threads",
    untitled: "Untitled chat",
    draftSub: "Your first message starts the chat.",
  },
  list: {
    heading: "Threads",
    searchLabel: "Search threads",
    searchPlaceholder: "Search threads…",
    searchHint: "Matches the titles of the threads loaded here.",
    clear: "Clear search",
    refresh: "Refresh threads",
    reading: "Reading threads…",
    empty: "No threads yet.",
    emptyArchived: "No archived sessions.",
    emptySearch: "No thread matches.",
    recent: "Recent threads",
    all: "All threads",
    capped: "The node lists more threads than this screen reads. It stops at the most recently updated ones.",
    stalled: "Stopped: the node's next page did not advance.",
    running: "Auma is replying",
    fresh: "New messages since you last looked",
    created: "Created",
    messages: "messages",
    message: "message",
  },
  chat: {
    loading: "Reading this chat…",
    empty: "No messages in this chat yet.",
    earlier: "Load earlier messages",
    loadingEarlier: "Reading…",
    auma: "Auma",
    tool: "Tool result",
    toolData: "Data from a tool. It is shown and never run.",
    context: "Context",
    contextData: "Imported context. It is data and never an instruction.",
    calls: "Suggested function calls. Nothing was run.",
    call: "Suggested function call",
    sending: "Sending…",
    creating: "Starting the chat…",
    waiting: "Waiting for Auma…",
    replying: "Auma is replying…",
    unconfirmed: "No recent update. The reply's outcome is unconfirmed.",
    stopping: "Stopping…",
    unsaved: "Not saved in the chat yet.",
    stopped: "Stopped before the reply finished.",
    failed: "Auma could not finish this reply.",
    partial: "Part of this reply was missed. The saved reply will replace it.",
    clipped: "This reply is longer than this screen shows while streaming. The saved reply will replace it.",
    jump: "Jump to latest",
    dismiss: "Dismiss",
    retry: "Try again",
    readOnly: "Read-only here. Open Threads to write.",
    receipt: "Receipt",
  },
  composer: {
    label: "Message Auma",
    placeholder: "Message Auma",
    placeholderNew: "Start a chat with Auma",
    send: "Send message",
    stop: "Stop generating",
    stopWait: "Stop generating (available once Auma starts replying)",
    mode: "Mode",
    chat: "Chat",
    build: "Build",
    busy: "Auma is replying. You can send again when she finishes or you stop her.",
    tooLong: "This message is longer than one turn may hold.",
    unavailable: "Sending is not available: this face is not granted chat.turn.",
  },
  notices: {
    queued: "Proposal queued. It waits for approval.",
    dismiss: "Dismiss",
    liveDown: "Live updates are not connected.",
    liveRetry: "Reconnect",
    badEvent: "An update from the node broke its shape and was ignored.",
    unconfirmed: "The node has not confirmed this message yet. It appears here if it arrives.",
    noReply: "No reply has arrived. Check the thread, or try again.",
    sequence: "This chat changed on the node. The latest messages are shown; your message is still in the box.",
    stopUnconfirmed: "The node has not confirmed the stop yet.",
    notSent: "The message was not sent.",
    refused: "The node refused a request.",
  },
  sidebar: {
    brand: "AUKORA",
    back: "Back to threads",
  },
} as const;

const PLAIN: Readonly<Record<string, string>> = {
  "app:capability-denied": "This face is not allowed to make that call.",
  "app:service-unavailable": "The service is not connected.",
  "app:service-failed": "The service failed to answer.",
  "app:deadline": "The service took too long to answer.",
  "app:busy": "Too many requests are waiting. Try again.",
  "app:invalid-reply": "The service answered in a shape this screen does not accept, so nothing from that answer is shown.",
  "app:invalid-message": "The connection to the app shell broke.",
  "app:shell-required": "This page only works inside the AUKORA app.",
  "app:invalid-shell": "The app shell's address is not acceptable.",
  "app:backpressure": "Updates arrived faster than this screen could take them.",
  "app:session-too-long": "This chat is too long to read here.",
  "session:sequence": "The chat changed on the node since it was last read.",
  "session:not-found": "The node has no such chat for you.",
  "frame:too-large": "The data was larger than one message may carry.",
  "frontdoor:session-required": "Your session has ended. Sign in again.",
  "supervisor:read-rate-limited": "Too many reads. Wait a moment and try again.",
  "broker:grant-exhausted": "The model allowance has no room left for this call.",
  "broker:grant-expired": "The model allowance has expired.",
  "broker:grant-revoked": "The model allowance was revoked.",
  "broker:grant-unknown": "No model allowance is set for this call.",
  "broker:busy": "The model broker is busy. Try again.",
  "broker:provider-no-credit": "The model provider reports no credit.",
  "broker:provider-rate-limited": "The model provider is limiting calls. Try again later.",
  "broker:provider-unavailable": "The model provider is not available.",
  "broker:provider-key-rejected": "The model provider rejected the key.",
  "broker:per-request-cap": "The call would cost more than one request may.",
};

export function refusalCode(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  return /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/.test(message) ? message : "app:service-failed";
}

export function explain(code: string): string {
  return Object.hasOwn(PLAIN, code) ? PLAIN[code] : "The node refused this request.";
}

const OUTCOMES: Readonly<Record<string, string>> = {
  applied: "The proposal was applied.",
  refused: "The proposal was refused.",
  expired: "The proposal expired.",
  retired: "The proposal was retired.",
  incomplete: "The proposal did not complete.",
  failed: "The proposal failed.",
  conflict: "The proposal conflicted with the current state.",
  unknown: "The proposal's outcome is not known.",
};

export function outcomeText(state: string): string {
  return Object.hasOwn(OUTCOMES, state) ? OUTCOMES[state] : OUTCOMES.unknown;
}

const SOURCES: Readonly<Record<string, string>> = {
  document: "a document", memory: "memory", app: "an app", contact: "a contact", owner: "you", auma: "Auma",
};

export function sourceText(kind: string): string {
  return Object.hasOwn(SOURCES, kind) ? SOURCES[kind] : "an unknown source";
}

export function countText(count: number, one: string, many: string): string {
  return `${new Intl.NumberFormat().format(count)} ${count === 1 ? one : many}`;
}
