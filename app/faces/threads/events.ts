// SPDX-License-Identifier: AGPL-3.0-or-later
// The face's one subscription to the node's session.event topic. Each value is read against the pinned records before
// anyone sees it; a value that breaks its shape is counted and dropped, and the subscription goes on.
import type { FaceClient } from "../../core/index.js";
import { refusalCode } from "./copy.js";
import { readEvent } from "./model.js";
import type { Event } from "./model.js";

export interface LiveHandlers {
  readonly event: (event: Event) => void;
  // A value that broke its shape. Carries the refusal code only, never the value.
  readonly bad: (code: string) => void;
  readonly state: (connected: boolean, code: string | null) => void;
}

export interface Live {
  // Subscribes again after the subscription ended or failed. Does nothing while it is connected.
  retry(): void;
}

export function listen(client: FaceClient, signal: AbortSignal, on: LiveHandlers): Live {
  let connected = false;
  let attempt = 0;
  const connect = () => {
    if (signal.aborted || connected) return;
    const mine = ++attempt;
    client.subscribe("body", "session.event", {}, value => {
      if (mine !== attempt) return;
      let event: Event;
      try { event = readEvent(value); }
      catch (error) { on.bad(refusalCode(error)); return; }
      on.event(event);
    }, {
      signal,
      onError: code => {
        if (mine !== attempt || signal.aborted) return;
        connected = false;
        on.state(false, code);
        // The shell offered a fresh connection, so this one only needs to ask again.
        if (code === "app:reconnected") connect();
      },
    }).then(dispose => {
      if (mine !== attempt || signal.aborted) { void dispose(); return; }
      connected = true;
      on.state(true, null);
    }, (error: unknown) => {
      if (mine === attempt && !signal.aborted) on.state(false, refusalCode(error));
    });
  };
  connect();
  return { retry: connect };
}
