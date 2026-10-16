// SPDX-License-Identifier: AGPL-3.0-or-later
// The one connection a face in this brick makes to the shell. The shell origin is the frame's own referrer, the plugin
// id selects the capability set the shell granted, and everything is released when the page goes away. A face opened
// outside the shell has no parent and refuses.
import { connectFace } from "../../core/index.js";
import type { FaceClient } from "../../core/index.js";

export interface FaceHost {
  readonly root: HTMLElement;
  readonly client: FaceClient;
  readonly signal: AbortSignal;
}

export function refusalText(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (/(?:session-required|binding-required|session-expired|signin-required)/.test(message)) {
    return "Sign in to view your binding.";
  }
  if (/(?:shell-required|frame-required|origin-mismatch)/.test(message)) return "Open AUMLOK inside the app.";
  return "Binding status unavailable. Try again shortly.";
}

/** Heading and status line first, then the face's own mount once the shell link exists. Returns the disposer. */
export function openFace(id: string, title: string, mount: (host: FaceHost) => void | Promise<void>): () => void {
  const root = document.getElementById("face");
  if (!root) throw new Error("app:unknown-face");
  const life = new AbortController();
  const heading = document.createElement("h1");
  heading.textContent = title;
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  status.textContent = "Connecting";
  root.replaceChildren(heading, status);
  let client: FaceClient | undefined;
  const dispose = () => {
    life.abort();
    client?.dispose();
    root.replaceChildren();
  };
  window.addEventListener("pagehide", dispose, { once: true, signal: life.signal });
  void (async () => {
    try {
      if (window.parent === window || !document.referrer) throw new Error("app:shell-required");
      const shellOrigin = new URL(document.referrer).origin;
      if (shellOrigin === "null") throw new Error("app:shell-required");
      client = connectFace({ shellOrigin, pluginId: id, signal: life.signal });
      if (life.signal.aborted) {
        client.dispose();
        return;
      }
      status.textContent = "";
      await mount({ root, client, signal: life.signal });
    } catch (error) {
      if (!life.signal.aborted) status.textContent = refusalText(error);
    }
  })();
  return dispose;
}
