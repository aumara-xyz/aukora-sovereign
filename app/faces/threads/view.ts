// SPDX-License-Identifier: AGPL-3.0-or-later
// The entry the shared face runtime (app/faces/runtime.ts) calls for the faces that read sessions. Threads and Sidebar
// start themselves from their own main.ts; this keeps the runtime's call working for them and for Archived sessions,
// which lists the sessions the node marks archived and reads them. A page that did not link this brick's stylesheets
// gets them here; they are same-origin files under the page's own policy.
import type { FaceClient } from "../../core/index.js";
import { FACE_CATALOG } from "../catalog.js";
import { mountSidebar } from "../sidebar/view.js";
import { mountChat } from "./chat.js";

const STYLES = ["./threads.css", "../sidebar/sidebar.css"] as const;

function styles(signal: AbortSignal): void {
  for (const path of STYLES) {
    const href = new URL(path, import.meta.url).href;
    if ([...document.querySelectorAll("link[rel='stylesheet']")].some(link => (link as HTMLLinkElement).href === href)) continue;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    document.head.append(link);
    signal.addEventListener("abort", () => link.remove(), { once: true });
  }
}

export function mountThreads(root: HTMLElement, client: FaceClient, signal: AbortSignal, face: string): void {
  const manifest = FACE_CATALOG.find(item => item.id === face);
  const grant = manifest ? manifest.capabilities[manifest.organ] : undefined;
  const granted: ReadonlySet<string> = new Set(grant ? grant.methods : []);
  styles(signal);
  if (face === "threads") mountChat(root, client, signal, granted);
  else if (face === "sidebar" || face === "archived") mountSidebar(root, client, signal, granted, face === "archived");
  else throw new Error("app:unknown-face");
}
