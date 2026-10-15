// SPDX-License-Identifier: AGPL-3.0-or-later
import { BrowserCopresenceEngine, browserStorage, type BrowserEngineOptions } from "./engine.ts";
import { cameraSurface, type FrameDecoder } from "./optical.ts";
import { createPortalPage } from "./page.ts";
import { BrowserChannelProbe } from "./senses.ts";

export type PortalMountOptions = Pick<BrowserEngineOptions, "node" | "deviceEpoch" | "contextFormatPinned" | "legacyVerifier"> & {
  readonly decode?: FrameDecoder;
};

export function mountPortal(host: HTMLElement, options: PortalMountOptions): () => void {
  const controls = document.createElement("div"), visuals = document.createElement("section");
  visuals.className = "copresence-visuals";
  const video = document.createElement("video"), frame = document.createElement("canvas"), bloom = document.createElement("canvas");
  const frameLabel = document.createElement("h2"), bloomLabel = document.createElement("h2");
  frameLabel.textContent = "Optical exchange"; bloomLabel.textContent = "Relationship bloom";
  frame.setAttribute("aria-label", "Signed optical exchange frames"); bloom.setAttribute("aria-label", "Relationship bloom");
  video.setAttribute("aria-label", "Local camera preview");
  visuals.append(frameLabel, frame, video, bloomLabel, bloom);
  host.append(visuals, controls);
  const storage = browserStorage(), channels = new BrowserChannelProbe();
  const optical = cameraSurface(frame, video, options.decode, bloom);
  const engine = new BrowserCopresenceEngine({ ...options, ...storage, channels });
  const unmount = createPortalPage({ prepare: method => channels.prepare(method), release: () => channels.close() }).mount(controls, { engine, attempts: storage.attempts, optical });
  return () => { unmount(); optical.clear(); channels.close(); visuals.remove(); controls.remove(); };
}
