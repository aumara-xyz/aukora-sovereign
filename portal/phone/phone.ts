// SPDX-License-Identifier: AGPL-3.0-or-later
// The phone's side of pairing, opened top-level at /pair#j=<token> from the code on the owner's screen. The token is
// in the fragment, so it never reaches a server log or a Referer; the page drops it from the address bar at once.
// The phone needs no account: it makes its own device key (non-extractable, this origin's IndexedDB), joins with the
// token, receives the node's pinned context and runs the same portal exchange as the owner's screen.
import { BrowserCopresenceEngine } from "../engine.js";
import { IndexedAttempts } from "../attempts.js";
import { cameraSurface } from "../optical.js";
import { refuse, utf8 } from "../bytes.js";
import type { PentoraExpansion } from "../bloom/index.js";
import type { PortalExchange, PortalObservation } from "../contracts.js";
import { contextNode, PairingClient, sleep, type PairingStatus } from "../node/client.js";
import { deviceKey, PHONE_DEVICE_STORE } from "../node/device-key.js";
import { frameDecoder } from "../node/decoder.js";

const PHASE: Record<PortalObservation["phase"], string> = {
  FACE: "Face the screens toward each other.",
  SEENYOU: "Seen you.",
  HANDSHAKE: "Locking in.",
  BLOOM: "Done here. Waiting for your node…",
  REFUSED: "That did not verify. Face the screens toward each other and try again.",
};
const ENDED: Record<string, string> = {
  "copresence:join-used": "This code was already used. Show a new one on your computer and scan it again.",
  "copresence:join-invalid": "This code is not known to your node. Show a new one on your computer and scan it again.",
  "copresence:pairing-expired": "This code has expired. Show a new one on your computer and scan it again.",
  "copresence:token-invalid": "Open this page by scanning the code on your computer.",
  "copresence:camera-decoder-unavailable": "This browser cannot read codes from the camera yet. Try another browser on this phone.",
};
const unavailablePentora: PentoraExpansion = { pairing_expansion: () => refuse("pairing-expansion-unavailable") };

const element = <T extends HTMLElement>(id: string): T => {
  const found = document.getElementById(id);
  if (!found) refuse("page");
  return found as T;
};
const page = document.querySelector<HTMLElement>("main.pair")!;
const lead = element<HTMLParagraphElement>("lead");
const phase = element<HTMLOutputElement>("phase");
const start = element<HTMLButtonElement>("start");
const frame = element<HTMLCanvasElement>("frame");
const video = element<HTMLVideoElement>("camera");
const client = new PairingClient();
const life = new AbortController();

function stage(name: "joining" | "ready" | "exchange" | "done" | "failed", message: string): void {
  page.dataset.stage = name;
  phase.textContent = message;
}

function readToken(): string | null {
  const match = /^#j=([A-Za-z0-9_-]{43})$/.exec(location.hash);
  // The token stays in memory only; the address bar and history keep the bare page.
  history.replaceState(null, "", location.pathname);
  return match ? match[1]! : null;
}

async function main(): Promise<void> {
  const token = readToken();
  if (!token) refuse("token-invalid");
  const key = await deviceKey(PHONE_DEVICE_STORE);
  const joined = await client.join(token, key.publicKey, life.signal);
  const bearer = joined.phone;
  let status: PairingStatus = joined.status;
  if (status.context === null) refuse("pairing-state");
  const context = status.context;
  const decode = frameDecoder();
  const attempts = new IndexedAttempts("aukora.copresence.attempts.phone.v1");
  const optical = cameraSurface(frame, video, unavailablePentora, decode);
  const engine = new BrowserCopresenceEngine({
    node: contextNode(context),
    deviceEpoch: 0,
    attempts,
    consumeReceipt: (digest, abort) => attempts.consumeReceipt(digest, abort),
    contextFormatPinned: () => true,
    deviceKey: key.keys,
    legacyVerifier: async () => refuse("legacy-unavailable"),
  });
  lead.textContent = "Hold this screen toward your computer's screen, about a hand apart, then press Start on both.";
  stage("ready", "");
  start.disabled = false;

  let running: { controller: AbortController; exchange: PortalExchange | null; attempt: string; ended: boolean } | null = null;
  const finish = async (run: NonNullable<typeof running>, outcome: "bloom" | "refused" | "cancelled"): Promise<void> => {
    if (run.ended) return;
    run.ended = true;
    run.controller.abort();
    run.exchange?.stop();
    try { await attempts.finish(run.attempt, outcome, new AbortController().signal); } catch { /* stays counted */ }
  };

  start.addEventListener("click", () => {
    if (running && !running.ended) return;
    start.disabled = true;
    const run = { controller: new AbortController(), exchange: null as PortalExchange | null, attempt: "", ended: false };
    running = run;
    stage("exchange", PHASE.FACE);
    void (async () => {
      try {
        run.attempt = await attempts.reserve("optical", run.controller.signal);
        run.exchange = await engine.begin({ domain: "copresence.v1", attemptId: run.attempt, method: "optical",
          contextBytes: utf8.encode(context), approvedText: null }, run.controller.signal);
        run.exchange.subscribe(observation => {
          if (run.ended) return;
          if (observation.frameBytes) optical.showFrame(observation.frameBytes);
          if (observation.phase === "REFUSED") {
            void finish(run, "refused");
            optical.clear();
            stage("failed", PHASE.REFUSED);
            start.disabled = false;
            return;
          }
          phase.textContent = PHASE[observation.phase];
        });
        await optical.scan(bytes => { void run.exchange?.receive(bytes); }, run.controller.signal);
      } catch (error) {
        void finish(run, run.controller.signal.aborted ? "cancelled" : "refused");
        optical.clear();
        const code = error instanceof Error ? error.message : "";
        stage("failed", /NotAllowed|NotFound|camera/i.test(code) || error instanceof DOMException
          ? "The camera is needed to see the other screen. Allow it and press Start again."
          : ENDED[code] ?? "That could not start. Press Start to try again.");
        start.disabled = false;
      }
    })();
  }, { signal: life.signal });

  // The node, not this page, decides: once it has verified and spent the receipt, both screens are done.
  for (;;) {
    await sleep(1500, life.signal);
    status = await client.phone(bearer, life.signal).catch(() => status);
    if (status.state === "spent" && status.verdict) {
      lead.textContent = "This phone is paired with your node.";
      stage("done", "Verified by your node.");
      start.hidden = true;
      // Keep showing the last frames a moment so the computer can finish reading them.
      await sleep(3000, life.signal);
      if (running) await finish(running, "bloom");
      optical.clear();
      return;
    }
    if (status.state === "closed" || status.state === "expired") {
      if (running) await finish(running, "cancelled");
      optical.clear();
      lead.textContent = "";
      stage("failed", ENDED["copresence:pairing-expired"]!);
      start.hidden = true;
      return;
    }
  }
}

main().catch(error => {
  const code = error instanceof Error ? error.message : "";
  lead.textContent = "";
  stage("failed", ENDED[code] ?? "This pairing could not open. Show a new code on your computer and scan it again.");
  start.hidden = true;
});
