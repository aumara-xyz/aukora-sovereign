// SPDX-License-Identifier: AGPL-3.0-or-later
// Rehearsal only: the owner's screen, composed like ui/owner/pairing.ts composes its pairing port. The scene's own
// context text goes in; the port must replace it with the node's pinned context.
import { createNodePairingPort } from "/portal/node/pairing-port.js";

const state = { url: "", final: null, phases: [], verdict: null, error: null };
window.__twin = state;
const element = id => document.getElementById(id);
const port = createNodePairingPort({ pollMs: 300, onVerdict: verdict => { state.verdict = verdict; } });
port.phoneLink.draw(element("link"));
const watch = setInterval(() => { if (port.phoneLink.url) { state.url = port.phoneLink.url; clearInterval(watch); } }, 100);

state.start = async () => {
  try {
    const controller = new AbortController();
    const services = await port.open({ frame: element("frame"), video: element("camera"), bloom: element("bloom") }, controller.signal);
    const attempt = await services.attempts.reserve("optical", controller.signal);
    const exchange = await services.engine.begin({ domain: "copresence.v1", attemptId: attempt, method: "optical",
      contextBytes: new TextEncoder().encode("AUKORA first pairing"), approvedText: null }, controller.signal);
    exchange.subscribe(observation => {
      if (state.phases.at(-1) !== observation.phase) state.phases.push(observation.phase);
      if (observation.frameBytes) services.optical.showFrame(observation.frameBytes);
      if ((observation.phase === "BLOOM" || observation.phase === "REFUSED") && !state.final) {
        state.final = { phase: observation.phase, verdict: observation.verdict,
          receipt: observation.receiptBytes ? Array.from(observation.receiptBytes) : null };
        void services.attempts.finish(attempt, observation.phase === "BLOOM" ? "bloom" : "refused", new AbortController().signal);
      }
    });
    await services.optical.scan(bytes => { void exchange.receive(bytes); }, controller.signal);
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
  }
};
