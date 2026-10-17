// SPDX-License-Identifier: AGPL-3.0-or-later
// Step 5: co-presence. A Pentora turns into being, the owner starts the pairing, two screens face each other and
// trade signed rotating codes (the portal engine), a verified receipt locks the Pentora into place, and the
// ceremony arrives. Co-presence is required: there is no way around this step. Evidence, never authority.
import type { OwnerDisposer } from "./contracts.js";
import { checkAbort } from "./abort.js";
import { brand } from "./brand.js";
import { mountCeremonyConclusion } from "./ceremony-ending.js";
import { mountOpeningPentora } from "./pentora-opening.js";
import { chimes, exchangeFeedback, feedbackFor } from "../../portal/feedback.js";
import { pairingPort } from "./pairing-port.js";
import { actionButton, fieldTable, label, lead, portalButton, statTiles } from "./primitives.js";
import type { PairingExchange, PairingObservation, PairingServices } from "./pairing-port.js";

// Both devices must use the same context text.
const CONTEXT = "AUKORA first pairing";
const REFUSED_TEXT = "That did not verify. Face the screens toward each other and try again.";
function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", className = ""): HTMLElementTagNameMap[K] {
  const result = document.createElement(tag);
  result.textContent = text;
  result.className = className;
  return result;
}

export type PairingOptions = {
  /** The owner's own screen ends in the arrival; a partner device ends on the locked Pentora. */
  readonly arrival: boolean;
};

export function mountPairing(host: HTMLElement, signal: AbortSignal, complete: () => void,
  options: PairingOptions = { arrival: true }): OwnerDisposer {
  checkAbort(signal);
  brand.hide();
  const lifetime = new AbortController();
  const live = lifetime.signal;
  signal.addEventListener("abort", () => lifetime.abort(), { once: true });

  const panel = node("section", "", "ceremony-pairing owner-scene");
  panel.dataset.stage = "intro";
  const figure = node("div", "", "pairing-figure");
  const pentora = mountOpeningPentora(figure, live);

  const text = node("div", "", "owner-text");
  const heading = node("h2", "Two devices. One moment.");
  heading.tabIndex = -1;
  const detail = node("p", "Scan the code with your phone, then face the two screens toward each other.", "owner-detail");
  text.append(heading, detail);

  const content = node("div", "", "owner-content pairing-intro");
  // "What is this?" is a PortalButton: it opens in place into the full explanation, with its numbers worked out from the code.
  const portal = portalButton({ tone: "violet", icon: "aura", title: "What is this?", summary: "Two screens, one moment",
    frameClass: "pairing-portal" });
  // The math sits one level down, in a portal of its own, so the first thing anyone reads is what this means.
  const math = portalButton({ tone: "blue", icon: "aura", title: "The math behind the visual", summary: "The Pentora, the exchange and the numbers",
    frameClass: "pairing-math" });
  math.body.append(
    label("The shape"),
    ...fieldTable([
      ["Points", "20: the vertices of a regular dodecahedron, all at radius 1"],
      ["Cubes", "5, each using 8 of the 20 points. Every point lies in 2 cubes: 5 × 8 = 40 = 20 × 2"],
      ["Edges", "60 = 5 cubes × 12 edges, none shared"],
      ["Cube edge", "2/√3 ≈ 1.1547, which is φ × the dodecahedron's edge (φ = 1.618…)"],
      ["Symmetry", "the full icosahedral group, order 120: 60 rotations and 60 with a reflection. The 60 rotations permute the five cubes as the even permutations, A₅"],
    ]),
    label("The relationship bloom, for pairing with another person"),
    statTiles([{ name: "Cells in the bloom", value: "110 trits", tone: "violet" }, { name: "Bits drawn", value: "174.35", tone: "violet" },
      { name: "Of the digest", value: "256 bits", tone: "blue" }]),
    ...fieldTable([
      ["Your own phone", "no bloom: the five cubes lock into place. The bloom is reserved for pairing with another person"],
      ["Pairing root", "SHA-256 of both person keys (2 × 32 bytes, sorted) = 256 bits"],
      ["Display digest", "SHA-256(“pentora.display.v1” ‖ 0x00 ‖ root) = 256 bits, read as one big number N"],
      ["Cells", "the 111 points of the pinned geometry minus the centre = 110; cell i holds trit ⌊N / 3ⁱ⌋ mod 3"],
      ["Bits drawn", "110 × log₂3 = 110 × 1.58496 = 174.35 bits (3¹¹⁰ ≈ 2¹⁷⁴·³⁵, under the 2²⁵⁶ it is cut from)"],
    ]),
    label("The exchange"),
    statTiles([{ name: "Nonces", value: "2 × 256 bits", tone: "mint" }, { name: "Frames", value: "4 + receipt", tone: "mint" }, { name: "Window", value: "10 s", tone: "mint" }]),
    ...fieldTable([
      ["Order", "A face, B face, A seen-you, B seen-you; then both sign one receipt"],
      ["Nonces", "2 × 32 bytes = 512 bits, each sealed first by a SHA-256 commitment (256 bits) and revealed only after the other's is shown"],
      ["Device keys", "ECDSA P-256, made in this browser and never exportable: public key 65 bytes, signature 64 bytes"],
      ["Signed core", "context 32 + nonces 2 × 32 + times 2 × 8 + transcript 32 = 144 bytes, under “copresence.v1”"],
      ["Frame", "a QR code in the smallest version that holds it: about 0.7 to 1.4 KB, versions 19 to 27, changing every 1 s; the receipt must land within 10 s"],
    ]),
    label("Your AUMLOK, for comparison"),
    ...fieldTable([
      ["Lists", "92 anchors · ROOT 942 · UNITE 1,170 · RISE 1,258 words"],
      ["Weakest anchor", "“branch”: 92 × (67 × 43 × 70 × 40 × 84 × 50) = 3,117,011,520,000 phrases"],
      ["Entropy", "log₂(3,117,011,520,000) = 41.50 bits at the weakest anchor, 43.09 bits on average"],
    ]),
  );
  portal.body.append(
    lead("Two screens face each other. Each one shows the other a signed code that changes every second, and each reads the other’s code with its camera. If both signatures check out inside a few seconds, the two screens shared the same moment, face to face."),
    lead("That is all it shows, and it is evidence rather than permission: it uses no location, and it does not by itself prove a human was there."),
    label("What it is for"),
    lead("This is how you will prove your own human network. Every time you do this with a friend or a loved one, your network of real people grows stronger. Bots and Sybil attacks, one machine pretending to be a thousand people, cannot sit in the same room with many real people at the same moment."),
    lead("The dead internet theory is no longer a theory. This is one way back to knowing who is real."),
    math.frame,
  );
  content.append(portal.frame);
  // While the explanation is open the code makes room for it.
  portal.head.addEventListener("click", () => { panel.toggleAttribute("data-explain", portal.isOpen()); }, { signal: live });

  const controls = node("div", "", "owner-controls pairing-intro");
  const made = actionButton("Start pairing", "mint");
  const start = made.button;
  start.classList.add("primary");
  controls.append(made.frame);

  const phoneLink = pairingPort?.phoneLink;
  panel.toggleAttribute("data-phone", Boolean(phoneLink));
  const phone = node("div", "", "pairing-phone pairing-intro");
  if (phoneLink) {
    const code = node("canvas", "", "pairing-link");
    code.setAttribute("aria-label", "Open on your phone");
    phoneLink.draw(code);
    phone.append(code, node("p", phoneLink.caption ?? "", "pairing-note"));
  }

  const exchange = node("div", "", "pairing-exchange");
  const tile = node("div", "", "pairing-tile");
  const frame = node("canvas", "", "pairing-frame");
  frame.setAttribute("aria-label", "Signed optical exchange frames");
  const bloom = node("canvas", "", "pairing-bloom");
  bloom.setAttribute("aria-label", "Relationship bloom");
  bloom.hidden = true;
  tile.append(frame, bloom);
  const video = node("video", "", "pairing-camera");
  video.setAttribute("aria-label", "Local camera preview");
  video.muted = true;
  video.playsInline = true;
  video.addEventListener("playing", () => { video.dataset.live = ""; }, { signal: live });
  const phase = node("output", "", "pairing-phase");
  phase.setAttribute("aria-live", "polite");
  const stop = node("button", "Stop", "secondary");
  stop.type = "button";
  // The four plain states and the ring that fills while the two screens hold steady; the message line stays `phase`.
  const feedback = exchangeFeedback(document, false);
  const sound = chimes();
  const soundToggle = node("button", "", "secondary pairing-sound");
  soundToggle.type = "button";
  const paintSound = (): void => { soundToggle.textContent = sound.muted ? "Sound off" : "Sound on"; soundToggle.setAttribute("aria-pressed", String(!sound.muted)); };
  paintSound();
  soundToggle.addEventListener("click", () => { sound.mute(!sound.muted); paintSound(); }, { signal: live });
  const actions = node("div", "", "pairing-actions");
  actions.append(stop, soundToggle);
  exchange.append(tile, phase, feedback.element, video, actions);

  const status = node("p", "", "owner-status");
  status.setAttribute("role", "status");
  if (!pairingPort) {
    start.disabled = true;
    status.textContent = "This node does not serve co-presence yet.";
  }
  panel.append(figure, phone, text, content, controls, exchange, status);
  host.replaceChildren(panel);

  let services: PairingServices | undefined;
  let session: { controller: AbortController; attempt: string; exchange: PairingExchange | null; scanStop: (() => void) | null;
    unsubscribe: (() => void) | null; terminal: boolean } | null = null;
  let arrivalTimer: ReturnType<typeof setTimeout> | undefined;
  let conclusion: OwnerDisposer | undefined;
  let stage = "intro";
  let recognised = false;
  let lastPhase: PairingObservation["phase"] = "FACE";

  function setStage(next: string): void {
    if (stage === next) return;
    stage = next;
    panel.classList.add("is-changing");
    setTimeout(() => {
      if (live.aborted) return;
      panel.dataset.stage = next;
      panel.classList.remove("is-changing");
    }, 520);
  }

  /** One place decides what is said and drawn: searching, seen, exchanging, verified, and how full the ring is. */
  function show(phaseNow: PairingObservation["phase"]): void {
    lastPhase = phaseNow;
    const state = feedbackFor(phaseNow, recognised);
    feedback.show(state.state, state.fill);
    say(state.message);
  }

  function say(message: string): void {
    if (phase.textContent === message) return;
    phase.textContent = message;
    phase.animate?.([{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }],
      { duration: 900, easing: "cubic-bezier(.16,1,.3,1)" });
  }

  async function finish(current: NonNullable<typeof session>, outcome: "bloom" | "refused" | "cancelled"): Promise<void> {
    if (current.terminal) return;
    current.terminal = true;
    try { await services?.attempts.finish(current.attempt, outcome, new AbortController().signal); }
    catch { /* The outcome stays pending; a stuck attempt only counts against the owner's own budget. */ }
  }

  function release(current: NonNullable<typeof session>): void {
    current.controller.abort();
    current.scanStop?.();
    current.unsubscribe?.();
    current.exchange?.stop();
  }

  function again(message: string): void {
    services = undefined;                   // the next start composes its engine afresh
    start.disabled = false;
    status.textContent = message;
    setStage("intro");
  }

  async function begin(): Promise<void> {
    if (session || live.aborted || !pairingPort) return;
    status.textContent = "";
    start.disabled = true;
    const current = { controller: new AbortController(), attempt: "", exchange: null as PairingExchange | null,
      scanStop: null as (() => void) | null, unsubscribe: null as (() => void) | null, terminal: false };
    session = current;
    const done = (): void => { if (session === current) session = null; };
    try {
      services ??= await pairingPort.open({ frame, video, bloom }, live);
      checkAbort(live);
      bloom.hidden = true;
      frame.hidden = false;
      services.optical.clear();
      // With a phone link, nothing is on the screen until the phone has opened it and joined.
      panel.toggleAttribute("data-waiting", Boolean(phoneLink));
      recognised = false;
      feedback.reset();
      if (phoneLink) say("Waiting for your phone to open the link."); else show("FACE");
      setStage("exchange");
      current.attempt = await services.attempts.reserve("optical", current.controller.signal);
      current.exchange = await services.engine.begin({ domain: "copresence.v1", attemptId: current.attempt, method: "optical",
        contextBytes: new TextEncoder().encode(CONTEXT), approvedText: null }, current.controller.signal);
      current.unsubscribe = current.exchange.subscribe(observation => {
        if (session !== current || live.aborted) return;
        panel.removeAttribute("data-waiting");
        if (observation.phase !== "BLOOM" && observation.phase !== "REFUSED") {
          show(observation.phase);
          if (observation.frameBytes) { services?.optical.showFrame(observation.frameBytes); frame.dataset.bytes = String(observation.frameBytes.length); }
          return;
        }
        const verdict = observation.verdict;
        const verified = observation.phase === "BLOOM" && observation.receiptBytes !== null && verdict !== null
          && (verdict.verdict === "CONSISTENT_CLAIMED" || (verdict.verdict === "UNDETERMINED" && (verdict.code ?? null) === null));
        if (!verified) {
          void finish(current, "refused");
          release(current);
          done();
          services?.optical.clear();
          again(REFUSED_TEXT);
          return;
        }
        // The engine repeats its last observation while the other screen reads it; the bloom and the arrival happen once.
        if (current.terminal) return;
        // The receipt is spent and the attempt closed before anything is shown. The own-device moment is the Pentora locking
        // into place (the relationship bloom is for pairing with another person), then "Verified", then the arrival.
        void finish(current, "bloom").then(async () => {
          if (session !== current || live.aborted) return;
          // The last frame stays on screen long enough for the other device to read it; only then does the Pentora lock.
          if (observation.frameBytes) { services?.optical.showFrame(observation.frameBytes); frame.dataset.bytes = String(observation.frameBytes.length); }
          // The ring is full as soon as the node has said yes; the Pentora locks a moment later.
          feedback.show("verified", 1);
          await new Promise<void>(resolve => setTimeout(resolve, 2400));
          if (session !== current || live.aborted) return;
          // The Pentora comes forward out of the background and shrinks into focus; only then does it lock into place.
          setStage("lock");
          await new Promise<void>(resolve => setTimeout(resolve, 2100));
          if (session !== current || live.aborted) return;
          const locking = pentora.lock();
          setTimeout(() => sound.locked(), 450);          // the cubes snap into alignment about half a second in
          await locking;
          if (session !== current || live.aborted) return;
          say("Verified.");
          arrivalTimer = setTimeout(() => {
            if (live.aborted) return;
            release(current);
            done();
            if (options.arrival) { pentora.dispose(); conclusion = mountCeremonyConclusion(host, signal, complete); }
          }, 1600);
        });
      });
      current.scanStop = await services.optical.scan(bytes => {
        if (!recognised && session === current) {
          // The first code the camera reads from the other screen: one ring of light, one soft sound, the state moves on.
          recognised = true;
          feedback.pulse(tile);
          sound.seen();
          show(lastPhase);
        }
        void current.exchange?.receive(bytes);
      }, current.controller.signal);
      if (session !== current) current.scanStop();
    } catch (error) {
      const stopped = current.controller.signal.aborted || live.aborted;
      release(current);
      if (current.attempt) await finish(current, stopped ? "cancelled" : "refused");
      done();
      services?.optical.clear();
      if (!stopped) {
        const code = error instanceof Error ? error.message : "";
        again(/camera|device|NotAllowed|NotFound|decoder/i.test(code) || (error instanceof DOMException)
          ? "The camera is needed to see the other screen. Allow it and start again."
          : "That could not start. Try again.");
      }
    }
  }

  start.addEventListener("click", () => { sound.unlock(); void begin(); }, { signal: live });
  stop.addEventListener("click", () => {
    const current = session;
    if (!current) return;
    release(current);
    void finish(current, "cancelled");
    session = null;
    services?.optical.clear();
    again("");                              // back to the pairing step, never a void
  }, { signal: live });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && session && stage === "exchange") stop.click();
  }, { signal: live });

  const dispose = (): void => {
    if (live.aborted) return;
    lifetime.abort();
    clearTimeout(arrivalTimer);
    if (session) { release(session); void finish(session, "cancelled"); session = null; }
    pentora.dispose();
    conclusion?.();
    panel.remove();
    signal.removeEventListener("abort", dispose);
  };
  signal.addEventListener("abort", dispose, { once: true });
  return dispose;
}
