// SPDX-License-Identifier: AGPL-3.0-or-later
import { clampHeight, heightWindow, MAX_HEIGHT, MIN_HEIGHT, nearestCrossing, requireHeight, sum, term, termCount } from "./math.js";
import type { WindowData } from "./math.js";
import { drawChart, drawFlower, drawTorus, drawTunnel } from "./scene.js";
import type { SceneOptions, TorusView } from "./scene.js";
import { HarpSound } from "./sound.js";
import { nearestReferenceZero, referenceDeviation } from "./reference.js";

function element<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  if (text) node.textContent = text;
  return node;
}

function button(text: string): HTMLButtonElement {
  const node = element("button", "", text);
  node.type = "button";
  return node;
}

function field(text: string, control: HTMLElement): HTMLLabelElement {
  const node = element("label", "harp-field");
  node.append(element("span", "", text), control);
  return node;
}

function slider(low: number, high: number, value: number, step: string): HTMLInputElement {
  const node = element("input");
  node.type = "range";
  node.min = String(low);
  node.max = String(high);
  node.step = step;
  node.value = String(value);
  return node;
}

function plot(name: string, className: string): HTMLCanvasElement {
  const canvas = element("canvas", className);
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", name);
  canvas.textContent = name;
  return canvas;
}

function panel(title: string): HTMLElement {
  const node = element("section", "harp-panel");
  const heading = element("h2", "", title);
  node.append(heading);
  return node;
}

function code(error: unknown): string {
  return error instanceof Error && /^zetaharp:[a-z0-9-]+$/.test(error.message)
    ? error.message : "zetaharp:unavailable";
}

export function mountHarp(root: HTMLElement, parentSignal: AbortSignal): void {
  if (parentSignal.aborted) return;
  const life = new AbortController();
  const signal = life.signal;
  const sound = new HarpSound();
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  let paused = reducedMotion.matches;
  let height = 1_000_000;
  let speed = 10 ** 2.4;
  let volume = .35;
  let degrees = false;
  let sounding = false;
  let audioBusy = false;
  let audioRevision = 0;
  let solo = false;
  let showReference = true;
  let showRemainder = true;
  let torusView: TorusView = "shadow";
  let data = heightWindow(height);
  let dirty = true;
  let frameId = 0;
  let lastFrame = performance.now();
  let lastDraw = 0;
  let lastReadout = 0;
  let crossingTarget: number | null = null;
  let scopeResult = false;
  let drag: { id: number; x: number; y: number } | null = null;
  let scrub: { id: number; window: WindowData } | null = null;
  const options: SceneOptions = { zoom: 1, yaw: -.25, pitch: .15, selected: 1, strings: true, resultant: true };

  const title = element("header", "harp-title");
  title.append(element("h1", "", "Zeta Harp"), element("p", "", "The Riemann–Siegel main sum, drawn as an instrument you can fly."));
  const fence = element("p", "harp-fence", "Known mathematics · finite approximation · not evidence for RH or GHP");
  const status = element("p", "harp-status");
  status.setAttribute("role", "status");
  const readout = element("div", "harp-readout");
  readout.setAttribute("aria-label", "Current computed values");
  const heightReadout = element("span");
  const countReadout = element("span");
  const sumReadout = element("span", "harp-gold");
  readout.append(heightReadout, countReadout, sumReadout);

  const cockpit = element("div", "harp-cockpit");
  const play = button("");
  const speedControl = slider(0, 4, 2.4, ".05");
  const speedValue = element("output");
  const speedField = field("Speed · height units/s", speedControl);
  speedField.append(speedValue);
  const zoom = slider(.4, 2.5, 1, ".05");
  const soundButton = button("Sound off");
  soundButton.setAttribute("aria-pressed", "false");
  const volumeControl = slider(0, 1, volume, ".01");
  const degreesButton = button("Degrees off");
  degreesButton.setAttribute("aria-pressed", "false");
  degreesButton.title = "Artistic semitone snapping. Off preserves the raw frequency law.";
  cockpit.append(play, speedField, field("Zoom", zoom), soundButton, field("Volume", volumeControl), degreesButton);
  const audioReadout = element("p", "harp-caption");
  audioReadout.setAttribute("aria-live", "off");

  const navigation = element("div", "harp-navigation");
  const heightControl = element("input");
  heightControl.type = "number";
  heightControl.min = String(MIN_HEIGHT);
  heightControl.max = String(MAX_HEIGHT);
  heightControl.step = "any";
  heightControl.value = String(height);
  const go = button("Go");
  navigation.append(field("Height t", heightControl), go);
  for (const [label, value] of [["130", 130], ["10⁴", 10_000], ["10⁶", 1_000_000], ["10⁸", MAX_HEIGHT]] as const) {
    const preset = button(label);
    preset.setAttribute("aria-label", `Go to height ${value}`);
    preset.addEventListener("click", () => move(value, true), { signal });
    navigation.append(preset);
  }
  const scrubber = slider(2, 8, 6, ".0001");
  const scrubberField = field("Height range · logarithmic", scrubber);
  const layers = element("div", "harp-layers");
  for (const [name, key] of [["Strings", "strings"], ["Gold resultant", "resultant"]] as const) {
    const toggle = element("input");
    toggle.type = "checkbox";
    toggle.checked = true;
    toggle.addEventListener("change", () => { options[key] = toggle.checked; dirty = true; }, { signal });
    layers.append(field(name, toggle));
  }
  for (const key of ["reference", "remainder"] as const) {
    const toggle = element("input");
    toggle.type = "checkbox";
    toggle.checked = true;
    toggle.addEventListener("change", () => {
      if (key === "reference") showReference = toggle.checked;
      else showRemainder = toggle.checked;
      dirty = true;
    }, { signal });
    layers.append(field(key === "reference" ? "Violet Z reference" : "Blue remainder reference", toggle));
  }

  const tunnel = plot("Phase tunnel. Drag to orbit; wheel to move height; Shift-wheel moves logarithmically. Arrow keys move; Space pauses.", "harp-tunnel");
  tunnel.tabIndex = 0;
  const instructions = element("p", "harp-caption", "Drag to orbit · wheel or ← → to fly · Shift for large steps · Space to pause. Gold is the full complex main sum, scaled by 1/3; its real part is M(t).");
  const chart = plot("Gold curve: finite main sum M(t). Drag to scrub height; arrow keys step height.", "harp-chart");
  chart.tabIndex = 0;

  const tools = element("div", "harp-tools");
  const flowerPanel = panel("Phasor flower");
  const flower = plot("Individual phase vectors. Click a vector tip to inspect a drawn term, or choose any active term by number.", "harp-flower");
  const termControl = element("input");
  termControl.type = "number";
  termControl.min = "1";
  termControl.step = "1";
  termControl.value = "1";
  const inspector = element("dl", "harp-inspector");
  const soloButton = button("Voice selected term");
  soloButton.setAttribute("aria-pressed", "false");
  flowerPanel.append(flower, field("Inspect term n", termControl), inspector, soloButton);
  const torusPanel = panel("Two phases on S¹ × S¹");
  const torusControls = element("div", "harp-torus-controls");
  torusControls.setAttribute("role", "group");
  torusControls.setAttribute("aria-label", "Torus projection");
  const torusButtons = new Map<TorusView, HTMLButtonElement>();
  for (const view of ["shadow", "slice", "unfold"] as const) {
    const control = button(view[0].toUpperCase() + view.slice(1));
    control.setAttribute("aria-pressed", String(view === torusView));
    control.addEventListener("click", () => {
      torusView = view;
      for (const [key, node] of torusButtons) node.setAttribute("aria-pressed", String(key === view));
      dirty = true;
    }, { signal });
    torusButtons.set(view, control);
    torusControls.append(control);
  }
  const torus = plot("Phase pair φ₁=θ(t), φ₂=θ(t)−t ln 2, modulo 2π. Gold dot is the current phase pair.", "harp-torus");
  torusPanel.append(torusControls, torus, element("p", "harp-caption", "Gold tracks (θ(t), θ(t) − t ln 2), modulo 2π. These phase coordinates carry no organism identity, health, or authority."));
  tools.append(flowerPanel, torusPanel);

  const scope = panel("Crossing explorer");
  const find = button("Find nearest sampled crossing");
  const jump = button("Go to crossing");
  const referenceZero = button("Nearest available reference zero");
  jump.disabled = true;
  const scopeReadout = element("p", "harp-caption", "Searches sign changes in the displayed 129-point window. These are computed crossings of a finite approximation, never certified zeros.");
  scopeReadout.setAttribute("role", "status");
  scope.append(find, jump, referenceZero, scopeReadout);
  const disclosure = element("details", "harp-disclosure");
  const disclosureTitle = element("summary", "", "Mathematics and sound disclosures");
  disclosure.append(disclosureTitle);
  for (const text of [
    "M(t) sums from n=1 to N=floor(√(t/(2π))); each term is (2/√n) cos(θ(t) − t ln n). M(t) is real; the imaginary coordinate is only an auxiliary phase drawing, never |Z|.",
    "θ(t) uses (t/2)(ln(t/(2π))−1) − π/8 + 1/(48t) + 7/(5760t³). Every chart sample recomputes the full finite sum, with compensated addition. The tunnel and chart share those samples. Up to 65 strings and 129 flower vectors are drawn; the gold sum includes every active term.",
    "Binary64 arithmetic and the truncated θ asymptotic introduce error. Four embedded numerical reference windows supply Z_ref and R_ref=Z_ref−M_ref. Their chart traces use linear interpolation only within supplied ranges and are absent elsewhere. They never become tunnel geometry. The reference zeros are Odlyzko-derived and numerically refined, not certified. No certified error bounds are supplied. A crossing search can miss even-multiplicity roots or multiple crossings between samples; term-entry discontinuities are excluded.",
    "Truth Audio uses fₙ = vₜ(θ′(t)−ln n)/(2π), with one global vₜ equal to the playback height velocity and one volume scale. Pause makes vₜ=0. In full-sum mode the first 24 terms have individual sine voices; the rest are grouped into at most eight logarithmic bands with amplitude √Σaₙ² and amplitude-weighted mean rate. Band grouping preserves squared amplitude, not the exact waveform or phase. Voice selected term isolates that term instead. Rates outside 8–12,000 Hz are muted, with the live count shown above.",
    "Degrees is artistic semitone quantization, off by default. Amplitudes and frequencies are computed spectral values, never measured signals. Sound begins only on its button. Everything stays in this frame's memory; this face sends no requests and stores no progress.",
    "This instrument illustrates known mathematics. Nothing shown or heard is evidence for or against the Riemann Hypothesis (RH) or the Golden Horizon Principle (GHP).",
  ]) disclosure.append(element("p", "", text));
  disclosure.append(element("p", "", referenceDeviation()));
  const guide = element("details", "harp-disclosure");
  guide.append(element("summary", "", "A three-step flight guide"));
  for (const text of [
    "1. Fly: use Play, Speed, a height preset, or the logarithmic height slider. Drag the tunnel to turn it; Zoom changes its scale. Drag the gold chart to stop and inspect a local height.",
    "2. Inspect: choose any active term n, or click a drawn flower-vector tip. The inspector reports its computed amplitude, phase, real contribution, rate, and cutoff-entry height. Shadow, Slice, and Unfold show the same two phase coordinates.",
    "3. Listen: turn Sound on, then Play. Volume changes one common gain. Voice selected term isolates the inspected term. Degrees changes to an artistic scale; leave it off for the raw frequency law. Sound starts off and turns off when this page is hidden.",
  ]) guide.append(element("p", "", text));
  const fold = element("details", "harp-disclosure");
  fold.append(element("summary", "", "The Fold · four explanatory rooms"));
  const foldRooms = element("div", "harp-torus-controls");
  foldRooms.setAttribute("role", "group");
  foldRooms.setAttribute("aria-label", "Fold explanation");
  const foldText = element("p");
  const rooms = [
    ["Fold", "A phase can grow without bound while its angle, reduced modulo 2π, stays on a circle. Several angles form a product of circles. The bounded view discards winding counts; it is a picture of phase, not a lossless encoding of the original height."],
    ["Wind", "A pair of constant rates with an irrational ratio does not repeat exactly on a two-torus. This does not make an arbitrary winding uniform over a finite observation. The harp uses θ′(t)−ln n; it inserts no golden-ratio rate, and logarithms of composite integers have dependencies."],
    ["Address", "Binning each of three angles into three arcs yields 27 labels. Many different phase points share each label. Such an address is a coarse description, not a unique identity, a cryptographic hash, or owner authorization."],
    ["Reference", "A known generator and its parameters can reproduce a structured picture. A reference is useful only while the generator and referenced data remain available. It does not imply unlimited lossless compression or regeneration of arbitrary private information."],
  ] as const;
  const roomButtons: HTMLButtonElement[] = [];
  rooms.forEach(([name, text], index) => {
    const room = button(name);
    room.setAttribute("aria-pressed", String(index === 0));
    room.addEventListener("click", () => {
      foldText.textContent = text;
      roomButtons.forEach((node, at) => node.setAttribute("aria-pressed", String(at === index)));
    }, { signal });
    roomButtons.push(room);
    foldRooms.append(room);
  });
  foldText.textContent = rooms[0][1];
  fold.append(foldRooms, foldText, element("p", "harp-caption", "These rooms explain mathematical views and architectural analogies. They establish no new physics, storage guarantee, identity, or authority, and offer no evidence for RH or GHP."));
  root.replaceChildren(title, fence, status, readout, cockpit, audioReadout, navigation, scrubberField, layers,
    tunnel, instructions, chart, tools, scope, guide, disclosure, fold);

  function syncPlay(): void {
    play.textContent = paused ? "Play" : "Pause";
    play.setAttribute("aria-pressed", String(!paused));
    speedValue.textContent = `${speed.toFixed(2)} /s`;
    speedControl.setAttribute("aria-valuetext", `${speed.toFixed(2)} height units per second`);
    scrubber.setAttribute("aria-valuetext", `Height ${height.toFixed(4)}`);
  }

  function move(value: number, stop: boolean): void {
    height = requireHeight(value);
    if (stop) paused = true;
    options.selected = Math.min(options.selected, termCount(height));
    heightControl.value = height.toFixed(6);
    scrubber.value = String(Math.log10(height));
    clearCrossing();
    dirty = true;
    syncPlay();
  }

  function clearCrossing(): void {
    if (!scopeResult) return;
    scopeResult = false;
    crossingTarget = null;
    jump.disabled = true;
    scopeReadout.textContent = "Height changed. Search again for computed crossings in the displayed window; these are never certified zeros.";
  }

  function fail(error: unknown): void {
    life.abort();
    status.setAttribute("role", "alert");
    status.textContent = `Unavailable · ${code(error)}`;
    for (const control of root.querySelectorAll("button, input")) (control as HTMLInputElement).disabled = true;
  }

  function draw(now: number): void {
    data = heightWindow(height);
    drawTunnel(tunnel, data, height, options);
    drawChart(chart, data, height, options.resultant, showReference, showRemainder);
    drawFlower(flower, height, options.selected);
    drawTorus(torus, height, torusView);
    const selected = term(height, options.selected);
    termControl.max = String(termCount(height));
    if (document.activeElement !== termControl) termControl.value = String(options.selected);
    const rows = [
      ["Amplitude (computed)", selected.amplitude.toFixed(6)],
      ["Phase (radians)", selected.phase.toFixed(6)],
      ["Real contribution", selected.real.toFixed(6)],
      ["Rate (cycles / height)", selected.rate.toFixed(6)],
      ["Cutoff-entry height", selected.entry.toFixed(6)],
    ];
    inspector.replaceChildren(...rows.flatMap(([name, value]) => [element("dt", "", name), element("dd", "", value)]));
    if (now - lastReadout >= 250 || paused) {
      const current = sum(height);
      heightReadout.textContent = `t ${height.toFixed(5)}`;
      countReadout.textContent = `N ${termCount(height)}`;
      sumReadout.textContent = `M(t) ${current.real.toFixed(6)}`;
      chart.setAttribute("aria-label", `Finite main sum M(t)=${current.real.toFixed(6)} at height ${height.toFixed(5)}. Drag to scrub.`);
      lastReadout = now;
    }
    if (document.activeElement !== heightControl) heightControl.value = height.toFixed(6);
    scrubber.value = String(Math.log10(height));
    syncPlay();
    dirty = false;
    lastDraw = now;
  }

  function tick(now: number): void {
    if (signal.aborted) return;
    try {
      const delta = Math.max(0, (now - lastFrame) / 1000);
      lastFrame = now;
      if (!paused && !document.hidden) {
        clearCrossing();
        height = clampHeight(height + speed * delta);
        if (height === MAX_HEIGHT) paused = true;
        dirty = true;
      }
      if (dirty && now - lastDraw >= 100 && !document.hidden) draw(now);
      if (now - lastDraw < 20 || sounding) {
        audioReadout.textContent = `${sounding ? "Sound on. " : "Sound off. "}${sound.update({
          height, velocity: paused || document.hidden ? 0 : speed, volume, degrees, solo: solo ? options.selected : null,
        })}`;
      }
      frameId = requestAnimationFrame(tick);
    } catch (error) { fail(error); }
  }

  function goToInput(): void {
    try { move(heightControl.valueAsNumber, true); status.textContent = ""; }
    catch (error) { status.textContent = code(error); }
  }
  play.addEventListener("click", () => { paused = !paused; dirty = true; syncPlay(); }, { signal });
  speedControl.addEventListener("input", () => { speed = 10 ** speedControl.valueAsNumber; dirty = true; syncPlay(); }, { signal });
  zoom.addEventListener("input", () => { options.zoom = zoom.valueAsNumber; dirty = true; }, { signal });
  volumeControl.addEventListener("input", () => { volume = volumeControl.valueAsNumber; dirty = true; }, { signal });
  degreesButton.addEventListener("click", () => {
    degrees = !degrees;
    degreesButton.textContent = degrees ? "Degrees on · artistic" : "Degrees off";
    degreesButton.setAttribute("aria-pressed", String(degrees));
    dirty = true;
  }, { signal });
  soundButton.addEventListener("click", async () => {
    if (audioBusy) return;
    audioBusy = true;
    const revision = ++audioRevision;
    soundButton.disabled = true;
    try {
      if (sounding) { sounding = false; await sound.disable(); }
      else { await sound.enable(); sounding = !signal.aborted && revision === audioRevision; }
      if (!signal.aborted) status.textContent = "";
    } catch (error) { sounding = false; if (!signal.aborted) status.textContent = code(error); }
    finally {
      audioBusy = false;
      if (!signal.aborted) {
        soundButton.disabled = false;
        soundButton.textContent = sounding ? "Sound on" : "Sound off";
        soundButton.setAttribute("aria-pressed", String(sounding));
        dirty = true;
      }
    }
  }, { signal });
  soloButton.addEventListener("click", () => {
    solo = !solo;
    soloButton.textContent = solo ? "Return to full sum audio" : "Voice selected term";
    soloButton.setAttribute("aria-pressed", String(solo));
    dirty = true;
  }, { signal });
  go.addEventListener("click", goToInput, { signal });
  heightControl.addEventListener("keydown", event => { if (event.key === "Enter") goToInput(); }, { signal });
  scrubber.addEventListener("input", () => move(clampHeight(10 ** scrubber.valueAsNumber), true), { signal });
  termControl.addEventListener("change", () => {
    const n = termControl.valueAsNumber;
    if (!Number.isInteger(n) || n < 1 || n > termCount(height)) { status.textContent = "zetaharp:term-range"; return; }
    options.selected = n;
    status.textContent = "";
    dirty = true;
  }, { signal });
  find.addEventListener("click", () => {
    try {
      paused = true;
      data = heightWindow(height);
      crossingTarget = nearestCrossing(data);
      scopeResult = true;
      jump.disabled = crossingTarget === null;
      scopeReadout.textContent = crossingTarget === null
        ? "No sampled sign-change crossing in this window. This does not prove the absence of crossings."
        : `Computed crossing (finite approximation): t ≈ ${crossingTarget.toFixed(9)}. Not a certified zero.`;
      dirty = true;
      syncPlay();
    } catch (error) { fail(error); }
  }, { signal });
  jump.addEventListener("click", () => {
    if (crossingTarget === null) { status.textContent = "zetaharp:crossing-unavailable"; return; }
    move(crossingTarget, true);
  }, { signal });
  referenceZero.addEventListener("click", () => {
    const nearest = nearestReferenceZero(height);
    if (!nearest) { scopeReadout.textContent = "No numerical reference zero is available in the navigation range."; return; }
    move(nearest.height, true);
    scopeResult = true;
    scopeReadout.textContent = `Numerical reference zero #${nearest.index}: t ≈ ${nearest.height_decimal}. ` +
      "Nearest among the supplied references, not a complete zero list and not a certified zero.";
  }, { signal });

  const step = (direction: number, large: boolean) => move(clampHeight(height + direction * (large ? data.half * 2 : data.half / 10)), true);
  for (const canvas of [tunnel, chart]) canvas.addEventListener("keydown", event => {
    if (event.key === " " && !event.repeat) { event.preventDefault(); paused = !paused; dirty = true; syncPlay(); }
    else if (event.key === "ArrowLeft" || event.key === "ArrowRight") { event.preventDefault(); step(event.key === "ArrowLeft" ? -1 : 1, event.shiftKey); }
  }, { signal });
  tunnel.addEventListener("wheel", event => {
    event.preventDefault();
    const next = event.shiftKey ? height * Math.exp(event.deltaY * .001) : height + event.deltaY * data.half * .002;
    move(clampHeight(Number.isFinite(next) ? next : MAX_HEIGHT), true);
  }, { passive: false, signal });
  tunnel.addEventListener("pointerdown", event => {
    if (event.button !== 0) return;
    drag = { id: event.pointerId, x: event.clientX, y: event.clientY };
    tunnel.setPointerCapture(event.pointerId);
    tunnel.focus();
  }, { signal });
  tunnel.addEventListener("pointermove", event => {
    if (!drag || drag.id !== event.pointerId) return;
    options.yaw += (event.clientX - drag.x) * .008;
    options.pitch = Math.max(-1, Math.min(1, options.pitch + (event.clientY - drag.y) * .008));
    drag.x = event.clientX;
    drag.y = event.clientY;
    dirty = true;
  }, { signal });
  for (const event of ["pointerup", "pointercancel", "lostpointercapture"]) tunnel.addEventListener(event, () => { drag = null; }, { signal });
  const scrubTo = (event: PointerEvent) => {
    if (!scrub || scrub.id !== event.pointerId) return;
    const bounds = chart.getBoundingClientRect();
    const fraction = Math.max(0, Math.min(1, (event.clientX - bounds.left - 32) / Math.max(1, bounds.width - 64)));
    const samples = scrub.window.samples;
    move(samples[0].height + fraction * (samples[samples.length - 1].height - samples[0].height), true);
  };
  chart.addEventListener("pointerdown", event => {
    if (event.button !== 0) return;
    scrub = { id: event.pointerId, window: data };
    chart.setPointerCapture(event.pointerId);
    chart.focus();
    scrubTo(event);
  }, { signal });
  chart.addEventListener("pointermove", scrubTo, { signal });
  for (const event of ["pointerup", "pointercancel", "lostpointercapture"]) chart.addEventListener(event, () => { scrub = null; }, { signal });
  flower.addEventListener("pointerdown", event => {
    const bounds = flower.getBoundingClientRect();
    const radius = Math.min(bounds.width, bounds.height) * .36;
    const count = termCount(height);
    const candidates = new Set(Array.from({ length: Math.min(128, count) }, (_, at) => 1 + Math.floor(at * count / Math.min(128, count))));
    candidates.add(options.selected);
    let nearest = 16;
    for (const n of candidates) {
      const value = term(height, n);
      const distance = Math.hypot(event.clientX - bounds.left - bounds.width / 2 - value.real * radius / 2,
        event.clientY - bounds.top - bounds.height / 2 + value.imaginary * radius / 2);
      if (distance < nearest) { options.selected = n; nearest = distance; }
    }
    dirty = true;
  }, { signal });

  const motionChange = () => { if (reducedMotion.matches) { paused = true; dirty = true; syncPlay(); } };
  reducedMotion.addEventListener("change", motionChange, { signal });
  window.addEventListener("resize", () => { dirty = true; }, { signal });
  document.addEventListener("visibilitychange", () => {
    lastFrame = performance.now();
    dirty = true;
    if (document.hidden) {
      ++audioRevision;
      sounding = false;
      void sound.disable();
      soundButton.textContent = "Sound off";
      soundButton.setAttribute("aria-pressed", "false");
      audioReadout.textContent = "Sound off while this page is hidden. Use Sound to resume.";
    }
  }, { signal });
  const observer = new ResizeObserver(() => { dirty = true; });
  observer.observe(tunnel);
  signal.addEventListener("abort", () => {
    cancelAnimationFrame(frameId);
    observer.disconnect();
    sound.dispose();
    parentSignal.removeEventListener("abort", abort);
  }, { once: true });
  const abort = () => life.abort();
  parentSignal.addEventListener("abort", abort, { once: true });
  draw(performance.now());
  audioReadout.textContent = `Sound off. ${sound.update({ height, velocity: paused ? 0 : speed, volume, degrees, solo: null })}`;
  frameId = requestAnimationFrame(tick);
}
