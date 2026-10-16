// SPDX-License-Identifier: AGPL-3.0-or-later
// The tri-pane. Three lanes sit in three grid tracks at all times; a lane with weight 0 is a zero-width track that
// is inert and invisible, never removed or moved, so what a hidden lane holds (its frames and their state) stays in
// the page. A lane that has the whole frame keeps its content at two thirds, centred, with no exception for any app.
// On a phone one lane shows at a time, full width, and the chosen composition is kept for when the screen widens.
import { COPY, TOKENS } from '../design/index.js';
import { BALANCED, LANES, cycle, soleLane, validWeights, wholeFrameLane } from './weights.js';
import type { Corner, LaneId, PaneWeights } from './weights.js';

export { LANES, PANE_WEIGHTS, validWeights } from './weights.js';
export type { Corner, LaneId, PaneWeights } from './weights.js';

export interface PaneState {
  /** The chosen composition. It does not change while a phone shows one lane. */
  readonly weights: PaneWeights;
  readonly phone: boolean;
  readonly phoneLane: LaneId;
  /** What is on screen now: the chosen weights, or the one lane of a phone with the whole frame. */
  readonly shown: PaneWeights;
}

const LANE_CORNERS: Readonly<Record<LaneId, readonly Corner[]>> = {
  threads: ['left'],
  surface: ['centre-left', 'centre-right'],
  menu: ['right'],
};
const CORNER_COPY: Readonly<Record<Corner, keyof typeof COPY.corners>> = {
  left: 'left',
  'centre-left': 'centreLeft',
  'centre-right': 'centreRight',
  right: 'right',
};

export class TriPane {
  readonly element: HTMLElement;
  /** The content element of each lane: what a lane shows goes in here. */
  readonly lanes: Readonly<Record<LaneId, HTMLElement>>;
  #sections: Readonly<Record<LaneId, HTMLElement>>;
  #weights: PaneWeights = BALANCED;
  #phoneLane: LaneId = 'threads';
  #narrow: MediaQueryList;
  #change: () => void;
  #observers = new Set<(state: PaneState) => void>();
  #disposed = false;

  constructor(parent: HTMLElement) {
    this.element = document.createElement('main');
    this.element.className = 'tri-pane';
    this.element.setAttribute('aria-label', COPY.workspace as string);
    const sections = {} as Record<LaneId, HTMLElement>;
    const lanes = {} as Record<LaneId, HTMLElement>;
    for (const id of LANES) {
      const section = document.createElement('section');
      section.className = 'lane';
      section.dataset.lane = id;
      section.setAttribute('aria-label', COPY.laneLabels[id]);
      const panel = document.createElement('div');
      panel.className = 'lane-panel';
      for (const corner of LANE_CORNERS[id]) panel.append(this.#cornerControl(corner));
      const body = document.createElement('div');
      body.className = 'lane-body';
      panel.append(body);
      section.append(panel);
      this.element.append(section);
      sections[id] = section;
      lanes[id] = body;
    }
    this.#sections = Object.freeze(sections);
    this.lanes = Object.freeze(lanes);
    parent.append(this.element);
    this.#narrow = matchMedia(`(max-width: ${TOKENS.metrics.phoneMaxWidth}px)`);
    this.#change = () => this.#render();
    this.#narrow.addEventListener('change', this.#change);
    this.#render();
  }

  get weights(): PaneWeights { return this.#weights; }
  get phoneLane(): LaneId { return this.#phoneLane; }
  get phone(): boolean { return this.#narrow.matches; }
  get state(): PaneState { return this.#state(); }

  /** Called after every change of composition, phone lane or screen class. Returns its own removal. */
  observe(observer: (state: PaneState) => void): () => void {
    this.#observers.add(observer);
    return () => { this.#observers.delete(observer); };
  }

  setWeights(weights: PaneWeights): void {
    if (!validWeights(weights)) throw new Error('shell:invalid-weights');
    this.#weights = Object.freeze([...weights]) as PaneWeights;
    this.#render();
  }

  /** Use one lane edge, as the corner buttons do. */
  cycle(corner: Corner): void {
    this.#weights = cycle(this.#weights, corner);
    this.#render();
  }

  showPhoneLane(lane: LaneId): void {
    if (!LANES.includes(lane)) throw new Error('shell:unknown-lane');
    this.#phoneLane = lane;
    this.#render();
  }

  /** Reveal a lane; only a hidden desktop lane resets the composition to balanced. */
  reveal(lane: LaneId): void {
    const index = LANES.indexOf(lane);
    if (index < 0) throw new Error('shell:unknown-lane');
    this.#phoneLane = lane;
    if (!this.phone && this.#weights[index] === 0) this.#weights = BALANCED;
    this.#render();
  }

  #cornerControl(corner: Corner): HTMLButtonElement {
    const control = document.createElement('button');
    control.type = 'button';
    control.className = 'corner';
    control.dataset.corner = corner;
    control.setAttribute('aria-label', COPY.corners[CORNER_COPY[corner]]);
    control.addEventListener('click', () => this.cycle(corner));
    return control;
  }

  #state(): PaneState {
    const phone = this.#narrow.matches;
    return Object.freeze({
      weights: this.#weights,
      phone,
      phoneLane: this.#phoneLane,
      shown: phone ? soleLane(this.#phoneLane) : this.#weights,
    });
  }

  #render(): void {
    if (this.#disposed) return;
    const state = this.#state();
    this.element.dataset.phone = String(state.phone);
    this.element.dataset.layout = state.shown.join('-');
    // The two-thirds measure belongs to a lane that has the whole frame on a screen wide enough to share it.
    this.element.dataset.measure = !state.phone && wholeFrameLane(state.shown) !== null ? 'focused' : 'shared';
    LANES.forEach((id, index) => {
      const active = state.shown[index] !== 0;
      const section = this.#sections[id];
      section.dataset.active = String(active);
      section.inert = !active;
      section.setAttribute('aria-hidden', String(!active));
    });
    for (const observer of [...this.#observers]) observer(state);
  }

  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#narrow.removeEventListener('change', this.#change);
    this.#observers.clear();
    this.element.remove();
  }
}
