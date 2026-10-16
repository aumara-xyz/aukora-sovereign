// SPDX-License-Identifier: AGPL-3.0-or-later
import { COPY, TOKENS } from '../design/index.js';
import { BALANCED, LANES, cycle, soleLane, validWeights, wholeFrameLane } from './weights.js';
import type { Corner, LaneId, PaneWeights } from './weights.js';

export { LANES, PANE_WEIGHTS, validWeights } from './weights.js';
export type { Corner, LaneId, PaneWeights } from './weights.js';
export interface PaneState {
  readonly weights: PaneWeights;
  readonly phone: boolean;
  readonly phoneLane: LaneId;
  readonly shown: PaneWeights;
}

const PRESETS: Readonly<Record<string, string>> = {
  '1-1-1': 'balanced', '2-1-0': 'left-wide', '2-0-1': 'left-menu-wide', '3-0-0': 'left-focus',
  '0-2-1': 'center-left-wide', '1-2-0': 'center-right-wide', '0-3-0': 'center-focus',
  '0-1-2': 'right-wide', '1-0-2': 'right-threads-wide', '0-0-3': 'right-focus',
};
const SIDES: Readonly<Record<LaneId, string>> = { threads: 'left', surface: 'center', menu: 'right' };
const CORNERS: Readonly<Record<LaneId, readonly Corner[]>> = {
  threads: ['left'], surface: ['centre-left', 'centre-right'], menu: ['right'],
};
const LABELS: Readonly<Record<Corner, string>> = {
  left: COPY.corners.left, 'centre-left': COPY.corners.centreLeft,
  'centre-right': COPY.corners.centreRight, right: COPY.corners.right,
};

export class TriPane {
  readonly element = document.createElement('div');
  readonly lanes: Readonly<Record<LaneId, HTMLElement>>;
  #sections = new Map<LaneId, HTMLElement>();
  #weights: PaneWeights = BALANCED;
  #phoneLane: LaneId = 'threads';
  #narrow = matchMedia(`(max-width: ${TOKENS.metrics.phoneMaxWidth}px)`);
  #life = new AbortController();
  #observers = new Set<(state: PaneState) => void>();
  #close = document.createElement('button');
  #conversation = false;

  constructor(parent: HTMLElement, closeConversation: () => void) {
    this.element.className = 'frame';
    this.element.dataset.surfacePresentation = 'contained';
    this.element.dataset.detailsCollapsed = 'true';
    this.element.setAttribute('aria-label', COPY.workspace as string);
    this.#close.type = 'button';
    this.#close.className = 'cornerControl';
    this.#close.dataset.corner = 'conversation-close';
    this.#close.setAttribute('aria-label', 'Close thread');
    this.#close.addEventListener('click', closeConversation, { signal: this.#life.signal });
    const lanes = {} as Record<LaneId, HTMLElement>;
    for (const id of LANES) {
      const section = document.createElement('section');
      const side = SIDES[id];
      section.className = `lane lane${side[0].toUpperCase()}${side.slice(1)}${id === 'surface' ? ' centerCol' : ''}`;
      section.dataset.lane = side;
      section.setAttribute('aria-label', COPY.laneLabels[id]);
      const shell = document.createElement('div');
      shell.className = 'laneShell';
      if (id === 'threads') shell.append(this.#close);
      for (const corner of CORNERS[id]) {
        const control = document.createElement('button');
        control.type = 'button';
        control.className = 'cornerControl';
        control.dataset.corner = corner.replace('centre', 'center');
        control.setAttribute('aria-label', LABELS[corner]);
        control.addEventListener('click', () => this.cycle(corner), { signal: this.#life.signal });
        shell.append(control);
      }
      const body = document.createElement('div');
      body.className = 'laneBody';
      shell.append(body);
      section.append(shell);
      this.element.append(section);
      this.#sections.set(id, section);
      lanes[id] = body;
    }
    const overlay = document.createElement('div');
    overlay.className = 'overlayLayer';
    overlay.dataset.shellOverlay = '';
    this.element.append(overlay);
    this.lanes = Object.freeze(lanes);
    parent.append(this.element);
    this.#narrow.addEventListener('change', () => this.#render(), { signal: this.#life.signal });
    this.#render();
  }

  get weights(): PaneWeights { return this.#weights; }
  get phone(): boolean { return this.#narrow.matches; }
  get phoneLane(): LaneId { return this.#phoneLane; }
  get state(): PaneState {
    return Object.freeze({ weights: this.#weights, phone: this.phone, phoneLane: this.#phoneLane,
      shown: this.phone ? soleLane(this.#phoneLane) : this.#weights });
  }

  observe(observer: (state: PaneState) => void): () => void {
    this.#observers.add(observer);
    return () => { this.#observers.delete(observer); };
  }

  setWeights(weights: PaneWeights): void {
    if (!validWeights(weights)) throw new Error('shell:invalid-weights');
    this.#weights = Object.freeze([...weights]) as PaneWeights;
    this.#render();
  }

  cycle(corner: Corner): void {
    if (this.phone) {
      const destination: Record<Corner, LaneId> = {
        left: 'surface', 'centre-left': 'threads', 'centre-right': 'menu', right: 'threads',
      };
      if (!Object.hasOwn(destination, corner)) throw new Error('shell:unknown-corner');
      this.showPhoneLane(destination[corner]);
    } else this.setWeights(cycle(this.#weights, corner));
  }

  showPhoneLane(lane: LaneId): void {
    if (!LANES.includes(lane)) throw new Error('shell:unknown-lane');
    this.#phoneLane = lane;
    this.#render();
  }

  reveal(lane: LaneId): void {
    const index = LANES.indexOf(lane);
    if (index < 0) throw new Error('shell:unknown-lane');
    this.#phoneLane = lane;
    if (!this.phone && this.#weights[index] === 0) this.#weights = BALANCED;
    this.#render();
  }

  conversation(open: boolean): void {
    this.#conversation = open;
    this.#render();
  }

  #render(): void {
    if (this.#life.signal.aborted) return;
    const state = this.state;
    const focused = !state.phone ? wholeFrameLane(state.shown) : null;
    this.element.dataset.phone = String(state.phone);
    this.element.dataset.panePreset = PRESETS[state.shown.join('-')];
    this.element.dataset.layout = state.shown.join('-');
    if (focused) {
      this.element.dataset.focusedLane = SIDES[focused];
      this.element.dataset.singleMeasure = 'two-thirds';
    } else {
      delete this.element.dataset.focusedLane;
      delete this.element.dataset.singleMeasure;
    }
    this.element.toggleAttribute('data-sidebar-collapsed', state.shown[0] === 0);
    this.element.toggleAttribute('data-conversation-open', this.#conversation);
    this.#close.hidden = !this.#conversation;
    LANES.forEach((id, index) => {
      const section = this.#sections.get(id)!;
      const active = state.shown[index] > 0;
      section.toggleAttribute('data-pane-active', active);
      section.inert = !active;
      section.setAttribute('aria-hidden', String(!active));
    });
    for (const observer of this.#observers) observer(state);
  }

  dispose(): void {
    this.#life.abort();
    this.#observers.clear();
    this.element.remove();
  }
}
