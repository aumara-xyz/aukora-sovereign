// SPDX-License-Identifier: AGPL-3.0-or-later
export type LaneId = 'threads' | 'surface' | 'menu';
export type PaneWeights = readonly [number, number, number];
export const LANES: readonly LaneId[] = ['threads', 'surface', 'menu'];

export const PANE_WEIGHTS: readonly PaneWeights[] = Object.freeze(
  Array.from({ length: 4 }, (_, left) =>
    Array.from({ length: 4 - left }, (_, center) =>
      Object.freeze([left, center, 3 - left - center]) as PaneWeights)).flat(),
);

export function validWeights(value: readonly number[]): value is PaneWeights {
  return value.length === 3 && value.every(n => Number.isInteger(n) && n >= 0 && n <= 3)
    && value.reduce((sum, n) => sum + n, 0) === 3;
}

export class TriPane {
  readonly element: HTMLElement;
  readonly lanes: Readonly<Record<LaneId, HTMLElement>>;
  #weights: PaneWeights = [1, 1, 1];
  #phoneLane: LaneId = 'threads';
  #narrow: MediaQueryList;
  #change: () => void;

  constructor(parent: HTMLElement) {
    this.element = document.createElement('main');
    this.element.className = 'tri-pane';
    this.element.setAttribute('aria-label', 'Spatial workspace');
    const lanes = {} as Record<LaneId, HTMLElement>;
    for (const id of LANES) {
      const lane = document.createElement('section');
      lane.className = 'lane';
      lane.dataset.lane = id;
      lane.setAttribute('aria-label', id === 'surface' ? 'App' : id === 'menu' ? 'Apps and System' : 'Threads');
      const content = document.createElement('div');
      content.className = 'lane-content';
      lane.append(content);
      this.element.append(lane);
      lanes[id] = content;
    }
    this.lanes = Object.freeze(lanes);
    parent.append(this.element);
    this.#narrow = matchMedia('(max-width: 700px)');
    this.#change = () => this.#render();
    this.#narrow.addEventListener('change', this.#change);
    this.#render();
  }

  get weights(): PaneWeights { return [...this.#weights] as unknown as PaneWeights; }
  get phoneLane(): LaneId { return this.#phoneLane; }

  setWeights(weights: PaneWeights): void {
    if (!validWeights(weights)) throw new Error('shell:invalid-weights');
    this.#weights = [...weights] as unknown as PaneWeights;
    this.#render();
  }

  showPhoneLane(lane: LaneId): void {
    if (!LANES.includes(lane)) throw new Error('shell:unknown-lane');
    this.#phoneLane = lane;
    this.#render();
  }

  reveal(lane: LaneId): void {
    this.#phoneLane = lane;
    const index = LANES.indexOf(lane);
    if (index < 0) throw new Error('shell:unknown-lane');
    if (this.#weights[index] === 0) this.#weights = [1, 1, 1];
    this.#render();
  }

  #render(): void {
    this.element.dataset.phone = String(this.#narrow.matches);
    this.element.dataset.weights = this.#weights.join('-');
    const visible = this.#narrow.matches ? 1 : this.#weights.filter(n => n > 0).length;
    this.element.dataset.single = String(visible === 1);
    this.element.style.gridTemplateColumns = this.#narrow.matches ? 'minmax(0, 1fr)'
      : this.#weights.filter(n => n > 0).map(n => `minmax(0, ${n}fr)`).join(' ');
    LANES.forEach((id, index) => {
      const lane = this.lanes[id].parentElement!;
      const active = this.#narrow.matches ? id === this.#phoneLane : this.#weights[index] !== 0;
      lane.hidden = !active;
      lane.inert = !active;
      lane.setAttribute('aria-hidden', String(!active));
    });
  }

  dispose(): void {
    this.#narrow.removeEventListener('change', this.#change);
    this.element.remove();
  }
}
