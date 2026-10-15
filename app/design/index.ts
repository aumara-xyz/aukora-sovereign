// SPDX-License-Identifier: AGPL-3.0-or-later
// The pinned design data as the browser reads it. The JSON files beside this module are the data, pinned by
// design-lock.json; this module only types them, freezes them and draws icons from them. The build turns the
// token colours and metrics into tokens.css, so a stylesheet and this module read the same bytes.
import copy from './copy.json' with { type: 'json' };
import fonts from './fonts.json' with { type: 'json' };
import icons from './icons.json' with { type: 'json' };
import tokens from './tokens.json' with { type: 'json' };

const SVG_NS = 'http://www.w3.org/2000/svg';

export interface DesignTokens {
  readonly colors: Readonly<Record<string, string>>;
  readonly metrics: {
    readonly radius: number;
    readonly laneRadius: number;
    readonly controlRadius: number;
    readonly laneGap: number;
    readonly frameInset: number;
    readonly phoneInset: number;
    readonly cornerSize: number;
    readonly focusedMeasure: readonly [number, number];
    readonly phoneMaxWidth: number;
  };
  readonly type: Readonly<Record<string, number>>;
  readonly motion: { readonly fast: number; readonly slow: number; readonly ease: string };
  readonly health: Readonly<Record<string, string>>;
}
export interface DesignCopy {
  readonly [key: string]: string | { readonly [key: string]: string };
  readonly laneTabs: { readonly threads: string; readonly surface: string; readonly menu: string };
  readonly laneLabels: { readonly threads: string; readonly surface: string; readonly menu: string };
  readonly corners: {
    readonly left: string;
    readonly centreLeft: string;
    readonly centreRight: string;
    readonly right: string;
  };
}
export interface DesignIcons {
  readonly viewBox: string;
  readonly strokeWidth: number;
  readonly paths: Readonly<Record<string, string>>;
  readonly brand: { readonly mark: string; readonly size: number };
}

function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const member of Object.values(value)) freeze(member);
    Object.freeze(value);
  }
  return value;
}

export const TOKENS = freeze(tokens) as unknown as DesignTokens;
export const COPY = freeze(copy) as unknown as DesignCopy;
export const ICONS = freeze(icons) as unknown as DesignIcons;
export const FONTS = freeze(fonts) as unknown as {
  readonly interface: readonly string[];
  readonly monospace: readonly string[];
  readonly bundled: readonly string[];
};

/** Copy strings carry {name} holes; a hole with no value is a defect and refuses. */
export function fill(template: string, values: Readonly<Record<string, string>>): string {
  return template.replace(/\{([a-zA-Z]+)\}/g, (_hole, name: string) => {
    const value = values[name];
    if (value === undefined) throw new Error('design:copy-hole');
    return value;
  });
}

/** A line icon from icons.json. The path is data; every attribute is set one by one, never parsed from markup. */
export function icon(name: string, className = 'icon'): SVGSVGElement {
  const path = ICONS.paths[name];
  if (path === undefined) throw new Error('design:unknown-icon');
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', className);
  svg.setAttribute('viewBox', ICONS.viewBox);
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', String(ICONS.strokeWidth));
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  const shape = document.createElementNS(SVG_NS, 'path');
  shape.setAttribute('d', path);
  svg.append(shape);
  return svg;
}

/** The brand mark's address beside this module, for an img whose alt text is empty. */
export function brandMarkUrl(): string {
  return new URL(`./${ICONS.brand.mark}`, import.meta.url).href;
}
