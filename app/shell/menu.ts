// SPDX-License-Identifier: AGPL-3.0-or-later
import data from '../design/spatial/menu.json' with { type: 'json' };
import type { FaceManifest } from '../faces/catalog.js';

type Tab = 'apps' | 'system' | 'yours';
const TABS: readonly Tab[] = ['apps', 'system', 'yours'];
const SVG = 'http://www.w3.org/2000/svg';

export function element<K extends keyof HTMLElementTagNameMap>(tag: K, className = '', text = ''): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = text;
  return node;
}

function tabIcon(tab: Tab): SVGSVGElement {
  const icon = document.createElementNS(SVG, 'svg');
  icon.setAttribute('class', 'menuTabIcon');
  icon.setAttribute('viewBox', '0 0 16 16');
  icon.setAttribute('aria-hidden', 'true');
  icon.setAttribute('focusable', 'false');
  for (const shape of data.icons[tab]) {
    if (!['path', 'rect', 'circle'].includes(shape.tag)) throw new Error('design:unknown-icon');
    const node = document.createElementNS(SVG, shape.tag);
    for (const [name, value] of Object.entries(shape.attributes)) {
      if (!['d', 'x', 'y', 'width', 'height', 'rx', 'cx', 'cy', 'r'].includes(name)) throw new Error('design:unknown-icon');
      node.setAttribute(name, String(value));
    }
    icon.append(node);
  }
  return icon;
}

export function menuCard(title: string, description: string, select: () => void, signal: AbortSignal) {
  const button = element('button', 'menuItem');
  button.type = 'button';
  const copy = element('span', 'menuCopy');
  const subtitle = element('span', '', description);
  copy.append(element('strong', '', title));
  if (description) copy.append(subtitle);
  button.append(copy);
  button.addEventListener('click', select, { signal });
  return { button, subtitle };
}

export function createMenu(signal: AbortSignal) {
  const stack = element('div', 'rightStack');
  const layer = element('div', 'rightLayer');
  layer.dataset.rightLayer = 'menu';
  const header = element('div', 'menuHeader');
  const heading = element('span', 'menuHeading');
  heading.dataset.menuHeading = '';
  const tabs = element('div', 'menuTabs');
  tabs.setAttribute('role', 'tablist');
  tabs.setAttribute('aria-label', 'Menu sections');
  const panel = element('div', 'menuPanel');
  panel.id = 'spatial-menu-panel';
  panel.setAttribute('role', 'tabpanel');
  const groups = new Map<Tab, HTMLElement>();
  const buttons = new Map<Tab, HTMLButtonElement>();
  const choose = (tab: Tab, focus = false) => {
    stack.dataset.menuTab = tab;
    heading.textContent = data.tabs[tab];
    panel.setAttribute('aria-labelledby', `spatial-menu-${tab}`);
    for (const [name, button] of buttons) {
      button.setAttribute('aria-selected', String(name === tab));
      button.tabIndex = name === tab ? 0 : -1;
      const group = groups.get(name)!;
      group.hidden = name !== tab;
      group.inert = name !== tab;
    }
    if (focus) buttons.get(tab)!.focus();
  };
  for (const [index, tab] of TABS.entries()) {
    const button = element('button', 'menuTab');
    button.type = 'button';
    button.id = `spatial-menu-${tab}`;
    button.dataset.menuTab = tab;
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-controls', panel.id);
    button.append(tabIcon(tab), element('span', 'visuallyHidden', data.tabs[tab]));
    button.addEventListener('click', () => choose(tab), { signal });
    button.addEventListener('keydown', event => {
      let next: number;
      if (event.key === 'ArrowRight') next = (index + 1) % TABS.length;
      else if (event.key === 'ArrowLeft') next = (index + TABS.length - 1) % TABS.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = TABS.length - 1;
      else return;
      event.preventDefault();
      choose(TABS[next], true);
    }, { signal });
    buttons.set(tab, button);
    tabs.append(button);
    const group = element('div', 'menuEntries');
    group.dataset.slot = `shell.menu.${tab}`;
    groups.set(tab, group);
    panel.append(group);
  }
  groups.get('yours')!.append(element('p', 'menuEmpty', data.yoursEmpty));
  header.append(heading, tabs);
  layer.append(header, panel);
  stack.append(layer);
  choose('system');
  return {
    element: stack,
    system: groups.get('system')!,
    add(manifest: FaceManifest, open: () => void): HTMLButtonElement {
      const tab = manifest.menu.section === 'system' ? 'system'
        : manifest.menu.section === 'aukora_apps' ? 'apps' : null;
      if (!tab || !Object.hasOwn(data.subtitles, manifest.id)) throw new Error('shell:unknown-face');
      const subtitle = (data.subtitles as Readonly<Record<string, string>>)[manifest.id];
      const card = menuCard(manifest.title, subtitle, open, signal);
      card.button.dataset.face = manifest.id;
      groups.get(tab)!.append(card.button);
      return card.button;
    },
  };
}
