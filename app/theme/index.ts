// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Organism, PluginDescriptor, PluginHandle, RpcService } from '../core/index.js';
import { projectTheme } from './project.js';
import type { ThemeState } from './project.js';

export * from './protocol.js';
export * from './bytes.js';
export * from './propose.js';
export * from './project.js';

export const THEME_SERVICE = 'theme';

/** Requires a target-reader service and creates no frame. */
export function themePlugin(root: HTMLElement, onState?: (state: Readonly<ThemeState>) => void): PluginDescriptor {
  return {
    id: 'auma-theme', requires: [THEME_SERVICE], menu: null, surface: null,
    setup(context) {
      const service = context.service<RpcService>(THEME_SERVICE);
      if (typeof service.call !== 'function') throw new Error('theme:reader-unavailable');
      const projection = projectTheme({
        root, signal: context.signal, onState,
        reader: { read: (body, signal) => Promise.resolve(service.call!('read', body, { signal })) },
      });
      context.effect(() => projection.dispose());
    },
  };
}

export function installTheme(organism: Organism, root: HTMLElement, onState?: (state: Readonly<ThemeState>) => void): PluginHandle {
  return organism.install(themePlugin(root, onState));
}
