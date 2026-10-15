// SPDX-License-Identifier: AGPL-3.0-or-later
import { openFace } from '../faces/aumlok/link.js';
import { mountStore } from './view.js';

openFace('store', 'App store', ({ root, client, signal }) => { mountStore(root, client, signal); });
