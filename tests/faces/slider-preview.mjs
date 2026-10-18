// SPDX-License-Identifier: AGPL-3.0-or-later
// Render the production slider against fixture services only; no owner origin, transport or persistence is connected.
import { LEVELS, mountSlider } from '../../app/release/app/faces/general/slider.js';

const requested = new URLSearchParams(location.search).get('setting');
let setting = LEVELS.some(level => level.setting === requested) ? requested : 'risky';
const life = new AbortController();
const root = document.getElementById('face');
mountSlider(root, {
  async call(service, method, params) {
    if (service !== 'body') throw new Error('preview:service-unavailable');
    if (method === 'slider.get') return { setting };
    if (method !== 'slider.set') throw new Error('preview:service-unavailable');
    if (LEVELS.findIndex(level => level.setting === params.setting) > LEVELS.findIndex(level => level.setting === setting)) {
      return { state: 'pending', setting, proposal_id: 'a'.repeat(32) };
    }
    setting = params.setting;
    return { state: 'applied', setting };
  },
}, life.signal);
root.querySelector('.ak-portal__head').click();
window.addEventListener('pagehide', () => life.abort(), { once: true });
