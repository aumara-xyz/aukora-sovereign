/* Inline SVG icons (stroke = currentColor). Screens carry icons and colour
   only; aria-labels provide the accessible name without visible text. */

const svg = inner =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;

export const ICONS = {
  key: svg('<circle cx="8" cy="14" r="4"/><path d="M11 11l8-8"/><path d="M16 6l3 3"/><path d="M13 9l2 2"/>'),
  approvals: svg('<rect x="4" y="3" width="16" height="18" rx="3"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/>'),
  record: svg('<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 4v2M12 18v2M4 12h2M18 12h2"/>'),
  memory: svg('<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4"/><path d="M9 12h6M9 16h6"/>'),
  refresh: svg('<path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v5h-5"/>'),
  download: svg('<path d="M12 4v11"/><path d="M7 11l5 5 5-5"/><path d="M5 20h14"/>'),
  search: svg('<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>'),
  demote: svg('<circle cx="12" cy="12" r="8"/><path d="M8 12h8"/>'),
  alarm: svg('<path d="M12 3L2.5 20h19z"/><path d="M12 9.5V14"/><circle cx="12" cy="17" r="0.5" fill="currentColor"/>'),
  check: svg('<path d="M5 12.5l4.5 4.5L19 7.5"/>'),
  model: svg('<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2"/>'),
  agent: svg('<path d="M3 12h4l2.5-7 4 14 2.5-7H21"/>'),
  chat: svg('<path d="M4 5h16v11H9l-5 4z"/><path d="M8 9.5h8M8 12.5h5"/>'),
  share: svg('<circle cx="6" cy="12" r="2.5"/><circle cx="17.5" cy="5.5" r="2.5"/><circle cx="17.5" cy="18.5" r="2.5"/><path d="M8.2 10.8l7-3.9M8.2 13.2l7 3.9"/>'),
};

export function iconButton(name, label, cls = 'icon-btn') {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = cls;
  b.setAttribute('aria-label', label);
  b.title = label;
  b.innerHTML = ICONS[name];
  return b;
}
