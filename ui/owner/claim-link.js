// SPDX-License-Identifier: AGPL-3.0-or-later
let linkedClaim = null;
const params = new URLSearchParams(location.hash.slice(1));
if (params.has('claim')) {
  linkedClaim = params.get('claim');
  history.replaceState(null, '', location.pathname);
}

// A claim link opened in a tab already showing this page changes only the hash, which
// does not reload it; reload so the new claim is read exactly as on a fresh visit.
window.addEventListener('hashchange', () => {
  if (new URLSearchParams(location.hash.slice(1)).has('claim')) location.reload();
});

export function takeLinkClaim() {
  const token = linkedClaim;
  linkedClaim = null;
  return token;
}
