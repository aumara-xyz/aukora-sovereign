/* Owner-origin router. Bootstrap order (SPEC §5): claim -> enrol -> bind ->
   owner screens, with sign-in (OWNER-API §7) when the node is bound/released
   but this browser holds no session. The bound UI is hash-routed:
   #/approvals, #/model, #/aura, #/memory, #/identity. */

import { api } from './api.js';
import { ICONS } from './icons.js';
import { bootStage } from './route-state.js';
import { showClaim } from './screens/claim.js';
import { showSignIn } from './screens/signin.js';
import { showBinding } from './screens/binding.js';
import { showIdentity } from './screens/identity.js';
import { showApprovals } from './screens/approvals.js';
import { showModel } from './screens/model.js';
import { showAura } from './screens/aura.js';
import { showMemory } from './screens/memory.js';
import { showMessages } from './screens/messages.js';
import { ownerRoute, configuredChatOrigin, postDecision } from './embed.js';
import { mountNostrIdentity } from './nostr-identity.js';
import { addOwnerLinks, chatSessionUrl } from './owner-links.js';
import { addSignOut } from './session-controls.js';
import { mountOwnerWitness } from './owner-witness.js';

const ROUTES = {
  approvals: showApprovals,
  model: showModel,
  aura: showAura,
  memory: showMemory,
  identity: showIdentity,
  messages: showMessages,
  aumlok: (app, options) => showIdentity(app, { ...options, embedded: true }),
  nostr: async app => {
    app.replaceChildren();
    const panel = document.createElement('main');
    panel.className = 'panel stage';
    app.appendChild(panel);
    await mountNostrIdentity(panel);
  },
};

function nav(active) {
  const nav = document.createElement('nav');
  nav.className = 'owner-nav';
  for (const [name, icon] of [['approvals', ICONS.approvals], ['model', ICONS.model], ['aura', ICONS.record], ['memory', ICONS.memory], ['messages', ICONS.chat], ['identity', ICONS.key]]) {
    const a = document.createElement('a');
    a.href = `#/${name}`;
    a.setAttribute('aria-label', name);
    a.innerHTML = icon;
    a.dataset.active = String(name === active);
    nav.appendChild(a);
  }
  addOwnerLinks(nav);
  return nav;
}

export function mountOwnerApp(app) {
  let listening = false;
  let chatOrigin;

  function frame() {
    const route = ownerRoute(location.hash);
    document.body.classList.toggle('owner-embed', route.embedded);
    return route;
  }

  async function route() {
    const { pane, embedded } = frame();
    app.replaceChildren();
    if (!pane) {
      const error = document.createElement('p');
      error.textContent = 'frontdoor:unknown-pane';
      app.appendChild(error);
      return;
    }
    const screen = ROUTES[pane] ?? ROUTES.approvals;
    if (!embedded) app.appendChild(nav(ROUTES[pane] ? pane : 'approvals'));
    const stage = document.createElement('div');
    stage.id = 'screen';
    stage.style.display = 'contents';
    // Keep the retained-head alarm available inside the panel as well.
    const observation = mountOwnerWitness(app);
    app.appendChild(stage);
    await screen(stage, {
      observation, embedded,
      onDecided: embedded && pane === 'approvals' ? async () => {
        const { pending } = await api.approvals();
        postDecision(chatOrigin, pending.length);
      } : undefined,
    });
  }

  async function boot() {
    const { embedded } = frame();
    const handoff = location.pathname === '/__aukora/handoff';
    let state;
    try {
      state = await api.state();
      if (handoff && state.session === true) {
        app.replaceChildren();
        location.replace(await chatSessionUrl());
        return;
      }
      if (embedded) chatOrigin = await configuredChatOrigin();
    } catch (ex) {
      app.replaceChildren();
      const err = document.createElement('p');
      err.className = 'instruct warn';
      err.textContent = ex.code ?? String(ex);
      app.appendChild(err);
      return;
    }
    if (handoff) return showSignIn(app, { onDone: boot });
    const stage = bootStage(state);
    if (stage === 'claim') return showClaim(app, { stage: 'claim', onDone: boot });
    if (stage === 'enrol' || stage === 'bind') {
      if (stage === 'enrol') await showClaim(app, { stage: 'enrol', onDone: boot });
      else await showBinding(app, { onDone: boot });
      if (!embedded) addSignOut(app);
      mountOwnerWitness(app);
      return;
    }
    if (stage === 'signin') return showSignIn(app, { onDone: boot });
    if (!listening) {
      window.addEventListener('hashchange', boot);
      listening = true;
    }
    await route();
  }
  return { boot };
}

const app = document.getElementById('app');
if (app) void mountOwnerApp(app).boot();
