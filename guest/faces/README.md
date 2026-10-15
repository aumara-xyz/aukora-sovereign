# Spatial app faces

The owner's spatial app from AUKORA Prime (`plugins/aukora-face/*` at Prime `7a6351f`), mounted
browser-only in the sandboxed agent exactly as Prime NEXT does: each face keeps its built
client bundle (`lib/client.js`, plus `lib/invariant.js` where present) and its `dsh.client`
manifest; its host half is replaced by `lib/host.mjs`, a no-op `apply()`, because the Prime host
halves reach services outside the sandbox (state files, Nostr, Kira, OpenRouter). Features
backed by those services answer as unavailable until they are rewired through FD 3.

Mount order (sovereign.patch.yml): layout sidebar threads apps messages documents settings memory organs.
The aumlok face is deliberately absent: the chat origin is served by the untrusted agent, so
the binding phrase and identity ceremonies stay on the owner origin and are never typed here. The stock ui-layout, ui-sidebar,
ui-workspace and ui-settings-general rows are disabled because the faces replace them.
The apps face serves only Dakini Code from `apps/vendor`, with its third-party licences.

The small plain-JavaScript organs face adds Aura, Kira, Aumlok, Nostr, Verifier and WASM core
status surfaces. It reuses the settings face's surface, panel and menu classes; the existing
Aura Coherence entry and Pentora bundle stay unchanged. The bridge serves the six surfaces
through an authenticated GET `/api/sovereign/organs`, using its existing FD 3 link and the
closed C4 `organs.reply` schema. The Aumlok status surface has no ceremony controls. Its owner
link and the Verifier link accept only the exact HTTPS origin supplied by the supervisor.
The explanatory sentence uses identity, recovery and proof download wording because the chat
origin must not invite sensitive ceremony input.

The organs face also replaces the stock Plugins settings section with a read-only enabled
inventory. The stock inventory includes disabled entries, so merely disabling a provider
does not hide it there. The composition additionally disables these four rows:

- `deepseek-llm-api-extensions`: provider-specific model controls are outside C4.
- `web`: its direct remote search and fetch providers are unavailable in the confined guest.
- `ui-settings-plugins`: its shell, subagent-model and remote-search configuration cards
  cannot configure the sovereign supervisor.
- `ui-settings-plugin-inventory`: its complete loader list includes every disabled plugin;
  the replacement keeps enabled plugins, including the sovereign bridge and local harness.

The existing `llm-deepseek` and `llm-pi-ai` refusals remain; Kimi is a profile of the latter,
not a separate row in the pinned harness. Existing remote services and telemetry remain
disabled. The host `plugin-inventory`, model registry, sessions, uploads and storage remain.

Run `node --test guest/test/organs.test.mjs` and `node guest/test/organs-mutations.mjs` using
the pinned Node binary. The mutation runner restores every edited file. The tests exercise
the authenticated HTTP handler through a real in-memory FD 3 codec exchange and render all
six fixture surfaces. The installed harness and a browser remain untested in this clone.

`foundation/` is Prime's `aukora-foundation` (AUKORA palette and brand, browser-only; its host
half is already a no-op), and `branding.mjs` serves the one AUMARA mark the faces load
(`/branding/aumara-icon-96.png`). Both are Peter's own assets.

## Stock apps

The stock route plugin is mounted after the unavailable services. It serves only:

- `/stock-apps/dakini-code/index.html`
- `/stock-apps/dakini-code/favicon.svg`
- `/stock-apps/dakini-code/assets/index-C2MMIvhO.css`
- `/stock-apps/dakini-code/assets/index-t74FFCZZ.js`
- `/stock-apps/dakini-code/assets/space-Bu4O81zr.js`

These five files total 1,056,074 bytes, copied unchanged from Prime's pinned stock baseline
`645d3213b8aede3b544269b4224ae09df06b0a42`. Dakini's space chunk includes Three.js r186;
it needs no standalone Three.js modules. The unused r180 modules and their licence are absent.

Auma Lingwa (`/stock-apps/auma-lingwa.html`) and Auma Live (`/stock-apps/auma-live.html`)
are withheld pending voice qualification, as in Prime. Browser speech recognition can send
the owner's audio to a third party; a sovereign node must not do this silently. Their vendor
files, support routes and exclusive licence notices are absent. Zeta Harp is also withheld:
its imported tree needs remote resources and a wider stock route surface. Human Graph is
not vendored. Authenticated GET and HEAD requests to these stock URLs get the same empty
404; unsupported methods get 405. No substitute app is shown.

Every file is verified against the closed route manifest's byte length and SHA-256 before
mounting. Symlinks, path aliases, nonregular files and replacement during open are refused.
Handlers serve the verified snapshot, check the guest session first, allow only GET/HEAD,
and refuse malformed raw targets. Unlisted stock paths receive the empty refusal fallback.
The front door still owns chat-origin isolation and CSP.

Licence records (seven files, 18,031 bytes) are retained byte for byte in
[`apps/LICENSES/`](apps/LICENSES/):

- [React/React DOM notices](apps/LICENSES/DAKINI-REACT-NOTICES.md),
  [React MIT licence](apps/LICENSES/upstream/npm/react@19.2.6/LICENSE).
- [Base UI notices](apps/LICENSES/DAKINI-BASE-UI-NOTICES.md),
  [Base UI MIT licence](apps/LICENSES/upstream/npm/@base-ui/react@1.7.0/LICENSE).
- [Lucide/Three notices](apps/LICENSES/DAKINI-LUCIDE-THREE-NOTICES.md),
  [Lucide ISC/Feather MIT licences](apps/LICENSES/upstream/npm/lucide-react@1.31.0/LICENSE),
  [Dakini's bundled Three r186 MIT licence](apps/LICENSES/upstream/npm/three@0.186.0/LICENSE).

The unchanged notices retain Prime-relative provenance links and a historical reference to
the separate r180 component. They do not establish a complete dependency inventory or
reproduced build. No new Rust dependency is added.

Run `/Users/peterviviani/.local/node-v24.11.1/bin/node --test guest/test/stock-apps.test.mjs`.
Run `guest/test/stock-apps-mutations.mjs` with that Node binary while no other guest tests
or edits are in progress; it restores each mutated file in `finally`. The withholding antibody
pins the five-file route set and fails if either Auma page or a legacy support route is served.
The installed harness, inherited FD 4 listener and browser rendering are untested in this
private clone. Activation and live qualification remain with the integrator.
