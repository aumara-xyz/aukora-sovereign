# Port notes: Prime's Spatial app on DeepSeek Harness 0.2.1-alpha.5

Source: Prime `plugins/aukora-face` at 3673b98 (licences and notices: `NOTICE`, `licenses/`) (built against dsh `0d1f500`, "untagged commit 5 after dsh-v0.1.6-alpha.1").
Target: `@deepseek-ai/dsh@0.2.1-alpha.5` (GitHub tag `dsh-v0.2.1-alpha.5`, `1517a4d`).

**The first commit of this branch (45da3d8) is the verbatim copy** (Prime's committed `lib/` build outputs omitted).
`git diff 45da3d8` shows every adaptation below and nothing else. Every `.module.css`, `spatial-tokens.css`, string,
locale and component is untouched except where a line below says so. `apps/vendor/**` is byte-identical to Prime
(`git diff 45da3d8 -- engine/plugins/aukora-face/apps/vendor` is empty).

Line numbers are **Prime's** (the verbatim commit), so each can be read straight from `git show 45da3d8:<path>`.
Marks: RAN = executed here, SOURCE = read in the DSH 0.2.1-alpha.5 source, GUESS = not verified.

## What was added besides the copy

| Path | Why |
|---|---|
| `build-face.py` | Builds the nine packages with the harness's own tsdown preset inside a DSH checkout (the preset's imports are relative into the monorepo, so a face cannot carry a copy). Same method as Prime's `scripts/build-face.py`. Also builds the foundation. RAN |
| `preview-face.py` | Assembles a profile `aukora` (dsh-base + one face bundle) in a scratch install and boots `dsh web`. RAN |
| `threads/src/client/icons.tsx`, `settings/src/client/icons.tsx` | The old icon glyphs, verbatim (see 8). |
| `../aukora-foundation/` | Prime's `plugins/aukora-foundation` (AUKORA brand slots and palette), verbatim except its `lib/` output. It is a separate Prime plugin, but the Spatial look needs it: without it the sidebar shows "deepseek HARNESS" and the lanes use the stock palette. RAN (screenshot) |
| `.gitignore`, `checks/scaffold.json` | `lib/` outputs are build products; `engine` is registered as a top-level directory. |

## Adaptations (old API -> new API)

### 1. Runtime invariants removed (all nine faces) - SOURCE `docs/upgrade-guide/v0.2.0-rc.2/remove-runtime-invariants`
`@deepseek-ai/dsh-invariants`, `ctx.invariants` and every `<package>/invariant` subpath are gone. Eight of the nine faces' `src/invariant.ts`
were empty companions (`install = () => {}`; memory had none), so deleting those loses nothing.
**`apps/src/invariant.ts` was not empty.** It validated every `auma-canvas/document` event, on load and on append: data holds only `document`; `document` is null or
an object with exactly the keys `css`, `markup`, `title`, `version`; `version` is 1; `title` is 1-160 characters and already trimmed; `markup` is a non-blank string; `css` is a string.
Those checks now live in the zod schema of `apps/src/auma-canvas/projection.ts` (`documentSchema` is a strict object with those fields, and `apply` parses each event's data
with `eventDataSchema`), so the replayed projection cannot hold a document the tool would never have written. Failing the append itself is no longer possible (no invariant service);
a bad event now fails the projection's `apply`. The tool (`auma-canvas-tool.ts`) already enforced the same rules before appending.
- Deleted: `{layout,sidebar,threads,apps,messages,documents,aumlok,settings}/src/invariant.ts` (memory had none; only apps' held logic, moved as above).
- `package.json`: `./invariant` export, both `@deepseek-ai/dsh-invariants` entries and `lib/invariant.js` in `files`
  (layout 20-22,58,77,84; sidebar 20-22,52,61,70; threads 20-22,61,77,93; apps 20-22,67,101,125; messages 23-25,60,67,79;
  documents 19-21,57,68,77; aumlok 20-22,62,72,86; settings 20-22,61,82,94; memory 59,69,81).
- `tsconfig*.json`: `src/invariant.ts` (layout/tsconfig.json:11, messages/tsconfig.host.json:14, settings/tsconfig.host.json:15,
  documents/tsconfig.host.json:12) and the `runtime-diagnostics/invariants` reference (layout 73, 49; sidebar 23; threads 41; apps client 31 / host 54;
  messages client 29 / host 20; documents client 29 / host 17; aumlok 20; settings client 45 / host 24; memory 29).
- `tsdown.config.ts:3` of each (apps:5, memory comment only): the `'lib/types/invariant.js'` entry.

### 2. Client bundle preset takes a directory - SOURCE `packages/client/tsdown.client.ts:96-125`
`clientBundle('@aukora/face-x', entries)` -> `clientBundle(import.meta.dirname, entries)`: `tsdown.config.ts:3` in layout, sidebar,
threads, messages, documents, aumlok, settings; `apps/tsdown.config.ts:3`; `memory/tsdown.config.ts:6`.
`plugins/aukora-face/tsdown.client.ts` (a re-export of `vendor/dsh/...` for running a config from a checkout) is deleted:
Sovereign has no `vendor/dsh`, and the overlay build resolves `../tsdown.client.ts` to upstream's own file.

### 3. tsconfig projects split into client and host halves - SOURCE `packages/client/{locale,ui-theme,ui-conversation,ui-settings}/tsconfig.{client,host}.json`
A reference to a package that now has both halves must name the half: `../locale` -> `../locale/tsconfig.client.json` (client) or `.../tsconfig.host.json` (host).
layout/tsconfig.json:46 (ui-conversation), 61 (locale), 67 (ui-theme); layout/tsconfig.host.json:37 (locale), 43 (ui-theme);
threads/tsconfig.json:20 (locale), 38 (ui-conversation); apps/tsconfig.client.json:29 (ui-conversation), 33 (locale);
aumlok/tsconfig.json:26; documents/tsconfig.client.json:32; memory/tsconfig.client.json:35; messages/tsconfig.client.json:32;
settings/tsconfig.client.json:47 (locale), 51 (ui-settings). Plus one new file entry (settings/tsconfig.client.json after :34, `src/client/icons.tsx`)
and new `../ui-workspace` references in layout/tsconfig.json and memory/tsconfig.client.json (see 4).

### 4. The Session Controller no longer owns a selection - SOURCE `api/session-controller/src/client/contract/sessions.ts`
Removed: `SessionListState.current`, `ISessions.open()`, `ISessions.clear()`. "Navigation belongs to view owners": the view owner is
`ctx.uiWorkspace`, which holds one `mainView` reference (`ISessions.retain(target, { source: 'mainView' })`) and persists the
selection under the same `dsh.sessions.current` key. The selection is therefore read as *the listed Session whose
`retainedBy.mainView > 0`*, exactly as the harness's own `ui-layout/src/client/DocumentTitle.tsx` does.
- `layout/src/client/AppFrame.tsx:184,188,236,240` -> new helper `mainViewSessionOf` (added after line 19).
- `layout/src/client/index.ts:195` `ctx.sessions.open(id)` -> `ctx.uiWorkspace.openSession(id)`; type import of `ui-workspace/client` (layout/index.ts after :11, package.json devDependency, tsconfig reference).
- `threads/src/client/tree.ts:235,246,305,307,350,424,445` -> `currentOf(list)` (new, exported, after :38).
- `threads/src/client/WorkspaceBrowser.tsx:260,661,767,846` -> `currentOf(list)`.
- `apps/src/client/AumaLiveSurface.tsx:22`, `settings/src/client/AuraCoherenceSurface.tsx:450`, `settings/src/client/SettingsOnboarding.tsx:36`: inline form of the same rule.
- `memory/src/client/index.ts:58`: `ctx.sessions.open(id)` -> `ctx.uiWorkspace.openSession(id)` (the row's comment already says it opens the conversation); type import after :10, devDependency and tsconfig reference.
- **`threads/src/client/navigation.ts` (the largest change).** This face replaces the harness's workspace browser, so it must publish `uiWorkspace`. The face's own copy
  of the old `UiWorkspace` interface and its `declare module` merge (26-87) are replaced by the harness's `UiWorkspace`/`StartSessionOptions` types
  (`ui-workspace/client`), and the service body (107-307) is the harness's own `UiWorkspaceService` (`ui-workspace/src/client/navigation.ts`) with the face's three differences kept:
  (a) a thread gesture opens the resident Conversation (`layout.openConversation()` in `replaceMain(..., 'reveal')` and at the top of `startSession`; a restored selection is `'preserve'`, never opens it, as before),
  (b) no default workspace is created on an empty install (the harness added `initializeDefault`; Prime had none), (c) failures are `console.warn`ed, not shown in a toast the face does not have.
  New interface members implemented: `pinSession`/`unpinSession`, `openSession(target)` taking a subagent address, `forkSession(id, onCreated, options)` (no longer navigates), `startSession(ws, options)` draft preparation, `archiveSession(id, options)`.
- `threads/src/client/index.ts:137` thread-row fork: `forkSession` no longer opens the child, so the row handler opens it unless a later navigation superseded it (same behaviour as before).

### 5. `SessionSummary.completed` removed -> `useSessionStatus(...).completionUnread` - SOURCE `ui-session/src/client/index.ts` (`SessionStatus`)
`threads/src/client/tree.ts:275,460` read `completed` from the summary. New exported `completedSessionsOf(statuses)`; `deriveGroups`, `deriveFlat`, `deriveSearchResults` and `sessionNode`
take a trailing optional `completed` set (tree.ts:295,338,390 signatures); `WorkspaceBrowser.tsx` reads `useSessionStatus` in the three bodies that derive rows (props at 217,558,721; calls at 330,579,584,588,736; JSX at 1252,1268,1286; destructure at 804) and passes the set.

### 6. `useSessionPendingInteraction` folded into `useSessionStatus` - SOURCE `ui-session/src/client/index.ts`
`settings/src/client/AuraCoherenceSurface.tsx:447,476`: `useSessionPendingInteraction(s => s)` + `.get(id)` -> `useSessionStatus(s => s)` + `.get(id)?.pendingInteraction`.

### 7. `ISessions.binding(id)` only borrows an already-retained Session - SOURCE `contract/sessions.ts` (`binding`, `using`)
Renaming a thread that is not open used to work through `binding()`. `threads/src/client/index.ts:130-133` (row rename) and `:196-198` (header rename) now hold a reference for the call:
`ctx.sessions.using(id, { source: 'workspaceOperation' }, ref => ref.binding.session.rename(title))`.

### 8. Icon artwork redrawn - SOURCE `ui-primitives/src/icons/index.tsx`
The `Icon<Name><Size>` exports (`IconPlusOutline16`, ...) were replaced by stroke glyphs named `Icon<Name>Regular|Medium`. The Spatial look is the old filled glyphs, so the twelve
(threads) and two (settings) the face uses are carried verbatim from the pinned harness into `icons.tsx`, and the import lines move: `threads/src/client/rows/Rows.tsx:11-13`,
`WorkspaceBrowser.tsx:14-15`, `WorkspacePicker.tsx:14`, `ThreadHeaderActions.tsx:4`, `ThreadListHeaderActions.tsx:3`; `settings/src/client/SettingsRoot.tsx:6`, `SettingsDocumentAction.tsx:5`.

### 9. `ctx.layout` carries `panelInfo` - SOURCE `ui-layout/src/client/service.ts:36-43`, read by `ui-sidebar-right/src/client/index.ts:139,142`
`layout/src/client/service.ts:31` adds `readonly panelInfo` to `ILayout`, `:95` the `LayoutController` constructor takes it; `layout/src/client/index.ts:126,136` build the controller after the constant `panelInfo` source (already published as the root hook).
Without it the right Sidebar plugin fails to activate and eleven plugins wait on its services (RAN: the "Failed to load plugins" screen).

### 10. `requiredConfinement` is not upstream - SOURCE Prime `patches/mandatory-agent-confinement.patch.json`
`layout/src/composer-mode.ts:5` imported it from `@deepseek-ai/dsh-sandbox`, where only Prime's patch layer put it. A local copy of its two guards (the `aukoraConfinement` provider exists, the policy is a confined mode with a root) sits at `:10`.
On a stock DSH there is no `aukoraConfinement` provider, so Chat/Build mode change answers "unavailable" (the same answer Prime gives without its confinement service). GUESS: Sovereign's own confinement is a Rust boundary and should replace this file's contract.

### 11. Settings namespaces are plugin Config - SOURCE `docs/subsystems`, `settings/settings/src/index.ts`, `ui-settings-general/src/index.ts`
- Host `settings/src/index.ts:16,137-146,189-194`: `ctx.settings.register('ui-onboarding', schema)` is gone; the welcome acknowledgement is now this plugin's own `Config { welcomeNoticeVersion: volatile }` plus `settings.configure({ auto: false })`, exactly as the harness's `ui-settings-general` declares it.
- Client `settings/src/client/index.ts:68,87`: the service `settingsScope` is `configForms`.
- **Consequence for composition:** `ui-settings-models` writes the welcome acknowledgement into the entry with id `ui-settings-general`, and the config editor refuses ids that two entries share (`config-editor/src/index.ts:39-44`), so a *disabled* upstream row of that id leaves nothing writable.
  `preview-face.py` therefore removes the four replaced rows from dsh-web-app's patch (it does not disable them) and gives the settings face the id `ui-settings-general`. RAN: Continue persists and stays dismissed across a restart.

## Disabled in Sovereign

The conductor's ruling (the plan Peter approved): **the engine holds no keys; its only ways out are the door and the broker; Kira 2 replaces OpenViking.** So the paths below
are off in Sovereign's composition. A composition switch was preferred; where the copied source itself held the way out (a `fetch`, an `execFile`, a `Function(...)`, an env read of a key) it is edited, minimally, and the edit is listed.
`checks/run.py` rule `engine-io` (`checks/walls.py` `engine_findings`) now fails any `.ts/.tsx/.js/.mjs` under `engine/` that uses the network, runs a program, reads `process.env` or evaluates a string unless
`checks/baseline.json` `engine_io_allowed` names the exact file with a reason. **None of the files below is on that list for the capability it had**; the residue is stated per row. Line numbers are Prime's (45da3d8).

| # | Disabled path (Prime) | How | Source edit |
|---|---|---|---|
| 1 | First-run OpenRouter key route: `layout/src/index.ts:259-269` (`POST first-run/key`, `first-run/key/remove`), `layout/src/first-run-host.ts:50,115` (`secrets/openrouter-key`) | The two routes are not registered; `rememberKey`/`forgetKey` are deleted, `firstRunAnswer` no longer reads a key file (`keyTail` is always null). The client still renders its field and gets a 404 on submit. | `layout/src/index.ts`, `layout/src/first-run-host.ts` |
| 2 | `apps/src/auma-live/presence.ts:206` (`openrouter.ai`) and the provider route | `OPENROUTER_ENDPOINT` is a non-address (`disabled-in-sovereign://...`); the global-`fetch` fallbacks in `presence.ts` (the constructor) and `reflex.ts` (`reflexTurn`) now reject; `process.env.AUKORA_OWNER_NAME` is no longer read (the `ownerName` config sets the name); `apps/src/index.ts` no longer reads `AUKORA_DISCLOSURE_RECIPIENT` (it was `?? 'openrouter.ai'`). **Composition:** `providerSendConsent: false` (also the schema default) in `preview-face.py`. | `presence.ts`, `reflex.ts`, `index.ts` |
| 3 | `memory/src/index.ts:64,76` (OpenViking, `x-api-key`) | Every way out refuses `memory:disabled-in-sovereign` (503): the endpoint/key/env reads (`memoryOpenVikingConfig`), the `fetch` (`vikingCall`), the state-directory env read and the load of Prime's Kira reader by computed path (`loadKiraMemoryReaderModule`, not in the list: a dynamic import of a path the engine does not own). Routes stay registered so the client gets a named refusal. The rest of the file is Prime's and unreachable. | `memory/src/index.ts` |
| 4 | `settings/src/index.ts:167` (`execFile python3 evidence/aura-evidence.py`) | `readAuraEvidence` answers a refusal document (`aura-evidence-disabled-in-sovereign`); `resolveGateState` (a dynamic import of Prime's Aura association plugin by path, reading `process.env`) is deleted with its constants; `settings/evidence/aura-evidence.py` is deleted. | `settings/src/index.ts`, `settings/evidence/aura-evidence.py` |
| 5 | `layout/src/health-sample.ts:81,95` (`/usr/bin/footprint`, `sysctl`) | `readFootprintViaBinary` and `readPressureLevel` resolve null (unmeasured, never a guess); `TMPDIR` is no longer read (`/tmp`). | `layout/src/health-sample.ts` |
| 6 | `apps/src/auma-live/voice.ts:84` (`new WebSocket` to the sidecar) and `voice-sidecar.ts:144` (spawn of the Python sidecar) | Both files are deleted, with the `ws` and `@types/ws` dependencies, their two `apps/tsconfig.host.json` entries and the `if (config.voiceEnabled)` block and import in `apps/src/index.ts` (Auma Live voice comes later). `voiceEnabled`/`voiceAutoStart` now default `false`, and `preview-face.py` sets them `false`. The browser keeps its own fallback. `apps/vendor/auma-live/voice/**` (the Python sidecar) stays as inert, hash-pinned bytes. | `apps/src/index.ts`, `apps/package.json`, `apps/tsconfig.host.json`, two files deleted |
| 7 | `layout/src/watchdog-limit.ts:80` (`Function(...)`) | The limit is unknown (null): the matched expression is never evaluated. | `layout/src/watchdog-limit.ts` |

**Composition switches, no source edit** (`preview-face.py`, a row after the face insert): `repoLensRoot: ''`, `repoLensLookups: 0`, `webLensLookups: 0`, `weightsControlScript: ''`, `organismDshHome: ''`, `organismRepo: ''`. They keep
`apps/src/auma-live/lens-exec.ts` (git/gh via `execFile`), `weights-control.ts` (`subprocess.spawn`) and `apps/src/vendor/organism.ts` (git/gh) from ever running. **Those three are not on the ruling list, still contain the capability, and are therefore on the `engine_io_allowed`
list** (with that reason); cutting them from the source needs the conductor's word. Not verified: that `dsh web` accepts the override row; it copies the shape of the existing `ui-settings-models` row, and the booted preview was not rerun.

**Could not be removed without editing copied files:** every row above except the composition switches needed an edit. Residue that stays on the allow-list because it is not a key, program or network reach of the disabled path: `layout/src/index.ts` still reads
`AUKORA_STATE_ROOT`/`AUKORA_STATE` through `stateRootOf(process.env)` (the owner-name file, approvals log and why store live there), and `apps/src/index.ts` reads `PATH` (a `statSync` probe; nothing is run).

## Reproducible build and the checks

- `pnpm-lock.yaml` here is the harness checkout's lockfile at the tag plus the nine face importers. `build-face.py` copies it over the checkout's and runs `pnpm install --frozen-lockfile`; `--update-lockfile` is the one way to change it.
  It also runs `scripts/generate-typert.ts` first (a fresh or re-copied checkout has no `lib/typert.remote-client.*`, and `tsc -b` stops on them).
- `checks/baseline.json` `copied_from_prime` lists exact files (the Prime exemption is no longer the whole folder). Every copied file that is byte-identical to Prime 3673b98 is pinned by sha256 in `checks/pins.json`, so any edit shows;
  a file edited here (the table above, section 1-11) is not pinned and answers to the ordinary checks.
- `NOTICE` and `licenses/` carry Prime's notices (DeepSeek Harness MIT, Dakini React/Base UI/Lucide/Three, Auma Lingwa CC-BY-SA), byte-identical to Prime's `licenses/` at the same relative paths.

## Peter's mode control (2026-10-17, face/laya; redesigned after "too tight, the bubbles are way too big, it must fit the one-third lane")

Not a port of Prime: a change to the composer. Everything sits on ONE row, no wrapping, and was checked at a 600px lane (1800px window) and at the 468px lane of a 1440px window.
- `layout/src/client/ComposerControls.tsx` (+ `.module.css`, `locales.ts`): the permission seat (`conversation.input.permission`, priority -10 over DSH's own `PermissionSelect`) holds, left to right: (1) ONE small switch, thin-border rail, knob left = Chat, knob right = Build, with the single word it shows ("Chat" or "Build"); (2) while Build is on, a compact slider with four notches 1-4 (1 = most careful) and the word "Risk" on its right, in the current level's colour; (3) the Vision eye button. The old read-only / workspace-write / YOLO slider and every YOLO string are gone. A host mode outside Chat/Build (`danger-full-access`) parks the knob in the middle and shows "—"; clicking it chooses Chat. Chat sends `/aukora-mode read-only`, Build `/aukora-mode workspace-write` (`composer-mode.ts`, unchanged except one error string). All long text is tooltip-only (`title`), none sits in the row.
- `layout/src/client/laya.ts`: the notches are `ask` (1, "Ask me everything"), `risky` (2, "Only risky things", the default), `limits` (3, "Within today's limits"), `trusted` (4, "Trusted: inside live grants, no daily count"). `layaLoosens` mirrors `SliderSetting::loosens`. Each level has its own palette colour: 1 mint, 2 blue, 3 violet, 4 gold. The knob and the "RISK" word, which sits to the right of the slider, take the full colour; the fill is the same colour mixed half-way toward the background and sits inside a hairline track border that nothing covers (the knob is 10px inside a 14px track). "BUILD"/"CHAT" and "RISK" are all caps (`text-transform`), same size and weight. There is no number beside the slider. The knob moves to the requested notch at once. While a loosening waits for the owner's passkey the knob carries a small lock and the fill is dimmed to half (tooltip: "Waiting for your passkey on the node"); a tightening, or moving back down, applies at once at full colour.
- **Preview-only auto-approval.** `createFaceLocalLaya` is the service that runs when there is no node. With nobody to hold the passkey, it approves a waiting loosening after 1.5 s (`PREVIEW_APPROVE_MS`; `previewApproveMs: 0` turns it off) and sets `note: 'approved-preview'`, shown for 2.5 s as a small "Approved (preview)" bubble above the slider. `LayaService` documents that a node-backed service MUST NEVER approve a loosening itself: `applied` rises only when the node reports the passkey approved it.
- **THE RUST SIDE NEEDS THE FOURTH SETTING.** `trusted` is Peter's and does not exist in `crates/laya` yet. `SliderSetting` (`standing.rs`) needs a fourth variant `Trusted` (wire name `trusted`, rank 3, so `loosens` already orders it; `from_wire`/`wire_name`/`clears` extended; `clears` is true for every grantable risk). `slider.rs` must treat it as: grantable classes clear inside a live standing grant with NO per-day count (`limits` keeps the count, and `per_day` stays the cap that `limits` spends); the never-grantable classes (`plugin`, `persist`, `shell-interactive`, `unknown`, `GrantShape::Never`) still ask under `trusted`, exactly as under every setting. The policy codec (`SliderPolicy::parse`/`canonical_bytes`, the pinned starter's hash) and the proposal path for a loosening need the new wire name. Until then the face-local store is the only place the fourth notch exists, and a node-backed `LayaService` must refuse to submit `trusted`.
- THE SEAMS are `LayaService` (`laya.ts`: `getState`, `subscribe`, `request`) and `VisionService` (`vision.ts`: `getState`, `subscribe`, `set`), both injected by `installComposerControls(ctx, laya, vision)`. Face-local versions keep the choice in `localStorage` (`aukora.face.laya.v1`, `aukora.face.vision.v1`); a node-backed `LayaService.request` submits `SliderPolicy::proposal` for a loosening and a direct write for a tightening.
- VISION is an eye icon button, no box: open eye = on, eye with a diagonal line = off, one click toggles; it starts off. Until Prime's `aukora-eye` (3673b98, `plugins/aukora-eye`, one tool `aukora_see`) is ported and a node-backed `VisionService` switches that tool, the click only records the choice (the tooltip says so). The plugin is not ported here.
- Fixed on the way: the Chat/Build command never reached the host on 0.2.1-alpha.5 (`ctx.get('remote').commands` throws "cannot get property remote.commands without inject"). `layout/src/client/index.ts` now declares `remote` and `remote.commands` and the selector calls `ctx.remote.commands.execute`, as `ui-plan` does. RAN in the preview with the stub below: Chat -> `read-only`, Build -> `workspace-write`, both confirmed by the host projection.
- `preview-face.py --stub-confinement` (preview only) provides a no-op `aukoraConfinement` so the switch is usable to look at on a stock DSH. It confines nothing and is not part of the face.

## Sovereignty (2026-10-17, face/sovereignty): a PREVIEW, stub data only

Not a port of Prime: a new System app asked for by Peter ("it shows all in portal buttons, so they're all categorized").
- `settings/src/client/sovereignty/`: `SovereigntyMenu.tsx` (System row, order -40, first), `SovereigntySurface.tsx` (surface `sovereignty`, a grid of eight
  `PortalButton`s from `@aukora/face-layout/client`; the open portal is the surface target, its own header closes it, Escape closes it then the surface),
  `views.tsx` (what opens under each), `parts.tsx`, `format.ts`, `model.ts` (the shapes, named after the crates that own them), `stub.ts` (**all the data, made up**).
  Registered in `settings/src/client/index.ts`; the files are listed in `settings/tsconfig.client.json`; `settings/package.json` marks `@aukora/face-layout/client` external (as messages does).
- **Read-only by construction.** It runs in the engine's origin. No function in the folder writes, fetches or approves; the only control that leads anywhere is
  `OwnerAction`, a plain link to the owner origin (`/approval/<proposal>`, `/passkey`, `/phrase/refresh`, `/witness`, or the owner origin's front page where no route exists yet).
- Wiring is a swap of `readSovereigntyStub` for a reader returning the same `SovereigntySnapshot`. The source of every field, what is stub and the open questions are in
  Peter's review folder (`SOVEREIGNTY-APP-SPEC.md`). `app/APP-LOCK.json` still lists eight System entries; Sovereignty is not in it (an open question, not a silent change).

## The spatial primitives (2026-10-17, face/sovereignty): Peter's standard, locked

Peter, on the Sovereignty preview: "lock this in as the new primitives". The measurements are the header of
`layout/src/client/primitives/primitives.css` (framework-neutral `ak-` classes and their tokens; another bundle, such
as the owner origin, copies that file verbatim), mirrored in Peter's `SPATIAL-DESIGN-RULES.md` rule 10. The React
components beside it (`components.tsx`, `icons.tsx`) only emit that markup and are exported from
`@aukora/face-layout/client`: AppSurface, AppHeader, PortalGrid/PortalCell, PortalButton, PortalDetail,
DetailSection/SectionLabel, RecordList/RecordRow, FieldTable, StatTiles, StatusPill, Meter, LevelScale, Quote, Lead,
Mono, LockedAction, Footnote, IconTile, AkIcon.
- `PortalButton` replaces the disclosure of the same name in Prime's `primitives.tsx` (pinned, kept, no longer exported
  under that name). It still accepts the old props, so Prime's memory app takes the new frame with no edit to it.
- A portal opens inside the lane it is in. Never route a portal's open state through `openSurface`: the shell's
  `selectSurface` always sets the pane preset to `center-right-wide` (that was the one-third-to-two-thirds snap).
- Edited Prime copies (pins refreshed): `settings/src/client/AuraCoherenceMenu.tsx`, `settings/src/client/SettingsMenu.tsx`,
  `aumlok/src/client/AumlokMenu.tsx`, `aumlok/src/client/IdentitySurface.tsx` (the System menu launchers).
- `app/design/spatial/` (the native shell's design lock, captures from Prime 3673b98) is NOT changed by this.

## Composition (what `preview-face.py` writes)
Profile `aukora`: `dsh-base`, then `@aukora/face-bundle` = dsh-web-app's `cordis.patch.yml` and presets with the rows `ui-layout`, `ui-sidebar`, `ui-workspace`, `ui-settings-general` removed
(Prime disabled the same four), `ui-settings-models` set to `credentialOnboarding: false` (Prime's order of 2026-09-27: no first-run form opens by itself; the harness added a "Get started" sign-in dialog), and the face rows inserted.
Everything lives under the scratch install, including `DSH_HOME`.

## Verified and not verified
RAN: `tsc -b` of all nine faces (client and host halves) clean; `tsdown` bundles for all nine plus the foundation; DSH boots the composition; the three lanes, hot corners (one third per tap: [1,2,0] -> [1,1,1] measured), the Apps and System tabs, all eight stock apps and the seven System pages mount with no console error; Auma Lingwa renders from the vendored tree; host routes `/api/auma-live/*`, `/api/aukora/{approvals,health,first-run,backend-identity,aura-evidence}` answer 200; the thread row opens the Conversation in the left lane; 50 of 50 CSS custom properties the face uses are defined by the new theme or by the face; one scratch vitest run of the changed pure code (tree.ts `currentOf`, `completedSessionsOf`, derived rows): 3 passed (not committed: `checks` forbids test suites).
NOT verified: a conversation with a model (no key here), the right-column details view for a Session with content, thread rows for real sessions (the scratch home has none), rename/fork/archive against live sessions, the `uiWorkspace` draft path (`startSession` with a prompt), Auma Live voice, Zeta Harp and Human Graph rendering (headless Chrome has no WebGL).
Pre-existing in Prime: `apps` `vendor:check` reports `vendor/manifest.json` stale on the pristine 3673b98 tree too.
