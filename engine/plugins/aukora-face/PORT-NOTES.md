# Port notes: Prime's Spatial app on DeepSeek Harness 0.2.1-alpha.5

Source: Prime `plugins/aukora-face` at 3673b98 (built against dsh `0d1f500`, "untagged commit 5 after dsh-v0.1.6-alpha.1").
Target: `@deepseek-ai/dsh@0.2.1-alpha.5` (GitHub tag `dsh-v0.2.1-alpha.5`, `1517a4d`).

**The first commit of this branch (600e3ae) is the verbatim copy** (Prime's committed `lib/` build outputs omitted).
`git diff 600e3ae` shows every adaptation below and nothing else. Every `.module.css`, `spatial-tokens.css`, string,
locale and component is untouched except where a line below says so. `apps/vendor/**` is byte-identical to Prime
(`git diff 600e3ae -- engine/plugins/aukora-face/apps/vendor` is empty).

Line numbers are **Prime's** (the verbatim commit), so each can be read straight from `git show 600e3ae:<path>`.
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
`@deepseek-ai/dsh-invariants`, `ctx.invariants` and every `<package>/invariant` subpath are gone. Each face's
`src/invariant.ts` was an empty companion (`install = () => {}`), so deleting it loses nothing.
- Deleted: `{layout,sidebar,threads,apps,messages,documents,aumlok,settings}/src/invariant.ts` (memory had none).
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

## Composition (what `preview-face.py` writes)
Profile `aukora`: `dsh-base`, then `@aukora/face-bundle` = dsh-web-app's `cordis.patch.yml` and presets with the rows `ui-layout`, `ui-sidebar`, `ui-workspace`, `ui-settings-general` removed
(Prime disabled the same four), `ui-settings-models` set to `credentialOnboarding: false` (Prime's order of 2026-09-27: no first-run form opens by itself; the harness added a "Get started" sign-in dialog), and the face rows inserted.
Everything lives under the scratch install, including `DSH_HOME`.

## Verified and not verified
RAN: `tsc -b` of all nine faces (client and host halves) clean; `tsdown` bundles for all nine plus the foundation; DSH boots the composition; the three lanes, hot corners (one third per tap: [1,2,0] -> [1,1,1] measured), the Apps and System tabs, all eight stock apps and the seven System pages mount with no console error; Auma Lingwa renders from the vendored tree; host routes `/api/auma-live/*`, `/api/aukora/{approvals,health,first-run,backend-identity,aura-evidence}` answer 200; the thread row opens the Conversation in the left lane; 50 of 50 CSS custom properties the face uses are defined by the new theme or by the face; one scratch vitest run of the changed pure code (tree.ts `currentOf`, `completedSessionsOf`, derived rows): 3 passed (not committed: `checks` forbids test suites).
NOT verified: a conversation with a model (no key here), the right-column details view for a Session with content, thread rows for real sessions (the scratch home has none), rename/fork/archive against live sessions, the `uiWorkspace` draft path (`startSession` with a prompt), Auma Live voice, Zeta Harp and Human Graph rendering (headless Chrome has no WebGL).
Pre-existing in Prime: `apps` `vendor:check` reports `vendor/manifest.json` stale on the pristine 3673b98 tree too.
