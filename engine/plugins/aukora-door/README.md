# aukora-door

The DeepSeek Harness (DSH) side of the AUKORA door: a Cordis plugin that makes the bytes that were judged the bytes
that run, and sends every crossing to the Rust door instead of running it in the engine.

Built against DSH 0.2.1-alpha.5 (master `1517a4d`): `ToolRuntime.prepareExecution` and `dispatchScheduledExecution`
in `packages/core/tools/src/index.ts`. Wire protocol: [PROTOCOL.md](PROTOCOL.md).

## What it is, and what it is not

It is a **policy hook with a Rust executor behind it**. It is not a wall. A hostile plugin in the same Node process
can bypass any in-process hook (direct `node:fs` or `child_process` imports, `ctx.get()`, the public
`events._hooks` list, deleting this plugin from the registry). The wall is OS confinement of the whole engine
(OpenShell: Landlock, seccomp, network policy, one socket to the door). What this plugin guarantees on every honest
path:

1. **Judge-then-swap is closed.** A verdict (class and digest of tool name plus canonical arguments) is recorded
   before the call; a guard and the execute wrapper both re-digest and refuse on any difference. For a local call
   the judged arguments are parsed back from the judged bytes, frozen and pinned onto the execution with
   non-writable, non-configurable properties, so a wrapper inside this one cannot swap them either.
2. **A crossing never runs here.** The execute wrapper does not call `next()`: it sends the exact canonical bytes
   to the door and returns the door's authored result.
3. **Everything fails closed:** missing socket, timeout, malformed reply, unknown tool, non-canonical arguments,
   missing verdict.

## How a call flows

```
tools/pre-execute  (ours, prepended)   bind name + arguments -> class + digest; record verdict by exec.token
        ... any other pre-execute listeners ...
guard              (ctx.tools.guard)   deny unless a verdict exists and the digest still matches
tools/execute      (ours, prepended)   re-digest; refuse on mismatch;
        local     -> pin judged args, next()
        crossing  -> door request over the unix socket; return its reply; never next()
tools/result       (ours)              forget the verdict
```

Verdicts are keyed by `exec.token`, the registry-assigned opaque symbol (callers cannot choose it), not by the
model-chosen `callId`.

## Classification (by channel)

`src/classify.ts`. The only inputs are the tool name and the arguments. A tool's own metadata is never read.

- **local:** file tools (`read`, `write`, `edit`, `str_replace_editor`, `read_image`, `glob`, `grep`,
  `working_directory`, `lsp`, and `present`, whose `files[].path` entries are checked) with every path argument lexically
  inside a workspace root; `bash`, `pwsh`, `job_*`, `run_code`
  (their `cwd`/`workdir` still checked); session tools (`todo_write`, `ask_user_question`, goal tools, `skill`, the read-only `session_*` history queries, ...);
  a `subagent` or `ralph` with no `provider`.
- **crossing:** `net` (`web_fetch`, `web_search`), `mcp` (`mcp__*`), `plugin` (`plugin_manager`, `plugin_*`),
  `memory` (`kira_*`, `memory_*`), `persist` (`schedule_create`, `schedule_update`), `delegate` (a subagent or `ralph` with a
  `provider`, and every `workflow`: its script can name a provider in code the table cannot judge),
  `shell-interactive` (every `terminal_*` tool: a persistent process whose later input is not in the bytes judged at open), `fs-outside` (a file tool whose path leaves the workspace), and **`unknown` for every name not listed**.

Honest limits: a plugin can register a tool under a name this table calls local, and path checks are lexical (no
symlink resolution). The OS wall is what stops harm in both cases; the table only decides which calls the door must
see. Shell text is not parsed: egress from `bash` is the network policy's job.

## Configuration

`apply(ctx, config)`; the supervisor supplies it when it starts the engine and the engine cannot write it.

| Key | Default | Meaning |
|---|---|---|
| `socketPath` | required | absolute, at most 100 bytes |
| `workspaceRoots` | required | absolute roots; empty means every file tool crosses |
| `connectTimeoutMs` | 2,000 | |
| `responseTimeoutMs` | 120,000 | |
| `maxFrameBytes` | 1,048,576 | |

A bad configuration throws at load time, so the engine does not start with the door half open.

## Files

```
package.json               main/exports -> lib/index.js, dsh.bundle.patch -> cordis.patch.yml
cordis.patch.yml            mounts the plugin in a DSH profile (the supervisor supplies the real config)
build.mjs                   src/*.ts -> lib/*.js, no dependencies; lib/ is build output and is not committed
PROTOCOL.md                 the socket protocol and the Rust side's obligations
src/index.ts                the Cordis plugin: name, inject, apply(ctx, config)
src/door.ts                 the three hooks and the verdict store (no DSH import)
src/canonical.ts            C1 canonical JSON and the call digest (matches crates/canon/src/json.rs)
src/classify.ts             channel classification
src/client.ts               the unix-socket client and strict reply parser
src/types.ts                shared shapes
test/vectors.json           cross-language vectors; test/gen-vectors.py makes them (independent implementation)
test/stub-door.ts           a stub of the Rust door (verifies like the real one must)
test/pipeline-sim.ts        a stand-in for DSH's tool pipeline, faithful to the cited lines
test/*.test.ts              canonical, classify, client, hostile, plugin wiring, build reproducibility
```

## Run the tests

Needs Node 24.11.1 (built-in TypeScript stripping; no install step, no dependencies):

```sh
~/.local/node-v24.11.1/bin/node --test engine/plugins/aukora-door/test/*.test.ts
```

Regenerate the vectors (Python standard library only): `python3 -B -I test/gen-vectors.py > test/vectors.json`.

## Load it

The engine's profile mounts this package and calls `apply` with the supervisor's config; Cordis passes the context.
It needs the `tools` service (`inject = ['tools']`). The source is erasable-syntax TypeScript that Node strips at
load; Node refuses to strip types under `node_modules`, so DSH needs built JavaScript: `node build.mjs` turns `src/*.ts`
into `lib/*.js` with Node's own `module.stripTypeScriptTypes` (no dependencies) and rewrites `.ts` specifiers to `.js`.
`package.json` `main` and `exports["."]` point at `./lib/index.js`. `lib/` is not committed: it is a pure function of
`src/` (`test/build.test.ts` rebuilds twice and compares bytes, and loads the result). Run the build before packaging.

`cordis.patch.yml` mounts the plugin; its `socketPath` and `workspaceRoots` are placeholders in the right shape, because
the supervisor writes the real ones and a bad value makes `apply` throw rather than start with the door half open.
A door older than this table refuses a `shell-interactive` claim as `bad-class`: it fails closed.

## Open questions

See the report that accompanied this branch; the short list is in the commit message.
