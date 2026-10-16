# ui/owner/
The trusted pop-ups (passkey, phrase, approvals, AUMLOK), served from the owner origin and shown only framed inside the app; never a page. Plain TypeScript, no npm dependencies.

**Bricks:** 10, 19, 20, 35, 45, 53, 75 (NORTH-STAR.md).

`contracts.ts` and `contract.json` freeze the owner boundary. The trusted owner
entry calls `mountOwner(root, modules)` on load. It reads the native-configured
shell origin from the CSP on a same-origin HEAD request for its entry module;
missing or ambiguous configuration refuses. Configuration is never taken from a
message, URL, or face.

`onboarding.ts` connects claim, passkey registration and possession, initial
binding, and sign-in to the owner routes. A shell-provided `#claim=` fragment is
removed before setup; a missing fragment can be entered as a claim link. The
seven words are generated, checked and sealed through the owner-only AUMLOK WASM
asset. The server receives only the existing v2 public submission and passkey
assertion. No phrase or root is sent to the parent or stored by this flow.

The router accepts only an enumerated pane route after matching the direct parent,
its exact configured origin, and a fresh channel. Approval routes carry a proposal
id; the cards service loads the exact card and authorization bytes from the
supervisor. Parent messages cannot provide those bytes. Phrase input and derivation
stay inside the owner pane and have no parent-message representation.

Workers own `passkey/`, `phrase/`, `cards/`, and `witness/`; `claim/` is reserved.
The witness adapter runs on each initialized visit and browser restoration, reports
rollback and fork alarms, and never changes permission to act. Panes must dispose
resources and honor their abort signal. The router also tears down their host and
listeners when closed. Frame-ancestor policy remains the frontdoor's responsibility.
