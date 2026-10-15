# ui/owner/
The trusted pop-ups (passkey, phrase, approvals, AUMLOK), served from the owner origin and shown only framed inside the app; never a page. Plain TypeScript, no npm dependencies.

**Bricks:** 10, 19, 20, 35, 45, 53, 75 (NORTH-STAR.md).

`contracts.ts` and `contract.json` freeze the owner boundary. The trusted owner
release calls `mountOwner(root, modules)` from `index.ts` with its configured shell
origin and owner services. The static entry remains unavailable without that
composition. Configuration is never taken from a message, URL, or face.

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
