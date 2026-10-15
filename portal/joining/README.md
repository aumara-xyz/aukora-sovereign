# Joining ceremony

Row 78 exports `createJoiningService(configuration).mount(context)`. The trusted
owner release composes this mount after successful claim, inside the existing
`claim` pane. There is no joining URL, second page, parent-message payload or
owner iframe created here. The configured owner and direct shell frame are
checked before any ceremony service runs.

`services.ts` defines local adapter ports, without changing a v1 wire format.
The authenticated joining service resumes a claim-bound checkpoint, prepares
the exact two-device context and records verified co-presence as evidence. The
context fixes both owner credential/public-key candidates, durable device keys,
epochs, session contributions, scopes, method and validity interval. Missing
candidates refuse; a fresh ephemeral key cannot stand in for a durable device
key. The codec and optical adapter must both implement this exact versioned
context, whose data policy is disabled until the conductor pins it.

`context-v1.json` supplies a canonical-context and domain-digest vector for the
host codec. The digest is SHA-256 over the ASCII `aukora:joining-context:v1`, a
NUL byte, then the C1 bytes. Required channel layers are explicit context fields;
the optical adapter cannot downgrade them during an exchange. This is a new
joining context, not an extra field in a frozen co-presence v1 object.

Two screens face each other. The optical adapter returns opaque receipt bytes.
The node rechecks the context, signatures and durable attempt/receipt spending
before a phrase checkpoint can appear. Receipt input never advances a stage
locally. Phrase and passkey adapters remain in the owner pane; their completion
callbacks cause an authenticated read-back. The phrase adapter receives no
parent-message secret input, and no phrase or root appears in the joining ports.
The page completes only after the service returns a matching bound checkpoint
with a passkey credential and Aura receipt sequence. Co-presence grants no
permission or device scope. This page draws no relationship bloom.

The existing generic portal engine does not implement this context: its device
key is ephemeral and its first FACE frame omits the owner keys, scopes and
expiry. It cannot be substituted for `JoiningOptical`. The existing phrase pane
refreshes a bound root and cannot serve as initial enrolment. The trusted release
must supply initial-enrolment, durable optical and joining transaction adapters;
without them this module cannot be mounted. No new health probe is declared for
this browser pane in the frozen portal boundary.
