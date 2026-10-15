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
key. The codec recomputes this exact versioned context, whose data policy is
disabled until the conductor pins it.

`context-v1.json` supplies a canonical-context and domain-digest vector for the
host codec. The digest is SHA-256 over the ASCII `aukora:joining-context:v1`, a
NUL byte, then the C1 bytes. Required channel layers are explicit context fields;
the portal cannot downgrade them during an exchange. This is a new
joining context, not an extra field in a frozen co-presence v1 object.

The `portal(host, method, signal)` factory supplies the frozen `PortalServices`
ports inside the joining step. It must prepare the selected sensors and release
its resources on abort. Joining reserves a durable attempt, then calls
`CopresenceEngine.begin` with domain `copresence.v1`, that attempt ID and a copy of
the canonical joining bytes as `contextBytes`. Required layers select `optical`,
`optical-audio` or `optical-audio-motion`; motion without sound refuses. The
private context's `screen-to-screen` label and digest remain unchanged. New
exchanges respect the shared engine's 4,096-byte context limit. Required intent
acknowledgement displays the portal's exact approved text and requires an explicit
checkbox before starting; otherwise `approvedText` is null.

Two screens face each other. Only a matching successful portal observation can
return opaque receipt bytes, after its attempt outcome has been persisted.
The node rechecks the context, signatures and durable attempt/receipt spending
before a phrase checkpoint can appear. Receipt input never advances a stage
locally. Phrase and passkey adapters remain in the owner pane; their completion
callbacks cause an authenticated read-back. The phrase adapter receives no
parent-message secret input, and no phrase or root appears in the joining ports.
The page completes only after the service returns a matching bound checkpoint
with a passkey credential and Aura receipt sequence. Co-presence grants no
permission or device scope. The final confirmation remains available for up to
ten seconds, bounded by context expiry, while the receipt is submitted. This page
draws no relationship bloom.

The shared browser engine still creates an ephemeral device key, and its first
FACE frame omits the context; later frames and the receipt bind it as `purpose`.
Before enabling joining, the engine owner must accept the prepared durable
signer and bind the exact context from the first frame through the receipt. The
frozen FACE key set requires a new versioned wrapper and vectors for that change.
Joining defines no alternate optical protocol. The existing phrase pane refreshes
a bound root and cannot serve as initial enrolment. The trusted release must
supply initial-enrolment and authenticated joining transaction adapters. No new
health probe is declared for this browser pane in the frozen portal boundary.
