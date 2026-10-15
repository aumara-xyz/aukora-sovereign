# deploy/go-sovereign/

Row 74 provides the public invitation page and its deployment allocator handler.
It has no owner frame, passkey, phrase, or node API. Successful allocation opens
the node's shell root with its claim token in the fragment. The invite secret
is entered later inside the owner pane on that node.

Compile the plain TypeScript as ES modules, preserving these relative module
names. Serve `index.html`, `style.css`, `index.js`, and `contracts.js` on one
HTTPS deployment origin. Serve `POST /allocate` with the function returned by
`createAllocationHandler` in `service.ts`. The HTTP host sets
`Content-Security-Policy: frame-ancestors 'none'`, disables request/response body
logging, and must not cache the page or allocation replies. No deployment host
entry point or operator allocator is currently connected in this repository.

The trusted host config supplies the deployment origin, the exact permitted
node shell origins, a seconds clock, and the `Allocator` implementation. None
comes from browser input. Every port is mandatory:

- `reserveVerifiedInvite` resolves the 16-byte code ID to its original signed
  invite, verifies the issuer, owner issuance receipt, ancestry, exact 48-hour
  lifetime and conserved allowance, and durably reserves that invite once. The
  reservation is bound to SHA-256 of the 32 random request-key bytes. Repeating
  the same request returns the same allocation; a different key cannot take it.
  Legacy handover commitments are SHA-256 of the retained secret's 64 lowercase
  hexadecimal ASCII characters. `signedInvite` retains the original event bytes.
  For legacy invitations, `signedBinding` and `claimBindingId` are null. For a
  conserved invitation they carry the separate issuer-signed
  `aukora:invite-claim-binding:v1` event and its ID: it binds that exact invite,
  code, network, original issue and expiry times, and handover commitment. The
  Rust invite-claim adapter verifies this binding without altering the original
  conserved invite. Missing bindings and caller-supplied commitments refuse.
- `provisionReserved` resumes only that reservation, through the existing
  guarded spawn machinery, with the release named in Peter's verified passkey
  release pointer. It must not allocate
  another name on retry, contact an existing listed node, or issue approvals.
  Before the node starts, it provisions the verified invite provenance, optional
  `signedBinding` public evidence and handover commitment beside the spawn claim
  commitment for the claim adapter (`InviteClaimHostContext.claim_binding`).
- `readback` reads the installed node's actual allocation ID, invite ID, both
  commitments, claim-binding ID, shell origin, unconsumed claim state and
  `releasePointerVerified`.
  The last value means the installed release matches Peter's signed operator
  release pointer; it never means the invitee has approved runtime effects.
  The handler compares these independently with the reserved admission, exact
  configured shell allowlist and returned claim token's raw-byte SHA-256.
- `handoffForRequest` returns the same claim token only for that reservation's
  matching request-key digest. Pending handoff bytes need protected retention;
  a disconnect cannot be treated as confirmed delivery. Consumed claims refuse.

Every port receives an abort signal and must preserve durable reservation state
when cancelled. The handler stops starting subsequent operations on disconnect,
limits request-body reading to ten seconds and the complete allocation to three
minutes, and rechecks expiry with a fresh trusted clock before handoff. A timed
out operation can be resumed through the same durable request reservation.

These durable and deployment operations belong to the trusted operator adapter;
the handler does not substitute browser claims or an in-memory invite ledger.
There is at most one allocation per invite. HTTP delivery is replayable by the
same request capability; it is not exactly-once delivery. The page keeps that
capability in memory for an explicit retry and clears it on handoff or exit.
Reload loses the capability, so the host needs a private recovery route for a
lost handoff. No recovery endpoint or reset of spent invitations is invented here.

The new request and handoff schemas have closed, canonical shapes and bounded
UTF-8 bodies. They do not change any frozen node route or invitation wire format.
`wire-v1.json` contains new data for conductor pinning. There is no declared
health probe for the landing page; invite health belongs to `crates/invites`.
