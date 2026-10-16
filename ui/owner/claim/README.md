# Owner claim pane

Row 75 exports `createClaimService(configuration).mount`, composed by the trusted
owner release as `OwnerModules.panes.claim`. The shell creates the frame and sends
only `/claim`; no parent message supplies a token, secret, configuration or receipt.
The person pastes the shell claim link and enters their retained invite secret here.
No claim secret is written to browser storage or returned to the parent.

The invited mode uses a versioned token string:
`aukora-invite-claim-v2.<spawn-token>.<handover-secret>`. The spawn token is canonical
unpadded base64url of 32 random bytes; the retained secret is 64 lowercase hexadecimal
characters. The frozen request stays `{token}` on owner-origin `POST /api/claim`.
The invites helper verifies the host spawn commitment and the signed invite's
SHA-256 commitment to the ASCII handover secret. Conserved invitations require a
separate issuer-signed `aukora:invite-claim-binding:v1` event, bound to the exact
invitation, network, code and expiry. Its distinct `d` tag cannot replace the invite.
The host's mandatory `verify_claim_owner_authority` callback must check the committed,
consumed C5 authorization over the exact binding content (or the original approved
legacy issuance). Its default refuses: a node signature alone grants no setup session.
An unmodified claim backend refuses the combined token. `host-token-v1` is an explicit release configuration for ordinary
operator-provisioned nodes, never an automatic fallback from invited mode.

Only the current exact claim-open response advances to the injected `joining` pane,
in the same frame. Claim opens setup; it does not establish passkey ownership.
Interrupted replies are uncertain and do not advance. Closing clears inputs and
aborts requests. The explicit resume button opens joining without resending a claim;
joining must independently authenticate the existing setup session and read its
checkpoint. Joining replaces the claim form, with no claim navigation alongside
the owner steps. JavaScript strings and browser networking do not support guaranteed
memory erasure. Configure the joining service and the host's claim consumer before
enabling the pane; this module adds no route or release entrypoint outside its tree.
