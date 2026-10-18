# Two-node text messaging

The shell's Messages face uses the supervisor's Nostr key. The engine has no
messaging send capability. Each owner adds the other node's npub with one
passkey card. An owner's signed-in shell session can then send without another
card. Sends, received messages and ingress refusal counts are recorded in Aura.

The node key is generated on first startup under the supervisor state directory:
`nostr-node-v1.key` (0600). Its public companion is `nostr-node-v1.npub` (0600).
The key remains in Ring 3; no face response, engine mount or log includes it.
Restart keeps the same npub. A missing key with an existing public companion
refuses startup instead of silently rotating identity. Identity shows the real
node npub; it is unbound until an explicit Nostr binding ceremony exists.
The key is random: the seven-word phrase does not derive, back up or restore
it. A node that loses its supervisor state loses this npub, and its contacts
must approve the new one.

What the owner is told in Messages: anyone using the signed-in shell session
can send as the owner, and each send is recorded in Aura; a contact card
approves an exact npub, not a person, so compare it with the other person in
person or on a call you trust before approving; relays cannot read the text but
see node IP addresses, recipient keys, message sizes and when each node
connects (the time on a gift wrap is randomized); both owners must add each
other before messages arrive. Aura records ids and times, never message text.

## Operator preparation

Build the release from a checkout of `main` on the existing Linux release builder, using the pinned
toolchain and Node version described in `deploy/engine/NODE.md`:

```sh
scripts/reproduce.sh build HEAD /path/to/release --twice
```

Offer the verified release to node A using the existing stage/offer route in
`deploy/engine/NODE.md` (O17–O20). The owner approves the resulting release card in
the owner pane; only then does the installed node switch releases. Do not copy
an unapproved binary over the running release or manufacture an approval.

Pin the same relays on both nodes. For the existing node:

```sh
deploy/spawn/spawn.sh egress <node-a> --on nebius-vm \
  --provider deepseek --relay wss://relay.damus.io --relay wss://nos.lol
```

Provider flags replace the provider list, so restate `--provider deepseek`.
The door's hosts are retained by the spawner. Restart the supervisor after
changing egress as prescribed by the operator deployment flow.

Create B with a distinct, unreserved name (for example `<node-b>`). The usual
Nebius account, SSH key, network and hourly estimate variables must already be
set. Creation spends money and uses the spawner's explicit spend switch:

```sh
deploy/spawn/spawn.sh create <node-b> --on nebius-vm \
  --release /path/to/release --provider deepseek \
  --relay wss://relay.damus.io --relay wss://nos.lol \
  --spend-ok --claim-out <private path>/node-b-claim
```

Give B's claim link privately to owner B. Do not commit it or paste it in a
shared log. Owner B claims the node with their own passkey and signs into their
shell. A and B have separate state, origins, cookies and passkey RP IDs.

## Owner ceremony and live check

1. Each owner opens Messages, copies **Your npub**, and exchanges it directly
   with the other owner. Identity also shows that same public key.
2. Each opens **Add contact**, pastes the other npub and optionally a name,
   then selects **Review contact**. Approve the one existing gate card with
   the passkey on the owner origin. A contact without co-presence is unpaired.
3. Refresh Contacts, open the contact's thread, type a short text and Send.
   No new passkey card is expected. The thread first shows queued status.
4. Allow a polling interval (normally 30 seconds); refresh the receiving
   thread. Reply from B and observe the text in A's thread. Confirm the send
   and receive Aura entries. Relay acceptance means published, not peer read.
5. Restart B and confirm both its npub and received text persist. A stranger's
   wrap must increase refusal counts once (later polls skip it) without creating a visible message.

Both contact cards must be approved before sending: ingress rejects strangers
before opening their message payload. This run does not add invitations,
co-presence or an engine send route.

NIP-42: the relay client answers a relay's AUTH challenge when its caller gives it a signer
(`crates/relay/src/auth.rs`), but the messaging transport gives none, so a relay that challenges a messaging query
or publish is refused for that operation (`relay:auth-required`) and the other relays carry on. The client also
accepts at most one challenge per operation (`MAX_AUTH_CHALLENGES = 1`) and refuses a relay that challenges again;
re-authenticating on a fresh challenge is a known follow-up.

## Face API

All calls use the existing authenticated face service transport, with the
Messages manifest granting only the listed methods:

- `aumlok.identity {}`: the identity response with `node_npub` and
  `node_key_bound` (false until an owner-approved Nostr binding exists).
- `network.contact.propose {npub, label}`: opens a contact approval proposal;
  `label` may be null. It does not approve or add the contact itself.
- `network.send {npub, text}`: queues the owner's text for an approved contact;
  the request must come from a bound shell session. Maximum UTF-8 text: 16,384 bytes.
- `network.contacts.list {limit, before}`: real contacts with an opaque
  continuation; page limit at most 100.
- `network.messages.list {npub, limit, before}`: real incoming and outgoing
  history for one contact; omitted npub reads the scoped history.
- `network.refusals.counts {}`: the existing counted refusal buckets.
- `network.conversation.mark {npub, pinned, archived}`: the owner's own pinned and
  archived marks on one approved contact's conversation; the request must come from
  a bound shell session. They are view state kept in the private messaging store
  (not an Aura record) and are never sent to the contact.
- `network.conversations.marks {}`: every marked conversation, at most 1,000.

The supervisor polls only validated relay URLs and pinned addresses in its
egress policy. TLS certificates are checked. A fresh host firewall status must
match the policy epoch/digest and loaded/live rules. Failures back off from 30
seconds to five minutes; SIGTERM stops ingress and joins bounded relay work.

The relay adapter pages each relay independently with persisted inclusive
`since`/`until` bounds. One query runs per poll, rotating relays; a sweep freezes
its upper bound so newer arrivals cannot continually displace older messages.
Each relay alternates history pages with an independent query of the newest
16 wraps in the two-day timestamp window. A long history sweep cannot freeze
that query's upper bound. Normal pages contain at most 16 wraps. A timestamp
boundary is queried again
with a query limit growing to 128. A query result larger than the delivery
byte budget is returned in bounded chunks; a persisted timestamp/ID marker
resumes the same query in NIP-01 order across polls and restarts. The relay
client separately bounds each query to 500 attempted events and 4 MiB of input.
A short response permits best-effort traversal past that timestamp; it is not
proof that the relay returned every stored event. Completed sweeps overlap the
two-day NIP-59 timestamp randomization
interval; every fourth subsequent sweep revisits all history, covering old
queued wraps first published after a long sender outage. Failed queries retain
their history position and still rotate to the next relay. Once the cursor and
retained retries settle, query failures reach the worker and trigger backoff.
A cursor advances
only after the page is admitted or durably refused.
Clearable refusals retain their ciphertext locally and retry eight per poll
across pagination and restarts. This queue holds at most 4096 wraps and 16 MiB
of ciphertext, evicting the oldest retained wraps first when either budget
fills. An evicted wrap requires the contact to resend it.

NIP-01 has inclusive, second-resolution time bounds and exact event IDs, with
no offset or exclusion cursor. A full 128-wrap single-second boundary therefore
logs `query-timestamp-saturated` and retains that history boundary. The client's
4 MiB input cap can retain a crowded second before the 128-item limit too;
chunking the returned batches does not increase that input cap. Independent
tail queries continue advancing their upper bound, including on that relay;
without them the frozen boundary would block new inbound as well as history.
A same-second flood can still hide wraps outside the relay response and block
older history. Relays may also return fewer events than requested, so history
completeness cannot be guaranteed. Lossless traversal of an arbitrarily crowded
second requires an additional relay paging capability. NIP-59 hides the real
sender behind an ephemeral
outer key, so a per-sender cap before opening the seal would not identify
contacts or constrain a stranger generating fresh outer keys.

Known admitted wraps and final refusals (a stranger, a bad signature or
encryption, another recipient, a replay, a bad payload) are skipped before an
Aura transaction or decryption. Final refusal IDs remain durable without the
old 4096-ID eviction boundary: each is counted once across overlap and restart.
This exact-once index grows with unique refused wraps, retaining only their
32-byte IDs. A message sent before both owners approved each other is not
retried and must be sent again. A refusal that can clear (clock skew, a contact
approval still syncing, a local store error) is never pinned. Its queued
ciphertext retries until the cause clears or the queue budget evicts it;
its separate retained retry counter limits repeated observations.

## Privacy and storage

NIP-59 gift wraps and NIP-44 hide the sender and message content from relays.
Relays still see recipient `p` tags, node IP addresses, encrypted sizes, polling
timing and which relays both nodes use. The sslip hostnames expose names/IPs.
There is no claim of traffic analysis resistance or sender anonymity from the
network operator.

The supervisor's private messaging directory is 0700 and database is 0600.
History text is stored there in plaintext for the owner's thread view; host
administrators with access to supervisor state can read it. Aura retains
message and contact identifiers, envelope commitments and timing. Do not share
private state databases as a diagnostic artifact. The schema migration is
versioned alongside the existing store; transport retries never create another
owner action or a fresh gift wrap for the same queued send.
