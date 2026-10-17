# Door socket protocol, v1

The wire between the DSH door plugin (`aukora-door`, client, inside the hostile engine process) and the Rust door
(server, outside the wall). One request line, one reply line, then the connection closes.

The client is untrusted code in a hostile process. The server believes nothing in a request except the bytes it
re-verifies itself.

## Transport and framing

- A unix stream socket. The supervisor puts its path in the plugin's configuration (`socketPath`, absolute, at most
  100 bytes). It is the only socket the engine can reach.
- **Identity is the socket, not the frame.** The server identifies the caller from the connection (`SO_PEERCRED` uid
  against an allowlist, or by which listening socket accepted it). No token, key or user name travels in a frame.
- **Request:** one UTF-8 line: a C1 canonical JSON object, then `\n`. **Reply:** one UTF-8 line: a JSON object
  (the Rust door should emit C1 canonical), then `\n`. After the reply the server closes. Bytes after the first
  newline are a protocol error.
- Each line is at most 1,048,576 bytes by default (`maxFrameBytes`, configurable 1 KiB..16 MiB). Larger payloads are
  not v1: they will cross as a sealed memfd handle over `SCM_RIGHTS` in a later version. The FD 3 limit of 65,536
  bytes (`crates/canon/src/frame.rs`) is a different channel and does not apply here.

## Request

```json
{"args_canonical_b64":"eyJ1cmwiOiJodHRwczovL2V4YW1wbGUub3JnIn0=","call_id":"call-7","class":"net","digest_sha256":"2bbe5488f10bf373b6cd97f38ab7edfbc09c1ae088acf5b61ceef46240eb6579","tool":"web_fetch","v":1}
```

| Field | Type | Meaning |
|---|---|---|
| `v` | `1` | Protocol version. Any other value is denied. |
| `call_id` | string | Unique per request: `<process nonce>-<counter>-<the model's call id, reduced to [A-Za-z0-9_.:-] and cut to 64 characters>`. 1..=128 printable ASCII bytes, no space. Echoed in the reply; the server consumes it once. |
| `tool` | string | The tool name as dispatched: 1..=256 bytes of `[A-Za-z0-9_.:-]`. The plugin accepts any well-formed name up to 256 bytes for its digest; the door refuses anything outside that alphabet as `bad-tool`. |
| `args_canonical_b64` | string | Standard base64 of the C1 canonical UTF-8 text of the tool arguments. |
| `digest_sha256` | string | 64 lowercase hex digits, the call digest below. A claim to be checked, never trusted. |
| `class` | string | The plugin's channel class for the call (table below). A hint to be checked, never trusted. |

The request has exactly these six fields. The client sends only crossings; a `local` call never reaches the door.

### Canonical arguments (C1)

Exactly `crates/canon/src/json.rs`: object keys sorted by UTF-16 code units, arrays in index order, no whitespace;
strings escape `"` `\` and `\b \f \n \r \t`, other U+0000..U+001F as lowercase `\u00xx`, everything else literal
UTF-8 (including U+007F, U+2028, U+2029); integers only, in -(2^53-1)..=(2^53-1), no `-0`, fraction or exponent;
literals `null`, `true`, `false`; no lone surrogates; no duplicate keys; at most 64 nested containers.
Arguments with a float, `NaN`, a bigint, a class instance, an accessor or a proxy are not canonical and are refused
by the plugin before anything is sent (`args-not-canonical`).

### Call digest

```
digest = lowercase_hex( SHA-256(
    "aukora:door-call:v1"        // 19 bytes, ASCII
 || 0x00
 || u32be( len(tool_utf8) )
 || tool_utf8
 || canonical_args_utf8 ) )
```

Worked example: `tool = "web_fetch"`, arguments `{"url":"https://example.org"}` give canonical text
`{"url":"https://example.org"}` and the digest in the request above. `test/vectors.json` holds nine more, produced
by an independent implementation (`test/gen-vectors.py`, standard library only); a Rust implementation must match
all of them byte for byte.

## Classes

The plugin classifies by channel, from the tool name and the argument shape, never from anything a plugin declares
about itself. The server re-derives its own class for the tool and uses the stricter of the two.

| `class` | Channel | Typical default |
|---|---|---|
| `net` | outbound network from a model tool (web fetch, web search) | broker/allowlist, else ask |
| `mcp` | a tool served by an MCP server (`mcp__*`) | ask unless pinned |
| `plugin` | plugin install, upgrade or removal | ask (owner fingerprint approval) |
| `memory` | any Kira call (`kira_*`, `memory_*`) | forwarded to the memory service with the engine's identity |
| `persist` | creating or changing a schedule (future autonomous action) | ask |
| `delegate` | a subagent or `ralph` with a named external provider; every `workflow` (its script can name a provider) | ask |
| `shell-interactive` | a persistent terminal (`terminal_*`): what runs later is not in the bytes judged at open | deny or ask |
| `fs-outside` | a file or working-directory argument outside the workspace roots | deny or ask |
| `unknown` | a tool name the plugin does not know | deny or ask |

Further classes (`land`, `spend`, `identity`, `send`, `device`) are reserved for later versions of the table. The
server denies a class it does not know.

## Reply

```json
{"call_id":"call-7","decision":"allow","result":{"text":"fetched","value":{"status":200}},"v":1}
{"call_id":"call-7","decision":"deny","refusal":"net-not-allowed","v":1}
{"call_id":"call-7","decision":"ask","refusal":"owner-approval-required","v":1}
```

| Field | Rule |
|---|---|
| `v` | `1` |
| `call_id` | must equal the request's |
| `decision` | `allow`, `deny` or `ask` |
| `result` | present exactly when `decision` is `allow`; an object with `value` (any JSON) and optional `text` (string) |
| `refusal` | optional on `deny` and `ask`, forbidden on `allow`; matches `^[a-z0-9][a-z0-9:._-]{0,127}$` |

No other field is allowed anywhere; the client rejects the whole reply otherwise.

- **allow:** the door executed the crossing. `result.value` must have the shape the tool's own output schema expects:
  DSH validates an authored result against the tool's output contract and renders the model-facing content from
  `value`. `text` is used only as the plain text content. The tool body in the engine does **not** run.
- **deny:** nothing ran. The model sees `Error: the door refused this action (<refusal>); nothing ran`.
- **ask:** nothing ran; the door has raised, or will raise, an owner card. The model sees that the owner has to
  approve first. A later retry is a new call with a new `call_id`. With the node's door the owner approves this exact
  call (its digest) on the owner origin; repeating the identical call then runs it once (`ask-<class>:pending` while it
  waits).

## What the Rust side must do

Implemented by `sovereign door serve` in `crates/supervisor/src/door` (see `crates/supervisor/DOOR.md`).

1. Parse the request strictly: exactly the six fields, `v` equal to 1, field types and sizes as above. Anything else:
   deny `bad-request`.
2. Decode `args_canonical_b64`, require valid UTF-8, parse it with the C1 parser, re-serialize it and require the
   bytes to equal the decoded bytes.
3. Recompute the digest from `tool` and the decoded bytes and compare in constant time. A mismatch is deny
   `digest-mismatch`. **Execute only the bytes it just verified,** never a value from elsewhere.
4. Re-derive the class from its own tool table and use the stricter of the two.
5. Consume `call_id` once, durably (surviving a restart), when the policy would allow or ask about the call; a repeat is deny `replay`. Refused calls burn no id. Replay protection covers the ledger's kept window, not forever.
6. Check the caller first, before reading anything: `SO_PEERCRED` against its allowlist; an unknown peer is deny `peer`. Rate-limit (`rate-limited`) before reading too.
7. Apply policy, the owner's passkey where required, and write the Aura receipt naming the digest, the class, the
   decision and the capsule or rules hash.
8. Fail closed on every error. Close after the single reply.

These are the holes Grok's toy boundary found and fixed (build TOCTOU, replay, foreign uid, consume-once across a
restart); the real door inherits them.

## What the plugin does with each outcome

| Outcome | Result the model sees | Code |
|---|---|---|
| allow | the door's authored success result | |
| deny | failure, nothing ran | the door's `refusal`, or `door-denied` |
| ask | failure, nothing ran | `ask:<refusal>` |
| socket missing, refused, or no accept in `connectTimeoutMs` | failure, nothing ran | `door-unavailable` |
| no reply within `responseTimeoutMs` | failure, the door may have acted | `door-timeout` |
| call cancelled while the door held it | failure, the door may have acted | `aborted` |
| malformed, mismatched, oversized or truncated reply | failure | `door-protocol` / `door-too-large` |
| name or arguments differ from what was judged | failure | `digest-mismatch` |
| no verdict recorded for the execution | failure | `no-verdict` |
| arguments are not canonical data | failure | `args-not-canonical` |
| could not pin the judged arguments (local call) | failure | `lock-failed` |

Every failure result carries `error.info = { name: "AukoraDoorRefusal", code }`.

## Versioning

`v` is 1. A server that wants to speak a later version listens on a different socket path; a client that receives
a reply with any other `v` denies the call.
