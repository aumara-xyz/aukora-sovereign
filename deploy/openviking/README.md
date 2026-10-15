# OpenViking on Linux x86_64

This optional index uses OpenViking **0.4.21**, Python **3.11**, and glibc
**2.31 or later**. Kira retains encrypted notes and re-reads every search hit;
the index holds derived plaintext on this node. The supervisor starts and
restarts OpenViking. It never starts inside the guest.

The prepared `requirements-prime-py311.lock` is an exact copy of Prime's
`vendor/openviking/requirements-macos-arm64-py311.lock`, SHA-256
`6c54600a9b9047e04cce43e3ca667e467f179286f9b88a803f6a29931025c8ff`.
Its 163 exact versions and artifact hashes include the Linux x86_64 wheel
`openviking-0.4.21-cp310-abi3-manylinux_2_31_x86_64.whl`, SHA-256
`e223518bd33b50bbd6b1c7860e4856cd7c477eb8656afdbe7871ff59355b37a6`.
This is a macOS resolution, **not a verified Linux dependency closure**. No
Linux resolver, artifact download, or real OpenViking install ran during this
change. Installation uses `pip --require-hashes --only-binary=:all: --no-deps`
and `pip check`; an unavailable artifact or incomplete closure fails instead
of fetching an unpinned version or building source.

On the integrator's networked host, prepare a Linux-specific lock for review:

```sh
sh deploy/openviking/setup.sh compile-lock /tmp/openviking-linux-py311.lock
# The command executed is:
uv pip compile --generate-hashes --python-version 3.11 \
  --python-platform x86_64-unknown-linux-gnu --only-binary=:all: \
  --index-url https://pypi.org/simple \
  --constraint deploy/openviking/requirements-prime-py311.lock \
  deploy/openviking/openviking.in --output-file /tmp/openviking-linux-py311.lock
```

Review that generated lock and test it on Linux before replacing the prepared
lock and its digest. `compile-lock` does not silently change the install input.

Provision a directory owned by the `aukora` supervisor user, mode `0700`, with
no symlink in its path. Run setup as that user on the networked Linux host:

```sh
sh deploy/openviking/setup.sh install /var/lib/aukora/openviking
sh deploy/openviking/setup.sh fetch-model /var/lib/aukora/openviking
# Or verify an existing model without downloading or copying it:
sh deploy/openviking/setup.sh verify-model /path/Qwen3-Embedding-0.6B-Q8_0.gguf
```

The local embedding profile matches Prime: Qwen3-Embedding-0.6B-Q8_0.gguf,
1,024 dimensions, served by an **operator-managed local CPU llama-server**
on `127.0.0.1:1934`. The model pin is SHA-256
`06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439`,
from Hugging Face revision `370f27d7550e0def9b39c1f16d3fbaa13aa67728`
of `Qwen/Qwen3-Embedding-0.6B-GGUF` (Apache-2.0). It is 639,150,592 bytes.
Qwen is chosen because Prime already pins this local model and supplies its
OpenAI-compatible embedding configuration; no external embedding provider
or paid broker route is implemented here.

With an already provisioned CPU llama-server, run it under a separate service:

```sh
llama-server -m /var/lib/aukora/openviking/models/Qwen3-Embedding-0.6B-Q8_0.gguf \
  --embedding --pooling last --host 127.0.0.1 --port 1934 \
  -c 2048 --parallel 1 --threads 2 --n-gpu-layers 0
```

The llama-server executable is **not installed, pinned, started, or supervised
by this setup script**. Its provision and service containment are operator
prerequisites. OpenViking is the sidecar managed by the sovereign supervisor.
No live model quality, memory footprint, or Linux llama flag compatibility
has been tested here. Keep both service ports private; never proxy them through
the node's public HTTP server.

Merge this optional object into `node.json` only after provisioning the local
embedder. Omission or `enabled: false` leaves the sidecar off:

```json
{
  "openviking": {
    "enabled": true,
    "command": "/var/lib/aukora/openviking/venv/bin/openviking-server",
    "port": 1933,
    "embedding_port": 1934,
    "data_dir": "/var/lib/aukora/openviking/data",
    "timeout_ms": 1000,
    "account": "aukora",
    "user": "owner"
  }
}
```

The supervisor owns the mode `0700` data directory and writes its own local
`ov.conf` and private API key there. Setup writes no node config, owner grant,
root key, or approval. Down or slow indexing and embedding must yield
`undetermined`, not an invented empty result.

Prime's `plan/ORGANISM.md:38` records the live retry-cap failure: an unbounded
2,325-token note exceeded the embedder context and produced HTTP 400; retries
reached 20. Prime's current
`plugins/aukora-kira/lib/recall-openviking.mjs` writes with
`processing_mode: "vectors_only"` and requires `result.vector_status` to be
`"complete"`, because OpenViking 0.4.21 can answer HTTP 200 after saving content
while embeddings fail. Bounded note parts and explicit vector completion are
required; health alone does not prove recall works.

The emulated HTTP subset follows Prime's
`plugins/aukora-kira/lib/recall-openviking.mjs`: its `call` helper (around
lines 195–215) sends JSON, `x-api-key`, `x-openviking-account`, and
`x-openviking-user`, and requires the `{"status":"ok","result":...}`
envelope. `GET /health` requires `{"healthy":true}` (around line 223).
`POST /api/v1/content/write` uses `uri`, `content`, `mode: "replace"`,
`wait: true`, `processing_mode: "vectors_only"`, `timeout`, and `tags`, and
requires `vector_status: "complete"` (line 439).
`DELETE /api/v1/fs?uri=<encoded-uri>` removes an index document (line 268).
`POST /api/v1/search/find` sends `query`, `target_uri`, and `limit`
(line 553); returned scores are thresholded locally. Prime also uses
`GET /api/v1/content/read?uri=<encoded-uri>&raw=true` to check indexed bytes.
The Rust recall path takes only candidate URI and score from the index and
re-reads the authenticated Kira record; index body text is never returned.
Its resource URI commits to an opaque note identifier rather than a plaintext
note hash. This preserves the frozen Aura contract's ban on plaintext hashes.

Index work is a durable URI-only SQLite queue. Demotion commits its removal
target before I/O; a supervisor worker retries it after the service returns.
Memory HTTP waits use separate connections to the same encrypted Kira database,
outside the owner admission lock. Owner recall rechecks the session after its
wait, so revocation withholds the result. Index writes and deletions share one
I/O guard; a concurrent recall reports `undetermined` rather than waiting on it.

The sandbox used to build this change denies loopback listeners. HTTP tests
therefore use a `test-support` Unix stream transport enabled only through the
supervisor's development dependency. Production always connects directly to
`127.0.0.1`; TCP round trips remain untested here. Process tests launch a fake
unhealthy executable and observe restart, private config, null logs, and stop.
Linux parent-death hardening is untested on this macOS builder. Normal shutdown
kills the process group; abrupt supervisor death relies on the installed
systemd unit's `KillMode=control-group` for descendants.

The generated configuration supplies only a local embedding endpoint and
clears inherited provider credentials. It does not sandbox arbitrary egress
from a compromised OpenViking process. The operator must provision and contain
the trusted local embedding daemon; this change makes no remote-provider or
paid-broker embedding claim. Without a locked NFKC normalizer, the quality
floor conservatively withholds notes containing non-ASCII letters or numbers
and the legacy From/When wrapper; emoji remain supported. This narrows semantic
coverage rather than accepting compatibility-script instructions that Prime
rejects. Encrypted storage and lexical recall with the feature off retain
their Unicode support. Full Prime quality parity has not been established.
