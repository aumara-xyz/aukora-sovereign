# OpenViking local index

Row 58 uses the vector database shipped with OpenViking 0.4.21. Kira supplies
document and query embeddings itself. The ordinary OpenViking content server
accepts query text and cannot implement that frozen interface. These units
therefore start the upstream vector database API and a separate local CPU
embedder.

Both units bind only `127.0.0.1`. They have no dependency on the AUKORA app or
on each other. The index stays in its starting state for 60 seconds after
execution; that grace does not assert health. Kira checks the HTTP health and
index pin separately and reports `undetermined` during a service failure or an
incomplete rebuild. The app must not acquire a `Requires=` or `BindsTo=` edge
to either unit.

## Files to provision

The systemd state directory is `aukora-openviking`; `%S` in the unit files is
systemd's state-directory specifier. All following names are relative to that
private directory:

| Path | Required contents |
|---|---|
| `venv/` | Python 3.11 environment containing OpenViking 0.4.21 and its reviewed, hash-pinned wheel closure, including uvicorn |
| `bin/llama-server` | Release-approved CPU llama.cpp server and its approved runtime libraries |
| `models/Qwen3-Embedding-0.6B-Q8_0.gguf` | Model matching `model.sha256` |
| `models/model.sha256` | This folder's checksum file, shipped with the release |
| `data/` | Derived index state; retained across service restarts |

Provision the existing `aukora` service account and ensure its state directory
and children are private and owned by that account. Keep executable files,
the Python environment, and model files immutable to unrelated users. The
approved release must cover the executable and native-library closure; a model
digest alone does not pin an executable. No package or model download is part
of either unit. Both services mount their executable, environment and model
subdirectories read-only.

`openviking.in` declares the upstream version; it is not a dependency lock.
Prepare and review a platform-specific wheel closure before deployment. Install
only from the supplied local wheelhouse, with pip's `--no-index`,
`--only-binary=:all:`, `--require-hashes` and `--no-deps` options against that
reviewed lock. An incomplete or unpinned closure must stop provisioning. This
folder does not contain a verified Linux wheel closure or a llama.cpp binary.

Install the unit files through the node's approved release route. The worker
does not enable a service, alter a release pointer, or write owner state. No
installed-unit or semantic-recall observation was performed while authoring
these files.

## Local protocol

The vector database listens on port `1933`. Its upstream entry point is
`openviking.storage.vectordb.service.server_fastapi:app`, loaded with uvicorn.
`VIKINGDB_PERSIST_PATH=data` selects the local persistent backend. It does not
load the text server's provider configuration. Its successful envelopes carry
`code: 0` and `data`; `GET /health` carries `status: "healthy"`.

Kira uses `/CreateVikingdbCollection`, `/CreateVikingdbIndex`,
`/api/vikingdb/data/upsert` and `/api/vikingdb/data/search/vector`. Those are
upstream vector APIs, not AUKORA public routes. Collections contain vectors and
opaque note metadata. Search content remains untrusted and Kira re-reads and
verifies every candidate against its authenticated store.

The embedder listens on port `1934` and exposes llama.cpp's OpenAI-compatible
`/v1/models` and `/v1/embeddings`. The configured model alias is its SHA-256.
Kira independently checks the local model file against that digest. The alias
is a service identity check, not cryptographic attestation of the server.
The model has 1,024 dimensions. Qwen query instructions belong to Kira's
embedder adapter; document content is embedded without that query prefix.

The units deny non-loopback IP traffic and discard service output. Do not
publish either port through the frontdoor, a reverse proxy, or the guest.
Neither health nor an index result grants authority.
