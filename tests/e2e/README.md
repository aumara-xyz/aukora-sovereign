# Installed-node acceptance

These are guided acceptance runs, not construction tests. Run them only after the
release lands and is installed on a disposable acceptance node. The worker does
not run them. Node 22 or newer and the separately installed `aukora-verify` are
required; no package installation is used.

From the repository root:

```sh
bash tests/e2e/m1.sh --node https://node.example --owner https://owner.example --release COMMIT --findings review-46.json
bash tests/e2e/m3.sh --node https://node.example --owner https://owner.example --release COMMIT --verifier bin/aukora-verify
bash tests/e2e/m7.sh --node https://node.example --owner https://owner.example --peer-node https://friend.example --peer-owner https://friend-owner.example --release COMMIT --verifier bin/aukora-verify
```

Use the same flags for M2, M4, M5, M6 and M8. `--release` is the exact 40-character
installed commit. The operator independently checks the loaded process and served
assets against that approved release. A checkout or an installation record alone
does not establish this. M7 needs two independently provisioned VMs, identities,
grants and passkeys. Inputs and verifier files are relative to the invocation
directory. The verifier must be outside the repository's build tree and already
installed; the runner never builds or installs it.

The runner sends bounded HTTPS probes without following redirects. It asks for
browser observations and the real owner's passkey actions; it never supplies an
approval. Enter `observed STEP-ID` only after doing the named action on the running
node. `blocked REASON`, EOF, a missing prerequisite, or a failed comparison stops
the run with a refusal. These attestations are explicitly counted as human
observations. They are not cryptographic evidence or authorization. The final
line reports the limits of automated checks; Peter still accepts the milestone.
No results, logs, receipts, secrets or other evidence files are written.

M1 reads the app lock, all 18 face manifests and their entry assets from the node.
Shell headings must match the design copy; each face's main heading must match
its registered title, with Lingwa's distinct `Auma · Lingwa` heading. The runner
checks served CSP and HSTS headers. The owner inspects the real sign-in and shell
handoff responses and enters only cookie attributes, never cookie values. Keep
the browser Network history through the ceremonies for these observations.

M1 rechecks the supplied post-merge findings and requires the complete archive
issue 46 inventory. That inventory is not present in this checkout. `--findings`
selects an operator-supplied JSON object with exactly `schema`, `source`, `ids`:
schema `aukora-review-46-index-v1`, source `archive-issue-46`, and a nonempty list
of unique finding identifiers. The operator must independently compare that list
with the full original issue; the runner cannot establish completeness itself.
Each finding then needs a new-code reproduction and observation. No absent
inventory or unmeasured finding counts as fixed.

M2 requires the installed host's real hostile driver. It asks for all 53 paired
operations frozen in `immune::hostile::HOSTILE_CASES`, with identical disposable
targets and request digests, exact confined denials and successful unconfined
controls. Missing fixtures, unavailable controls and exhausted budgets fail.
The runner validates reported host measurements, not guest claims. The current
supervisor entry point has no hostile-driver command; the operator must stop
until that installed integration exists. Disposable sentinel keys and fixtures
are required; never paste a model key, passkey, phrase or session bearer into an
ordinary prompt. Cookie inputs for M7 use a separate hidden terminal reader,
covering both shell and owner cookies in both directions with same-node controls.

Cold verification invokes the actual verifier with a separately retained owner
checkpoint and independently pinned public key. Success requires `VERIFIED` with
all four integrity checks and both identity/checkpoint observations satisfied.
Wrong-key, edited and truncated bundles must fail. Exported bytes do not prove a
passkey ceremony or a physical effect; those remain separate human observations.

The runs never reboot a machine, change a model route, crash a process or spend a
grant automatically. The operator performs those named steps through the owner
route on the acceptance nodes. M4 keeps its observations in this terminal, so run
it from a different machine that survives the node's real reboot. No clone rule
is inferred. Health observations are separate from fingerprint bytes and never
authorize an effect.
