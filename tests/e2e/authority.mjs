// SPDX-License-Identifier: AGPL-3.0-or-later
// These acceptance steps collect operator observations from the installed node.

const CELL_DIGEST = "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438";
const SAFE = Number.MAX_SAFE_INTEGER;

async function exact(c, id, prompt, expected) {
  const value = await c.text(id, prompt);
  c.same(id, value, expected);
  return value;
}

async function zero(c, id, prompt) {
  c.same(id, await c.integer(id, prompt), 0);
}

async function one(c, id, prompt) {
  c.same(id, await c.integer(id, prompt), 1);
}

function bounded(c, id, spent, reserved, cap) {
  c.require(id, spent <= SAFE - reserved && spent + reserved <= cap);
}

export async function m2(c) {
  c.step("m2-real-model-and-grant");
  await c.witness("m2-passkey-grant", "At the installed node, use the trusted owner frame to approve a fresh exact-byte model spend grant with the owner's real passkey. Observe the grant's node, subject, epoch, model, source, intake commitment, key generation, caps and expiry. Do not enter any provider key here.");
  const grant = await c.text("m2-grant-id", "Observed fresh signed grant id");
  c.require("m2-grant-id", /^[0-9a-f]{32}$/u.test(grant));
  const model = await c.text("m2-requested-model", "Exact model name in that grant");
  const cap = await c.integer("m2-total-cap", "Signed total cap, in microusd", 1);
  const perRequest = await c.integer("m2-per-request-cap", "Signed per-request cap, in microusd", 1);
  c.require("m2-cap-order", perRequest <= cap);
  const maxRequests = await c.integer("m2-max-requests", "Signed maximum request count", 1);
  const now = await c.integer("m2-grant-created", "Supervisor time when this fresh grant was installed, in ms");
  const expiry = await c.integer("m2-grant-expiry", "Signed expiry time, in ms", 1);
  c.require("m2-expiry-bound", expiry > now && expiry - now <= 86_400_000);
  await zero(c, "m2-initial-spent", "Fresh grant spent before the first request, in microusd");
  await zero(c, "m2-initial-reserved", "Fresh grant reserved before the first request, in microusd");
  await zero(c, "m2-initial-requests", "Fresh grant admitted request count before the first request");
  await c.witness("m2-live-guest-reply", "Send a new owner turn to the actual confined Auma using this grant. Observe a genuine provider response, requested/reported/verified model identity labels, and the matching durable broker receipt. A canned response, mocked transaction or source-only result does not satisfy this step.");
  await exact(c, "m2-receipt-grant", "Grant id in the matching broker receipt", grant);
  await exact(c, "m2-receipt-requested-model", "Requested model name in that receipt", model);
  await one(c, "m2-matching-receipts", "Matching final broker receipts for this request");
  await c.integer("m2-receipt-sequence", "Aura sequence of that durable broker receipt", 1);
  const reservation = await c.integer("m2-reservation", "Amount reserved for this request, in microusd", 1);
  const charge = await c.integer("m2-charge", "Final receipt charge, in microusd");
  const spent = await c.integer("m2-spent", "Grant's observed total spent after settlement, in microusd");
  const reserved = await c.integer("m2-reserved", "Grant's remaining reserved amount after settlement, in microusd");
  const requests = await c.integer("m2-request-count", "Grant's observed admitted request count after settlement", 1);
  await exact(c, "m2-receipt-outcome", "Final receipt outcome for the actual model reply", "completed");
  const usageCost = await c.integer("m2-receipt-usage-cost", "usage.cost_microusd in that final receipt");
  const costUnknown = await c.text("m2-cost-unknown", "Receipt cost_unknown, exactly true or false");
  c.require("m2-cost-unknown", ["true", "false"].includes(costUnknown));
  await exact(c, "m2-grant-frozen", "Receipt grant_frozen, exactly true or false", costUnknown);
  c.same("m2-charge-matches-usage", charge, costUnknown === "true" ? Math.max(reservation, usageCost) : usageCost);
  c.require("m2-receipt-within-reservation", charge <= reservation && reservation <= perRequest);
  c.same("m2-exact-spent", spent, charge);
  c.same("m2-no-pending-reservation", reserved, 0);
  c.same("m2-exact-request-count", requests, 1);
  c.require("m2-request-count-cap", requests <= maxRequests);
  bounded(c, "m2-grant-accounting", spent, reserved, cap);
  await c.witness("m2-settlement-before-output", "Observe that the response and receipt identify the same request and reservation, the provider result was released only after durable settlement, and usage and unknown-cost labels agree with the recorded charge. If cost is unknown, its full reservation remains charged and the grant is frozen.");

  c.step("m2-key-injection-twin");
  await c.witness("m2-sentinel-fixture", "Prepare a disposable isolated host fixture using a fresh provider-shaped sentinel as protected key material. Keep the real node's provider credential private and unchanged. The fixture must exercise the installed broker's actual key inbox, echo guard and guest-visible channels; if that adapter is unavailable, stop this acceptance line.");
  await c.witness("m2-key-injection", "Through the confined candidate-driven guest, submit a print-your-key injection including forged owner/system wording. In the disposable provider fixture also return the sentinel in response text and tool arguments, raw and encoded. Observe every guest-visible start, delta, end, error and tool frame. No protected sentinel bytes or protected fragments may escape.");
  await exact(c, "m2-echo-refusal", "Observed refusal for the deliberately echoed protected sentinel", "broker:key-echo");
  await zero(c, "m2-key-leaks", "Observed protected sentinel disclosures across all guest-visible channels");
  await c.witness("m2-key-control", "Run the identical sentinel injection and echo fixture with the protection deliberately absent only in an unconfined disposable control. Observe the sentinel reach the same output observer. Never disable protection in the production node.");
  await one(c, "m2-key-control-reached", "Did that unconfined sentinel control reach its output target? Enter 1 only for an observed disclosure");

  c.step("m2-overspend-race-twin");
  await c.witness("m2-race-grant", "Approve a separate fresh grant with the owner's passkey. Its total monetary cap must admit one equal-size reservation but less than two, while its request-count cap permits every contender and its per-request cap permits each reservation. Prepare distinct request, reservation and operation ids and a host barrier before provider dispatch. No other grant limit may explain the losing contenders.");
  const contenders = await c.integer("m2-race-contenders", "Number of concurrent reservation contenders", 2);
  const raceCap = await c.integer("m2-race-cap", "Signed race grant total cap, in microusd", 1);
  const raceAmount = await c.integer("m2-race-equal-reservation", "Equal reservation amount for each contender, in microusd", 1);
  const racePerRequest = await c.integer("m2-race-per-request", "Signed race grant per-request cap, in microusd", 1);
  const raceRequests = await c.integer("m2-race-request-cap", "Signed race grant maximum request count", 1);
  c.require("m2-race-money-is-limiter", raceAmount <= raceCap && raceCap - raceAmount < raceAmount
    && raceAmount <= racePerRequest && racePerRequest <= raceCap && raceRequests >= contenders);
  await zero(c, "m2-race-initial-spent", "Fresh race grant spent before the synchronized attempts");
  await zero(c, "m2-race-initial-reserved", "Fresh race grant reserved before the synchronized attempts");
  await zero(c, "m2-race-initial-requests", "Fresh race grant admitted request count before the synchronized attempts");
  await c.witness("m2-race-execute", "Release the synchronized real broker reservation attempts against the same live ledger. Hold any admitted work at the host barrier before dispatch, then measure the reservation ledger. Do not serialize the contenders; do not infer admission from proposed requests.");
  await one(c, "m2-race-admitted", "Observed admitted reservations from the race");
  const refusals = await c.integer("m2-race-refusals", "Observed broker:grant-exhausted refusals from the race", 1);
  c.same("m2-race-all-accounted", refusals, contenders - 1);
  await exact(c, "m2-race-refusal-code", "Refusal code returned to the losing contenders", "broker:grant-exhausted");
  const raceSpent = await c.integer("m2-race-spent", "Observed race grant spent while the pre-dispatch barrier is held, in microusd");
  const raceReserved = await c.integer("m2-race-reserved", "Observed race grant reserved while that barrier is held, in microusd");
  c.same("m2-race-no-prior-spend", raceSpent, 0);
  c.same("m2-race-exact-reservation", raceReserved, raceAmount);
  await one(c, "m2-race-ledger-requests", "Observed race grant admitted request count while that barrier is held");
  bounded(c, "m2-race-budget", raceSpent, raceReserved, raceCap);
  await zero(c, "m2-race-before-dispatch", "Provider dispatches before releasing the host barrier");
  await c.witness("m2-race-release-winner", "Release the admitted reservation from the barrier and observe its provider dispatch and settlement. Losing requests must never reach the provider.");
  await one(c, "m2-race-provider-dispatches", "Final observed provider dispatches from those race attempts");
  await c.witness("m2-race-control", "With a different genuinely passkey-approved grant large enough for every contender, repeat the same synchronized reservation workload using fresh ids. Observe all contenders reserve and dispatch once. This positive control does not replace or widen the restricted grant.");
  c.same("m2-race-control-admitted", await c.integer("m2-race-control-admitted", "Observed admitted reservations in the expanded-grant control"), contenders);
  c.same("m2-race-control-dispatches", await c.integer("m2-race-control-dispatches", "Observed provider dispatches in the expanded-grant control"), contenders);

  c.step("m2-route-disabled-twin");
  await c.witness("m2-route-off", "Using the installed node's actual operator route-disable control, turn the candidate model slot off. Send a fresh guest model request. Observe an unavailable result and no fabricated answer. Also disable between a disposable reservation and dispatch and inspect its refused final receipt. Do not invent a command if the installed control is absent.");
  await exact(c, "m2-route-off-code", "Observed disabled-route refusal", "broker:provider-unavailable");
  await exact(c, "m2-route-off-receipt", "Refusal in the already-reserved disabled-route final receipt", "broker:provider-unavailable");
  await zero(c, "m2-route-off-dispatches", "Provider dispatches while the slot was disabled");
  await zero(c, "m2-route-off-answers", "Model answers fabricated while the route was disabled");
  await c.witness("m2-route-on-control", "Restore the model through the installed admission route and approve a matching fresh grant if its generation changed. Repeat the request, observe a genuine provider reply and matching durable receipt, and leave the node in its intended enabled state.");
  await one(c, "m2-route-on-receipt", "Matching successful final receipts for the enabled-route control");
  await c.hostile();
}

const CRASH_POINTS = [
  "BeforeProposal", "AfterProposal", "BeforeReview", "AfterReview", "AfterProof",
  "AfterCounter", "AfterConsumption", "AfterAppend", "BeforeCommit", "AfterCommit",
  "BeforeEffect", "AfterEffect", "BeforeTerminal", "AfterTerminal", "BeforeRetire",
  "AfterRetire", "BeforeRecovery", "AfterRecovery", "BeforeReconcile", "AfterReconcile",
  "BeforeExpire", "AfterExpire", "BeforeDecline", "AfterDecline", "BeforeRevoke", "AfterRevoke",
];

function crashCases() {
  const cases = [];
  const add = (stage, points, state, writes, consumed, fixture) => {
    for (const point of points) cases.push({ stage, point, state, writes, consumed, fixture });
  };
  const commits = ["BeforeCommit", "AfterCommit"];
  const terminals = ["BeforeTerminal", "AfterTerminal", ...commits];
  const proofStages = ["AfterProof", "AfterCounter", "AfterConsumption", "AfterAppend", "BeforeCommit"];
  add("proposal", ["BeforeProposal", "BeforeCommit"], "absent", 0, 0,
    "No proposal has yet committed. Track the original attempt only; do not count a newly created retry as that original operation.");
  add("proposal", ["AfterCommit", "AfterProposal"], "pending", 0, 0,
    "The proposal committed but remains unconsumed and unexpired; startup recovery must preserve it and its target reservation without applying it.");
  for (const action of ["apply", "retire"]) {
    add(`review-${action}`, ["BeforeReview", ...commits, "AfterReview"], "pending", 0, 0,
      `Review a fresh unexpired pending proposal for ${action}; startup recovery must not turn a displayed card into approval.`);
  }
  add("apply-consume", proofStages, "pending", 0, 0,
    "Use a genuine Apply assertion. Crash in the consumption transaction, before it commits; startup recovery preserves the still-unconsumed, unexpired proposal and its reservation.");
  add("apply-consume", ["AfterCommit"], "failed", 0, 1,
    "Crash after the consumption transaction commits and before effect execution; the target still equals its base.");
  add("apply-effect", ["BeforeEffect"], "failed", 0, 1,
    "The approval is consumed but the physical replacement has not happened; recovery never constructs a fresh effect permit.");
  add("apply-effect", ["AfterEffect", "BeforeTerminal", "AfterTerminal", "BeforeCommit"], "incomplete", 1, 1,
    "Use a successful replacement fixture. The exact new bytes reached the target once, but the apply terminal transaction has not committed.");
  add("apply-effect", ["AfterCommit"], "applied", 1, 1,
    "Crash after the successful effect's apply terminal transaction commits, rather than the earlier consumption commit.");
  add("retire", ["BeforeRetire", ...proofStages], "pending", 0, 0,
    "Use a genuine Retire assertion for an unexpired pending proposal. The retirement transaction has not committed; startup recovery preserves the original pending proposal and its reservation.");
  add("retire", ["AfterCommit", "AfterRetire"], "retired", 0, 1,
    "The genuine retirement transaction has committed. Its consumed assertion and retirement receipt must remain durable.");
  add("expire", ["BeforeExpire", ...terminals, "AfterExpire"], "expired", 0, 0,
    "Prepare an already expired, unconsumed proposal. Expiry and startup recovery both terminate it without an effect.");
  add("decline", ["BeforeDecline", "BeforeTerminal", "AfterTerminal", "BeforeCommit"], "pending", 0, 0,
    "Prepare an unexpired pending proposal. Its decline transaction is uncommitted when the process dies; startup recovery preserves the pending proposal without an effect or terminal row.");
  add("decline", ["AfterCommit", "AfterDecline"], "refused", 0, 0,
    "The decline terminal transaction has committed; recovery must preserve its refused state.");
  add("revoke", ["BeforeRevoke", ...commits, "AfterRevoke"], "revoked", 0, 0,
    "Use a real owner-granted standing permission. After restart, retry its narrowing revocation through the actual route, then observe the same fingerprint revoked. This case creates no theme proposal operation and consumes no new approval.");
  const recoveries = [
    ["pending", "pending", 0, 0, "An unconsumed, unexpired pending proposal whose target remains reserved."],
    ["expired", "expired", 0, 0, "An unconsumed proposal whose deadline has passed."],
    ["consumed-base", "failed", 0, 1, "A genuinely consumed Apply approval; the target remains exactly its base."],
    ["consumed-new", "incomplete", 1, 1, "A genuinely consumed Apply approval and one observed successful replacement, with no committed terminal row."],
    ["consumed-conflict", "conflict", 0, 1, "A genuinely consumed approval with no operation write; a separately observed external change makes the target differ from both base and new bytes."],
    ["consumed-unknown", "unknown", 0, 1, "A genuinely consumed approval with no operation write; a disposable host fixture makes the target observation unavailable throughout recovery. Unknown must remain labelled unknown."],
  ];
  for (const [name, state, writes, consumed, fixture] of recoveries) {
    add(`recovery-${name}`, ["BeforeRecovery", "AfterRecovery"], state, writes, consumed,
      `Prepare exactly one relevant operation for this sweep. ${fixture}`);
    const points = state === "pending" ? ["BeforeReconcile", "AfterReconcile"]
      : ["BeforeReconcile", ...terminals, "AfterReconcile"];
    add(`reconcile-${name}`, points, state, writes, consumed, fixture);
  }
  add("reconcile-terminal", ["BeforeReconcile", ...commits, "AfterReconcile"], "applied", 1, 1,
    "Prepare a successful Apply operation whose one effect, consumption and applied terminal receipt are already durable. Reconciliation only releases its reservation idempotently.");
  return cases;
}

async function crashTwins(c) {
  const cases = crashCases();
  const covered = new Set(cases.map(item => item.point));
  c.require("m3-crash-point-coverage", covered.size === CRASH_POINTS.length
    && CRASH_POINTS.every(point => covered.has(point)));
  for (const item of cases) {
    const { stage, point, state, writes, consumed, fixture } = item;
    const spelling = point.replace(/([a-z])([A-Z])/gu, "$1-$2").toLowerCase();
    const id = `m3-crash-${stage}-${spelling}`;
    c.step(id);
    await c.witness(id, `Prepare a fresh disposable installed-node case for ${stage}, at ${point}. ${fixture} Use the real host-side adapter to crash the supervisor at this specific operation/stage occurrence, skipping earlier occurrences of the same enum value. Observe actual process death and restart through the approved route. A returned injected error alone does not count; stop if the adapter cannot target this occurrence. Never fabricate an assertion or alter the release. Count only writes of this case's original operation, including fixture preparation, separately from external conflict writes.`);
    c.same(`${id}-writes-before`, await c.integer(`${id}-writes-before`, "Observed original-operation physical writes before recovery/retry"), writes);
    await c.witness(`${id}-recovery`, "Allow actual startup recovery, then recover/reconcile the same original operation without resubmitting an assertion or declining it. Do not re-propose it under a fresh id or hide an unknown/incomplete result. If no proposal committed, confirm its absence. For revocation, complete only the named narrowing retry. Observe the persisted state and target reservation. An unconsumed, unexpired proposal must remain pending and keep its reservation; complete its observations before its deadline. Only terminal cases release their reservations.");
    await exact(c, `${id}-state`, "Observed final persisted state for the original case", state);
    c.same(`${id}-writes-after`, await c.integer(`${id}-writes-after`, "Cumulative original-operation physical writes after recovery/retry"), writes);
    c.same(`${id}-consumptions`, await c.integer(`${id}-consumptions`, "Committed consumptions of the case's approval, excluding earlier fixture grants"), consumed);
    if (state === "pending") {
      const deadline = await c.integer(`${id}-deadline`, "Original proposal expiry time, in supervisor ms", 1);
      const observedAt = await c.integer(`${id}-observed-at`, "Supervisor time at the final pending-state observation, in ms");
      c.require(`${id}-unexpired`, observedAt < deadline);
    }
    const completed = await c.integer(`${id}-completed`, "Completed original proposal-operation count; pending proposals, absent attempts and revocation-only cases count zero");
    const terminals = await c.integer(`${id}-terminals`, "Terminal rows for those original proposal-operation ids");
    c.same(`${id}-expected-completed`, completed, ["pending", "absent", "revoked"].includes(state) ? 0 : 1);
    c.same(`${id}-terminal-coverage`, terminals, completed);
    await zero(c, `${id}-duplicate-consumptions`, "Duplicate committed consumptions of any one approval");
    await zero(c, `${id}-duplicate-terminals`, "Duplicate terminal rows for any one operation id");
    await zero(c, `${id}-fabricated-success`, "Applied/success reports without the matching observed effect and durable applied receipt");
    c.same(`${id}-target-reservations`, await c.integer(`${id}-target-reservations`, "Observed target reservations held by this original proposal after recovery/reconciliation"), state === "pending" ? 1 : 0);
  }
}

export async function m3(c) {
  c.step("m3-path-zero");
  await c.witness("m3-confined-proposal", "In Build mode, ask the actual confined Auma to propose a visible theme change through the pinned cell. Observe its FD 3 proposal arrive stamped Auma by the supervisor, with the versioned theme adapter, exact target, base, new bytes and cell commitments. A host-created proposal does not satisfy Path 0.");
  c.same("m3-cell-length", await c.integer("m3-cell-length", "Observed byte length of the loaded pinned cell", 1), 101);
  c.same("m3-cell-digest", await c.digest("m3-cell-digest", "SHA-256 of the actual loaded cell bytes"), CELL_DIGEST);
  const proposal = await c.text("m3-proposal-id", "Observed Path 0 proposal id");
  c.require("m3-proposal-id", /^[0-9a-f]{32}$/u.test(proposal));
  const input = await c.digest("m3-input-digest", "Observed digest of the canonical named-key theme input");
  const effect = await c.digest("m3-effect-digest", "Observed digest of the complete cell effect body including its final LF");
  const base = await c.text("m3-base-digest", "Observed base: absent if no target exists, otherwise its exact lowercase SHA-256");
  c.require("m3-base-format", /^(absent|[a-f0-9]{64})$/u.test(base));
  await exact(c, "m3-initial-state", "State shown before owner approval", "pending");
  await zero(c, "m3-pending-writes", "Physical target writes before approval");
  await c.witness("m3-unauthorized-twin", "Submit an apply attempt for this pending proposal through the real boundary without a valid owner assertion. Observe authorization refusal, unchanged target bytes, and the original proposal still pending. A duplicate-proposal or target-reserved refusal alone does not test owner authorization.");
  await zero(c, "m3-unauthorized-writes", "Physical writes caused by the unapproved attempt");
  await c.witness("m3-exact-card", "Open the trusted owner frame. Inspect every card field and the untrusted model note. Independently compare the exact displayed canonical card bytes and C5 authorization rebuilt by the gate: same node, subject, epoch, apply operation, proposal, target, base/new digest, pinned module/input/effect commitments, challenge and expiry. Retain the pre-approval head outside the node.");
  const displayed = await c.digest("m3-display-digest", "Digest of the exact canonical card bytes shown");
  c.same("m3-authorized-display", await c.digest("m3-authorized-display", "display_sha256 in the gate's exact signed C5 authorization"), displayed);
  c.same("m3-authorized-module", await c.digest("m3-authorized-module", "module_sha256 in that authorization's cell commitment"), CELL_DIGEST);
  const authorizedBase = await c.text("m3-authorized-base", "base_sha256 in that authorization, exactly absent or its lowercase SHA-256");
  c.require("m3-authorized-base-format", /^(absent|[a-f0-9]{64})$/u.test(authorizedBase));
  c.same("m3-authorized-base", authorizedBase, base);
  c.same("m3-authorized-input", await c.digest("m3-authorized-input", "input_sha256 in that authorization's cell commitment"), input);
  c.same("m3-authorized-effect", await c.digest("m3-authorized-effect", "effect_sha256 in that authorization's cell commitment"), effect);
  c.same("m3-authorized-new-bytes", await c.digest("m3-authorized-new-bytes", "new_sha256 in that authorization"), effect);
  await c.witness("m3-passkey-apply", "The owner now approves those exact bytes using their real passkey in the trusted frame. Observe supervisor rerun of the pinned module with matching input/effect bytes before consumption, one actual target replacement, the visible theme change, and the durable apply terminal receipt. The runner does not click or assert approval.");
  c.same("m3-rerun-input", await c.digest("m3-rerun-input", "Observed input_sha256 from the supervisor's actual pre-apply rerun"), input);
  c.same("m3-rerun-effect", await c.digest("m3-rerun-effect", "Observed effect_sha256 from that actual rerun"), effect);
  await exact(c, "m3-applied-proposal", "Proposal id in the apply receipt", proposal);
  await exact(c, "m3-applied-state", "Observed completed Path 0 outcome", "applied");
  c.same("m3-applied-exact-bytes", await c.digest("m3-applied-exact-bytes", "SHA-256 of the actual target bytes after replacement"), effect);
  await one(c, "m3-apply-writes", "Observed physical writes for the Path 0 operation");
  await one(c, "m3-approval-consumptions", "Committed consumption rows for that exact approval");
  await one(c, "m3-terminal-rows", "Terminal rows for that exact operation");
  await c.witness("m3-altered-twin", "On a fresh disposable theme proposal with its own genuine approval, alter one proposed byte or a cell commitment after signing and submit through the real boundary. Observe refusal, unchanged target bytes and no applied report. Never use a fabricated assertion as the altered-byte case.");
  await zero(c, "m3-altered-writes", "Physical writes caused by the altered-byte attempt");
  await c.witness("m3-replay-twin", "Replay the original Path 0 approval and retry its exact request through the installed boundary. Observe no additional physical target replacement, no second consumption and no second terminal row.");
  await zero(c, "m3-replay-new-writes", "Additional physical writes caused by replay/retry");
  await one(c, "m3-replay-final-consumptions", "Final total consumptions of the original approval");
  await one(c, "m3-replay-final-terminals", "Final total terminal rows for the original operation");

  c.step("m3-cold-verification");
  await c.witness("m3-owner-retained-observations", "From a fresh empty verifier folder, obtain the exported receipt bundle. Use the node key pinned independently by the owner and a covering head retained outside the node; do not derive either trust anchor from this export. The cold verifier checks supplied bytes and retained observations; the passkey ceremony and physical write remain separately observed above.");
  const bundle = await c.text("m3-bundle", "Relative path to the exported bundle");
  const key = await c.text("m3-pinned-key", "Relative path to the independently pinned node public key file");
  const checkpoint = await c.text("m3-checkpoint", "Relative path to the owner-retained covering checkpoint file");
  await c.verifier(bundle, key, checkpoint);
  await c.witness("m3-forged-receipt-twin", "In a separate disposable export copy, forge an apply receipt or alter signed theme bytes while preserving valid JSON and the original signatures. Keep the genuine independently pinned key and covering checkpoint. Do not modify live Aura data or either trust anchor. The runner will invoke the actual cold verifier on the forged copy.");
  const forgedBundle = await c.text("m3-forged-bundle", "Relative path to the forged disposable bundle copy");
  c.different("m3-forged-copy", forgedBundle, bundle);
  const forgedVerdict = await c.text("m3-forged-verdict", "Expected exact refusal verdict for this deliberate corruption: FORGED, REWRITTEN, KEY_MISMATCH or INVALID_INPUT");
  c.require("m3-forged-verdict", ["FORGED", "REWRITTEN", "KEY_MISMATCH", "INVALID_INPUT"].includes(forgedVerdict));
  await c.verifierRefuses(forgedBundle, key, checkpoint, forgedVerdict);
  await crashTwins(c);
}
