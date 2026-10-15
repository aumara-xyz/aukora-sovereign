use super::*;

const START: i64 = 1_760_000_000_000;
const TARGET: &str = "plugins/owner-note/note.md";
const PERMISSION: &str = "gate/permission";

struct Approval {
    auth: Value,
    owner: Value,
    digest: Value,
    proof: Value,
    consumed: Value,
}

fn permission(mode: &str, count: i64, expires: i64) -> Value {
    object(&[
        ("v", Value::Int(1)),
        ("mode", string(mode)),
        (
            "targets",
            Value::Array(if mode == "ask" {
                vec![]
            } else {
                vec![string(TARGET)]
            }),
        ),
        ("kinds", Value::Array(vec![string("put")])),
        ("max_count", Value::Int(count)),
        ("expires_at", Value::Int(expires)),
        ("nonce", string("ab".repeat(16))),
    ])
}

fn append_at(writer: &mut Writer, kind: &str, phase: &str, op: &str, body: Value, at: i64) {
    writer.append(kind, phase, op, body);
    let last = writer.rows.last_mut().unwrap();
    last.at = at;
    last.sign(&writer.key);
}

fn row_reference(writer: &Writer) -> Value {
    let row = writer.rows.last().unwrap();
    object(&[
        ("seq", Value::Int(row.seq)),
        ("hash", string(hex::encode(row.hash))),
    ])
}

fn approval_with(
    writer: &mut Writer,
    index: usize,
    target: &str,
    bytes: &str,
    at: i64,
    standing: Option<Value>,
    edit: impl FnOnce(&mut Value, &mut Value, &mut Value),
) -> Approval {
    let op = format!("{index:032x}");
    let mut card = object(&[
        ("v", Value::Int(1)),
        (
            "risk",
            string(if target == PERMISSION {
                "critical"
            } else {
                "routine"
            }),
        ),
        ("says", string("Apply exact bytes")),
        ("facts", Value::Array(vec![])),
        (
            "from_to",
            object(&[("base", Value::Null), ("new", string(bytes))]),
        ),
        ("model_note", string("untrusted fixture note")),
    ]);
    let mut auth = object(&[
        ("v", Value::Int(1)),
        ("node", string("12".repeat(16))),
        ("subject", string(format!("aukora:1:{}", "34".repeat(32)))),
        (
            "op",
            string(if target == PERMISSION {
                "permission"
            } else {
                "apply"
            }),
        ),
        ("proposal", string(&op)),
        ("target", string(target)),
        ("base_sha256", string("absent")),
        ("new_sha256", string(hex::encode(hash(bytes.as_bytes())))),
        ("cell", Value::Null),
        (
            "display_sha256",
            string(hex::encode(hash(card.canonical().as_bytes()))),
        ),
        ("challenge", string(format!("{index:064x}"))),
        (
            "expires_at",
            Value::Int(if standing.is_some() {
                START + 1_000
            } else {
                START + 10_000
            }),
        ),
        ("epoch", Value::Int(1)),
    ]);
    let mut owner = object(&[
        ("subject", auth.get("subject")),
        ("epoch", auth.get("epoch")),
        ("binding_sha256", string("cd".repeat(32))),
    ]);
    edit(&mut auth, &mut card, &mut owner);
    auth.set(
        "display_sha256",
        string(hex::encode(hash(card.canonical().as_bytes()))),
    );
    let content = object(
        &["v", "node", "target", "base_sha256", "new_sha256", "cell"]
            .map(|name| (name, auth.get(name))),
    );
    auth.set(
        "operation",
        string(hex::encode(hash(
            &[
                b"aukora:operation-content:v1\0".as_slice(),
                content.canonical().as_bytes(),
            ]
            .concat(),
        ))),
    );
    append_at(
        writer,
        "gate.propose",
        "intent",
        &op,
        object(&[
            ("target", auth.get("target")),
            ("base_sha256", auth.get("base_sha256")),
            ("new_sha256", auth.get("new_sha256")),
            ("digest", auth.get("operation")),
        ]),
        at,
    );
    append_at(
        writer,
        "gate.review",
        "fact",
        &op,
        object(&[
            ("authorization", auth.clone()),
            ("owner_state", owner.clone()),
            ("card", card),
        ]),
        at,
    );
    let review = row_reference(writer);
    let digest = string(hex::encode(hash(
        &[
            b"aukora:owner-authorization:v1\0".as_slice(),
            auth.canonical().as_bytes(),
        ]
        .concat(),
    )));
    let proof_bytes = b"disposable proof bytes; passkey verified at live gate";
    let proof = standing
        .as_ref()
        .map(|reference| reference.get("proof_sha256"))
        .unwrap_or_else(|| string(hex::encode(hash(proof_bytes))));
    let mut body = object(&[
        ("authorization", auth.clone()),
        ("authorization_sha256", digest.clone()),
        ("proof_sha256", proof.clone()),
        ("owner_state", owner.clone()),
        ("review_issue", review.clone()),
        ("spent", Value::Bool(true)),
    ]);
    if let Some(reference) = standing {
        body.set("standing_permission", reference);
    } else {
        body.set("proof_hex", string(hex::encode(proof_bytes)));
    }
    append_at(writer, "gate.consume", "settle", &op, body, at);
    let mut consumed = row_reference(writer);
    consumed.set("ledger_seq", consumed.get("seq"));
    consumed.set("ledger_hash", consumed.get("hash"));
    let mut review = review;
    review.set("ledger_seq", review.get("seq"));
    review.set("ledger_hash", review.get("hash"));
    consumed.set("review_issue", review);
    Approval {
        auth,
        owner,
        digest,
        proof,
        consumed,
    }
}

fn approval(
    writer: &mut Writer,
    index: usize,
    target: &str,
    bytes: &str,
    at: i64,
    standing: Option<Value>,
) -> Approval {
    approval_with(writer, index, target, bytes, at, standing, |_, _, _| {})
}

fn apply(writer: &mut Writer, approval: &Approval, standing: Option<Value>, at: i64) {
    let digest = standing
        .as_ref()
        .map(|reference| reference.get("authorization_sha256"))
        .unwrap_or_else(|| approval.digest.clone());
    let authority = object(&[
        ("version", Value::Int(1)),
        ("kind", string("aukora-owner-authorization-ref/v1")),
        ("authorization_id", digest.clone()),
        ("authorization_sha256", digest),
        ("proof_sha256", approval.proof.clone()),
    ]);
    let receipt = object(&[
        ("v", Value::Int(3)),
        ("kind", string("change")),
        ("proposal", approval.auth.get("proposal")),
        ("target", approval.auth.get("target")),
        ("node", approval.auth.get("node")),
        ("base_sha256", approval.auth.get("base_sha256")),
        ("new_sha256", approval.auth.get("new_sha256")),
        ("approver", approval.owner.get("subject")),
        ("applied_at", Value::Int(at)),
        ("owner_accepted_at_ms", Value::Int(at)),
        ("owner_consumption", approval.consumed.clone()),
        ("owner_authorization", authority),
        ("standing_permission", standing.unwrap_or(Value::Null)),
    ]);
    let Value::Str(op) = approval.auth.get("proposal") else {
        unreachable!()
    };
    append_at(
        writer,
        "gate.apply",
        "terminal",
        &op,
        object(&[("receipt", receipt)]),
        at,
    );
}

fn activate(writer: &mut Writer, index: usize, value: Value, at: i64) -> Approval {
    let approval = approval(writer, index, PERMISSION, &value.canonical(), at, None);
    apply(writer, &approval, None, at);
    approval
}

fn reference(approval: &Approval) -> Value {
    object(&[
        ("v", Value::Int(1)),
        ("proposal", approval.auth.get("proposal")),
        ("authorization_sha256", approval.digest.clone()),
        ("proof_sha256", approval.proof.clone()),
        (
            "consume",
            object(&[
                ("seq", approval.consumed.get("seq")),
                ("hash", approval.consumed.get("hash")),
            ]),
        ),
        ("kind", string("put")),
    ])
}

fn auto(writer: &mut Writer, index: usize, target: &str, reference: Value, at: i64) {
    let approval = approval(
        writer,
        index,
        target,
        "Covered note",
        at,
        Some(reference.clone()),
    );
    apply(writer, &approval, Some(reference), at);
}

fn permitted(count: i64) -> (Writer, Approval) {
    let mut writer = Writer::new();
    let approved = activate(
        &mut writer,
        1,
        permission("limits", count, START + 1_000),
        START,
    );
    (writer, approved)
}

fn engines(writer: &Writer, code: Option<&str>) {
    let report = path0_report(writer);
    if let Some(code) = code {
        assert!(
            matches!(report.verdict, verifier::Verdict::Rewritten(_)),
            "{report:?}"
        );
        assert!(
            report.findings.iter().any(|finding| finding.contains(code)),
            "{report:?}"
        );
    } else {
        assert_eq!(report.verdict, verifier::Verdict::Verified, "{report:?}");
    }
    let fixture = Fixture::new();
    let key = hex::encode(writer.key.verifying_key().to_bytes());
    let head = writer.head(writer.rows.len()).canonical();
    let outputs = cold_engines(
        &fixture,
        &cold_bundle(writer).canonical(),
        Some(&key),
        Some(&head),
    );
    for output in &outputs {
        let text = output_text(output);
        if let Some(code) = code {
            assert_eq!(output.status.code(), Some(2), "{text}");
            assert!(text.contains(code), "{text}");
        } else {
            assert_verdict(output, 0, "VERIFIED");
        }
    }
}

#[test]
fn antibody_standing_covered_auto_apply_and_permission_digest_verify_cold() {
    for mode in ["risky", "limits"] {
        let mut writer = Writer::new();
        let permission = activate(&mut writer, 1, permission(mode, 2, START + 1_000), START);
        auto(&mut writer, 2, TARGET, reference(&permission), START + 1);
        auto(&mut writer, 3, TARGET, reference(&permission), START + 999);
        engines(&writer, None);
    }
}

#[test]
fn antibody_standing_rejects_target_outside_scope() {
    let (mut writer, permission) = permitted(1);
    auto(
        &mut writer,
        2,
        "plugins/other/note.md",
        reference(&permission),
        START + 1,
    );
    engines(&writer, Some("verifier:standing-scope"));
}

#[test]
fn antibody_standing_rejects_kind_outside_scope() {
    let (mut writer, permission) = permitted(1);
    let mut reference = reference(&permission);
    reference.set("kind", string("delete"));
    auto(&mut writer, 2, TARGET, reference, START + 1);
    engines(&writer, Some("verifier:standing-scope"));
}

#[test]
fn antibody_standing_rejects_consumption_at_or_after_expiry() {
    for at in [START + 1_000, START + 1_001] {
        let (mut writer, permission) = permitted(1);
        auto(&mut writer, 2, TARGET, reference(&permission), at);
        engines(&writer, Some("verifier:standing-expired"));
        let terminal = writer.rows.last_mut().unwrap();
        terminal.kind = "gate.recover".into();
        terminal.body = object(&[("state", string("failed"))]);
        terminal.sign(&writer.key);
        engines(&writer, Some("verifier:standing-expired"));
    }
}

#[test]
fn antibody_standing_rejects_effect_at_or_after_expiry() {
    for at in [START + 1_000, START + 1_001] {
        let (mut writer, permission) = permitted(1);
        let reference = reference(&permission);
        let approval = approval(
            &mut writer,
            2,
            TARGET,
            "Covered note",
            START + 1,
            Some(reference.clone()),
        );
        apply(&mut writer, &approval, Some(reference), at);
        engines(&writer, Some("verifier:standing-expired"));
    }
}

#[test]
fn antibody_standing_rejects_count_overrun() {
    let (mut writer, permission) = permitted(1);
    auto(&mut writer, 2, TARGET, reference(&permission), START + 1);
    auto(&mut writer, 3, TARGET, reference(&permission), START + 2);
    engines(&writer, Some("verifier:standing-count"));
}

#[test]
fn antibody_standing_counts_consumptions_with_failed_effects() {
    let (mut writer, permission) = permitted(1);
    let failed = approval(
        &mut writer,
        2,
        TARGET,
        "Failed note",
        START + 1,
        Some(reference(&permission)),
    );
    let Value::Str(op) = failed.auth.get("proposal") else {
        unreachable!()
    };
    append_at(
        &mut writer,
        "gate.recover",
        "terminal",
        &op,
        object(&[("state", string("failed"))]),
        START + 1,
    );
    auto(&mut writer, 3, TARGET, reference(&permission), START + 2);
    engines(&writer, Some("verifier:standing-count"));
}

#[test]
fn antibody_standing_rejects_after_signed_revoke() {
    let (mut writer, permission) = permitted(1);
    activate(&mut writer, 2, permission_value_ask(), START + 1);
    auto(&mut writer, 3, TARGET, reference(&permission), START + 2);
    engines(&writer, Some("verifier:standing-revoked"));
}

fn permission_value_ask() -> Value {
    permission("ask", 0, START + 1_000)
}

#[test]
fn antibody_standing_failed_signed_revoke_disables_prior_permission() {
    let (mut writer, permission) = permitted(1);
    let revoke = approval(
        &mut writer,
        2,
        PERMISSION,
        &permission_value_ask().canonical(),
        START + 1,
        None,
    );
    let Value::Str(op) = revoke.auth.get("proposal") else {
        unreachable!()
    };
    append_at(
        &mut writer,
        "gate.recover",
        "terminal",
        &op,
        object(&[("state", string("failed"))]),
        START + 1,
    );
    auto(&mut writer, 3, TARGET, reference(&permission), START + 2);
    engines(&writer, Some("verifier:standing-revoked"));
}

#[test]
fn antibody_standing_rejects_forged_or_unknown_permission_reference() {
    for field in [
        "proposal",
        "authorization_sha256",
        "proof_sha256",
        "consume-hash",
        "consume-seq",
    ] {
        let (mut writer, permission) = permitted(1);
        let mut reference = reference(&permission);
        match field {
            "consume-hash" | "consume-seq" => {
                let mut consume = reference.get("consume");
                if field == "consume-hash" {
                    consume.set("hash", string("00".repeat(32)));
                } else {
                    consume.set("seq", Value::Int(999));
                }
                reference.set("consume", consume);
            }
            "proposal" => reference.set(field, string("00".repeat(16))),
            _ => reference.set(field, string("00".repeat(32))),
        }
        auto(&mut writer, 2, TARGET, reference, START + 1);
        if field == "proof_sha256" {
            writer.rows[6]
                .body
                .set("proof_sha256", permission.proof.clone());
            let mut receipt = writer.rows[7].body.get("receipt");
            let mut authority = receipt.get("owner_authorization");
            authority.set("proof_sha256", permission.proof.clone());
            receipt.set("owner_authorization", authority);
            writer.rows[7].body.set("receipt", receipt);
            resign_references(&mut writer, 6);
        }
        engines(&writer, Some("verifier:standing-reference"));
    }
}

#[test]
fn antibody_standing_permission_needs_prior_applied_passkey_consumption() {
    let mut writer = Writer::new();
    let permission = approval(
        &mut writer,
        1,
        PERMISSION,
        &permission("limits", 1, START + 1_000).canonical(),
        START,
        None,
    );
    auto(&mut writer, 2, TARGET, reference(&permission), START + 1);
    engines(&writer, Some("verifier:standing-permission"));
}

#[test]
fn antibody_standing_permission_without_passkey_proof_is_refused() {
    let (mut writer, permission) = permitted(1);
    let Value::Object(fields) = &mut writer.rows[2].body else {
        unreachable!()
    };
    fields.retain(|(name, _)| name != "proof_hex");
    resign_references(&mut writer, 2);
    let mut permission = permission;
    permission
        .consumed
        .set("hash", string(hex::encode(writer.rows[2].hash)));
    auto(&mut writer, 2, TARGET, reference(&permission), START + 1);
    engines(&writer, Some("verifier:missing-field-proof_hex"));
}

#[test]
fn antibody_standing_receipt_must_match_consumed_permission() {
    let (mut writer, permission) = permitted(1);
    let reference = reference(&permission);
    let approval = approval(
        &mut writer,
        2,
        TARGET,
        "Covered note",
        START + 1,
        Some(reference.clone()),
    );
    let mut forged = reference;
    forged.set("kind", string("delete"));
    apply(&mut writer, &approval, Some(forged), START + 1);
    engines(&writer, Some("verifier:gate-evidence"));
}

fn rewrite_hashes(value: &mut Value, hashes: &std::collections::BTreeMap<String, String>) {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if name == "hash" || name == "ledger_hash" {
                    if let Value::Str(hash) = value {
                        if let Some(replacement) = hashes.get(hash) {
                            *hash = replacement.clone();
                        }
                    }
                } else {
                    rewrite_hashes(value, hashes);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite_hashes(value, hashes);
            }
        }
        _ => {}
    }
}

fn resign_references(writer: &mut Writer, from: usize) {
    let mut hashes = std::collections::BTreeMap::new();
    for index in from..writer.rows.len() {
        let old = hex::encode(writer.rows[index].hash);
        rewrite_hashes(&mut writer.rows[index].body, &hashes);
        writer.rows[index].prev = if index == 0 {
            DOMAIN.into()
        } else {
            hex::encode(writer.rows[index - 1].hash)
        };
        writer.rows[index].sign(&writer.key);
        hashes.insert(old, hex::encode(writer.rows[index].hash));
    }
}

#[test]
fn antibody_standing_reference_schema_and_auto_proof_are_closed() {
    for variant in ["version", "extra", "proof"] {
        let (mut writer, permission) = permitted(1);
        let mut reference = reference(&permission);
        match variant {
            "version" => reference.set("v", Value::Int(2)),
            "extra" => reference.set("extra", Value::Bool(true)),
            _ => {}
        }
        auto(&mut writer, 2, TARGET, reference, START + 1);
        if variant == "proof" {
            writer.rows[6].body.set("proof_hex", string("aa"));
            resign_references(&mut writer, 6);
        }
        engines(&writer, Some("verifier:standing-reference"));
    }
}

#[test]
fn antibody_standing_consumed_proof_must_match_permission() {
    let (mut writer, permission) = permitted(1);
    let reference = reference(&permission);
    let mut approval = approval(
        &mut writer,
        2,
        TARGET,
        "Covered note",
        START + 1,
        Some(reference.clone()),
    );
    approval.proof = string("00".repeat(32));
    writer.rows[6]
        .body
        .set("proof_sha256", approval.proof.clone());
    resign_references(&mut writer, 6);
    approval
        .consumed
        .set("hash", string(hex::encode(writer.rows[6].hash)));
    approval
        .consumed
        .set("ledger_hash", string(hex::encode(writer.rows[6].hash)));
    apply(&mut writer, &approval, Some(reference), START + 1);
    engines(&writer, Some("verifier:standing-reference"));
}

#[test]
fn antibody_standing_rejects_owner_or_node_change() {
    for variant in ["binding", "node", "epoch", "subject"] {
        let (mut writer, permission) = permitted(1);
        let reference = reference(&permission);
        let approved = approval_with(
            &mut writer,
            2,
            TARGET,
            "Covered note",
            START + 1,
            Some(reference.clone()),
            |auth, _, owner| match variant {
                "node" => auth.set("node", string("ab".repeat(16))),
                "binding" => owner.set("binding_sha256", string("ab".repeat(32))),
                "epoch" => {
                    auth.set("epoch", Value::Int(2));
                    owner.set("epoch", Value::Int(2));
                }
                _ => {
                    auth.set("subject", string(format!("aukora:1:{}", "ab".repeat(32))));
                    owner.set("subject", auth.get("subject"));
                }
            },
        );
        apply(&mut writer, &approved, Some(reference), START + 1);
        engines(&writer, Some("verifier:standing-owner"));
    }
}

#[test]
fn antibody_standing_permission_schema_is_closed_and_bounded() {
    for (name, value) in [
        ("v", Value::Int(2)),
        ("mode", string("always")),
        ("targets", Value::Array(vec![])),
        ("targets", Value::Array(vec![string(TARGET); 33])),
        (
            "targets",
            Value::Array(vec![
                string(format!("plugins/a/{}.md", "a".repeat(180)));
                32
            ]),
        ),
        ("kinds", Value::Array(vec![string("delete")])),
        ("max_count", Value::Int(0)),
        ("max_count", Value::Int(1_000_001)),
        ("expires_at", Value::Int(0)),
        ("nonce", string("bad")),
        ("extra", Value::Bool(true)),
    ] {
        let mut writer = Writer::new();
        let mut value_permission = permission("limits", 1, START + 1_000);
        value_permission.set(name, value);
        let approved = activate(&mut writer, 1, value_permission, START);
        auto(&mut writer, 2, TARGET, reference(&approved), START + 1);
        engines(&writer, Some("verifier:standing-permission"));
    }
}

#[test]
fn antibody_standing_permission_targets_must_be_safe_names() {
    for target in [
        "gate/permission",
        "plugins/Identity/key.md",
        "plugins/owner/../note.md",
        "plugins/owner//note.md",
        "plugins/owner/note.js",
        "plugins/owner\\note.md",
        "owner/note.md",
        "plugins/owner/note\u{7f}.md",
        "plugins/owner/notes-é.md",
    ] {
        let mut writer = Writer::new();
        let mut value = permission("limits", 1, START + 1_000);
        value.set("targets", Value::Array(vec![string(target)]));
        let approved = activate(&mut writer, 1, value, START);
        auto(&mut writer, 2, target, reference(&approved), START + 1);
        engines(&writer, Some("verifier:standing-permission"));
    }
}

#[test]
fn antibody_standing_never_uses_ask_permission() {
    let mut writer = Writer::new();
    let approved = activate(&mut writer, 1, permission_value_ask(), START);
    auto(&mut writer, 2, TARGET, reference(&approved), START + 1);
    engines(&writer, Some("verifier:standing-scope"));
}

#[test]
fn antibody_standing_auto_authorization_cannot_extend_permission_lifetime() {
    let (mut writer, permission) = permitted(1);
    let reference = reference(&permission);
    let approved = approval_with(
        &mut writer,
        2,
        TARGET,
        "Covered note",
        START + 1,
        Some(reference.clone()),
        |auth, _, _| auth.set("expires_at", Value::Int(START + 1_001)),
    );
    apply(&mut writer, &approved, Some(reference), START + 1);
    engines(&writer, Some("verifier:standing-expired"));
}

#[test]
fn antibody_standing_auto_authorization_must_be_live_at_consume_and_apply() {
    for expired_at_consume in [true, false] {
        let (mut writer, permission) = permitted(1);
        let reference = reference(&permission);
        let approved = approval_with(
            &mut writer,
            2,
            TARGET,
            "Covered note",
            START + 1,
            Some(reference.clone()),
            |auth, _, _| auth.set("expires_at", Value::Int(START + 2)),
        );
        if expired_at_consume {
            writer.rows[6].at = START + 2;
            resign_references(&mut writer, 6);
        } else {
            apply(&mut writer, &approved, Some(reference), START + 2);
        }
        engines(&writer, Some("verifier:standing-expired"));
    }
}

#[test]
fn antibody_standing_auto_apply_requires_routine_card_and_small_base() {
    for variant in ["risk", "base"] {
        let (mut writer, permission) = permitted(1);
        let reference = reference(&permission);
        let approved = approval_with(
            &mut writer,
            2,
            TARGET,
            "Covered note",
            START + 1,
            Some(reference.clone()),
            |auth, card, _| {
                if variant == "risk" {
                    card.set("risk", string("critical"));
                } else {
                    let base = "x".repeat(65_537);
                    auth.set("base_sha256", string(hex::encode(hash(base.as_bytes()))));
                    let mut from_to = card.get("from_to");
                    from_to.set("base", string(base));
                    card.set("from_to", from_to);
                }
            },
        );
        apply(&mut writer, &approved, Some(reference), START + 1);
        engines(&writer, Some("verifier:standing-scope"));
    }
}

#[test]
fn antibody_standing_receipt_uses_permission_authorization_digest() {
    let (mut writer, permission) = permitted(1);
    auto(&mut writer, 2, TARGET, reference(&permission), START + 1);
    let mut receipt = writer.rows[7].body.get("receipt");
    let mut authority = receipt.get("owner_authorization");
    let auto_digest = writer.rows[6].body.get("authorization_sha256");
    authority.set("authorization_id", auto_digest.clone());
    authority.set("authorization_sha256", auto_digest);
    receipt.set("owner_authorization", authority);
    writer.rows[7].body.set("receipt", receipt);
    resign_references(&mut writer, 7);
    engines(&writer, Some("verifier:gate-evidence"));
}

#[test]
fn antibody_standing_receipt_applied_time_must_match_signed_row() {
    let (mut writer, permission) = permitted(1);
    auto(&mut writer, 2, TARGET, reference(&permission), START + 1);
    let mut receipt = writer.rows[7].body.get("receipt");
    receipt.set("applied_at", Value::Int(START));
    writer.rows[7].body.set("receipt", receipt);
    resign_references(&mut writer, 7);
    engines(&writer, Some("verifier:gate-evidence"));
}

#[test]
fn antibody_standing_normal_receipt_cannot_claim_standing_authority() {
    let (mut writer, permission) = permitted(1);
    let mut receipt = writer.rows[3].body.get("receipt");
    receipt.set("standing_permission", reference(&permission));
    writer.rows[3].body.set("receipt", receipt);
    resign_references(&mut writer, 3);
    engines(&writer, Some("verifier:gate-evidence"));
}

#[test]
fn antibody_standing_source_must_be_owner_permission_on_slider_target() {
    for variant in ["target", "operation"] {
        let mut writer = Writer::new();
        let approved = approval_with(
            &mut writer,
            1,
            if variant == "target" {
                TARGET
            } else {
                PERMISSION
            },
            &permission("limits", 1, START + 1_000).canonical(),
            START,
            None,
            |auth, _, _| {
                auth.set(
                    "op",
                    string(if variant == "target" {
                        "permission"
                    } else {
                        "apply"
                    }),
                )
            },
        );
        apply(&mut writer, &approved, None, START);
        auto(&mut writer, 2, TARGET, reference(&approved), START + 1);
        engines(&writer, Some("verifier:standing-permission"));
    }
    let (mut writer, approved) = permitted(2);
    let nested = approval(
        &mut writer,
        2,
        PERMISSION,
        &permission("limits", 1, START + 1_000).canonical(),
        START + 1,
        Some(reference(&approved)),
    );
    apply(&mut writer, &nested, Some(reference(&approved)), START + 1);
    auto(&mut writer, 3, TARGET, reference(&nested), START + 2);
    engines(&writer, Some("verifier:standing-scope"));
    assert!(path0_report(&writer)
        .findings
        .iter()
        .any(|finding| finding.contains("verifier:standing-permission")));
    let output = Command::new("python3")
        .args([
            "-B",
            "-c",
            r#"
import json, runpy, sys
gate = runpy.run_path(sys.argv[1])
rows = json.loads(sys.argv[2])["rows"]
row = rows[-2]
try:
    gate["gate_standing"](rows, row, row["at"], row["seq"])
except gate["ColdRefusal"] as error:
    assert str(error) == "verifier:standing-permission", str(error)
else:
    raise AssertionError("nested standing permission accepted")
"#,
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify.py"))
        .arg(cold_bundle(&writer).canonical())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
}

#[test]
fn antibody_standing_auto_operation_must_apply() {
    let (mut writer, permission) = permitted(1);
    let reference = reference(&permission);
    let approved = approval_with(
        &mut writer,
        2,
        TARGET,
        "Covered note",
        START + 1,
        Some(reference.clone()),
        |auth, _, _| auth.set("op", string("permission")),
    );
    apply(&mut writer, &approved, Some(reference), START + 1);
    engines(&writer, Some("verifier:standing-scope"));
}

#[test]
fn antibody_standing_owner_epoch_bool_is_not_an_integer() {
    let mut writer = Writer::new();
    let approved = approval_with(
        &mut writer,
        1,
        PERMISSION,
        &permission("limits", 1, START + 1_000).canonical(),
        START,
        None,
        |_, _, owner| owner.set("epoch", Value::Bool(true)),
    );
    apply(&mut writer, &approved, None, START);
    engines(&writer, Some("verifier:gate-evidence"));
}

#[test]
fn antibody_standing_revoke_before_effect_disables_spent_auto_consumption() {
    let (mut writer, permission) = permitted(1);
    let reference = reference(&permission);
    let approved = approval(
        &mut writer,
        2,
        TARGET,
        "Covered note",
        START + 1,
        Some(reference.clone()),
    );
    activate(&mut writer, 3, permission_value_ask(), START + 2);
    apply(&mut writer, &approved, Some(reference), START + 3);
    engines(&writer, Some("verifier:standing-revoked"));
}
