// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use aumlok::webauthn::PublicKey;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value as Json};

pub(crate) fn binding() -> OwnerBinding {
    let node_id = "11".repeat(16);
    let rp_id = format!("owner-{node_id}");
    OwnerBinding {
        node_id,
        origin: format!("https://{rp_id}"),
        rp_id,
    }
}

fn verify(
    evidence: &Evidence,
    pinned: Option<&PinnedOwner>,
    enforce_counter: bool,
) -> Result<VerifiedApproval> {
    super::verify(evidence, &binding(), pinned, enforce_counter)
}

fn json_bytes(value: &Json) -> Vec<u8> {
    canonical(value).unwrap()
}

fn text(value: &Json) -> String {
    String::from_utf8(json_bytes(value)).unwrap()
}

pub(crate) fn authorization(evidence: &Evidence) -> Json {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&evidence.auth_bytes).unwrap()).unwrap()
}

pub(crate) fn set_authorization(evidence: &mut Evidence, auth: &Json) {
    evidence.auth_bytes = URL_SAFE_NO_PAD.encode(json_bytes(auth));
}

fn signed_assertion(evidence: &mut Evidence, count: u32) {
    let bytes = URL_SAFE_NO_PAD.decode(&evidence.auth_bytes).unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(hex::decode(domain_hash(AUTH_DOMAIN, &bytes)).unwrap());
    let client = json_bytes(&json!({
        "type":"webauthn.get", "challenge":challenge,
        "origin":evidence.origin, "crossOrigin":false
    }));
    let mut authenticator = Sha256::digest(evidence.rp_id.as_bytes()).to_vec();
    authenticator.push(if evidence.credential.backup_eligible {
        13
    } else {
        5
    });
    authenticator.extend_from_slice(&count.to_be_bytes());
    let signed = [authenticator.as_slice(), Sha256::digest(&client).as_slice()].concat();
    let key = if evidence.credential.public_key
        == PublicKey::Ed25519(SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes())
    {
        SigningKey::from_bytes(&[20; 32])
    } else {
        SigningKey::from_bytes(&[19; 32])
    };
    evidence.assertion = AssertionMaterial {
        kind: "passkey".into(),
        credential_id: evidence.credential.credential_id.clone(),
        client_data_json: URL_SAFE_NO_PAD.encode(&client),
        authenticator_data: URL_SAFE_NO_PAD.encode(&authenticator),
        signature: URL_SAFE_NO_PAD.encode(key.sign(&signed).to_bytes()),
        user_handle: Some(evidence.credential.user_handle.clone()),
    };
}

fn row(kind: &str, actor: &str, op: &str, phase: &str, body: Json) -> EvidenceRow {
    EvidenceRow {
        seq: 0,
        prev: String::new(),
        hash: String::new(),
        sig: String::new(),
        at: 0,
        kind: kind.into(),
        actor: actor.into(),
        op: op.into(),
        phase: phase.into(),
        body: text(&body),
    }
}

pub(crate) fn rechain(evidence: &mut Evidence) {
    let key = if evidence.node_public_key
        == hex::encode(SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes())
    {
        SigningKey::from_bytes(&[32; 32])
    } else {
        SigningKey::from_bytes(&[31; 32])
    };
    let mut previous = aura::DOMAIN.to_string();
    for (index, row) in evidence.rows.iter_mut().enumerate() {
        row.seq = index as u64 + 1;
        row.prev = previous;
        let entry = row.entry().unwrap();
        let digest = aura::entry_hash(&row.prev, &entry.fields(), row.seq).unwrap();
        row.hash = hex::encode(digest);
        row.sig = STANDARD.encode(key.sign(&digest).to_bytes());
        previous = row.hash.clone();
    }
}

pub(crate) fn resign(evidence: &mut Evidence) {
    signed_assertion(evidence, 0);
    rebuild_rows(evidence);
}

pub(crate) fn set_counter(evidence: &mut Evidence, count: u32) {
    signed_assertion(evidence, count);
    rebuild_rows(evidence);
}

fn rebuild_rows(evidence: &mut Evidence) {
    let auth = authorization(evidence);
    let proposal = auth["proposal"].as_str().unwrap();
    let subject = auth["subject"].as_str().unwrap();
    let auth_bytes = URL_SAFE_NO_PAD.decode(&evidence.auth_bytes).unwrap();
    let auth_sha = domain_hash(AUTH_DOMAIN, &auth_bytes);
    let proof = canonical(&evidence.assertion).unwrap();
    let proof_sha = hash(&proof);
    let owner = json!({"subject":subject,"epoch":auth["epoch"],"binding_sha256":"44".repeat(32)});
    let count = evidence.rows.len();
    evidence.rows[count - 4] = row(
        "gate.propose",
        "supervisor",
        proposal,
        "intent",
        json!({
            "target":auth["target"],"base_sha256":auth["base_sha256"],
            "new_sha256":auth["new_sha256"],"digest":auth["operation"],"expires_at":auth["expires_at"]
        }),
    );
    let card = json!({"v":1,"risk":"critical","says":"Start the agent runtime","facts":[],"from_to":{},"model_note":""});
    evidence.rows[count - 3] = row(
        "gate.review",
        "gate",
        proposal,
        "fact",
        json!({
            "authorization":auth,"owner_state":owner,"card":card
        }),
    );
    rechain(evidence);
    let review = &evidence.rows[count - 3];
    let review_ref = json!({"seq":review.seq,"hash":review.hash});
    evidence.rows[count - 2] = row(
        "gate.consume",
        subject,
        proposal,
        "settle",
        json!({
            "authorization_sha256":auth_sha,"proof_sha256":proof_sha,"proof_hex":hex::encode(&proof),
            "authorization":auth,"owner_state":owner,"review_issue":review_ref,"spent":true
        }),
    );
    rechain(evidence);
    let consume = &evidence.rows[count - 2];
    let key_sha = hash(&hex::decode(&evidence.node_public_key).unwrap());
    let receipt = json!({
        "v":3,"kind":"change","proposal":proposal,"target":auth["target"],
        "base_sha256":auth["base_sha256"],"new_sha256":auth["new_sha256"],
        "node":auth["node"],"approver":subject,"gate_pubkey_sha256":key_sha,
        "owner_authorization":{"version":1,"kind":"aukora-owner-authorization-ref/v1",
            "authorization_id":auth_sha,"authorization_sha256":auth_sha,"proof_sha256":proof_sha},
        "owner_consumption":{"seq":consume.seq,"hash":consume.hash,"review_issue":review_ref}
    });
    evidence.rows[count - 1] = row(
        "gate.apply",
        subject,
        proposal,
        "terminal",
        json!({"receipt":receipt}),
    );
    rechain(evidence);
}

pub(crate) fn fixture(epoch: u64, padding: usize, seed: u8) -> Evidence {
    let node = "11".repeat(16);
    let subject = format!("aukora:1:{}", "23".repeat(32));
    let rp_id = format!("owner-{node}");
    let release = ReleaseRecord {
        v: 1,
        digest: format!("{seed:02x}").repeat(32),
        components: None,
    };
    let new_sha = hash(&canonical(&release).unwrap());
    let content = json!({"v":1,"node":node,"target":"release","base_sha256":"absent","new_sha256":new_sha,"cell":null});
    let card = json!({"v":1,"risk":"critical","says":"Start the agent runtime","facts":[],"from_to":{},"model_note":""});
    let auth = json!({
        "v":1,"node":node,"subject":subject,"op":"release","proposal":format!("{seed:02x}").repeat(16),
        "target":"release","base_sha256":"absent","new_sha256":new_sha,"cell":null,
        "display_sha256":hash(&json_bytes(&card)),"challenge":"aa".repeat(32),"expires_at":10_000,
        "epoch":epoch,"operation":domain_hash(OPERATION_DOMAIN,&json_bytes(&content))
    });
    let credential = Credential {
        owner_id: subject,
        credential_id: URL_SAFE_NO_PAD.encode([7; 16]),
        public_key: PublicKey::Ed25519(
            SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes(),
        ),
        user_handle: URL_SAFE_NO_PAD.encode([8; 16]),
        sign_count: 0,
        backup_eligible: false,
    };
    let placeholder = AssertionMaterial {
        kind: String::new(),
        credential_id: String::new(),
        client_data_json: String::new(),
        authenticator_data: String::new(),
        signature: String::new(),
        user_handle: None,
    };
    let mut rows = (0..padding)
        .map(|_| row("boot.facts", "supervisor", "", "fact", json!({})))
        .collect::<Vec<_>>();
    rows.extend((0..4).map(|_| row("boot.facts", "supervisor", "", "fact", json!({}))));
    let mut evidence = Evidence {
        v: 1,
        auth_bytes: URL_SAFE_NO_PAD.encode(json_bytes(&auth)),
        assertion: placeholder,
        credential,
        origin: format!("https://{rp_id}"),
        rp_id,
        rows,
        node_public_key: hex::encode(SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes()),
        release,
    };
    resign(&mut evidence);
    evidence
}

fn refused(evidence: &Evidence, reason: &'static str) {
    assert_eq!(verify(evidence, None, true).unwrap_err(), Refusal(reason));
}

fn mutate_body(evidence: &mut Evidence, index_from_end: usize, mutate: impl FnOnce(&mut Json)) {
    let index = evidence.rows.len() - index_from_end;
    let mut body: Json = serde_json::from_str(&evidence.rows[index].body).unwrap();
    mutate(&mut body);
    evidence.rows[index].body = text(&body);
    rechain(evidence);
    if index_from_end >= 2 {
        refresh_references(evidence);
    }
}

fn refresh_references(evidence: &mut Evidence) {
    let count = evidence.rows.len();
    let review = &evidence.rows[count - 3];
    let reference = json!({"seq":review.seq,"hash":review.hash});
    let mut consume: Json = serde_json::from_str(&evidence.rows[count - 2].body).unwrap();
    consume["review_issue"] = reference.clone();
    evidence.rows[count - 2].body = text(&consume);
    rechain(evidence);
    let consumed = &evidence.rows[count - 2];
    let mut terminal: Json = serde_json::from_str(&evidence.rows[count - 1].body).unwrap();
    terminal["receipt"]["owner_consumption"] = json!({
        "seq":consumed.seq,"hash":consumed.hash,"review_issue":reference
    });
    evidence.rows[count - 1].body = text(&terminal);
    rechain(evidence);
}

#[test]
fn genuine_assertion_and_signed_prefix_are_verified_without_supervisor_trust() {
    let evidence = fixture(1, 2, 1);
    let verified = verify(&evidence, None, true).unwrap();
    assert_eq!(verified.signer_epoch, 1);
    assert_eq!(verified.ledger_seq, 6);
    assert_eq!(verified.release, "01".repeat(32));
    verified.validate().unwrap();
    verify(&evidence, Some(&verified.owner), true).unwrap();
}

#[test]
fn antibody_floor_pre_a3_release_requires_fresh_approval() {
    let mut old = fixture(1, 0, 1);
    let mut auth = authorization(&old);
    for (key, value) in [
        ("owner_epoch", json!(1)),
        ("owner_root_id", json!("44".repeat(32))),
        ("binding_sha256", json!("44".repeat(32))),
        ("issued_at", json!(0)),
        ("issued_at_ms", json!(0)),
        (
            "gate",
            json!(hash(&hex::decode(&old.node_public_key).unwrap())),
        ),
        ("pubkey_fp", json!("55".repeat(8))),
    ] {
        auth[key] = value;
    }
    assert_eq!(auth.as_object().unwrap().len(), 21);
    set_authorization(&mut old, &auth);
    resign(&mut old);
    let refusal = verify(&old, None, true).unwrap_err();
    assert_eq!(refusal, Refusal("floor:pre-a3-release-reapprove"));
    assert_eq!(
        refusal.to_string(),
        "floor:pre-a3-release-reapprove: approve the release again"
    );
    let mut unknown = old.clone();
    let mut auth = authorization(&unknown);
    let gate = auth.as_object_mut().unwrap().remove("gate").unwrap();
    auth["unexpected"] = gate;
    set_authorization(&mut unknown, &auth);
    resign(&mut unknown);
    refused(&unknown, "floor:authorization-format");

    let mut fresh = fixture(1, 0, 1);
    let mut auth = authorization(&fresh);
    auth["proposal"] = json!("02".repeat(16));
    auth["challenge"] = json!("bb".repeat(32));
    set_authorization(&mut fresh, &auth);
    resign(&mut fresh);
    assert_ne!(old.auth_bytes, fresh.auth_bytes);
    assert_eq!(old.release, fresh.release);
    let approval = verify(&fresh, None, true).unwrap();
    let floor = crate::advance_floor(None, &approval).unwrap();
    crate::check_floor(Some(&floor), &approval).unwrap();

    auth["unexpected"] = json!(true);
    set_authorization(&mut fresh, &auth);
    resign(&mut fresh);
    refused(&fresh, "floor:authorization-format");
}

#[test]
fn antibody_floor_evidence_version_is_closed() {
    for version in [0, 3] {
        let mut evidence = node_principal_fixture();
        evidence.v = version;
        refused(&evidence, "floor:evidence-version");
    }
}

fn node_principal_fixture() -> Evidence {
    let mut evidence = fixture(1, 0, 1);
    evidence.v = 2;
    evidence.credential.owner_id = format!(
        "owner:{}",
        authorization(&evidence)["node"].as_str().unwrap()
    );
    resign(&mut evidence);
    evidence
}

#[test]
fn antibody_floor_evidence_versions_cannot_relabel_an_owner_principal() {
    let mut old = fixture(1, 0, 1);
    old.v = 2;
    refused(&old, "floor:owner-binding");
    let mut current = node_principal_fixture();
    current.v = 1;
    refused(&current, "floor:owner-binding");
}

#[test]
fn antibody_floor_node_principal_stays_bound_to_node_and_owner_origin() {
    let genuine = node_principal_fixture();
    verify(&genuine, None, true).unwrap();
    for field in ["owner", "rp", "origin"] {
        let mut changed = genuine.clone();
        match field {
            "owner" => changed.credential.owner_id = format!("owner:{}", "ff".repeat(16)),
            "rp" => {
                changed.rp_id =
                    format!("chat-{}", authorization(&changed)["node"].as_str().unwrap());
                changed.origin = format!("https://{}", changed.rp_id);
            }
            _ => changed.origin = format!("https://child.{}", changed.rp_id),
        }
        resign(&mut changed);
        refused(&changed, "floor:owner-binding");
    }
}

#[test]
fn antibody_floor_node_principal_cannot_replace_a_protected_credential_pin() {
    let original = fixture(1, 0, 1);
    let pinned = verify(&original, None, true).unwrap().owner;
    let current = node_principal_fixture();
    assert_eq!(
        verify(&current, Some(&pinned), true).unwrap_err(),
        Refusal("floor:credential-not-pinned")
    );
    let pinned = verify(&current, None, true).unwrap().owner;
    for field in ["key", "handle", "backup", "credential"] {
        let mut changed = current.clone();
        match field {
            "key" => {
                changed.credential.public_key = PublicKey::Ed25519(
                    SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes(),
                );
            }
            "handle" => changed.credential.user_handle = URL_SAFE_NO_PAD.encode([9; 16]),
            "backup" => changed.credential.backup_eligible = true,
            _ => changed.credential.credential_id = URL_SAFE_NO_PAD.encode([9; 16]),
        }
        resign(&mut changed);
        assert_eq!(
            verify(&changed, Some(&pinned), true).unwrap_err(),
            Refusal("floor:credential-not-pinned")
        );
    }
}

#[test]
fn exact_canonical_c5_schema_is_required() {
    for field in [
        "v",
        "node",
        "subject",
        "proposal",
        "operation",
        "base_sha256",
        "new_sha256",
        "display_sha256",
        "challenge",
        "epoch",
        "expires_at",
        "cell",
    ] {
        let mut evidence = fixture(1, 0, 1);
        let mut auth = authorization(&evidence);
        auth[field] = match field {
            "v" => json!(2),
            "epoch" => json!(0),
            "expires_at" => json!(9_007_199_254_740_992u64),
            "cell" => json!({}),
            _ => json!("invalid"),
        };
        if field == "expires_at" {
            evidence.auth_bytes = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&auth).unwrap());
        } else {
            set_authorization(&mut evidence, &auth);
        }
        if matches!(field, "v" | "epoch" | "cell") {
            resign(&mut evidence);
        }
        refused(&evidence, "floor:authorization-format");
    }
    for field in ["cell", "epoch", "operation"] {
        let mut evidence = fixture(1, 0, 1);
        let mut auth = authorization(&evidence);
        auth.as_object_mut().unwrap().remove(field);
        set_authorization(&mut evidence, &auth);
        refused(&evidence, "floor:authorization-format");
    }
    let mut evidence = fixture(1, 0, 1);
    let mut auth = authorization(&evidence);
    auth["owner_epoch"] = json!(1);
    set_authorization(&mut evidence, &auth);
    refused(&evidence, "floor:authorization-format");
    let mut evidence = fixture(1, 0, 1);
    let bytes = URL_SAFE_NO_PAD.decode(&evidence.auth_bytes).unwrap();
    evidence.auth_bytes = URL_SAFE_NO_PAD.encode([b" ".as_slice(), bytes.as_slice()].concat());
    resign(&mut evidence);
    refused(&evidence, "floor:authorization-format");
    evidence.auth_bytes = "not+base64".into();
    refused(&evidence, "floor:authorization-format");
}

#[test]
fn release_operation_and_target_are_required_even_with_a_valid_assertion() {
    for field in ["op", "target"] {
        let mut evidence = fixture(1, 0, 1);
        let mut auth = authorization(&evidence);
        auth[field] = json!("apply");
        set_authorization(&mut evidence, &auth);
        resign(&mut evidence);
        refused(&evidence, "floor:authorization-op");
    }
}

#[test]
fn release_record_bytes_and_component_bytes_are_bound() {
    let mut evidence = fixture(1, 0, 1);
    evidence.release.digest = "02".repeat(32);
    refused(&evidence, "floor:release-digest");
    let mut evidence = fixture(1, 0, 1);
    evidence.release.components = Some(Components {
        node: "03".repeat(32),
        harness: "04".repeat(32),
        guest: "05".repeat(32),
    });
    refused(&evidence, "floor:release-digest");
    let mut auth = authorization(&evidence);
    auth["new_sha256"] = json!(hash(&canonical(&evidence.release).unwrap()));
    let content = json!({"v":1,"node":auth["node"],"target":"release","base_sha256":"absent","new_sha256":auth["new_sha256"],"cell":null});
    auth["operation"] = json!(domain_hash(OPERATION_DOMAIN, &json_bytes(&content)));
    set_authorization(&mut evidence, &auth);
    resign(&mut evidence);
    verify(&evidence, None, true).unwrap();
    evidence.release.components.as_mut().unwrap().guest = "06".repeat(32);
    refused(&evidence, "floor:release-digest");
}

#[test]
fn malformed_release_record_is_refused() {
    for field in ["v", "digest", "node", "harness", "guest"] {
        let mut evidence = fixture(1, 0, 1);
        evidence.release.components = Some(Components {
            node: "03".repeat(32),
            harness: "04".repeat(32),
            guest: "05".repeat(32),
        });
        match field {
            "v" => evidence.release.v = 2,
            "digest" => evidence.release.digest = "bad".into(),
            "node" => evidence.release.components.as_mut().unwrap().node = "bad".into(),
            "harness" => evidence.release.components.as_mut().unwrap().harness = "bad".into(),
            _ => evidence.release.components.as_mut().unwrap().guest = "bad".into(),
        }
        let mut auth = authorization(&evidence);
        auth["new_sha256"] = json!(hash(&canonical(&evidence.release).unwrap()));
        let content = json!({"v":1,"node":auth["node"],"target":"release","base_sha256":"absent","new_sha256":auth["new_sha256"],"cell":null});
        auth["operation"] = json!(domain_hash(OPERATION_DOMAIN, &json_bytes(&content)));
        set_authorization(&mut evidence, &auth);
        resign(&mut evidence);
        refused(&evidence, "floor:release-format");
    }
}

#[test]
fn operation_digest_is_recomputed_over_exact_c5_content() {
    let mut evidence = fixture(1, 0, 1);
    let mut auth = authorization(&evidence);
    auth["operation"] = json!("ff".repeat(32));
    set_authorization(&mut evidence, &auth);
    resign(&mut evidence);
    refused(&evidence, "floor:operation-digest");
}

#[test]
fn owner_origin_subject_and_node_key_have_fixed_shapes() {
    for field in ["rp", "origin", "owner", "node-key"] {
        let mut evidence = fixture(1, 0, 1);
        match field {
            "rp" => {
                evidence.rp_id = "chat-node".into();
                evidence.origin = format!("https://{}", evidence.rp_id);
                resign(&mut evidence);
            }
            "origin" => {
                evidence.origin = format!("https://child.{}", evidence.rp_id);
                resign(&mut evidence);
            }
            "owner" => evidence.credential.owner_id = "other".into(),
            _ => evidence.node_public_key = "invalid".into(),
        }
        refused(&evidence, "floor:owner-binding");
    }
    let mut evidence = fixture(1, 0, 1);
    evidence.node_public_key = "00".repeat(32);
    refused(&evidence, "floor:node-key");
}

#[test]
fn owner_pin_cannot_be_changed_by_the_supervisor() {
    let evidence = fixture(1, 0, 1);
    let pinned = verify(&evidence, None, true).unwrap().owner;
    for field in ["credential", "key", "handle", "backup"] {
        let mut changed = evidence.clone();
        match field {
            "credential" => changed.credential.credential_id = URL_SAFE_NO_PAD.encode([9; 16]),
            "key" => {
                changed.credential.public_key =
                    PublicKey::Ed25519(SigningKey::from_bytes(&[20; 32]).verifying_key().to_bytes())
            }
            "handle" => changed.credential.user_handle = URL_SAFE_NO_PAD.encode([9; 16]),
            _ => changed.credential.backup_eligible = true,
        }
        resign(&mut changed);
        assert_eq!(
            verify(&changed, Some(&pinned), true).unwrap_err(),
            Refusal("floor:credential-not-pinned")
        );
    }
}

#[test]
fn evidence_allows_node_signer_rotation_with_the_same_owner_credential() {
    let evidence = fixture(1, 0, 1);
    let pinned = verify(&evidence, None, true).unwrap().owner;
    let mut changed = fixture(2, 0, 2);
    changed.node_public_key =
        hex::encode(SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes());
    resign(&mut changed);
    verify(&changed, Some(&pinned), true).unwrap();
}

#[test]
fn forged_assertion_and_wrong_challenge_are_refused() {
    let mut evidence = fixture(1, 0, 1);
    let mut signature = URL_SAFE_NO_PAD
        .decode(&evidence.assertion.signature)
        .unwrap();
    signature[0] ^= 1;
    evidence.assertion.signature = URL_SAFE_NO_PAD.encode(signature);
    rebuild_rows(&mut evidence);
    refused(&evidence, "floor:assertion-invalid");
    let mut evidence = fixture(1, 0, 1);
    let mut auth = authorization(&evidence);
    auth["challenge"] = json!("bb".repeat(32));
    set_authorization(&mut evidence, &auth);
    rebuild_rows(&mut evidence);
    refused(&evidence, "floor:assertion-invalid");
}

#[test]
fn protected_counter_is_used_for_advance_but_historical_check_still_verifies() {
    let mut evidence = fixture(1, 0, 1);
    signed_assertion(&mut evidence, 4);
    rebuild_rows(&mut evidence);
    let mut owner = verify(&evidence, None, true).unwrap().owner;
    owner.credential.sign_count = 4;
    evidence.credential.sign_count = 0;
    assert_eq!(
        verify(&evidence, Some(&owner), true).unwrap_err(),
        Refusal("floor:counter-replayed")
    );
    verify(&evidence, Some(&owner), false).unwrap();
    resign(&mut evidence);
    assert_eq!(
        verify(&evidence, Some(&owner), true).unwrap_err(),
        Refusal("floor:counter-replayed")
    );
}

#[test]
fn aura_chain_signatures_and_complete_prefix_are_required() {
    for field in ["hash", "sig", "prev", "body", "seq", "prefix"] {
        let mut evidence = fixture(1, 2, 1);
        match field {
            "hash" => evidence.rows[0].hash = "ff".repeat(32),
            "sig" => evidence.rows[0].sig = STANDARD.encode([0; 64]),
            "prev" => evidence.rows[1].prev = "ff".repeat(32),
            "body" => evidence.rows[0].body = "{\"changed\":true}".into(),
            "seq" => evidence.rows[1].seq = 9,
            _ => {
                evidence.rows.remove(0);
            }
        }
        refused(&evidence, "floor:aura-invalid");
    }
    let mut evidence = fixture(1, 0, 1);
    evidence.rows[0].body = format!(" {}", evidence.rows[0].body);
    refused(&evidence, "floor:aura-body");
}

#[test]
fn terminal_must_name_the_exact_release_proposal() {
    for field in ["kind", "phase", "op", "actor"] {
        let mut evidence = fixture(1, 0, 1);
        let row = evidence.rows.last_mut().unwrap();
        match field {
            "kind" => row.kind = "gate.recover".into(),
            "phase" => row.phase = "fact".into(),
            "op" => row.op = "ff".repeat(16),
            _ => row.actor = "someone".into(),
        }
        rechain(&mut evidence);
        refused(&evidence, "floor:aura-terminal");
    }
}

#[test]
fn propose_review_consume_order_and_phases_are_enforced() {
    for (offset, field, value) in [
        (4, "phase", "fact"),
        (4, "actor", "guest"),
        (3, "kind", "boot.facts"),
        (3, "phase", "settle"),
        (3, "op", "other"),
        (2, "phase", "fact"),
        (2, "actor", "other"),
    ] {
        let mut evidence = fixture(1, 0, 1);
        let index = evidence.rows.len() - offset;
        match field {
            "kind" => evidence.rows[index].kind = value.into(),
            "phase" => evidence.rows[index].phase = value.into(),
            "op" => evidence.rows[index].op = value.into(),
            _ => evidence.rows[index].actor = value.into(),
        }
        rechain(&mut evidence);
        refresh_references(&mut evidence);
        if offset >= 3 {
            let review_index = evidence.rows.len() - 3;
            let new_review = json!({"seq":evidence.rows[review_index].seq,"hash":evidence.rows[review_index].hash});
            mutate_body(&mut evidence, 2, |body| body["review_issue"] = new_review);
        }
        refused(
            &evidence,
            if offset == 4 {
                "floor:aura-binding"
            } else {
                "floor:aura-order"
            },
        );
    }
    let mut evidence = fixture(1, 0, 1);
    evidence.rows.swap(0, 1);
    rechain(&mut evidence);
    let review = json!({"seq":evidence.rows[0].seq,"hash":evidence.rows[0].hash});
    let mut consumed: Json = serde_json::from_str(&evidence.rows[2].body).unwrap();
    consumed["review_issue"] = review.clone();
    evidence.rows[2].body = text(&consumed);
    rechain(&mut evidence);
    let reference =
        json!({"seq":evidence.rows[2].seq,"hash":evidence.rows[2].hash,"review_issue":review});
    mutate_body(&mut evidence, 1, |body| {
        body["receipt"]["owner_consumption"] = reference
    });
    refused(&evidence, "floor:aura-order");
}

#[test]
fn aura_signed_rows_cannot_rebind_the_authorization() {
    for field in ["target", "base_sha256", "new_sha256", "digest"] {
        let mut evidence = fixture(1, 0, 1);
        mutate_body(&mut evidence, 4, |body| body[field] = json!("wrong"));
        refused(&evidence, "floor:aura-binding");
    }
    for (offset, field) in [
        (3, "authorization"),
        (2, "authorization"),
        (2, "authorization_sha256"),
        (2, "spent"),
        (3, "owner_state"),
        (2, "owner_state"),
    ] {
        let mut evidence = fixture(1, 0, 1);
        mutate_body(&mut evidence, offset, |body| body[field] = json!(false));
        if offset == 3 {
            let review = json!({"seq":evidence.rows[1].seq,"hash":evidence.rows[1].hash});
            mutate_body(&mut evidence, 2, |body| body["review_issue"] = review);
        }
        refused(&evidence, "floor:aura-binding");
    }
    let mut evidence = fixture(1, 0, 1);
    mutate_body(&mut evidence, 3, |body| {
        body["card"]["says"] = json!("Different approved card")
    });
    let review = json!({"seq":evidence.rows[1].seq,"hash":evidence.rows[1].hash});
    mutate_body(&mut evidence, 2, |body| body["review_issue"] = review);
    refused(&evidence, "floor:aura-card");
}

#[test]
fn retained_proof_must_be_the_independently_verified_assertion() {
    for field in ["proof_hex", "proof_sha256", "assertion"] {
        let mut evidence = fixture(1, 0, 1);
        mutate_body(&mut evidence, 2, |body| {
            if field == "assertion" {
                let mut assertion = serde_json::to_value(evidence_assertion_placeholder()).unwrap();
                assertion["credential_id"] = json!("another");
                let proof = json_bytes(&assertion);
                body["proof_hex"] = json!(hex::encode(&proof));
                body["proof_sha256"] = json!(hash(&proof));
            } else {
                body[field] = json!("wrong");
            }
        });
        if field == "assertion" {
            let index = evidence.rows.len() - 2;
            let consume: Json = serde_json::from_str(&evidence.rows[index].body).unwrap();
            mutate_body(&mut evidence, 1, |body| {
                body["receipt"]["owner_authorization"]["proof_sha256"] =
                    consume["proof_sha256"].clone();
            });
        }
        refused(&evidence, "floor:aura-proof");
    }
}

#[test]
fn retained_proof_budget_is_checked_before_json_parsing() {
    let mut evidence = fixture(1, 0, 1);
    let proof = [vec![b' '; 65_537], canonical(&evidence.assertion).unwrap()].concat();
    let proof_sha = hash(&proof);
    mutate_body(&mut evidence, 2, |body| {
        body["proof_hex"] = json!(hex::encode(&proof));
        body["proof_sha256"] = json!(proof_sha);
    });
    mutate_body(&mut evidence, 1, |body| {
        body["receipt"]["owner_authorization"]["proof_sha256"] = json!(proof_sha);
    });
    refused(&evidence, "floor:aura-proof");
}

#[test]
fn release_proposal_and_consumption_each_have_one_row() {
    let mut evidence = fixture(1, 0, 1);
    evidence.rows.insert(0, evidence.rows[0].clone());
    rechain(&mut evidence);
    refresh_references(&mut evidence);
    refused(&evidence, "floor:aura-binding");
    let mut evidence = fixture(1, 0, 1);
    evidence.rows.insert(2, evidence.rows[2].clone());
    rechain(&mut evidence);
    let review = json!({"seq":evidence.rows[1].seq,"hash":evidence.rows[1].hash});
    let consumed =
        json!({"seq":evidence.rows[2].seq,"hash":evidence.rows[2].hash,"review_issue":review});
    mutate_body(&mut evidence, 1, |body| {
        body["receipt"]["owner_consumption"] = consumed
    });
    refused(&evidence, "floor:aura-binding");
}

#[test]
fn antibody_legacy_immune_fact_does_not_shadow_release_proposal() {
    let mut evidence = fixture(1, 2, 1);
    let auth = authorization(&evidence);
    let proposal = auth["proposal"].as_str().unwrap();
    let index = evidence.rows.len() - 3;
    evidence.rows.insert(
        index,
        row(
            "gate.propose",
            "supervisor",
            proposal,
            "fact",
            json!({"runtime_digest":"01".repeat(32),"immune_release":{
                "new_sha256":auth["new_sha256"],"antibody_corpus_sha256":"ab".repeat(32),
                "antibody_pass_count":20,"antibody_total":20,"antibody_ids":["a"]
            }}),
        ),
    );
    rechain(&mut evidence);
    refresh_references(&mut evidence);
    verify(&evidence, None, true).unwrap();
}

#[test]
fn antibody_release_proposal_selection_ignores_other_actor_intents() {
    let mut evidence = fixture(1, 0, 1);
    let mut other = evidence.rows[0].clone();
    other.actor = "guest".into();
    evidence.rows.insert(1, other);
    rechain(&mut evidence);
    refresh_references(&mut evidence);
    verify(&evidence, None, true).unwrap();
}

fn evidence_assertion_placeholder() -> AssertionMaterial {
    fixture(1, 0, 1).assertion
}

#[test]
fn terminal_receipt_is_bound_to_proposal_auth_key_and_consumption() {
    for path in [
        vec!["v"],
        vec!["kind"],
        vec!["proposal"],
        vec!["node"],
        vec!["approver"],
        vec!["target"],
        vec!["base_sha256"],
        vec!["new_sha256"],
        vec!["gate_pubkey_sha256"],
        vec!["owner_authorization", "version"],
        vec!["owner_authorization", "kind"],
        vec!["owner_authorization", "authorization_id"],
        vec!["owner_authorization", "authorization_sha256"],
        vec!["owner_authorization", "proof_sha256"],
        vec!["owner_consumption", "seq"],
        vec!["owner_consumption", "hash"],
        vec!["owner_consumption", "review_issue", "seq"],
        vec!["owner_consumption", "review_issue", "hash"],
    ] {
        let mut evidence = fixture(1, 0, 1);
        mutate_body(&mut evidence, 1, |body| {
            let mut value = &mut body["receipt"];
            for field in &path {
                value = &mut value[*field];
            }
            *value = json!("wrong");
        });
        refused(&evidence, "floor:aura-receipt");
    }
}

#[test]
fn antibody_floor_configured_node_rp_and_origin_cannot_be_chosen_by_evidence() {
    let mut genuine = fixture(1, 0, 1);
    genuine.rp_id = "owner-s2-1-2-3-4.sslip.io".into();
    genuine.origin = format!("https://{}", genuine.rp_id);
    resign(&mut genuine);
    let configured = OwnerBinding {
        node_id: binding().node_id,
        rp_id: genuine.rp_id.clone(),
        origin: genuine.origin.clone(),
    };
    super::verify(&genuine, &configured, None, true).unwrap();
    for field in ["node", "rp", "origin"] {
        let mut evidence = genuine.clone();
        match field {
            "node" => {
                let mut auth = authorization(&evidence);
                auth["node"] = json!("ff".repeat(16));
                let content = json!({"v":1, "node":auth["node"], "target":auth["target"],
                    "base_sha256":auth["base_sha256"], "new_sha256":auth["new_sha256"], "cell":null});
                auth["operation"] = json!(domain_hash(OPERATION_DOMAIN, &json_bytes(&content)));
                set_authorization(&mut evidence, &auth);
            }
            "rp" => {
                evidence.rp_id = "owner-another-node.sslip.io".into();
            }
            _ => evidence.origin = "https://child.owner-s2-1-2-3-4.sslip.io".into(),
        }
        resign(&mut evidence);
        assert_eq!(
            super::verify(&evidence, &configured, None, true).unwrap_err(),
            Refusal("floor:owner-binding")
        );
    }
}
