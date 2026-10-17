// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner rule, end to end with real signatures: a ledger the way the gate writes it (the authority wrapper as the row
//! body) is VERIFIED only with the v2 export and every retained passkey assertion verifying under the pinned owner key.
//! Every key here is derived from a fixed test seed; nothing is random and nothing touches a node.

use crate::{
    consistency, format::digest, verify_bundle, verify_bundle_with_owner_pin, verify_chain, BundleInputs,
    ChainInputs, Scope, Verdict, VerificationReport,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::{Signature, SigningKey as OwnerKey};

const NODE_SEED: [u8; 32] = [0x25; 32];
const OPERATION: &str = "abababababababababababababababab";
const PROPOSAL: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const NODE_ID: &str = "01010101010101010101010101010101";
const NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DISPLAY: &str = "4444444444444444444444444444444444444444444444444444444444444444";
const TARGET: &str = "app/theme";
const RELYING_PARTY: &str = "owner.example";
const OWNER_ORIGIN: &str = "https://owner.example";
const TOP_ORIGIN: &str = "https://top.example";
const DOMAIN: &str = "aukora:aura-record:v1";

fn canonical(json: &str) -> Vec<u8> {
    canon::json::canonicalize(json.as_bytes()).expect("test JSON is valid")
}

fn owner_key(seed: u8) -> OwnerKey {
    OwnerKey::from_slice(&[seed; 32]).expect("test seed is a scalar")
}

fn sec1(key: &OwnerKey) -> Vec<u8> {
    key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

fn node_key() -> SigningKey {
    SigningKey::from_bytes(&NODE_SEED)
}

fn node_hex() -> String {
    hex::encode(node_key().verifying_key().to_bytes())
}

/// One node-signed row: `(canonical row JSON, hash)`.
fn row(number: u64, previous: &str, kind: &str, phase: &str, actor: &str, op: &str, body: &str) -> (String, String) {
    let at = 1_760_000_000_000_u64 + number;
    let hashed = canonical(&format!(
        r#"{{"prev":"{previous}","at":{at},"kind":"{kind}","actor":"{actor}","op":"{op}","phase":"{phase}","body":{body},"sequence":{number},"domain":"{DOMAIN}"}}"#
    ));
    let hash = digest(&hashed);
    let signature = STANDARD.encode(node_key().sign(&hash).to_bytes());
    let hash = hex::encode(hash);
    let json = canonical(&format!(
        r#"{{"seq":{number},"prev":"{previous}","hash":"{hash}","sig":"{signature}","at":{at},"kind":"{kind}","actor":"{actor}","op":"{op}","phase":"{phase}","body":{body}}}"#
    ));
    (String::from_utf8(json).expect("canonical JSON is UTF-8"), hash)
}

fn wrapper(number: u64, previous: &str, payload: &str) -> String {
    format!(
        r#"{{"schema":"aukora-aura-authority-body-v1","algorithm":"sha256","epoch":1,"sequence":{number},"previous_hash":"{previous}","payload":{payload}}}"#
    )
}

/// The owner authorization the passkey signs, as the JSON object `C5` defines (14 members, operation digest recomputed).
fn authorization() -> String {
    authorization_for("apply", TARGET)
}

fn authorization_for(op: &str, target: &str) -> String {
    let subject = format!("aukora:1:{}", "03".repeat(32));
    let content = canonical(&format!(
        r#"{{"v":1,"node":"{NODE_ID}","target":"{target}","base_sha256":"absent","new_sha256":"{NEW}","cell":null}}"#
    ));
    let operation = hex::encode(digest(&[b"aukora:operation-content:v1\0".as_slice(), &content].concat()));
    String::from_utf8(canonical(&format!(
        r#"{{"v":1,"node":"{NODE_ID}","subject":"{subject}","op":"{op}","proposal":"{PROPOSAL}","target":"{target}","base_sha256":"absent","new_sha256":"{NEW}","cell":null,"display_sha256":"{DISPLAY}","challenge":"{}","expires_at":1760000100000,"epoch":1,"operation":"{operation}"}}"#,
        "05".repeat(16)
    )))
    .expect("canonical JSON is UTF-8")
}

fn operation_digest() -> String {
    operation_of(&authorization())
}

fn operation_of(json: &str) -> String {
    let value = canon::json::parse_strict(json.as_bytes()).expect("valid");
    match value.get("operation").map(canon::json::Value::view) {
        Some(canon::json::ValueView::Text(text)) => text.to_owned(),
        _ => unreachable!("the authorization carries its operation digest"),
    }
}

/// The retained assertion entry for the consume row at `sequence`, signed by `signer`, bound to the key `bound`.
fn entry(sequence: u64, signer: &OwnerKey, bound: &OwnerKey) -> String {
    entry_for(sequence, &authorization(), signer, bound)
}

fn entry_for(sequence: u64, auth: &str, signer: &OwnerKey, bound: &OwnerKey) -> String {
    let credential = [7_u8; 32];
    let key = format!(
        r#"{{"v":1,"algorithm":"ecdsa-p256-sha256","bytes":"{}"}}"#,
        STANDARD.encode(sec1(bound))
    );
    let binding = format!(
        r#"{{"schema":"aukora-aura-owner-binding-storage-v1","v":1,"algorithm":"ecdsa-p256-sha256","credential":"{}","key":{key},"epoch":1,"relying_party":"{RELYING_PARTY}","owner_origin":"{OWNER_ORIGIN}","top_origin":"{TOP_ORIGIN}","counter":0}}"#,
        STANDARD.encode(credential)
    );
    let challenge = URL_SAFE_NO_PAD.encode(digest(
        &[b"aukora:owner-authorization:v1\0".as_slice(), auth.as_bytes()].concat(),
    ));
    let client = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{OWNER_ORIGIN}","topOrigin":"{TOP_ORIGIN}","crossOrigin":true}}"#
    );
    let mut authenticator = digest(RELYING_PARTY.as_bytes()).to_vec();
    authenticator.push(0x05);
    authenticator.extend_from_slice(&1_u32.to_be_bytes());
    let signed = [authenticator.as_slice(), &digest(client.as_bytes())].concat();
    let signature: Signature = signer.sign(&signed);
    let proof = format!(
        r#"{{"authorization":{auth},"credential":"{}","authenticator_data":"{}","client_data_json":"{}","signed_bytes":"{}","public_keys":[{key}],"signatures":{{"v":1,"components":[{{"v":1,"algorithm":"ecdsa-p256-sha256","bytes":"{}"}}]}}}}"#,
        URL_SAFE_NO_PAD.encode(credential),
        STANDARD.encode(&authenticator),
        STANDARD.encode(client.as_bytes()),
        STANDARD.encode(&signed),
        STANDARD.encode(signature.to_der().as_bytes())
    );
    String::from_utf8(canonical(&format!(
        r#"{{"sequence":{sequence},"binding":{binding},"proof":{proof}}}"#
    )))
    .expect("canonical JSON is UTF-8")
}

struct Ledger {
    /// The v1 cold export: the node's claimed key, head and rows.
    proof: String,
    /// The independently retained head covering the whole export.
    head: String,
    rows: Vec<String>,
}

/// One row to write: kind, phase, actor, operation id and the authority-wrapper payload (None: a plain fact body).
type Spec = (&'static str, &'static str, &'static str, String, Option<String>);

fn fact() -> Spec {
    ("boot.facts", "fact", "supervisor", String::new(), None)
}

fn propose() -> Spec {
    let operation = operation_digest();
    let payload = format!(
        r#"{{"proposal":"{PROPOSAL}","target":"{TARGET}","operation":"{operation}","new_sha256":"{NEW}","state":"proposed"}}"#
    );
    ("gate.propose", "intent", "owner", OPERATION.to_owned(), Some(payload))
}

/// The owner's approval of the change; `extra` is spliced into the payload (for example a `standing` member).
fn consume(new: &str, extra: &str) -> Spec {
    let approval = hex::encode(digest(authorization().as_bytes()));
    let operation = operation_digest();
    let payload = format!(
        r#"{{"proposal":"{PROPOSAL}","target":"{TARGET}","operation":"{operation}","base_sha256":"absent","new_sha256":"{new}","state":"consumed","consumed_approval":"{approval}"{extra}}}"#
    );
    ("gate.consume", "settle", "owner", OPERATION.to_owned(), Some(payload))
}

fn apply_with(op: &str, target: &str, new: &str) -> Spec {
    let operation = operation_digest();
    let payload = format!(
        r#"{{"proposal":"{PROPOSAL}","target":"{target}","operation":"{operation}","base_sha256":"absent","new_sha256":"{new}","state":"applied"}}"#
    );
    ("gate.apply", "terminal", "owner", op.to_owned(), Some(payload))
}

fn apply_to(op: &str, target: &str) -> Spec {
    apply_with(op, target, NEW)
}

fn apply() -> Spec {
    apply_to(OPERATION, TARGET)
}

/// boot fact, propose, consume (needs the owner assertion), apply: all but the first with the wrapper body. `consumed_new`
/// is the `new_sha256` the consume row records (and the apply that rests on it), so a different one is a row the assertion
/// no longer describes.
fn ledger(consumed_new: &str) -> Ledger {
    assemble(vec![fact(), propose(), consume(consumed_new, ""), apply_with(OPERATION, TARGET, consumed_new)])
}

fn assemble(specs: Vec<Spec>) -> Ledger {
    let mut rows = Vec::new();
    let mut hashes = Vec::new();
    let mut previous = DOMAIN.to_owned();
    for (index, (kind, phase, actor, op, payload)) in specs.iter().enumerate() {
        let number = index as u64 + 1;
        let body = match payload {
            // A body written as it is, to build a wrapper the node should never have signed.
            Some(payload) if payload.starts_with("raw:") => payload["raw:".len()..].to_owned(),
            Some(payload) => wrapper(number, &previous, payload),
            None => r#"{"index":0,"message":"honest"}"#.to_owned(),
        };
        let (json, hash) = row(number, &previous, kind, phase, actor, op.as_str(), &body);
        hashes.push(<[u8; 32]>::try_from(hex::decode(&hash).expect("hex")).expect("32 bytes"));
        rows.push(json);
        previous = hash;
    }
    let head = format!(
        r#"{{"schema":"aukora-aura-retained-head-v1","leafConvention":"rfc6962-leaf-sha256-0x00-prefixed-v1","sequence":{n},"hash":"{previous}","treeSize":{n},"root":"{}"}}"#,
        hex::encode(consistency::root(&hashes)),
        n = rows.len()
    );
    let head = String::from_utf8(canonical(&head)).expect("canonical JSON is UTF-8");
    let proof = String::from_utf8(canonical(&format!(
        r#"{{"schema":"aukora-aura-cold-proof-v1","publicKey":"{}","head":{head},"rows":[{}]}}"#,
        node_hex(),
        rows.join(",")
    )))
    .expect("canonical JSON is UTF-8");
    Ledger { proof, head, rows }
}

impl Ledger {
    /// The v2 export: the same proof with its retained assertions.
    fn v2(&self, entries: &[String]) -> Vec<u8> {
        canonical(&format!(
            r#"{{"schema":"aukora-aura-cold-proof-v2","body":{{"proof":{},"owner_assertions":[{}]}}}}"#,
            self.proof,
            entries.join(",")
        ))
    }
}

fn pin(key: &OwnerKey) -> Vec<u8> {
    hex::encode(sec1(key)).into_bytes()
}

fn run(export: &[u8], ledger: &Ledger, owner: Option<&[u8]>) -> VerificationReport {
    let node = node_hex();
    verify_bundle_with_owner_pin(
        BundleInputs {
            bundle: export,
            pinned_key: Some(node.as_bytes()),
            checkpoint: Some(ledger.head.as_bytes()),
        },
        owner,
    )
    .expect("the export is admitted")
}

fn codes(report: &VerificationReport) -> Vec<&'static str> {
    report.findings().iter().map(|finding| finding.code.reason).collect()
}

fn honest() -> (Ledger, String) {
    (ledger(NEW), entry(3, &owner_key(0x42), &owner_key(0x42)))
}

#[test]
fn every_assertion_verifying_under_the_pinned_owner_key_is_verified() {
    let (ledger, entry) = honest();
    let report = run(&ledger.v2(&[entry]), &ledger, Some(&pin(&owner_key(0x42))));
    assert_eq!(report.verdict(), Verdict::Verified, "{:?}", report.findings());
    assert!(report.findings().is_empty());
    assert_eq!(report.owner_signatures(), Scope::Checked);
    assert_eq!(report.integrity().owner_bindings, Scope::Checked);
}

#[test]
fn a_different_owner_key_is_a_key_mismatch() {
    let (ledger, entry) = honest();
    let report = run(&ledger.v2(&[entry]), &ledger, Some(&pin(&owner_key(0x43))));
    assert_eq!(report.verdict(), Verdict::KeyMismatch);
    assert_eq!(codes(&report), ["owner-key-mismatch"]);
    assert_eq!(report.owner_signatures(), Scope::Unchecked);
}

#[test]
fn a_missing_assertion_is_refused() {
    let (ledger, _) = honest();
    let report = run(&ledger.v2(&[]), &ledger, Some(&pin(&owner_key(0x42))));
    assert_eq!(report.verdict(), Verdict::InvalidInput);
    assert_eq!(codes(&report), ["owner-proof"]);
    assert_ne!(report.owner_signatures(), Scope::Checked);
}

#[test]
fn an_assertion_signed_by_another_key_is_forged() {
    let ledger = ledger(NEW);
    let forged = entry(3, &owner_key(0x43), &owner_key(0x42));
    let report = run(&ledger.v2(&[forged]), &ledger, Some(&pin(&owner_key(0x42))));
    assert_eq!(report.verdict(), Verdict::Forged);
    assert_eq!(codes(&report), ["owner-signature"]);
}

#[test]
fn a_row_the_node_re_signed_after_its_payload_changed_no_longer_matches_the_assertion() {
    // The chain is intact (the node signed the changed row), but the owner approved different bytes.
    let altered = "3".repeat(64);
    let ledger = ledger(&altered);
    let report = run(
        &ledger.v2(&[entry(3, &owner_key(0x42), &owner_key(0x42))]),
        &ledger,
        Some(&pin(&owner_key(0x42))),
    );
    assert_eq!(report.verdict(), Verdict::InvalidInput);
    assert_eq!(codes(&report), ["owner-assertion-link"]);
    assert_ne!(report.owner_signatures(), Scope::Checked);
}

#[test]
fn a_payload_edited_without_the_node_signing_it_is_rewritten() {
    let (mut ledger, entry) = honest();
    ledger.proof = ledger.proof.replacen(NEW, &"3".repeat(64), 1);
    let report = run(&ledger.v2(&[entry]), &ledger, Some(&pin(&owner_key(0x42))));
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_ne!(report.owner_signatures(), Scope::Checked);
}

#[test]
fn a_v1_export_cannot_be_verified_whatever_pin_is_supplied() {
    let (ledger, _) = honest();
    for owner in [None, Some(pin(&owner_key(0x42)))] {
        let report = run(ledger.proof.as_bytes(), &ledger, owner.as_deref());
        assert_eq!(report.verdict(), Verdict::Unchecked);
        assert_eq!(codes(&report), ["owner-signatures-unchecked"]);
        assert_eq!(report.findings()[0].sequence, None);
        assert_eq!(report.integrity().owner_bindings, Scope::Unchecked);
        assert_eq!(report.owner_signatures(), Scope::Unchecked);
    }
    let node = node_hex();
    let report = verify_bundle(BundleInputs {
        bundle: ledger.proof.as_bytes(),
        pinned_key: Some(node.as_bytes()),
        checkpoint: Some(ledger.head.as_bytes()),
    })
    .expect("admitted");
    assert_eq!(codes(&report), ["owner-signatures-unchecked"]);
}

#[test]
fn a_v2_export_without_a_pin_is_unchecked_not_verified() {
    let (ledger, entry) = honest();
    let report = run(&ledger.v2(&[entry]), &ledger, None);
    assert_eq!(report.verdict(), Verdict::Unchecked);
    assert_eq!(codes(&report), ["owner-signatures-unchecked"]);
    assert_eq!(report.owner_signatures(), Scope::Unchecked);
}

#[test]
fn rows_alone_never_verify_a_ledger_that_needs_the_owner() {
    let (ledger, _) = honest();
    let rows = format!("{}\n", ledger.rows.join("\n"));
    let node = node_hex();
    let report = verify_chain(ChainInputs {
        pinned_key: node.as_bytes(),
        rows: rows.as_bytes(),
        retained: None,
        presented: None,
        retained_rows: None,
        checkpoint: Some(ledger.head.as_bytes()),
    })
    .expect("admitted");
    assert_eq!(report.verdict(), Verdict::Unchecked);
    assert_eq!(codes(&report), ["owner-signatures-unchecked"]);
}

/// Rows the node signed and no owner approved: whatever else is supplied, none of these may be VERIFIED.
fn unapproved(specs: Vec<Spec>) -> VerificationReport {
    let ledger = assemble(specs);
    run(ledger.proof.as_bytes(), &ledger, Some(&pin(&owner_key(0x42))))
}

#[test]
fn an_apply_with_no_consume_is_rewritten_at_the_apply() {
    let report = unapproved(vec![fact(), propose(), apply()]);
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_eq!(codes(&report), ["gate-reference"]);
    assert_eq!(report.findings()[0].sequence, Some(3));
    assert_eq!(report.integrity().owner_bindings, Scope::Unchecked);
}

#[test]
fn a_consume_that_comes_after_the_apply_is_no_approval() {
    let report = unapproved(vec![fact(), propose(), apply(), consume(NEW, "")]);
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_eq!(report.findings()[0].sequence, Some(3));
}

#[test]
fn a_second_apply_for_one_consume_is_rewritten_at_the_first_apply() {
    let report = unapproved(vec![fact(), propose(), consume(NEW, ""), apply(), apply()]);
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_eq!(report.findings()[0].sequence, Some(4));
    assert_eq!(codes(&report)[0], "gate-reference");
}

#[test]
fn an_apply_of_something_else_than_was_approved_is_rewritten() {
    let report = unapproved(vec![fact(), propose(), consume(NEW, ""), apply_to(OPERATION, "app/other")]);
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_eq!(report.findings()[0].sequence, Some(4));
}

/// The apply of the approved change, with the `base_sha256` it carries replaced (`None` leaves it out).
fn apply_over(base: Option<&str>) -> Spec {
    let (kind, phase, actor, op, payload) = apply();
    let carried = base.map_or(String::new(), |base| format!(r#""base_sha256":"{base}","#));
    let payload = payload.expect("payload").replace(r#""base_sha256":"absent","#, &carried);
    (kind, phase, actor, op, Some(payload))
}

#[test]
fn an_apply_over_another_base_than_was_approved_is_rewritten() {
    let other = "99".repeat(32);
    for (what, base) in [("another base", Some(other.as_str())), ("no base", None)] {
        let report = unapproved(vec![fact(), propose(), consume(NEW, ""), apply_over(base)]);
        assert_eq!(report.verdict(), Verdict::Rewritten, "{what}");
        assert_eq!(codes(&report), ["gate-reference"], "{what}");
        assert_eq!(report.findings()[0].sequence, Some(4), "{what}");
    }
    let report = unapproved(vec![fact(), propose(), consume(NEW, ""), apply_over(Some("absent"))]);
    assert_ne!(report.verdict(), Verdict::Rewritten, "the approved base is no finding");
}

#[test]
fn a_consume_with_no_base_is_no_approval_of_an_apply() {
    let (kind, phase, actor, op, payload) = consume(NEW, "");
    let payload = payload.expect("payload").replace(r#""base_sha256":"absent","#, "");
    let report = unapproved(vec![fact(), propose(), (kind, phase, actor, op, Some(payload)), apply()]);
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_eq!(report.findings()[0].sequence, Some(4));
}

fn lines(rows: &[String]) -> Vec<u8> {
    rows.iter().flat_map(|row| row.bytes().chain(*b"\n")).collect()
}

fn chain_with_prefix(rows: &[String], prefix: &[String]) -> VerificationReport {
    let (node, rows, prefix) = (node_hex(), lines(rows), lines(prefix));
    verify_chain(ChainInputs {
        pinned_key: node.as_bytes(),
        rows: &rows,
        retained: None,
        presented: None,
        retained_rows: Some(&prefix),
        checkpoint: None,
    })
    .expect("the rows are admitted")
}

#[test]
fn a_retained_prefix_that_does_not_verify_is_forged_not_merely_unchecked() {
    let rows = ledger(NEW).rows;
    let mut forged = rows[..2].to_vec();
    let start = forged[0].find(r#""sig":""#).expect("a signature") + r#""sig":""#.len();
    forged[0].replace_range(start..start + 88, &format!("{}==", "A".repeat(86)));
    let report = chain_with_prefix(&rows, &forged);
    assert_eq!((report.verdict(), codes(&report)), (Verdict::Forged, vec!["signature"]));
    assert_eq!(report.findings()[0].sequence, Some(1));
    let honest = chain_with_prefix(&rows, &rows[..2]);
    assert!(
        !codes(&honest).iter().any(|code| ["signature", "invalid-retained-prefix", "retained-row-mismatch"].contains(code)),
        "an honest prefix is no finding about the prefix: {:?}",
        codes(&honest)
    );
}

#[test]
fn a_retained_prefix_names_a_changed_row_and_a_missing_tail_as_the_python_twin_does() {
    let rows = ledger(NEW).rows;
    let changed = chain_with_prefix(&ledger(&"33".repeat(32)).rows, &rows);
    assert_eq!((changed.verdict(), codes(&changed)), (Verdict::Rewritten, vec!["retained-row-mismatch"]));
    assert_eq!(changed.findings()[0].sequence, Some(3));
    let shorter = chain_with_prefix(&rows[..3], &rows);
    let missing = shorter.findings().iter().find(|finding| finding.code.reason == "shorter-than-checkpoint");
    assert_eq!((shorter.verdict(), missing.map(|finding| finding.sequence)), (Verdict::Rewritten, Some(Some(4))));
}

#[test]
fn an_earlier_head_without_a_presented_head_is_no_observation() {
    let ledger = ledger(NEW);
    let (node, rows) = (node_hex(), lines(&ledger.rows));
    let inputs = |retained, presented| ChainInputs {
        pinned_key: node.as_bytes(),
        rows: &rows,
        retained,
        presented,
        retained_rows: None,
        checkpoint: None,
    };
    for (retained, presented) in [(Some(ledger.head.as_bytes()), None), (None, Some(ledger.head.as_bytes()))] {
        let refusal = verify_chain(inputs(retained, presented)).expect_err("the pair is required");
        assert_eq!(refusal.reason, "observation-pair");
    }
}

#[test]
fn an_apply_with_no_operation_id_is_rewritten() {
    let report = unapproved(vec![fact(), propose(), apply_to("", TARGET)]);
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_eq!(codes(&report), ["gate-reference"]);
}

#[test]
fn an_absent_null_or_unlinked_standing_never_means_no_owner_is_needed() {
    // None of these consumes names a grant that exists in the ledger, so each needs the owner's assertion: without the
    // v2 export that carries it, the ledger is UNCHECKED and never VERIFIED.
    let fake = format!(
        r#","standing":{{"permission":"{OPERATION}","permission_proposal":"{PROPOSAL}","permission_digest":"{NEW}","proposal":"{PROPOSAL}","operation":"{}","use_number":1}}"#,
        operation_digest()
    );
    for extra in [
        "",
        r#","standing":null"#,
        r#","standing":{}"#,
        r#","standing":"granted""#,
        r#","standing_permission":{}"#,
        fake.as_str(),
    ] {
        let report = unapproved(vec![fact(), propose(), consume(NEW, extra), apply()]);
        assert_eq!(report.verdict(), Verdict::Unchecked, "{extra}: {:?}", codes(&report));
        assert_eq!(codes(&report), ["owner-signatures-unchecked"], "{extra}");
    }
}

#[test]
fn a_ledger_that_applies_nothing_needs_no_owner() {
    let report = unapproved(vec![fact()]);
    assert_eq!(report.verdict(), Verdict::Verified, "{:?}", report.findings());
    assert_eq!(report.owner_signatures(), Scope::Unchecked);
    // A proposal that never reached a terminal row is the existing terminal-count finding, not an approval.
    let report = unapproved(vec![fact(), propose()]);
    assert_eq!(report.verdict(), Verdict::Unchecked);
    assert_eq!(codes(&report), ["terminal-count"]);
}

#[test]
fn the_permission_grant_asserts_itself() {
    // A permission change is approved by its own assertion; without the v2 export it is UNCHECKED, not an unlinked apply.
    let report = unapproved(vec![fact(), propose(), apply_to(OPERATION, "gate/permission")]);
    assert_eq!(report.verdict(), Verdict::Unchecked);
    assert_eq!(codes(&report), ["owner-signatures-unchecked"]);
}

/// A row as a value, without hashes or signatures: enough for the checks that read rows against rows.
fn bare(number: u64, kind: &str, phase: &str, actor: &str, op: &str, epoch: u64, payload: &str) -> canon::json::Value {
    let prev = format!("{:0>64}", number - 1);
    let body = format!(
        r#"{{"schema":"aukora-aura-authority-body-v1","algorithm":"sha256","epoch":{epoch},"sequence":{number},"previous_hash":"{prev}","payload":{payload}}}"#
    );
    crate::format::canonical(&canonical(&format!(
        r#"{{"seq":{number},"prev":"{prev}","hash":"{prev}","sig":"","at":1,"kind":"{kind}","actor":"{actor}","op":"{op}","phase":"{phase}","body":{body}}}"#
    )))
    .unwrap_or_else(|code| panic!("a row: {code}"))
}

#[test]
fn only_a_standing_use_of_an_owner_signed_grant_in_the_ledger_needs_no_assertion() {
    let permission = "ee".repeat(16);
    let grant_digest = "55".repeat(32);
    let grant_payload = |actor: &str, state: &str| {
        (
            actor.to_owned(),
            format!(
                r#"{{"proposal":"{}","target":"gate/permission","state":"{state}","new_sha256":"{grant_digest}"}}"#,
                "99".repeat(16)
            ),
        )
    };
    let reference = |use_number: u32, digest_hex: &str| {
        format!(
            r#"{{"permission":"{permission}","permission_proposal":"{}","permission_digest":"{digest_hex}","proposal":"{PROPOSAL}","operation":"{}","use_number":{use_number}}}"#,
            "99".repeat(16),
            operation_digest()
        )
    };
    let rows = |actor: &str, state: &str, epoch: u64, standing: &str| {
        let (actor, grant) = grant_payload(actor, state);
        let approval = hex::encode(digest(&canonical(standing)));
        vec![
            bare(1, "boot.facts", "fact", "supervisor", "", 1, "{}"),
            bare(2, "gate.apply", "terminal", &actor, &permission, 1, &grant),
            bare(
                3,
                "gate.consume",
                "settle",
                "owner",
                OPERATION,
                epoch,
                &format!(
                    r#"{{"proposal":"{PROPOSAL}","operation":"{}","state":"consumed","consumed_approval":"{approval}","standing":{standing}}}"#,
                    operation_digest()
                ),
            ),
        ]
    };
    let needs = |rows: &[canon::json::Value]| rows.last().is_none_or(|consume| super::link::needs(rows, consume).unwrap_or(true));
    let honest = reference(1, &grant_digest);
    assert!(!needs(&rows("owner", "applied", 1, &honest)), "a linked standing use needs no assertion of its own");
    for (what, rows) in [
        ("a grant that is not the one named", rows("owner", "applied", 1, &reference(1, &"66".repeat(32)))),
        ("use number zero", rows("owner", "applied", 1, &reference(0, &grant_digest))),
        ("a grant a node wrote (not the owner)", rows("supervisor", "applied", 1, &honest)),
        ("a grant that was not applied", rows("owner", "refused", 1, &honest)),
        ("a grant of another owner epoch", rows("owner", "applied", 2, &honest)),
    ] {
        assert!(needs(&rows), "{what} must need the owner's assertion");
    }
    let mut without = rows("owner", "applied", 1, &honest);
    without.remove(1);
    assert!(needs(&without), "a standing use with no grant row in the ledger needs the owner");
}

#[test]
fn a_spend_grant_a_revocation_and_a_memory_permission_are_never_bound() {
    // Built from an owner's passkey proof, but neither the node's export nor this verifier can link them to an assertion
    // yet, so the node alone says the owner approved them: owner-provenance at the row, never VERIFIED.
    for kind in ["broker.grant", "broker.revoke", "kira.permission"] {
        let payload = format!(r#"{{"proposal":"{PROPOSAL}","state":"applied"}}"#);
        let report = unapproved(vec![fact(), (kind, "terminal", "owner", OPERATION.to_owned(), Some(payload))]);
        assert_eq!(report.verdict(), Verdict::Unchecked, "{kind}");
        assert_eq!(codes(&report), ["owner-provenance"], "{kind}");
        assert_eq!(report.findings()[0].sequence, Some(2), "{kind}");
        assert_eq!(report.integrity().owner_bindings, Scope::Unchecked, "{kind}");
    }
}

/// A permission grant: approved by the assertion on its own row, so no consume.
fn permission_rows(op: &str) -> [Spec; 2] {
    let auth = authorization_for("permission", "gate/permission");
    let operation = operation_of(&auth);
    let approval = hex::encode(digest(auth.as_bytes()));
    let payload = |state: &str, extra: &str| {
        format!(
            r#"{{"proposal":"{PROPOSAL}","target":"gate/permission","operation":"{operation}","base_sha256":"absent","new_sha256":"{NEW}","state":"{state}"{extra}}}"#
        )
    };
    [
        ("gate.propose", "intent", "owner", op.to_owned(), Some(payload("proposed", ""))),
        (
            "gate.apply",
            "terminal",
            "owner",
            op.to_owned(),
            Some(payload("applied", &format!(r#","consumed_approval":"{approval}""#))),
        ),
    ]
}

fn permission_entry(sequence: u64) -> String {
    entry_for(sequence, &authorization_for("permission", "gate/permission"), &owner_key(0x42), &owner_key(0x42))
}

fn verify_v2(ledger: &Ledger, entries: &[String]) -> VerificationReport {
    run(&ledger.v2(entries), ledger, Some(&pin(&owner_key(0x42))))
}

#[test]
fn a_null_standing_with_the_owners_assertion_is_an_ordinary_approval() {
    // The real gate writes no `standing` on a passkey consume (outcome_body has none); a null one is as good as absent: the
    // consume needs the assertion, and with it the ledger verifies.
    for extra in ["", r#","standing":null"#] {
        let ledger = assemble(vec![fact(), propose(), consume(NEW, extra), apply()]);
        let report = verify_v2(&ledger, &[entry(3, &owner_key(0x42), &owner_key(0x42))]);
        assert_eq!(report.verdict(), Verdict::Verified, "{extra:?}: {:?}", codes(&report));
        assert_eq!(report.owner_signatures(), Scope::Checked);
    }
}

#[test]
fn a_present_malformed_standing_is_a_finding_even_with_an_assertion() {
    for extra in [r#","standing":{}"#, r#","standing":"granted""#, r#","standing_permission":{}"#] {
        let ledger = assemble(vec![fact(), propose(), consume(NEW, extra), apply()]);
        let report = verify_v2(&ledger, &[entry(3, &owner_key(0x42), &owner_key(0x42))]);
        assert_eq!(report.verdict(), Verdict::InvalidInput, "{extra}");
        assert_eq!(report.owner_signatures(), Scope::Unchecked, "{extra}");
    }
}

#[test]
fn a_permission_grant_verifies_on_its_own_assertion() {
    let [propose, apply] = permission_rows(OPERATION);
    let ledger = assemble(vec![fact(), propose, apply]);
    let report = verify_v2(&ledger, &[permission_entry(3)]);
    assert_eq!(report.verdict(), Verdict::Verified, "{:?}", codes(&report));
}

#[test]
fn one_assertion_cannot_approve_two_permission_grants() {
    let other = "bc".repeat(16);
    let [first_propose, first_apply] = permission_rows(OPERATION);
    let [second_propose, second_apply] = permission_rows(&other);
    let ledger = assemble(vec![fact(), first_propose, first_apply, second_propose, second_apply]);
    // The same authorization offered for both rows: the second is a reuse.
    let report = verify_v2(&ledger, &[permission_entry(3), permission_entry(5)]);
    assert_eq!(report.verdict(), Verdict::InvalidInput);
    assert_eq!(codes(&report), ["owner-proof"]);
    // And an assertion at the wrong row is refused, not matched by operation.
    let report = verify_v2(&ledger, &[permission_entry(5)]);
    assert_ne!(report.verdict(), Verdict::Verified);
}

#[test]
fn two_permission_applies_for_one_operation_are_rewritten_at_the_first() {
    let [propose, apply] = permission_rows(OPERATION);
    let [_, again] = permission_rows(OPERATION);
    let report = unapproved(vec![fact(), propose, apply, again]);
    assert_eq!(report.verdict(), Verdict::Rewritten);
    assert_eq!(report.findings()[0].sequence, Some(3));
    assert_eq!(codes(&report)[0], "gate-reference");
}

#[test]
fn a_wrapper_the_node_signed_malformed_is_rewritten_at_its_row() {
    // A consume that declares the authority wrapper but has no epoch (and no sequence or links): REWRITTEN gate-evidence.
    let bad = r#"raw:{"schema":"aukora-aura-authority-body-v1","algorithm":"sha256","payload":{}}"#.to_owned();
    for kind in [("gate.consume", "settle"), ("gate.apply", "terminal")] {
        let rows = vec![fact(), propose(), (kind.0, kind.1, "owner", OPERATION.to_owned(), Some(bad.clone()))];
        let report = unapproved(rows);
        assert_eq!(report.verdict(), Verdict::Rewritten, "{kind:?}");
        assert_eq!(codes(&report), ["gate-evidence"], "{kind:?}");
        assert_eq!(report.findings()[0].sequence, Some(3), "{kind:?}");
    }
}
