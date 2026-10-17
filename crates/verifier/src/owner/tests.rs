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
    let subject = format!("aukora:1:{}", "03".repeat(32));
    let content = canonical(&format!(
        r#"{{"v":1,"node":"{NODE_ID}","target":"{TARGET}","base_sha256":"absent","new_sha256":"{NEW}","cell":null}}"#
    ));
    let operation = hex::encode(digest(&[b"aukora:operation-content:v1\0".as_slice(), &content].concat()));
    String::from_utf8(canonical(&format!(
        r#"{{"v":1,"node":"{NODE_ID}","subject":"{subject}","op":"apply","proposal":"{PROPOSAL}","target":"{TARGET}","base_sha256":"absent","new_sha256":"{NEW}","cell":null,"display_sha256":"{DISPLAY}","challenge":"{}","expires_at":1760000100000,"epoch":1,"operation":"{operation}"}}"#,
        "05".repeat(16)
    )))
    .expect("canonical JSON is UTF-8")
}

fn operation_digest() -> String {
    let json = authorization();
    let value = canon::json::parse_strict(json.as_bytes()).expect("valid");
    match value.get("operation").map(canon::json::Value::view) {
        Some(canon::json::ValueView::Text(text)) => text.to_owned(),
        _ => unreachable!("the authorization carries its operation digest"),
    }
}

/// The retained assertion entry for the consume row at `sequence`, signed by `signer`, bound to the key `bound`.
fn entry(sequence: u64, signer: &OwnerKey, bound: &OwnerKey) -> String {
    let auth = authorization();
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

/// boot fact, propose, consume (needs the owner assertion), apply: all but the first with the wrapper body. `consumed_new`
/// is the `new_sha256` the consume row records, so a different one is a row the assertion no longer describes.
fn ledger(consumed_new: &str) -> Ledger {
    let approval = hex::encode(digest(authorization().as_bytes()));
    let operation = operation_digest();
    let mut rows = Vec::new();
    let mut hashes = Vec::new();
    let mut previous = DOMAIN.to_owned();
    let specs: [(&str, &str, &str, &str, Option<String>); 4] = [
        ("boot.facts", "fact", "supervisor", "", None),
        (
            "gate.propose",
            "intent",
            "owner",
            OPERATION,
            Some(format!(
                r#"{{"proposal":"{PROPOSAL}","target":"{TARGET}","operation":"{operation}","new_sha256":"{NEW}","state":"proposed"}}"#
            )),
        ),
        (
            "gate.consume",
            "settle",
            "owner",
            OPERATION,
            Some(format!(
                r#"{{"proposal":"{PROPOSAL}","target":"{TARGET}","operation":"{operation}","base_sha256":"absent","new_sha256":"{consumed_new}","state":"consumed","consumed_approval":"{approval}"}}"#
            )),
        ),
        (
            "gate.apply",
            "terminal",
            "owner",
            OPERATION,
            Some(format!(
                r#"{{"proposal":"{PROPOSAL}","target":"{TARGET}","operation":"{operation}","new_sha256":"{NEW}","state":"applied"}}"#
            )),
        ),
    ];
    for (index, (kind, phase, actor, op, payload)) in specs.iter().enumerate() {
        let number = index as u64 + 1;
        let body = match payload {
            Some(payload) => wrapper(number, &previous, payload),
            None => r#"{"index":0,"message":"honest"}"#.to_owned(),
        };
        let (json, hash) = row(number, &previous, kind, phase, actor, op, &body);
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
