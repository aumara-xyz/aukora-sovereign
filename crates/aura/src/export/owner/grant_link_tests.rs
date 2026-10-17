// SPDX-License-Identifier: AGPL-3.0-or-later
//! Does the node's own export check accept an owner assertion retained on a grant row?
//!
//! `Ledger::export_cold_proof_v2` retains every committed C5 assertion (`authority_consumptions` with a credential) and
//! ends with `ColdProofV2::canonical_bytes`, which verifies each one against its row. `consume` stores the assertion of
//! a broker grant like any other, so the question is what `ColdProofV2::verify` says about an assertion on a
//! `broker.grant` row. This builds two ledgers that differ only in the row that carries the assertion (an owner-approved
//! change's consume, and a spend grant) with every key, signature and hash valid, and asks that.

use super::*;
use canon::{
    alg::{AlgorithmId, PublicKey},
    ids::CredentialId,
};
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::{Signature as Es256, SigningKey as OwnerKey};

const OPERATION: &str = "abababababababababababababababab";
const PROPOSAL: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const RELYING_PARTY: &str = "owner.example";
const ORIGIN: &str = "https://owner.example";
const TOP: &str = "https://top.example";

fn value(json_text: &str) -> Value {
    json::parse_strict(json_text.as_bytes()).expect("test JSON")
}

fn canonical(json_text: &str) -> String {
    String::from_utf8(json::canonicalize(json_text.as_bytes()).expect("test JSON")).expect("UTF-8")
}

fn node() -> SigningKey {
    SigningKey::from_bytes(&[0x25; 32])
}

fn owner() -> OwnerKey {
    OwnerKey::from_slice(&[0x42; 32]).expect("scalar")
}

fn sec1(key: &OwnerKey) -> Vec<u8> {
    key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

/// A node-signed row whose body is the authority wrapper around `payload`.
fn row(number: u64, previous: Option<Digest32>, kind: &str, phase: &str, op: &str, payload: &str) -> RowV1 {
    let before = previous.map_or_else(|| canon::domain::AURA_RECORD_DOMAIN.to_owned(), |hash| hash.to_string());
    let body = format!(
        r#"{{"schema":"aukora-aura-authority-body-v1","algorithm":"sha256","epoch":1,"sequence":{number},"previous_hash":"{before}","payload":{payload}}}"#
    );
    let wire = format!(
        r#"{{"seq":{number},"prev":"{before}","hash":"{}","sig":"{}","at":{},"kind":"{kind}","actor":"owner","op":"{op}","phase":"{phase}","body":{body}}}"#,
        "00".repeat(32),
        STANDARD.encode([0_u8; 64]),
        1_760_000_000_000_u64 + number
    );
    let mut row = crate::export::parse_row(&value(&wire)).expect("a row");
    row.hash = crate::record::entry_hash_v1(&row).expect("hash");
    row.signature = node().sign(row.hash.as_bytes()).to_bytes();
    row
}

/// The C5 authorization the passkey signs (14 members, operation digest recomputed), for `operation` on `target`.
fn authorization(operation: &str, target: &str) -> String {
    let node_id = "01".repeat(16);
    let content = canonical(&format!(
        r#"{{"v":1,"node":"{node_id}","target":"{target}","base_sha256":"absent","new_sha256":"{NEW}","cell":null}}"#
    ));
    let digest = Digest32::sha256(&[b"aukora:operation-content:v1\0".as_slice(), content.as_bytes()].concat());
    canonical(&format!(
        r#"{{"v":1,"node":"{node_id}","subject":"aukora:1:{}","op":"{operation}","proposal":"{PROPOSAL}","target":"{target}","base_sha256":"absent","new_sha256":"{NEW}","cell":null,"display_sha256":"{}","challenge":"{}","expires_at":1760000100000,"epoch":1,"operation":"{digest}"}}"#,
        "03".repeat(32),
        "44".repeat(32),
        "05".repeat(16)
    ))
}

fn evidence(sequence: u64, auth: &str) -> OwnerAssertionEvidenceV2 {
    let key = owner();
    let credential = vec![7_u8; 32];
    let tagged = format!(
        r#"{{"v":1,"algorithm":"ecdsa-p256-sha256","bytes":"{}"}}"#,
        STANDARD.encode(sec1(&key))
    );
    let challenge = URL_SAFE_NO_PAD.encode(
        Digest32::sha256(&[b"aukora:owner-authorization:v1\0".as_slice(), auth.as_bytes()].concat()).as_bytes(),
    );
    let client = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}","topOrigin":"{TOP}","crossOrigin":true}}"#
    );
    let mut authenticator = Digest32::sha256(RELYING_PARTY.as_bytes()).as_bytes().to_vec();
    authenticator.push(0x05);
    authenticator.extend_from_slice(&1_u32.to_be_bytes());
    let signed = [authenticator.as_slice(), Digest32::sha256(client.as_bytes()).as_bytes()].concat();
    let signature: Es256 = p256::ecdsa::signature::Signer::sign(&key, &signed);
    let proof = format!(
        r#"{{"authorization":{auth},"credential":"{}","authenticator_data":"{}","client_data_json":"{}","signed_bytes":"{}","public_keys":[{tagged}],"signatures":{{"v":1,"components":[{{"v":1,"algorithm":"ecdsa-p256-sha256","bytes":"{}"}}]}}}}"#,
        URL_SAFE_NO_PAD.encode(&credential),
        STANDARD.encode(&authenticator),
        STANDARD.encode(client.as_bytes()),
        STANDARD.encode(&signed),
        STANDARD.encode(signature.to_der().as_bytes())
    );
    OwnerAssertionEvidenceV2 {
        sequence,
        binding: OwnerBinding {
            v: 1,
            algorithm: AlgorithmId::EcdsaP256Sha256,
            credential_id: CredentialId::new(credential).expect("credential"),
            public_key: PublicKey {
                v: 1,
                algorithm: AlgorithmId::EcdsaP256Sha256,
                bytes: sec1(&key),
            },
            epoch: 1,
            relying_party: RELYING_PARTY.into(),
            owner_origin: ORIGIN.into(),
            top_origin: TOP.into(),
            sign_counter: 0,
        },
        proof: value(&canonical(&proof)),
    }
}

fn export(rows: Vec<RowV1>, sequence: u64, auth: &str) -> ColdProofV2 {
    let mut tree = crate::merkle::Frontier::default();
    for row in &rows {
        tree.push(row.hash).expect("push");
    }
    let last = rows.last().expect("rows").hash;
    ColdProofV2 {
        proof: ColdProofV1 {
            head: RetainedHeadV1 {
                sequence: rows.len() as u64,
                hash: last,
                tree_size: rows.len() as u64,
                root: tree.root(),
            },
            public_key: node().verifying_key().to_bytes(),
            rows,
        },
        owner_assertions: vec![evidence(sequence, auth)],
    }
}

const LIMITS: ExportLimits = ExportLimits {
    max_bytes: 1 << 20,
    max_rows: 64,
};

/// boot, propose, then the row carrying the assertion: `(kind, phase, payload)` is a consume or a grant.
fn ledger(kind: &str, phase: &str, payload: &str, auth: &str) -> ColdProofV2 {
    let boot = row(1, None, "boot.facts", "fact", "", "{}");
    let propose = row(
        2,
        Some(boot.hash),
        "gate.propose",
        "intent",
        OPERATION,
        &format!(
            r#"{{"proposal":"{PROPOSAL}","target":"{}","operation":"{}","new_sha256":"{NEW}","state":"proposed"}}"#,
            member(&value(auth), "target").and_then(string).expect("target"),
            member(&value(auth), "operation").and_then(string).expect("operation")
        ),
    );
    let carrier = row(3, Some(propose.hash), kind, phase, OPERATION, payload);
    export(vec![boot, propose, carrier], 3, auth)
}

#[test]
fn an_assertion_on_a_consume_row_passes_the_export_check_and_one_on_a_grant_or_permission_row_does_not() {
    // Control: the owner's approval of a change, retained on its gate.consume row.
    let auth = authorization("apply", "app/theme");
    let approval = Digest32::sha256(auth.as_bytes());
    let operation = string(member(&value(&auth), "operation").expect("operation")).expect("text").to_owned();
    let consume = ledger(
        "gate.consume",
        "settle",
        &format!(
            r#"{{"proposal":"{PROPOSAL}","target":"app/theme","operation":"{operation}","base_sha256":"absent","new_sha256":"{NEW}","state":"consumed","consumed_approval":"{approval}"}}"#
        ),
        &auth,
    );
    consume.verify().expect("the control is a valid v2 export");
    consume.canonical_bytes(LIMITS).expect("and it serialises");

    // The same keys, hashes, signatures and chain, with the assertion on a row built from an owner proof of another kind.
    for (kind, operation, target) in [
        ("broker.grant", "grant", "model/grant"),
        ("broker.revoke", "grant", "model/grant"),
        ("kira.permission", "permission", "kira/permission"),
    ] {
        let auth = authorization(operation, target);
        let digest = string(member(&value(&auth), "operation").expect("operation")).expect("text").to_owned();
        let carrier = ledger(
            kind,
            "terminal",
            &format!(
                r#"{{"proposal":"{PROPOSAL}","target":"{target}","operation":"{digest}","base_sha256":"absent","new_sha256":"{NEW}","state":"applied"}}"#
            ),
            &auth,
        );
        assert!(
            carrier.verify().is_err() && carrier.canonical_bytes(LIMITS).is_err(),
            "ColdProofV2::verify accepted an owner assertion on a {kind} row, which export_cold_proof_v2 would then emit"
        );
    }
}
