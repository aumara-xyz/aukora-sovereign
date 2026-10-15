// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use p256::ecdsa::{signature::Signer, SigningKey};
use serde_json::{json, Value};

fn genuine() -> Value {
    serde_json::from_slice(include_bytes!("../tests/vectors/receipts/genuine.json")).unwrap()
}

fn bytes(r: &Value) -> Vec<u8> {
    serde_json::to_vec(r).unwrap()
}

fn refused(r: &Value, code: &str) {
    assert_eq!(verify_receipt(&bytes(r)).unwrap_err().code(), code);
}

fn changed(field: &str, value: Value, code: &str) {
    let mut r = genuine();
    r[field] = value;
    refused(&r, code);
}

fn signed_intent(text: &str, side: &str, same_key: bool) -> Value {
    let key_a = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key_b = SigningKey::from_bytes((&[if same_key { 1 } else { 2 }; 32]).into()).unwrap();
    let pk_a = hex::encode(key_a.verifying_key().to_sec1_point(false).as_bytes());
    let pk_b = hex::encode(key_b.verifying_key().to_sec1_point(false).as_bytes());
    let digest = domain("copresence.intent.v1", &[text.as_bytes()]);
    let salt = [0x5a; 16];
    let nonce = domain("copresence.intent-nonce.v1", &[&digest, &salt]);
    let (nonce_a, nonce_b) = if side == "A" {
        (&nonce[..8], &[7; 8][..])
    } else {
        (&[7; 8][..], &nonce[..8])
    };
    let core = domain(
        "copresence.v0",
        &[
            &hex::decode(&pk_a).unwrap(),
            &hex::decode(&pk_b).unwrap(),
            nonce_a,
            nonce_b,
            &1_700_000_000_u64.to_be_bytes(),
        ],
    );
    let sig_a: Signature = key_a.sign(&core);
    let sig_b: Signature = key_b.sign(&core);
    let (asker, approver_nonce, approver) = if side == "A" {
        (&pk_a, nonce_b, &key_b)
    } else {
        (&pk_b, nonce_a, &key_a)
    };
    let ack_message = domain(
        "copresence.intent-ack.v1",
        &[&digest, &hex::decode(asker).unwrap(), approver_nonce],
    );
    let ack: Signature = approver.sign(&ack_message);
    json!({"v":0,"pk_A":pk_a,"pk_B":pk_b,"nonce_A":hex::encode(nonce_a),"nonce_B":hex::encode(nonce_b),
        "t_A":1_700_000_000,"t_B":1_700_000_000,"sig_A":hex::encode(sig_a.to_bytes()),"sig_B":hex::encode(sig_b.to_bytes()),
        "intent":{"text":text,"digest":hex::encode(digest),"salt":hex::encode(salt),"side":side,"ack":{"sig":hex::encode(ack.to_bytes())}}})
}

fn intent_refused(r: &Value, text: &str, options: IntentOptions<'_>, code: &str) {
    assert_eq!(
        verify_intent(&bytes(r), text, options).unwrap_err().code(),
        code
    );
}

#[test]
fn antibody_copresence_structure_version_and_required_fields() {
    assert_eq!(
        verify_receipt(b"{").unwrap_err().code(),
        "copresence:json_parse_error"
    );
    changed("v", json!(1), "copresence:unsupported_version");
    for name in [
        "pk_A", "pk_B", "nonce_A", "nonce_B", "t_A", "t_B", "sig_A", "sig_B",
    ] {
        changed(name, Value::Null, "copresence:missing_field");
        let mut r = genuine();
        r.as_object_mut().unwrap().remove(name);
        refused(&r, "copresence:missing_field");
    }
}

#[test]
fn antibody_copresence_timestamp_type_window_and_encoding() {
    changed(
        "t_A",
        json!("1791537966"),
        "copresence:timestamps_must_be_numbers",
    );
    changed(
        "t_B",
        json!("1791537970"),
        "copresence:timestamps_must_be_numbers",
    );
    changed("t_A", json!(1791537971), "copresence:negative_time_skew");
    changed(
        "t_A",
        json!(1791537959),
        "copresence:ceremony_window_exceeded",
    );
    for time in [
        json!(0),
        json!(4),
        json!(4.5),
        json!(-1),
        json!(18446744073709551616.0),
    ] {
        let mut r = genuine();
        r["t_A"] = time.clone();
        r["t_B"] = time;
        let expected = if [0.0, 4.0].contains(&r["t_B"].as_f64().unwrap()) {
            "copresence:sig_A_invalid"
        } else {
            "copresence:timestamp_encoding_error"
        };
        refused(&r, expected);
    }
    for time in [1791537970.0, 1791537960.0, 1791537960.5] {
        let mut r = genuine();
        r["t_A"] = json!(time);
        assert!(verify_receipt(&bytes(&r)).is_ok());
    }
}

#[test]
fn antibody_copresence_public_key_format_and_curve_both_sides() {
    for (field, malformed, invalid) in [
        (
            "pk_A",
            "copresence:malformed_public_key_A",
            "copresence:invalid_public_key_A",
        ),
        (
            "pk_B",
            "copresence:malformed_public_key_B",
            "copresence:invalid_public_key_B",
        ),
    ] {
        for value in [
            json!(""),
            json!("04zz"),
            json!(true),
            json!(format!("03{}", "11".repeat(64))),
            json!(format!("04{}", "zz".repeat(64))),
            json!(format!("{}00", genuine()[field].as_str().unwrap())),
            json!(&genuine()[field].as_str().unwrap()[..128]),
        ] {
            changed(field, value, malformed);
        }
        changed(field, json!(format!("04{}", "00".repeat(64))), invalid);
    }
}

#[test]
fn antibody_copresence_nonce_and_signature_encodings() {
    for (field, code) in [
        ("nonce_A", "copresence:malformed_nonce_A"),
        ("nonce_B", "copresence:malformed_nonce_B"),
        ("sig_A", "copresence:malformed_signature_A"),
        ("sig_B", "copresence:malformed_signature_B"),
    ] {
        for bad in [
            json!(false),
            json!(""),
            json!("zz".repeat(genuine()[field].as_str().unwrap().len() / 2)),
        ] {
            changed(field, bad, code);
        }
    }
}

#[test]
fn antibody_copresence_both_signatures_authenticate_the_core() {
    changed("sig_A", json!("00".repeat(64)), "copresence:sig_A_invalid");
    changed("sig_B", json!("00".repeat(64)), "copresence:sig_B_invalid");
    for field in ["nonce_A", "nonce_B"] {
        changed(field, json!("00".repeat(8)), "copresence:sig_A_invalid");
    }
    let mut r = genuine();
    r["t_A"] = json!(1791537971);
    r["t_B"] = json!(1791537971);
    refused(&r, "copresence:sig_A_invalid");
}

#[test]
fn antibody_copresence_geo_types_accuracy_and_contradiction() {
    let mut r = genuine();
    r["geo_A"] = json!({"lat":0,"lon":0});
    r["geo_B"] = json!({"lat":0,"lon":"0"});
    refused(&r, "copresence:invalid_geo_coordinates");
    r["geo_B"] = json!({"lat":0,"lon":0,"acc":0});
    refused(&r, "copresence:suspicious_spoofed_accuracy");
    r["geo_B"] = json!({"lat":0,"lon":10,"acc":1});
    r["sentinel_verdict"] = json!("CONSISTENT_CLAIMED");
    refused(&r, "copresence:suspicious_spacetime_contradiction");
    r["geo_B"] = json!({"lat":0,"lon":0,"acc":1});
    assert!(verify_receipt(&bytes(&r)).is_ok());
    for side in ["geo_A", "geo_B"] {
        for accuracy in [0.0, 0.99] {
            let mut bad = r.clone();
            bad[side]["acc"] = json!(accuracy);
            refused(&bad, "copresence:suspicious_spoofed_accuracy");
        }
        for field in ["lat", "lon"] {
            let mut bad = r.clone();
            bad[side][field] = json!("0");
            refused(&bad, "copresence:invalid_geo_coordinates");
        }
    }
}

#[test]
fn antibody_copresence_accuracy_uses_javascript_number_coercion() {
    let mut r = genuine();
    r["geo_A"] = json!({"lat":0,"lon":0,"acc":15});
    for accuracy in [
        json!(""),
        json!(" \t "),
        json!("0b0"),
        json!("0o0"),
        json!("0x0"),
        json!("\u{feff}0\u{feff}"),
        json!([null]),
        json!([[0]]),
    ] {
        r["geo_B"] = json!({"lat":0,"lon":0,"acc":accuracy});
        refused(&r, "copresence:suspicious_spoofed_accuracy");
    }
    for accuracy in [
        json!("\u{85}0\u{85}"),
        json!("not a number"),
        json!("Infinity"),
        json!("0x"),
        json!("0b"),
        json!("0o"),
        json!("0b2"),
        json!("-inf"),
        json!("-infinity"),
        json!({}),
    ] {
        r["geo_B"] = json!({"lat":0,"lon":0,"acc":accuracy});
        assert!(verify_receipt(&bytes(&r)).is_ok());
    }
    for side in ["geo_A", "geo_B"] {
        for accuracy in [json!({"toString":null}), json!([[{"toString":"x"}]])] {
            let mut r = genuine();
            r["geo_A"] = json!({"lat":0,"lon":0,"acc":15});
            r["geo_B"] = json!({"lat":0,"lon":0,"acc":15});
            r[side]["acc"] = accuracy;
            refused(&r, "copresence:telemetry_coercion_error");
        }
    }
    r["geo_A"] = json!({"lat":0,"lon":0,"acc":0});
    r["geo_B"] = json!({"lat":0,"lon":0,"acc":{"toString":1}});
    refused(&r, "copresence:telemetry_coercion_error");
    r["geo_A"]["acc"] = json!(0.5);
    refused(&r, "copresence:telemetry_coercion_error");
}

#[test]
fn antibody_copresence_audio_types_match_and_delay_bounds() {
    for (audio, code) in [
        (json!({"nonce":"zz"}), "copresence:malformed_audio_nonce"),
        (json!({"matched":null}), "copresence:invalid_audio_matched"),
        (
            json!({"matched":false}),
            "copresence:suspicious_audio_nonce_mismatch",
        ),
        (json!({"delay_ms":"5"}), "copresence:invalid_audio_delay"),
        (
            json!({"delay_ms":4.99}),
            "copresence:suspicious_audio_delay_impossible",
        ),
        (
            json!({"delay_ms":150.01}),
            "copresence:suspicious_audio_relay_detected",
        ),
    ] {
        changed("audio", audio, code);
    }
    for delay in [5, 150] {
        let mut r = genuine();
        r["audio"] = json!({"delay_ms":delay,"matched":true});
        assert!(verify_receipt(&bytes(&r)).is_ok());
    }
}

#[test]
fn antibody_copresence_intent_exact_text_digest_and_structure() {
    let options = IntentOptions::default();
    intent_refused(&genuine(), "approve", options, "copresence:no_intent");
    for side in ["A", "B"] {
        let r = signed_intent("approve", side, false);
        assert!(verify_intent(&bytes(&r), "approve", options).is_ok());
        intent_refused(&r, "approve ", options, "copresence:intent_mismatch");
        for (field, value, code) in [
            (
                "digest",
                json!("00".repeat(32)),
                "copresence:intent_mismatch",
            ),
            ("text", json!("other"), "copresence:intent_mismatch"),
            ("side", json!("C"), "copresence:malformed_intent"),
            (
                "salt",
                json!("zz".repeat(16)),
                "copresence:malformed_intent",
            ),
            (
                "salt",
                json!("00".repeat(16)),
                "copresence:intent_not_committed",
            ),
            ("ack", Value::Null, "copresence:no_owner_signature"),
            ("ack", json!({"sig":"00"}), "copresence:no_owner_signature"),
            (
                "ack",
                json!({"sig":"00".repeat(64)}),
                "copresence:bad_owner_signature",
            ),
        ] {
            let mut bad = r.clone();
            bad["intent"][field] = value;
            intent_refused(&bad, "approve", options, code);
        }
        let other = signed_intent("other", side, false);
        let mut lifted = r.clone();
        lifted["intent"]["ack"] = other["intent"]["ack"].clone();
        intent_refused(
            &lifted,
            "approve",
            options,
            "copresence:bad_owner_signature",
        );
    }
}

#[test]
fn antibody_copresence_intent_requires_distinct_keys_and_pinned_approver() {
    let same = signed_intent("approve", "A", true);
    assert!(verify_receipt(&bytes(&same)).is_ok());
    intent_refused(
        &same,
        "approve",
        IntentOptions::default(),
        "copresence:same_key_on_both_sides",
    );
    let r = signed_intent("approve", "B", false);
    let key = r["pk_A"].as_str().unwrap().to_uppercase();
    assert!(verify_intent(
        &bytes(&r),
        "approve",
        IntentOptions {
            approver: Some(&key),
            ..Default::default()
        }
    )
    .is_ok());
    intent_refused(
        &r,
        "approve",
        IntentOptions {
            approver: Some("wrong"),
            ..Default::default()
        },
        "copresence:wrong_approver",
    );
}

#[test]
fn antibody_copresence_intent_freshness_is_bounded_when_requested() {
    let r = signed_intent("approve", "A", false);
    for (age, max_age, expected) in [
        (10.0, 9.0, Some("copresence:stale_receipt")),
        (0.0, -1.0, Some("copresence:stale_receipt")),
        (0.0, f64::NAN, Some("copresence:stale_receipt")),
        (-5.01, 10.0, Some("copresence:receipt_from_the_future")),
        (-5.0, 10.0, None),
        (10.0, 10.0, None),
    ] {
        let result = verify_intent(
            &bytes(&r),
            "approve",
            IntentOptions {
                max_age: Some(max_age),
                now: 1_700_000_000.0 + age,
                ..Default::default()
            },
        );
        if let Some(code) = expected {
            assert_eq!(result.unwrap_err().code(), code);
        } else {
            assert!(result.is_ok());
        }
    }
}

#[test]
fn antibody_copresence_accepts_high_s_and_uppercase_hex_like_javascript() {
    let mut r = genuine();
    for field in ["pk_A", "pk_B", "nonce_A", "nonce_B", "sig_A", "sig_B"] {
        r[field] = json!(r[field].as_str().unwrap().to_uppercase());
    }
    assert!(verify_receipt(&bytes(&r)).is_ok());
    for name in ["sig_A", "sig_B"] {
        let signature =
            Signature::from_slice(&hex::decode(r[name].as_str().unwrap()).unwrap()).unwrap();
        let (rr, ss) = signature.split_scalars();
        let low = Signature::from_scalars(rr.to_bytes(), (-ss).to_bytes()).unwrap();
        r[name] = json!(hex::encode(low.to_bytes()));
    }
    assert!(verify_receipt(&bytes(&r)).is_ok());
}
