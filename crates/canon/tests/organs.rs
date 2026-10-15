// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::{
    canonical_json, codes, decode_frame, encode_frame, parse, Direction, FrameBody, Value,
    MAX_ORGAN_NPUB_BYTES, MAX_OWNER_ORIGIN_BYTES, MAX_SAFE_INTEGER,
};

const VECTORS: &[u8] = include_bytes!("../vectors/organs.json");

fn text(value: &Value) -> &str {
    let Value::String(value) = value else {
        panic!("expected string");
    };
    value
}

fn vectors() -> Vec<Value> {
    let Value::Array(values) = parse(VECTORS).unwrap() else {
        panic!("expected vector array");
    };
    values
}

fn fixture() -> Value {
    parse(text(vectors()[0].get("input").unwrap()).as_bytes()).unwrap()
}

fn at<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    if path.is_empty() {
        return value;
    }
    let Value::Object(fields) = value else {
        panic!("expected object");
    };
    let child = fields.iter_mut().find(|(key, _)| key == path[0]).unwrap();
    at(&mut child.1, &path[1..])
}

fn check_change(path: &[&str], replacement: Value, expected: Option<&str>) {
    let mut value = fixture();
    *at(&mut value, path) = replacement;
    let bytes = canonical_json(&value).unwrap();
    let decoded = decode_frame(&bytes, Direction::Supervisor);
    if let Some(code) = expected {
        assert_eq!(decoded.unwrap_err().code(), code, "{path:?}");
    } else {
        assert_eq!(encode_frame(&decoded.unwrap()).unwrap(), bytes, "{path:?}");
    }
}

#[test]
fn organs_shared_vectors_and_direction_round_trip() {
    for vector in vectors() {
        let bytes = text(vector.get("input").unwrap()).as_bytes();
        let direction = match text(vector.get("frame_direction").unwrap()) {
            "guest" => Direction::Guest,
            "supervisor" => Direction::Supervisor,
            other => panic!("unknown direction {other}"),
        };
        match vector.get("frame_refusal") {
            Some(code) => assert_eq!(
                decode_frame(bytes, direction).unwrap_err().code(),
                text(code)
            ),
            None => assert_eq!(
                encode_frame(&decode_frame(bytes, direction).unwrap()).unwrap(),
                text(vector.get("canonical").unwrap()).as_bytes()
            ),
        }
    }
}

#[test]
fn organs_reply_has_exact_public_fields() {
    for path in [
        vec!["body"],
        vec!["body", "aumlok"],
        vec!["body", "aura"],
        vec!["body", "kira"],
        vec!["body", "nostr"],
        vec!["body", "wasm"],
    ] {
        let mut value = fixture();
        let Value::Object(fields) = at(&mut value, &path) else {
            unreachable!()
        };
        fields.push(("secret".into(), Value::String("private".into())));
        assert_eq!(
            decode_frame(&canonical_json(&value).unwrap(), Direction::Supervisor)
                .unwrap_err()
                .code(),
            codes::FRAME_UNKNOWN_FIELD,
            "{path:?}"
        );
        let mut value = fixture();
        let Value::Object(fields) = at(&mut value, &path) else {
            unreachable!()
        };
        let names = fields
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in names {
            let mut value = fixture();
            let Value::Object(fields) = at(&mut value, &path) else {
                unreachable!()
            };
            fields.retain(|(key, _)| key != &name);
            assert_eq!(
                decode_frame(&canonical_json(&value).unwrap(), Direction::Supervisor)
                    .unwrap_err()
                    .code(),
                codes::FRAME_MISSING_FIELD,
                "{path:?}.{name}"
            );
        }
    }
    let request = br#"{"body":{"secret":"private"},"id":"a","kind":"organs","v":1}"#;
    assert_eq!(
        decode_frame(request, Direction::Guest).unwrap_err().code(),
        codes::FRAME_UNKNOWN_FIELD
    );
    let request = br#"{"body":[],"id":"a","kind":"organs","v":1}"#;
    assert_eq!(
        decode_frame(request, Direction::Guest).unwrap_err().code(),
        codes::FRAME_NOT_OBJECT
    );
}

#[test]
fn organs_counts_are_nonnegative_safe_integers() {
    for path in [
        ["body", "approvals_pending"].as_slice(),
        &["body", "aumlok", "passkeys"],
        &["body", "aura", "sequence"],
        &["body", "kira", "notes"],
        &["body", "kira", "demoted"],
        &["body", "nostr", "witness_accepted"],
    ] {
        for bad in [
            Value::Integer(-1),
            Value::Null,
            Value::Bool(false),
            Value::String("1".into()),
        ] {
            check_change(path, bad, Some(codes::FRAME_INVALID_FIELD));
        }
        for good in [0, MAX_SAFE_INTEGER] {
            check_change(path, Value::Integer(good), None);
        }
        let mut value = fixture();
        *at(&mut value, path) = Value::Integer(MAX_SAFE_INTEGER);
        let text = String::from_utf8(canonical_json(&value).unwrap())
            .unwrap()
            .replace("9007199254740991", "9007199254740992");
        assert_eq!(
            decode_frame(text.as_bytes(), Direction::Supervisor)
                .unwrap_err()
                .code(),
            codes::CANON_INTEGER_RANGE
        );
    }
}

#[test]
fn organs_reply_field_types_are_checked() {
    for field in ["bound", "refresh_due"] {
        for bad in [
            Value::Null,
            Value::Integer(0),
            Value::String("false".into()),
        ] {
            check_change(
                &["body", "aumlok", field],
                bad,
                Some(codes::FRAME_INVALID_FIELD),
            );
        }
        for good in [true, false] {
            check_change(&["body", "aumlok", field], Value::Bool(good), None);
        }
    }
    for field in ["aumlok", "aura", "kira", "nostr", "wasm"] {
        for bad in [Value::Null, Value::Array(vec![]), Value::Bool(false)] {
            check_change(&["body", field], bad, Some(codes::FRAME_NOT_OBJECT));
        }
    }
}

#[test]
fn organs_digests_require_lowercase_hex64() {
    for (organ, field) in [("aura", "root"), ("wasm", "module_sha256")] {
        for bad in [
            "".into(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            check_change(
                &["body", organ, field],
                Value::String(bad),
                Some(codes::FRAME_INVALID_FIELD),
            );
        }
        check_change(
            &["body", organ, field],
            Value::Integer(0),
            Some(codes::FRAME_INVALID_FIELD),
        );
    }
}

#[test]
fn organs_strings_are_bounded_by_utf8_bytes() {
    for (path, maximum, nullable) in [
        (vec!["body", "owner_origin"], MAX_OWNER_ORIGIN_BYTES, false),
        (
            vec!["body", "nostr", "node_npub"],
            MAX_ORGAN_NPUB_BYTES,
            true,
        ),
        (
            vec!["body", "nostr", "agent_npub"],
            MAX_ORGAN_NPUB_BYTES,
            true,
        ),
    ] {
        for bad in [
            "".into(),
            "x".repeat(maximum + 1),
            "😀".repeat(maximum / 4 + 1),
        ] {
            check_change(&path, Value::String(bad), Some(codes::FRAME_INVALID_FIELD));
        }
        for good in ["x".repeat(maximum), "😀".repeat(maximum / 4)] {
            check_change(&path, Value::String(good), None);
        }
        check_change(&path, Value::Integer(0), Some(codes::FRAME_INVALID_FIELD));
        check_change(
            &path,
            Value::Null,
            if nullable {
                None
            } else {
                Some(codes::FRAME_INVALID_FIELD)
            },
        );
    }
}

#[test]
fn organs_encoder_checks_constructed_reply() {
    let mut frame =
        decode_frame(&canonical_json(&fixture()).unwrap(), Direction::Supervisor).unwrap();
    let FrameBody::OrgansReply(body) = &mut frame.body else {
        unreachable!()
    };
    body.kira.notes = -1;
    assert_eq!(
        encode_frame(&frame).unwrap_err().code(),
        codes::FRAME_INVALID_FIELD
    );
}

fn source(value: &mut Value, index: usize) -> &mut Value {
    let Value::Array(sources) = at(value, &["body", "aura", "sources"]) else {
        panic!("expected sources");
    };
    &mut sources[index]
}

fn check_source(index: usize, change: impl FnOnce(&mut Value), expected: Option<&str>) {
    let mut value = fixture();
    change(source(&mut value, index));
    let bytes = canonical_json(&value).unwrap();
    let result = decode_frame(&bytes, Direction::Supervisor);
    match expected {
        Some(code) => assert_eq!(result.unwrap_err().code(), code),
        None => assert_eq!(encode_frame(&result.unwrap()).unwrap(), bytes),
    }
}

#[test]
fn aura_sources_have_exact_shape_and_order() {
    for bad in [Value::Null, Value::Bool(false), Value::Object(vec![])] {
        check_change(
            &["body", "aura", "sources"],
            bad,
            Some(codes::FRAME_INVALID_FIELD),
        );
    }
    let mut value = fixture();
    let Value::Array(sources) = at(&mut value, &["body", "aura", "sources"]) else {
        unreachable!()
    };
    for length in [0, 2, 4] {
        check_change(
            &["body", "aura", "sources"],
            Value::Array((0..length).map(|i| sources[i % 3].clone()).collect()),
            Some(codes::FRAME_INVALID_FIELD),
        );
    }
    for index in 0..3 {
        for bad in [Value::Null, Value::Array(vec![]), Value::Bool(false)] {
            check_source(index, |s| *s = bad, Some(codes::FRAME_NOT_OBJECT));
        }
        for name in ["absence", "entries", "head", "name"] {
            check_source(
                index,
                |s| {
                    let Value::Object(fields) = s else {
                        unreachable!()
                    };
                    fields.retain(|(key, _)| key != name);
                },
                Some(codes::FRAME_MISSING_FIELD),
            );
        }
        check_source(
            index,
            |s| {
                let Value::Object(fields) = s else {
                    unreachable!()
                };
                fields.push(("secret".into(), Value::String("private".into())));
            },
            Some(codes::FRAME_UNKNOWN_FIELD),
        );
        for name in ["gate-ledger", "kira-chain", "code-chain", "unknown"] {
            if ["gate-ledger", "kira-chain", "code-chain"][index] == name {
                continue;
            }
            check_source(
                index,
                |s| *at(s, &["name"]) = Value::String(name.into()),
                Some(codes::FRAME_INVALID_FIELD),
            );
        }
    }
}

#[test]
fn aura_source_heads_and_absences_are_consistent() {
    for index in 0..3 {
        let absence = [
            "gate-ledger-empty",
            "kira-ledger-empty",
            "code-record-missing",
        ][index];
        check_source(
            index,
            |s| {
                *at(s, &["head"]) = Value::Null;
                *at(s, &["entries"]) = Value::Integer(0);
                *at(s, &["absence"]) = Value::String(absence.into());
            },
            None,
        );
        for entries in [Value::Null, Value::Bool(false), Value::String("0".into())] {
            check_source(
                index,
                |s| {
                    *at(s, &["head"]) = Value::Null;
                    *at(s, &["entries"]) = entries;
                    *at(s, &["absence"]) = Value::String(absence.into());
                },
                Some(codes::FRAME_INVALID_FIELD),
            );
        }
        for bad in [
            Value::Null,
            Value::String("".into()),
            Value::String("invented".into()),
        ] {
            check_source(
                index,
                |s| {
                    *at(s, &["head"]) = Value::Null;
                    *at(s, &["entries"]) = Value::Integer(0);
                    *at(s, &["absence"]) = bad;
                },
                Some(codes::FRAME_INVALID_FIELD),
            );
        }
        check_source(
            index,
            |s| {
                *at(s, &["head"]) = Value::Null;
                *at(s, &["entries"]) = Value::Integer(1);
                *at(s, &["absence"]) = Value::String(absence.into());
            },
            Some(codes::FRAME_INVALID_FIELD),
        );
        for entries in [1, MAX_SAFE_INTEGER] {
            check_source(
                index,
                |s| {
                    *at(s, &["head"]) = Value::String("a".repeat(64));
                    *at(s, &["entries"]) = Value::Integer(entries);
                    *at(s, &["absence"]) = Value::Null;
                },
                None,
            );
        }
        for entries in [
            Value::Integer(-1),
            Value::Integer(0),
            Value::Null,
            Value::Bool(false),
            Value::String("1".into()),
        ] {
            check_source(
                index,
                |s| {
                    *at(s, &["head"]) = Value::String("a".repeat(64));
                    *at(s, &["entries"]) = entries;
                    *at(s, &["absence"]) = Value::Null;
                },
                Some(codes::FRAME_INVALID_FIELD),
            );
        }
        for head in [
            Value::String("A".repeat(64)),
            Value::String("g".repeat(64)),
            Value::String("a".repeat(63)),
            Value::Bool(false),
        ] {
            check_source(
                index,
                |s| {
                    *at(s, &["head"]) = head;
                    *at(s, &["entries"]) = Value::Integer(1);
                    *at(s, &["absence"]) = Value::Null;
                },
                Some(codes::FRAME_INVALID_FIELD),
            );
        }
        check_source(
            index,
            |s| {
                *at(s, &["head"]) = Value::String("a".repeat(64));
                *at(s, &["entries"]) = Value::Integer(1);
                *at(s, &["absence"]) = Value::String(absence.into());
            },
            Some(codes::FRAME_INVALID_FIELD),
        );
    }
}
