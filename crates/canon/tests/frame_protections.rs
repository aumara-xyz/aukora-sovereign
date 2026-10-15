// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::{
    canonical_json, codes, decode_frame, encode_frame, parse, Direction, Frame, FrameBody,
    MemoryRecall,
};

fn bytes(kind: &str, body: &str) -> Vec<u8> {
    canonical_json(
        &parse(format!(r#"{{"body":{body},"id":"a","kind":"{kind}","v":1}}"#).as_bytes()).unwrap(),
    )
    .unwrap()
}
fn refuse(kind: &str, body: &str, direction: Direction, code: &str) {
    assert_eq!(
        decode_frame(&bytes(kind, body), direction)
            .unwrap_err()
            .code(),
        code,
        "{kind}: {body}"
    );
}
fn accept(kind: &str, body: &str, direction: Direction) {
    let bytes = bytes(kind, body);
    let frame = decode_frame(&bytes, direction).unwrap();
    assert_eq!(encode_frame(&frame).unwrap(), bytes);
}
fn propose(digest: &str, b64: &str) -> String {
    format!(r#"{{"base_sha256":"{digest}","new_bytes_b64":"{b64}","note":"n","target":"t"}}"#)
}
fn reply(seq: i64, prompt: i64, completion: i64, cost: i64) -> String {
    format!(
        r#"{{"content":null,"tool_calls":[],"finish_reason":"stop","receipt_seq":{seq},"usage":{{"prompt_tokens":{prompt},"completion_tokens":{completion},"cost_microusd":{cost}}}}}"#
    )
}

#[test]
fn envelope_refusal_precedence_is_fixed() {
    let cases = [
        (
            r#"{"body":{},"id":"a","kind":"status","v":"1"}"#,
            codes::FRAME_INVALID_FIELD,
        ),
        (
            r#"{"body":0,"id":0,"kind":0,"v":2}"#,
            codes::FRAME_UNSUPPORTED_VERSION,
        ),
        (
            r#"{"body":0,"id":0,"kind":0,"v":1}"#,
            codes::FRAME_INVALID_FIELD,
        ),
        (
            r#"{"body":0,"id":"!","kind":0,"v":1}"#,
            codes::FRAME_INVALID_ID,
        ),
        (
            r#"{"body":0,"id":"a","kind":0,"v":1}"#,
            codes::FRAME_INVALID_FIELD,
        ),
        (
            r#"{"body":0,"id":"a","kind":"bogus","v":1}"#,
            codes::FRAME_UNKNOWN_KIND,
        ),
        (
            r#"{"body":{},"id":"a","kind":"status","surprise":0}"#,
            codes::FRAME_UNKNOWN_FIELD,
        ),
        (
            r#"{"body":{},"id":"a","kind":"status"}"#,
            codes::FRAME_MISSING_FIELD,
        ),
        (
            r#"{"id":"a","kind":"status","v":2}"#,
            codes::FRAME_MISSING_FIELD,
        ),
    ];
    for (input, code) in cases {
        assert_eq!(
            decode_frame(input.as_bytes(), Direction::Guest)
                .unwrap_err()
                .code(),
            code
        );
    }
    for id in [String::new(), "x".repeat(65), "é".into(), "a/b".into()] {
        let input = format!(r#"{{"body":{{}},"id":"{id}","kind":"status","v":1}}"#);
        assert_eq!(
            decode_frame(input.as_bytes(), Direction::Guest)
                .unwrap_err()
                .code(),
            codes::FRAME_INVALID_ID
        );
    }
    let input = format!(
        r#"{{"body":{{}},"id":"{}","kind":"status","v":1}}"#,
        "a".repeat(64)
    );
    decode_frame(input.as_bytes(), Direction::Guest).unwrap();
}

#[test]
fn scalar_checks_precede_nested_checks() {
    refuse(
        "model.call",
        r#"{"grant_id":1,"max_output_tokens":1,"messages":[1],"model":"m","tools":[]}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "model.call",
        r#"{"grant_id":"g","max_output_tokens":0,"messages":[1],"model":"m","tools":[]}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "memory.put",
        r#"{"category":"c","cell":{},"statement":1}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "memory.put",
        r#"{"category":1,"cell":null,"statement":"s"}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "recall",
        r#"{"items":[{}],"result":"bogus"}"#,
        Direction::Supervisor,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "model.reply",
        r#"{"content":false,"finish_reason":null,"receipt_seq":1,"tool_calls":[{}],"usage":{}}"#,
        Direction::Supervisor,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "model.reply",
        r#"{"content":null,"finish_reason":null,"receipt_seq":1,"tool_calls":[{}],"usage":0}"#,
        Direction::Supervisor,
        codes::FRAME_MISSING_FIELD,
    );
    refuse(
        "model.call",
        r#"{"grant_id":"g","max_output_tokens":1,"messages":[{"content":1,"role":"assistant","tool_calls":[{}]}],"model":"m","tools":[]}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "model.call",
        r#"{"grant_id":"g","max_output_tokens":1,"messages":[],"model":"m","tools":[{"type":"invalid","function":0}]}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "model.call",
        r#"{"grant_id":"g","max_output_tokens":1,"messages":[],"model":"m","tools":[{"type":"function","function":{"description":1,"name":"n","parameters":0}}]}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
}

#[test]
fn every_digest_field_requires_lowercase_hex_64() {
    let valid = "a".repeat(64);
    for bad in [
        "".into(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        "é".repeat(32),
    ] {
        refuse(
            "propose",
            &propose(&bad, ""),
            Direction::Guest,
            codes::FRAME_INVALID_FIELD,
        );
        refuse(
            "read.reply",
            &format!(r#"{{"target":"t","sha256":"{bad}","bytes_b64":""}}"#),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
        for field in ["effect_sha256", "input_sha256", "module_sha256"] {
            let cell = format!(r#"{{"effect_sha256":"{valid}","input_sha256":"{valid}","module_sha256":"{valid}"}}"#)
                .replace(&format!(r#""{field}":"{valid}""#), &format!(r#""{field}":"{bad}""#));
            refuse(
                "memory.put",
                &format!(r#"{{"category":"c","cell":{cell},"statement":"s"}}"#),
                Direction::Guest,
                codes::FRAME_INVALID_FIELD,
            );
            let p = propose(&valid, "");
            refuse(
                "propose",
                &format!("{},\"cell\":{cell}}}", &p[..p.len() - 1]),
                Direction::Guest,
                codes::FRAME_INVALID_FIELD,
            );
        }
    }
    accept("propose", &propose(&valid, ""), Direction::Guest);
}

#[test]
fn base64_is_padded_standard_with_zero_pad_bits() {
    let digest = "0".repeat(64);
    for bad in [
        "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "AA=A", "====", "SGVsbG8_", "SGVsbG8-", "Z g=",
        "Zg==AAAA", "éé",
    ] {
        refuse(
            "propose",
            &propose(&digest, bad),
            Direction::Guest,
            codes::FRAME_INVALID_FIELD,
        );
        refuse(
            "read.reply",
            &format!(r#"{{"target":"t","sha256":"{digest}","bytes_b64":"{bad}"}}"#),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
    }
    for good in ["", "Zg==", "Zm8=", "Zm9v", "/w==", "+/8="] {
        accept("propose", &propose(&digest, good), Direction::Guest);
        accept(
            "read.reply",
            &format!(r#"{{"target":"t","sha256":"{digest}","bytes_b64":"{good}"}}"#),
            Direction::Supervisor,
        );
    }
    let large = "AAAA".repeat(21_846); // 65,538 decoded bytes; rejected before interpretation.
    refuse(
        "propose",
        &propose(&digest, &large),
        Direction::Guest,
        codes::FRAME_TOO_LARGE,
    );
}

#[test]
fn every_count_has_nonnegative_semantic_bounds() {
    for limit in [-1, 0, 101] {
        refuse(
            "memory.recall",
            &format!(r#"{{"query":"x","limit":{limit}}}"#),
            Direction::Guest,
            codes::FRAME_INVALID_FIELD,
        );
    }
    for limit in [1, 100] {
        accept(
            "memory.recall",
            &format!(r#"{{"query":"x","limit":{limit}}}"#),
            Direction::Guest,
        );
    }
    for n in [-1, 0, 32769] {
        refuse(
            "model.call",
            &format!(
                r#"{{"grant_id":"g","model":"m","messages":[],"tools":[],"max_output_tokens":{n}}}"#
            ),
            Direction::Guest,
            codes::FRAME_INVALID_FIELD,
        );
    }
    for n in [1, 32768] {
        accept(
            "model.call",
            &format!(
                r#"{{"grant_id":"g","model":"m","messages":[],"tools":[],"max_output_tokens":{n}}}"#
            ),
            Direction::Guest,
        );
    }
    for n in [-1, 32769] {
        refuse(
            "model.reply",
            &reply(1, n, 0, 0),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
        refuse(
            "model.reply",
            &reply(1, 0, n, 0),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
    }
    for n in [-1, 0] {
        refuse(
            "model.reply",
            &reply(n, 0, 0, 0),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
        refuse(
            "recall",
            &format!(
                r#"{{"result":"found","items":[{{"note_id":"n","text":"t","cite_seq":{n}}}]}}"#
            ),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
    }
    refuse(
        "model.reply",
        &reply(1, 0, 0, -1),
        Direction::Supervisor,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "status.reply",
        r#"{"bound":true,"grant_id":null,"grant_remaining":-1,"ready":true}"#,
        Direction::Supervisor,
        codes::FRAME_INVALID_FIELD,
    );
    for n in [0, canon::MAX_SAFE_INTEGER] {
        accept(
            "model.reply",
            &reply(1, 32768, 32768, n),
            Direction::Supervisor,
        );
        accept(
            "status.reply",
            &format!(r#"{{"bound":true,"grant_id":null,"grant_remaining":{n},"ready":true}}"#),
            Direction::Supervisor,
        );
    }
    accept(
        "model.reply",
        &reply(canon::MAX_SAFE_INTEGER, 0, 0, 0),
        Direction::Supervisor,
    );
    accept(
        "recall",
        &format!(
            r#"{{"result":"found","items":[{{"note_id":"n","text":"t","cite_seq":{}}}]}}"#,
            canon::MAX_SAFE_INTEGER
        ),
        Direction::Supervisor,
    );
}

#[test]
fn direction_rejects_every_opposite_authority_kind() {
    for kind in [
        "accepted",
        "outcome",
        "model.reply",
        "read.reply",
        "recall",
        "refusal",
        "status.reply",
        "organs.reply",
    ] {
        refuse(kind, "{}", Direction::Guest, codes::FRAME_UNKNOWN_KIND);
    }
    for kind in [
        "propose",
        "read",
        "model.call",
        "memory.put",
        "memory.recall",
        "status",
        "organs",
    ] {
        refuse(kind, "{}", Direction::Supervisor, codes::FRAME_UNKNOWN_KIND);
    }
}

#[test]
fn v11_tools_and_replies_round_trip_without_losing_fields() {
    accept("read", r#"{"target":"note.md"}"#, Direction::Guest);
    accept(
        "read.reply",
        &format!(
            r#"{{"target":"note.md","sha256":"{}","bytes_b64":"Zg=="}}"#,
            "0".repeat(64)
        ),
        Direction::Supervisor,
    );
    accept(
        "status.reply",
        r#"{"ready":true,"bound":false,"grant_id":null,"grant_remaining":null}"#,
        Direction::Supervisor,
    );
    let call = r#"{"id":"call1","type":"function","function":{"name":"read","arguments":"{}"}}"#;
    accept(
        "model.call",
        &format!(
            r#"{{"grant_id":"g","model":"m","max_output_tokens":1,"messages":[{{"role":"assistant","content":null,"tool_calls":[{call}]}},{{"role":"tool","content":"ok","tool_call_id":"call1"}}],"tools":[{{"type":"function","function":{{"name":"read","description":"Read bytes","parameters":{{"type":"object","properties":{{"𐀀":{{"type":"string"}},"":{{"type":"integer"}}}}}}}}}}]}}"#
        ),
        Direction::Guest,
    );
    accept(
        "model.reply",
        &format!(
            r#"{{"content":null,"finish_reason":"tool_calls","receipt_seq":1,"tool_calls":[{call}],"usage":{{"prompt_tokens":1,"completion_tokens":2,"cost_microusd":0}}}}"#
        ),
        Direction::Supervisor,
    );
    refuse(
        "model.call",
        r#"{"grant_id":"g","model":"m","max_output_tokens":1,"messages":[],"tools":[{"type":"function","function":{"name":"f","description":"d","parameters":[]}}]}"#,
        Direction::Guest,
        codes::FRAME_NOT_OBJECT,
    );
    refuse(
        "model.call",
        r#"{"grant_id":"g","model":"m","max_output_tokens":1,"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":{}}}]}],"tools":[]}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "status.reply",
        r#"{"ready":1,"bound":true,"grant_id":null,"grant_remaining":null}"#,
        Direction::Supervisor,
        codes::FRAME_INVALID_FIELD,
    );
}

#[test]
fn encoder_validates_manually_constructed_body_and_refusal_registry() {
    let frame = Frame {
        v: 1,
        id: "a".into(),
        body: FrameBody::MemoryRecall(MemoryRecall {
            query: "x".into(),
            limit: 0,
        }),
    };
    assert_eq!(
        encode_frame(&frame).unwrap_err().code(),
        codes::FRAME_INVALID_FIELD
    );
    refuse(
        "refusal",
        r#"{"code":"gate:invented","next":""}"#,
        Direction::Supervisor,
        codes::FRAME_INVALID_FIELD,
    );
    for code in codes::ALL {
        accept(
            "refusal",
            &format!(r#"{{"code":"{code}","next":""}}"#),
            Direction::Supervisor,
        );
    }
}

#[test]
fn decoded_base64_budget_is_checked_independently_of_frame_size() {
    for (encoded, expected) in [
        ("", vec![]),
        ("Zg==", vec![b'f']),
        ("Zm8=", b"fo".to_vec()),
        ("Zm9v", b"foo".to_vec()),
        ("/w==", vec![255]),
        ("+/8=", vec![251, 255]),
    ] {
        assert_eq!(canon::decode_base64(encoded).unwrap(), expected);
    }
    let exact = format!("{}AA==", "AAAA".repeat(21_845));
    assert_eq!(canon::decode_base64(&exact).unwrap(), vec![0; 65_536]);
    let oversize = format!("{}AAA=", "AAAA".repeat(21_845));
    assert_eq!(
        canon::decode_base64(&oversize).unwrap_err().code(),
        codes::FRAME_INVALID_FIELD
    );
}

#[test]
fn body_shape_precedes_field_types_and_frame_bytes_are_bounded_and_canonical() {
    refuse(
        "model.call",
        r#"{"grant_id":1,"max_output_tokens":1,"messages":[],"model":"m"}"#,
        Direction::Guest,
        codes::FRAME_MISSING_FIELD,
    );
    refuse(
        "status",
        r#"{"extra":0}"#,
        Direction::Guest,
        codes::FRAME_UNKNOWN_FIELD,
    );
    let input = b" {\"body\":{},\"id\":\"a\",\"kind\":\"status\",\"v\":1}";
    assert_eq!(
        decode_frame(input, Direction::Guest).unwrap_err().code(),
        codes::FRAME_NOT_CANONICAL
    );
    let large = bytes("read", &format!(r#"{{"target":"{}"}}"#, "a".repeat(65_537)));
    assert_eq!(
        decode_frame(&large, Direction::Guest).unwrap_err().code(),
        codes::FRAME_TOO_LARGE
    );
}

#[test]
fn primitive_field_types_and_container_shapes_are_checked() {
    refuse(
        "read",
        r#"{"target":false}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse(
        "memory.recall",
        r#"{"limit":"1","query":"q"}"#,
        Direction::Guest,
        codes::FRAME_INVALID_FIELD,
    );
    refuse("status", "[]", Direction::Guest, codes::FRAME_NOT_OBJECT);
    for (bound, grant_id, remaining, ready) in [
        ("1", "null", "null", "true"),
        ("true", "false", "null", "true"),
        ("true", "null", "false", "true"),
        ("true", "null", "null", "1"),
    ] {
        refuse(
            "status.reply",
            &format!(
                r#"{{"bound":{bound},"grant_id":{grant_id},"grant_remaining":{remaining},"ready":{ready}}}"#
            ),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
    }
    for (content, finish, calls) in [
        ("false", "null", "[]"),
        ("null", "false", "[]"),
        ("null", "null", "false"),
    ] {
        refuse(
            "model.reply",
            &format!(
                r#"{{"content":{content},"finish_reason":{finish},"receipt_seq":1,"tool_calls":{calls},"usage":{{"prompt_tokens":0,"completion_tokens":0,"cost_microusd":0}}}}"#
            ),
            Direction::Supervisor,
            codes::FRAME_INVALID_FIELD,
        );
    }
    for (messages, tools) in [
        ("false", "[]"),
        ("[]", "false"),
        (r#"[{"content":false,"role":"assistant"}]"#, "[]"),
        (
            r#"[{"content":null,"role":"assistant","tool_call_id":false}]"#,
            "[]",
        ),
        (
            r#"[{"content":null,"role":"assistant","tool_calls":false}]"#,
            "[]",
        ),
    ] {
        refuse(
            "model.call",
            &format!(
                r#"{{"grant_id":"g","max_output_tokens":1,"model":"m","messages":{messages},"tools":{tools}}}"#
            ),
            Direction::Guest,
            codes::FRAME_INVALID_FIELD,
        );
    }
    refuse(
        "recall",
        r#"{"result":"empty","items":false}"#,
        Direction::Supervisor,
        codes::FRAME_INVALID_FIELD,
    );
}
