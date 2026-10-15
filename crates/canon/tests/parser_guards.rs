// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::{canonical_json, decode_guest_frame, decode_supervisor_frame, parse, Value};

const FRAME_BUDGET: usize = 65_536;

#[test]
fn i64_min_is_refused_before_adjacent_or_trailing_defects() {
    let inputs: &[&[u8]] = &[
        b"-9223372036854775808",
        b"[-9223372036854775808\"x\"]",
        b"-9223372036854775808 null",
        br#"{"body":{"limit":-9223372036854775808,"query":"x"},"id":"a","kind":"memory.recall","v":1}"#,
    ];
    for input in inputs {
        assert_eq!(parse(input).unwrap_err().code(), "canon:integer-range");
        assert_eq!(
            decode_guest_frame(input).unwrap_err().code(),
            "canon:integer-range"
        );
        assert_eq!(
            decode_supervisor_frame(input).unwrap_err().code(),
            "canon:integer-range"
        );
    }
    assert_eq!(
        canonical_json(&Value::Integer(i64::MIN))
            .unwrap_err()
            .code(),
        "canon:integer-range"
    );
}

#[test]
fn duplicate_decoded_keys_are_refused() {
    for input in [
        br#"{"a":0,"a":1}"#.as_slice(),
        br#"{"a":0,"\u0061":1}"#.as_slice(),
        br#"{"\ud83d\ude00":0,"\ud83d\ude00":1}"#.as_slice(),
    ] {
        assert_eq!(parse(input).unwrap_err().code(), "canon:duplicate-key");
    }
}

// Debug builds exercise the same exact-budget inputs. Release builds also assert
// the median of five parses/decodes is under 20 ms, avoiding a single scheduler
// interruption turning a parser regression check into a flaky wall-clock test.
fn measure_frame(label: &str, mut check: impl FnMut()) {
    check();
    #[cfg(debug_assertions)]
    println!("RUST PARSER GUARD PASS {label} exact 65536 bytes (timing release-only)");
    #[cfg(not(debug_assertions))]
    {
        use std::time::{Duration, Instant};
        let mut samples = Vec::with_capacity(5);
        for _ in 0..5 {
            let started = Instant::now();
            check();
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let median = samples[2];
        assert!(
            median < Duration::from_millis(20),
            "{label}: exact 65536-byte frame took {median:?}, budget is 20 ms"
        );
        println!(
            "RUST PARSER GUARD PASS {label} exact 65536 bytes median {:.3} ms <20 ms",
            median.as_secs_f64() * 1_000.0
        );
    }
}

#[test]
fn maximal_utf8_frame_remains_linear() {
    let prefix = br#"{"body":{"code":"gate:stale-base","next":""#;
    let suffix = br#""},"id":"x","kind":"refusal","v":1}"#;
    let available = FRAME_BUDGET - prefix.len() - suffix.len();
    let mut frame = prefix.to_vec();
    frame.extend("é".repeat(available / 2).as_bytes());
    frame.extend(std::iter::repeat_n(b'a', available % 2));
    frame.extend(suffix);
    assert_eq!(frame.len(), FRAME_BUDGET);
    measure_frame("multibyte-string", || {
        assert!(decode_supervisor_frame(&frame).is_ok());
    });
}

#[test]
fn maximal_distinct_two_character_keys_remain_n_log_n() {
    // Two printable ASCII characters keep comparisons short and maximise the
    // number of distinct keys in one frame (over 8,000). Both JSON escape bytes
    // are excluded so each integer member consumes seven bytes with its comma.
    let alphabet = (b'!'..=b'~')
        .filter(|byte| !matches!(byte, b'"' | b'\\'))
        .collect::<Vec<_>>();
    let keys = alphabet
        .iter()
        .flat_map(|left| {
            alphabet.iter().map(move |right| {
                (
                    String::from_utf8(vec![*left, *right]).unwrap(),
                    Value::Integer(0),
                )
            })
        })
        .take(8_464)
        .collect::<Vec<_>>();
    let mut envelope = Value::Object(vec![
        ("body".into(), Value::Object(keys)),
        ("id".into(), Value::String("x".into())),
        ("kind".into(), Value::String("status".into())),
        ("v".into(), Value::Integer(1)),
    ]);
    let available = FRAME_BUDGET - canonical_json(&envelope).unwrap().len();
    let Value::Object(fields) = &mut envelope else {
        unreachable!();
    };
    let Value::Object(body) = &mut fields[0].1 else {
        unreachable!();
    };
    // Replacing a one-byte integer with a quoted string adds its length + 1.
    body[0].1 = Value::String("x".repeat(available - 1));
    let frame = canonical_json(&envelope).unwrap();
    assert_eq!(frame.len(), FRAME_BUDGET);
    measure_frame("distinct-two-character-keys", || {
        assert_eq!(
            decode_guest_frame(&frame).unwrap_err().code(),
            "frame:unknown-field"
        );
    });
}

#[test]
fn manually_constructed_values_cannot_bypass_serializer_protections() {
    let duplicate = Value::Object(vec![
        ("a".into(), Value::Null),
        ("a".into(), Value::Bool(true)),
    ]);
    assert_eq!(
        canonical_json(&duplicate).unwrap_err().code(),
        "canon:duplicate-key"
    );
    for object in [false, true] {
        let mut value = Value::Null;
        for _ in 0..64 {
            value = if object {
                Value::Object(vec![("x".into(), value)])
            } else {
                Value::Array(vec![value])
            };
        }
        assert!(canonical_json(&value).is_ok());
        value = if object {
            Value::Object(vec![("x".into(), value)])
        } else {
            Value::Array(vec![value])
        };
        assert_eq!(
            canonical_json(&value).unwrap_err().code(),
            "canon:nesting-too-deep"
        );
    }
}
