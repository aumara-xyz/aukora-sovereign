// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline v0 co-presence evidence: two keys signed a shared core, never proof of a person.
//! Freshness is optional; single use and recording every attempt belong to the caller.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

mod json;
use json::Value;

// JS reason (before its explanatory colon) -> Rust code:
// json_parse_error                     copresence:json_parse_error
// unsupported_version                  copresence:unsupported_version
// missing_field                        copresence:missing_field
// timestamps_must_be_numbers           copresence:timestamps_must_be_numbers
// negative_time_skew                   copresence:negative_time_skew
// ceremony_window_exceeded             copresence:ceremony_window_exceeded
// malformed_public_key_A / _B          copresence:malformed_public_key_A / _B
// invalid_public_key_A / _B            copresence:invalid_public_key_A / _B
// malformed_nonce_A / _B               copresence:malformed_nonce_A / _B
// malformed_signature_A / _B           copresence:malformed_signature_A / _B
// sig_A_invalid / sig_B_invalid        copresence:sig_A_invalid / sig_B_invalid
// invalid_geo_coordinates              copresence:invalid_geo_coordinates
// suspicious_spoofed_accuracy           copresence:suspicious_spoofed_accuracy
// suspicious_spacetime_contradiction    copresence:suspicious_spacetime_contradiction
// malformed_audio_nonce                copresence:malformed_audio_nonce
// invalid_audio_matched                copresence:invalid_audio_matched
// suspicious_audio_nonce_mismatch       copresence:suspicious_audio_nonce_mismatch
// invalid_audio_delay                  copresence:invalid_audio_delay
// suspicious_audio_delay_impossible    copresence:suspicious_audio_delay_impossible
// suspicious_audio_relay_detected       copresence:suspicious_audio_relay_detected
// no_intent                            copresence:no_intent
// intent_mismatch                      copresence:intent_mismatch
// malformed_intent                     copresence:malformed_intent
// intent_not_committed                 copresence:intent_not_committed
// same_key_on_both_sides                copresence:same_key_on_both_sides
// no_owner_signature                   copresence:no_owner_signature
// bad_owner_signature                  copresence:bad_owner_signature
// wrong_approver                       copresence:wrong_approver
// stale_receipt                        copresence:stale_receipt
// receipt_from_the_future              copresence:receipt_from_the_future
// Intent's "receipt: " wrapper preserves the base reason above.
// Node's uncaught BigInt/BE64 RangeError -> copresence:timestamp_encoding_error.
// Node's uncaught telemetry ToPrimitive TypeError -> copresence:telemetry_coercion_error.
// RustCrypto reports invalid signatures as false, without Node's unreachable
// sig_A_verification_error / sig_B_verification_error exception diagnostics.
// File/usage errors belong to the CLI, not the byte verifier.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal(&'static str);

impl Refusal {
    pub const fn code(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refusal {}

type Result<T> = std::result::Result<T, Refusal>;

#[derive(Clone, Copy, Debug, Default)]
pub struct IntentOptions<'a> {
    pub approver: Option<&'a str>,
    pub max_age: Option<f64>,
    /// Epoch seconds, used only with max_age. The caller supplies its clock.
    pub now: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedIntent {
    pub core: String,
    pub text_digest: String,
    pub approver_key: String,
    pub asker_key: String,
    pub t_b: f64,
}

fn require(condition: bool, code: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Refusal(code))
    }
}

fn parse(bytes: &[u8]) -> Result<Value> {
    // Node's readFileSync(..., 'utf8') replaces invalid UTF-8.
    json::parse(&String::from_utf8_lossy(bytes)).map_err(|_| Refusal("copresence:json_parse_error"))
}

fn is_hex(value: &Value, length: usize) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == length && s.as_bytes().iter().all(u8::is_ascii_hexdigit))
}

fn decoded(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("checked hex")).expect("checked hex")
}

fn key(value: &Value, side: &str) -> Result<(VerifyingKey, Vec<u8>)> {
    require(
        is_hex(value, 130) && value.as_str().is_some_and(|s| s.starts_with("04")),
        if side == "A" {
            "copresence:malformed_public_key_A"
        } else {
            "copresence:malformed_public_key_B"
        },
    )?;
    let raw = decoded(value);
    let public = VerifyingKey::from_sec1_bytes(&raw).map_err(|_| {
        Refusal(if side == "A" {
            "copresence:invalid_public_key_A"
        } else {
            "copresence:invalid_public_key_B"
        })
    })?;
    Ok((public, raw))
}

fn domain(label: &str, pieces: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label.as_bytes());
    hash.update([0]);
    for piece in pieces {
        hash.update(piece);
    }
    hash.finalize().into()
}

fn signature_valid(public: &VerifyingKey, message: &[u8], signature: &Value) -> bool {
    Signature::from_slice(&decoded(signature))
        .is_ok_and(|signature| public.verify(message, &signature).is_ok())
}

fn timestamp(value: f64) -> Result<[u8; 8]> {
    require(
        value.is_finite()
            && value.fract() == 0.0
            && (0.0..18_446_744_073_709_551_616.0).contains(&value),
        "copresence:timestamp_encoding_error",
    )?;
    Ok((value as u64).to_be_bytes())
}

struct Receipt {
    value: Value,
    core: [u8; 32],
}

fn receipt(bytes: &[u8]) -> Result<Receipt> {
    let r = parse(bytes)?;
    require(
        r["v"].as_f64() == Some(0.0),
        "copresence:unsupported_version",
    )?;
    for name in [
        "v", "pk_A", "pk_B", "nonce_A", "nonce_B", "t_A", "t_B", "sig_A", "sig_B",
    ] {
        require(!r[name].is_null(), "copresence:missing_field")?;
    }
    require(
        r["t_A"].is_number() && r["t_B"].is_number(),
        "copresence:timestamps_must_be_numbers",
    )?;
    let time_b = r["t_B"].as_f64().expect("number");
    let diff = time_b - r["t_A"].as_f64().expect("number");
    require(
        diff.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less),
        "copresence:negative_time_skew",
    )?;
    require(
        diff.partial_cmp(&10.0) != Some(std::cmp::Ordering::Greater),
        "copresence:ceremony_window_exceeded",
    )?;
    let (pub_a, raw_a) = key(&r["pk_A"], "A")?;
    let (pub_b, raw_b) = key(&r["pk_B"], "B")?;
    require(is_hex(&r["nonce_A"], 16), "copresence:malformed_nonce_A")?;
    require(is_hex(&r["nonce_B"], 16), "copresence:malformed_nonce_B")?;
    let core = domain(
        "copresence.v0",
        &[
            &raw_a,
            &raw_b,
            &decoded(&r["nonce_A"]),
            &decoded(&r["nonce_B"]),
            &timestamp(time_b)?,
        ],
    );
    require(is_hex(&r["sig_A"], 128), "copresence:malformed_signature_A")?;
    require(is_hex(&r["sig_B"], 128), "copresence:malformed_signature_B")?;
    require(
        signature_valid(&pub_a, &core, &r["sig_A"]),
        "copresence:sig_A_invalid",
    )?;
    require(
        signature_valid(&pub_b, &core, &r["sig_B"]),
        "copresence:sig_B_invalid",
    )?;
    telemetry(&r)?;
    Ok(Receipt { value: r, core })
}

/// Checks the frozen JavaScript v0 receipt rules, including optional telemetry.
pub fn verify_receipt(bytes: &[u8]) -> Result<()> {
    receipt(bytes).map(|_| ())
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => *n != 0.0 && !n.is_nan(),
        Value::String(s) => !s.is_empty(),
        Value::UnpairedString(_) => true,
        _ => true,
    }
}

fn js_number(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Number(n) => *n,
        Value::String(s) => string_number(s),
        Value::UnpairedString(_) => f64::NAN,
        Value::Array(_) => string_number(&js_string(value)),
        _ => f64::NAN,
    }
}

fn string_number(text: &str) -> f64 {
    let text = text.trim_matches(|c| {
        matches!(c,
            '\u{0009}'..='\u{000d}' | ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' |
            '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
        )
    });
    if text.is_empty() {
        return 0.0;
    }
    for (prefixes, radix) in [(["0x", "0X"], 16), (["0b", "0B"], 2), (["0o", "0O"], 8)] {
        if let Some(digits) = prefixes.iter().find_map(|p| text.strip_prefix(p)) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return f64::NAN;
            }
            return digits.chars().fold(0.0, |number, c| {
                number * f64::from(radix) + f64::from(c.to_digit(radix).expect("digit"))
            });
        }
    }
    match text {
        "Infinity" | "+Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        _ if text
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E')) =>
        {
            f64::NAN
        }
        _ => text.parse().unwrap_or(f64::NAN),
    }
}

fn js_string(value: &Value) -> String {
    enum Part<'a> {
        Value(&'a Value, bool),
        Comma,
    }
    let mut pending = vec![Part::Value(value, false)];
    let mut text = String::new();
    while let Some(part) = pending.pop() {
        let (value, in_array) = match part {
            Part::Comma => {
                text.push(',');
                continue;
            }
            Part::Value(value, in_array) => (value, in_array),
        };
        match value {
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate().rev() {
                    pending.push(Part::Value(value, true));
                    if index > 0 {
                        pending.push(Part::Comma);
                    }
                }
            }
            Value::Null if in_array => {}
            value => text.push_str(&value.to_string()),
        }
    }
    text
}

fn coercion_defined(value: &Value) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(_) if value.get("toString").is_some() => return false,
            Value::Array(values) => pending.extend(values.iter()),
            _ => {}
        }
    }
    true
}

fn js_add(a: &Value, b: &Value) -> Value {
    if matches!(a, Value::UnpairedString(_)) || matches!(b, Value::UnpairedString(_)) {
        return Value::UnpairedString(vec![0xd800]);
    }
    if a.is_string()
        || a.is_object()
        || a.is_array()
        || b.is_string()
        || b.is_object()
        || b.is_array()
    {
        Value::String(js_string(a) + &js_string(b))
    } else {
        Value::Number(js_number(a) + js_number(b))
    }
}

fn telemetry(r: &Value) -> Result<()> {
    if truthy(&r["geo_A"]) && truthy(&r["geo_B"]) {
        let a = &r["geo_A"];
        let b = &r["geo_B"];
        require(
            [&a["lat"], &a["lon"], &b["lat"], &b["lon"]]
                .iter()
                .all(|v| v.is_number()),
            "copresence:invalid_geo_coordinates",
        )?;
        let default = Value::from(15);
        let acc_a = a.get("acc").unwrap_or(&default);
        let acc_b = b.get("acc").unwrap_or(&default);
        // The JS refusal diagnostic also coerces both accuracies.
        require(
            coercion_defined(acc_a) && coercion_defined(acc_b),
            "copresence:telemetry_coercion_error",
        )?;
        require(
            !(js_number(acc_a) < 1.0 || js_number(acc_b) < 1.0),
            "copresence:suspicious_spoofed_accuracy",
        )?;
        let radians = |value: f64| (value * std::f64::consts::PI) / 180.0;
        let lat_a = radians(a["lat"].as_f64().expect("number"));
        let lat_b = radians(b["lat"].as_f64().expect("number"));
        let d_lat =
            radians(b["lat"].as_f64().expect("number") - a["lat"].as_f64().expect("number"));
        let d_lon =
            radians(b["lon"].as_f64().expect("number") - a["lon"].as_f64().expect("number"));
        let hav =
            (d_lat / 2.0).sin().powi(2) + lat_a.cos() * lat_b.cos() * (d_lon / 2.0).sin().powi(2);
        let distance = 6_371_000.0 * 2.0 * hav.sqrt().atan2((1.0 - hav).sqrt());
        let max_distance = js_number(&js_add(&js_add(acc_a, acc_b), &Value::from(50)));
        let consistent = matches!(
            r["sentinel_verdict"].as_str(),
            Some("CONSISTENT_CLAIMED" | "GENUINE_LOCAL_PROXIMITY")
        );
        require(
            !(consistent && distance > max_distance),
            "copresence:suspicious_spacetime_contradiction",
        )?;
    }
    if truthy(&r["audio"]) {
        let audio = &r["audio"];
        if let Some(nonce) = audio.get("nonce") {
            require(is_hex(nonce, 32), "copresence:malformed_audio_nonce")?;
        }
        if let Some(matched) = audio.get("matched") {
            require(matched.is_boolean(), "copresence:invalid_audio_matched")?;
            require(
                matched != &Value::Bool(false),
                "copresence:suspicious_audio_nonce_mismatch",
            )?;
        }
        if let Some(delay) = audio.get("delay_ms") {
            require(delay.is_number(), "copresence:invalid_audio_delay")?;
            let delay = delay.as_f64().expect("number");
            require(delay >= 5.0, "copresence:suspicious_audio_delay_impossible")?;
            require(delay <= 150.0, "copresence:suspicious_audio_relay_detected")?;
        }
    }
    Ok(())
}

/// Checks exact text, its nonce commitment and the other device's session signature.
/// A valid result does not establish identity, human presence, execution or single use.
pub fn verify_intent(
    bytes: &[u8],
    text: &str,
    options: IntentOptions<'_>,
) -> Result<VerifiedIntent> {
    let receipt = receipt(bytes)?;
    let r = receipt.value;
    let it = &r["intent"];
    require(it.is_object() || it.is_array(), "copresence:no_intent")?;
    let digest = domain("copresence.intent.v1", &[text.as_bytes()]);
    require(
        it["text"].as_str() == Some(text)
            && js_string(&it["digest"]).to_lowercase() == hex::encode(digest),
        "copresence:intent_mismatch",
    )?;
    let side = it["side"].as_str();
    require(
        matches!(side, Some("A" | "B")) && is_hex(&it["salt"], 32),
        "copresence:malformed_intent",
    )?;
    let (side, other) = if side == Some("A") {
        ("A", "B")
    } else {
        ("B", "A")
    };
    let nonce = domain(
        "copresence.intent-nonce.v1",
        &[&digest, &decoded(&it["salt"])],
    );
    require(
        r[format!("nonce_{side}")]
            .as_str()
            .expect("checked nonce")
            .to_lowercase()
            == hex::encode(&nonce[..8]),
        "copresence:intent_not_committed",
    )?;
    let asker_key = r[format!("pk_{side}")]
        .as_str()
        .expect("checked key")
        .to_lowercase();
    let approver_key = r[format!("pk_{other}")]
        .as_str()
        .expect("checked key")
        .to_lowercase();
    require(
        asker_key != approver_key,
        "copresence:same_key_on_both_sides",
    )?;
    require(
        truthy(&it["ack"]) && is_hex(&it["ack"]["sig"], 128),
        "copresence:no_owner_signature",
    )?;
    let message = domain(
        "copresence.intent-ack.v1",
        &[
            &digest,
            &hex::decode(&asker_key).expect("checked key"),
            &decoded(&r[format!("nonce_{other}")]),
        ],
    );
    let (public, _) = key(&r[format!("pk_{other}")], other)?;
    require(
        signature_valid(&public, &message, &it["ack"]["sig"]),
        "copresence:bad_owner_signature",
    )?;
    require(
        options
            .approver
            .filter(|p| !p.is_empty())
            .is_none_or(|p| p.to_lowercase() == approver_key),
        "copresence:wrong_approver",
    )?;
    let t_b = r["t_B"].as_f64().expect("checked timestamp");
    if let Some(max_age) = options.max_age {
        let age = options.now - t_b;
        require(
            max_age >= 0.0 && age.partial_cmp(&max_age) != Some(std::cmp::Ordering::Greater),
            "copresence:stale_receipt",
        )?;
        require(
            age.partial_cmp(&-5.0) != Some(std::cmp::Ordering::Less),
            "copresence:receipt_from_the_future",
        )?;
    }
    Ok(VerifiedIntent {
        core: hex::encode(receipt.core),
        text_digest: hex::encode(digest),
        asker_key,
        approver_key,
        t_b,
    })
}

#[cfg(test)]
mod tests;
