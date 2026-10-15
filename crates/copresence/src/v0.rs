// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen `copresence.v0` evidence. Hardened rules belong to `v1`.

use crate::{
    receipt_json::{self, Value},
    PublicKeyBytes, Refusal, Result,
};
use canon::digest::Digest32;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub use canon::domain::{
    COPRESENCE_CORE_DOMAIN as CORE_DOMAIN, COPRESENCE_INTENT_ACK_DOMAIN as INTENT_ACK_DOMAIN,
    COPRESENCE_INTENT_DOMAIN as INTENT_DOMAIN,
    COPRESENCE_INTENT_NONCE_DOMAIN as INTENT_NONCE_DOMAIN,
};

pub const MAX_WINDOW_SECONDS: u64 = 10;
pub const NONCE_BYTES: usize = 8;
pub const INTENT_SALT_BYTES: usize = 16;

/// V0 core layout: domain, NUL, pk_A, pk_B, nonce_A, nonce_B, BE64(t_B).
/// t_A remains outside the signed core; its window check is 0..=10 seconds.
/// Both signatures use P-256/SHA-256 over the 32-byte core digest as a message.
#[derive(Clone, Debug)]
pub struct CoreInput {
    pub pk_a: PublicKeyBytes,
    pub pk_b: PublicKeyBytes,
    pub nonce_a: [u8; NONCE_BYTES],
    pub nonce_b: [u8; NONCE_BYTES],
    pub t_b_seconds: u64,
}

/// Opaque verifier output. Neither public keys nor times identify a human.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    core: Digest32,
    pk_a: PublicKeyBytes,
    pk_b: PublicKeyBytes,
    t_a_seconds: f64,
    t_b_seconds: f64,
}

impl VerifiedReceipt {
    pub const fn core(&self) -> Digest32 {
        self.core
    }

    pub const fn public_keys(&self) -> (PublicKeyBytes, PublicKeyBytes) {
        (self.pk_a, self.pk_b)
    }

    pub const fn timestamps_seconds(&self) -> (f64, f64) {
        (self.t_a_seconds, self.t_b_seconds)
    }
}

/// Optional legacy intent freshness and expected approver, supplied by caller.
#[derive(Clone, Copy, Debug, Default)]
pub struct IntentOptions<'a> {
    pub approver_hex: Option<&'a str>,
    pub max_age_seconds: Option<f64>,
    pub now_seconds: f64,
}

/// Exact-text device acknowledgement evidence; no passkey approval is implied.
#[derive(Clone, Debug)]
pub struct VerifiedIntent {
    receipt: VerifiedReceipt,
    text_digest: Digest32,
    asker: PublicKeyBytes,
    approver: PublicKeyBytes,
}

impl VerifiedIntent {
    pub const fn receipt(&self) -> &VerifiedReceipt {
        &self.receipt
    }

    pub const fn text_digest(&self) -> Digest32 {
        self.text_digest
    }

    pub const fn participants(&self) -> (PublicKeyBytes, PublicKeyBytes) {
        (self.asker, self.approver)
    }
}

/// Computes the frozen v0 digest, retaining its unsigned t_A behavior.
pub fn core_digest(input: &CoreInput) -> Result<Digest32> {
    Ok(hash(
        CORE_DOMAIN,
        &[
            &input.pk_a.0,
            &input.pk_b.0,
            &input.nonce_a,
            &input.nonce_b,
            &input.t_b_seconds.to_be_bytes(),
        ],
    ))
}

/// V0 verification entry point. Refusal order and telemetry coercions follow
/// the pinned corpus; no hardened restrictions are retrofitted onto v0.
pub fn verify_receipt(bytes: &[u8]) -> Result<VerifiedReceipt> {
    validate(bytes).map(|(_, receipt)| receipt)
}

/// Adds exact text, nonce commitment and approver signature checks to v0.
/// Fixture text means TEXT.txt without its one trailing LF.
pub fn verify_intent(
    bytes: &[u8],
    expected_text: &str,
    options: IntentOptions<'_>,
) -> Result<VerifiedIntent> {
    let (value, receipt) = validate(bytes)?;
    let intent = field(&value, "intent");
    require(
        matches!(intent, Value::Object(_) | Value::Array(_)),
        "no_intent",
    )?;
    let text_digest = hash(INTENT_DOMAIN, &[expected_text.as_bytes()]);
    require(
        text_is(field(intent, "text"), expected_text)
            && js_string(field(intent, "digest")).to_lowercase() == text_digest.to_string(),
        "intent_mismatch",
    )?;
    let side_a = text_is(field(intent, "side"), "A");
    require(
        (side_a || text_is(field(intent, "side"), "B"))
            && hex_bytes::<INTENT_SALT_BYTES>(field(intent, "salt")).is_some(),
        "malformed_intent",
    )?;
    let salt =
        hex_bytes::<INTENT_SALT_BYTES>(field(intent, "salt")).ok_or(error("malformed_intent"))?;
    let committed = hash(INTENT_NONCE_DOMAIN, &[text_digest.as_bytes(), &salt]);
    let (asker, approver, asker_nonce, approver_nonce) = if side_a {
        (
            receipt.pk_a,
            receipt.pk_b,
            field(&value, "nonce_A"),
            field(&value, "nonce_B"),
        )
    } else {
        (
            receipt.pk_b,
            receipt.pk_a,
            field(&value, "nonce_B"),
            field(&value, "nonce_A"),
        )
    };
    require(
        hex_bytes::<NONCE_BYTES>(asker_nonce)
            .as_ref()
            .map(|n| n.as_slice())
            == Some(&committed.as_bytes()[..NONCE_BYTES]),
        "intent_not_committed",
    )?;
    require(asker != approver, "same_key_on_both_sides")?;
    let ack = field(intent, "ack");
    let sig = hex_bytes::<64>(field(ack, "sig"));
    require(truthy(ack) && sig.is_some(), "no_owner_signature")?;
    let nonce = hex_bytes::<NONCE_BYTES>(approver_nonce).ok_or(error("malformed_intent"))?;
    let message = hash(
        INTENT_ACK_DOMAIN,
        &[text_digest.as_bytes(), &asker.0, &nonce],
    );
    require(
        verify_signature(
            &approver,
            message.as_bytes(),
            &sig.ok_or(error("no_owner_signature"))?,
        ),
        "bad_owner_signature",
    )?;
    if let Some(expected) = options.approver_hex.filter(|s| !s.is_empty()) {
        require(
            expected.to_lowercase() == hex::encode(approver.0),
            "wrong_approver",
        )?;
    }
    if let Some(max_age) = options.max_age_seconds {
        let age = options.now_seconds - receipt.t_b_seconds;
        require(
            max_age >= 0.0 && age.partial_cmp(&max_age) != Some(std::cmp::Ordering::Greater),
            "stale_receipt",
        )?;
        require(
            age.partial_cmp(&-5.0) != Some(std::cmp::Ordering::Less),
            "receipt_from_the_future",
        )?;
    }
    Ok(VerifiedIntent {
        receipt,
        text_digest,
        asker,
        approver,
    })
}

fn error(reason: &'static str) -> Refusal {
    Refusal {
        organ: "copresence",
        reason,
    }
}

fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error(reason))
    }
}

fn hash(domain: &str, parts: &[&[u8]]) -> Digest32 {
    let mut state = Sha256::new();
    state.update(domain.as_bytes());
    state.update([0]);
    for part in parts {
        state.update(part);
    }
    Digest32::from_bytes(state.finalize().into())
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    static ABSENT: Value = Value::Null;
    if let Value::Object(entries) = value {
        entries
            .iter()
            .rev()
            .find(|(key, _)| key.iter().copied().eq(name.encode_utf16()))
            .map(|(_, value)| value)
            .unwrap_or(&ABSENT)
    } else {
        &ABSENT
    }
}

fn present<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    match value {
        Value::Object(entries) => entries
            .iter()
            .rev()
            .find(|(key, _)| key.iter().copied().eq(name.encode_utf16()))
            .map(|(_, v)| v),
        _ => None,
    }
}

fn text_is(value: &Value, expected: &str) -> bool {
    matches!(value, Value::Text(text) if text.iter().copied().eq(expected.encode_utf16()))
}

fn hex_bytes<const N: usize>(value: &Value) -> Option<[u8; N]> {
    let Value::Text(units) = value else {
        return None;
    };
    if units.len() != N * 2 {
        return None;
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(units.chunks_exact(2)) {
        let digit = |unit: u16| -> Option<u8> {
            match unit {
                48..=57 => Some((unit - 48) as u8),
                65..=70 => Some((unit - 55) as u8),
                97..=102 => Some((unit - 87) as u8),
                _ => None,
            }
        };
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Some(bytes)
}

fn public_key(value: &Value, a: bool) -> Result<PublicKeyBytes> {
    let malformed = if a {
        "malformed_public_key_A"
    } else {
        "malformed_public_key_B"
    };
    let bytes = hex_bytes::<65>(value)
        .filter(|b| b[0] == 4)
        .ok_or(error(malformed))?;
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| {
        error(if a {
            "invalid_public_key_A"
        } else {
            "invalid_public_key_B"
        })
    })?;
    Ok(PublicKeyBytes(bytes))
}

fn verify_signature(key: &PublicKeyBytes, message: &[u8], bytes: &[u8; 64]) -> bool {
    let Ok(public) = VerifyingKey::from_sec1_bytes(&key.0) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(bytes) else {
        return false;
    };
    public.verify(message, &sig).is_ok()
}

fn validate(bytes: &[u8]) -> Result<(Value, VerifiedReceipt)> {
    let value = receipt_json::read_legacy(bytes)?;
    require(
        matches!(field(&value, "v"), Value::Number(n) if *n == 0.0),
        "unsupported_version",
    )?;
    for name in [
        "v", "pk_A", "pk_B", "nonce_A", "nonce_B", "t_A", "t_B", "sig_A", "sig_B",
    ] {
        require(!matches!(field(&value, name), Value::Null), "missing_field")?;
    }
    let (Value::Number(t_a), Value::Number(t_b)) = (field(&value, "t_A"), field(&value, "t_B"))
    else {
        return Err(error("timestamps_must_be_numbers"));
    };
    let elapsed = t_b - t_a;
    require(
        elapsed.partial_cmp(&0.0) != Some(std::cmp::Ordering::Less),
        "negative_time_skew",
    )?;
    require(
        elapsed.partial_cmp(&(MAX_WINDOW_SECONDS as f64)) != Some(std::cmp::Ordering::Greater),
        "ceremony_window_exceeded",
    )?;
    let pk_a = public_key(field(&value, "pk_A"), true)?;
    let pk_b = public_key(field(&value, "pk_B"), false)?;
    let nonce_a =
        hex_bytes::<NONCE_BYTES>(field(&value, "nonce_A")).ok_or(error("malformed_nonce_A"))?;
    let nonce_b =
        hex_bytes::<NONCE_BYTES>(field(&value, "nonce_B")).ok_or(error("malformed_nonce_B"))?;
    require(
        t_b.is_finite() && t_b.fract() == 0.0 && (0.0..18_446_744_073_709_551_616.0).contains(t_b),
        "timestamp_encoding_error",
    )?;
    let core = core_digest(&CoreInput {
        pk_a,
        pk_b,
        nonce_a,
        nonce_b,
        t_b_seconds: *t_b as u64,
    })?;
    let sig_a = hex_bytes::<64>(field(&value, "sig_A")).ok_or(error("malformed_signature_A"))?;
    let sig_b = hex_bytes::<64>(field(&value, "sig_B")).ok_or(error("malformed_signature_B"))?;
    require(
        verify_signature(&pk_a, core.as_bytes(), &sig_a),
        "sig_A_invalid",
    )?;
    require(
        verify_signature(&pk_b, core.as_bytes(), &sig_b),
        "sig_B_invalid",
    )?;
    telemetry(&value)?;
    let receipt = VerifiedReceipt {
        core,
        pk_a,
        pk_b,
        t_a_seconds: *t_a,
        t_b_seconds: *t_b,
    };
    Ok((value, receipt))
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Boolean(b) => *b,
        Value::Number(n) => *n != 0.0 && !n.is_nan(),
        Value::Text(s) => !s.is_empty(),
        _ => true,
    }
}

fn js_string(value: &Value) -> String {
    let mut output = String::new();
    let mut pending = vec![(Some(value), false)];
    while let Some((next, array_item)) = pending.pop() {
        let Some(next) = next else {
            output.push(',');
            continue;
        };
        match next {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate().rev() {
                    pending.push((Some(item), true));
                    if index != 0 {
                        pending.push((None, false));
                    }
                }
            }
            Value::Null if array_item => {}
            Value::Null => output.push_str("null"),
            Value::Boolean(b) => output.push_str(if *b { "true" } else { "false" }),
            Value::Text(s) => output.push_str(&String::from_utf16_lossy(s)),
            Value::Object(_) => output.push_str("[object Object]"),
            Value::Number(n) => output.push_str(&number_text(*n)),
        }
    }
    output
}

fn number_text(number: f64) -> String {
    if number == 0.0 {
        return "0".into();
    }
    if number.is_nan() {
        return "NaN".into();
    }
    if number == f64::INFINITY {
        return "Infinity".into();
    }
    if number == f64::NEG_INFINITY {
        return "-Infinity".into();
    }
    let plain = number.to_string();
    if (1e-6..1e21).contains(&number.abs()) {
        return plain;
    }
    let unsigned = plain.trim_start_matches('-');
    let point = unsigned.find('.').unwrap_or(unsigned.len());
    let digits: String = unsigned.chars().filter(|c| *c != '.').collect();
    let first = digits.find(|c| c != '0').unwrap_or(0);
    let significant = digits[first..].trim_end_matches('0');
    let exponent = point as i32 - first as i32 - 1;
    let mut scientific = if number.is_sign_negative() {
        "-".to_owned()
    } else {
        String::new()
    };
    scientific.push_str(&significant[..1]);
    if significant.len() > 1 {
        scientific.push('.');
        scientific.push_str(&significant[1..]);
    }
    scientific.push('e');
    if exponent >= 0 {
        scientific.push('+');
    }
    scientific.push_str(&exponent.to_string());
    scientific
}

fn js_number(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Boolean(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Value::Number(n) => *n,
        Value::Object(_) => f64::NAN,
        other => {
            let text = js_string(other);
            let text = text.trim_matches(|c: char| {
                matches!(c,
                '\u{9}'..='\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' |
                '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
            });
            if text.is_empty() {
                return 0.0;
            }
            for (prefix, base) in [("0x", 16), ("0b", 2), ("0o", 8)] {
                if text
                    .get(..2)
                    .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
                {
                    let mut number = 0.0;
                    let digits = &text[2..];
                    if digits.is_empty() {
                        return f64::NAN;
                    }
                    for c in digits.chars() {
                        let Some(digit) = c.to_digit(base) else {
                            return f64::NAN;
                        };
                        number = number * f64::from(base) + f64::from(digit);
                    }
                    return number;
                }
            }
            match text {
                "Infinity" | "+Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                _ if text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b)) =>
                {
                    text.parse().unwrap_or(f64::NAN)
                }
                _ => f64::NAN,
            }
        }
    }
}

fn primitive_string(value: &Value) -> bool {
    matches!(value, Value::Text(_) | Value::Array(_) | Value::Object(_))
}

fn js_add(a: &Value, b: &Value) -> Value {
    if primitive_string(a) || primitive_string(b) {
        Value::Text((js_string(a) + &js_string(b)).encode_utf16().collect())
    } else {
        Value::Number(js_number(a) + js_number(b))
    }
}

fn coercible(value: &Value) -> bool {
    let mut pending = vec![value];
    while let Some(next) = pending.pop() {
        match next {
            Value::Object(_) if present(next, "toString").is_some() => return false,
            Value::Array(items) => pending.extend(items.iter()),
            _ => {}
        }
    }
    true
}

fn telemetry(value: &Value) -> Result<()> {
    let (a, b) = (field(value, "geo_A"), field(value, "geo_B"));
    if truthy(a) && truthy(b) {
        let coordinates = [
            field(a, "lat"),
            field(a, "lon"),
            field(b, "lat"),
            field(b, "lon"),
        ];
        require(
            coordinates.iter().all(|v| matches!(v, Value::Number(_))),
            "invalid_geo_coordinates",
        )?;
        let default = Value::Number(15.0);
        let (acc_a, acc_b) = (
            present(a, "acc").unwrap_or(&default),
            present(b, "acc").unwrap_or(&default),
        );
        require(
            coercible(acc_a) && coercible(acc_b),
            "telemetry_coercion_error",
        )?;
        require(
            !(js_number(acc_a) < 1.0 || js_number(acc_b) < 1.0),
            "suspicious_spoofed_accuracy",
        )?;
        let radians = |number: f64| (number * std::f64::consts::PI) / 180.0;
        let lat_a = radians(js_number(coordinates[0]));
        let lat_b = radians(js_number(coordinates[2]));
        let d_lat = radians(js_number(coordinates[2]) - js_number(coordinates[0]));
        let d_lon = radians(js_number(coordinates[3]) - js_number(coordinates[1]));
        let hav =
            (d_lat / 2.0).sin().powi(2) + lat_a.cos() * lat_b.cos() * (d_lon / 2.0).sin().powi(2);
        let distance = 12_742_000.0 * hav.sqrt().atan2((1.0 - hav).sqrt());
        let bound = js_number(&js_add(&js_add(acc_a, acc_b), &Value::Number(50.0)));
        let verdict = field(value, "sentinel_verdict");
        let consistent =
            text_is(verdict, "CONSISTENT_CLAIMED") || text_is(verdict, "GENUINE_LOCAL_PROXIMITY");
        require(
            !(consistent && distance > bound),
            "suspicious_spacetime_contradiction",
        )?;
    }
    let audio = field(value, "audio");
    if truthy(audio) {
        if let Some(nonce) = present(audio, "nonce") {
            require(hex_bytes::<16>(nonce).is_some(), "malformed_audio_nonce")?;
        }
        if let Some(matched) = present(audio, "matched") {
            require(
                matches!(matched, Value::Boolean(_)),
                "invalid_audio_matched",
            )?;
            require(
                !matches!(matched, Value::Boolean(false)),
                "suspicious_audio_nonce_mismatch",
            )?;
        }
        if let Some(delay) = present(audio, "delay_ms") {
            let Value::Number(delay) = delay else {
                return Err(error("invalid_audio_delay"));
            };
            require(*delay >= 5.0, "suspicious_audio_delay_impossible")?;
            require(*delay <= 150.0, "suspicious_audio_relay_detected")?;
        }
    }
    Ok(())
}
