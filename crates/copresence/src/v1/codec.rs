// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::{
    receipt_json::{read_hardened, Value, HARDENED_LIMITS},
    Side,
};

pub(crate) fn text(value: impl AsRef<str>) -> Value {
    Value::Text(value.as_ref().encode_utf16().collect())
}

pub(crate) fn number(value: u64) -> Result<Value> {
    crypto::integer(value)?;
    Ok(Value::Number(value as f64))
}

pub(crate) fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.encode_utf16().collect(), value))
            .collect(),
    )
}

pub(crate) fn hex_value(bytes: &[u8]) -> Value {
    text(hex::encode(bytes))
}

fn digest_value(value: Digest32) -> Value {
    hex_value(value.as_bytes())
}

fn option_digest(value: Option<Digest32>) -> Value {
    value.map_or(Value::Null, digest_value)
}

fn participant_value(value: &Participant) -> Result<Value> {
    crypto::validate_participant(value)?;
    Ok(object([
        ("node", hex_value(value.node.as_bytes())),
        ("device_key", hex_value(&value.device_key.0)),
        ("device_epoch", number(value.device_epoch)?),
        ("session_id", hex_value(&value.session_id)),
        ("attempt_sequence", number(value.attempt_sequence)?),
    ]))
}

fn method_value(value: Method) -> Value {
    text(match value {
        Method::ScreenToScreen => "screen-to-screen",
        Method::Remote => "remote",
        Method::Relayed => "relayed",
    })
}

fn layers_value(value: RequiredLayers) -> Value {
    object([
        ("sound", Value::Boolean(value.sound)),
        ("motion", Value::Boolean(value.motion)),
        ("intent_ack", Value::Boolean(value.intent_ack)),
    ])
}

pub(crate) fn context_value(value: &Context) -> Result<Value> {
    crypto::validate_context(value)?;
    Ok(object([
        ("a", participant_value(&value.a)?),
        ("b", participant_value(&value.b)?),
        ("method", method_value(value.method)),
        ("required_layers", layers_value(value.required_layers)),
        ("purpose", text(&value.purpose)),
        ("intent", option_digest(value.intent)),
    ]))
}

fn channels_value(value: &ChannelCommitments) -> Value {
    object([
        ("sound", option_digest(value.sound)),
        ("motion", option_digest(value.motion)),
    ])
}

fn core_value(value: &CoreInput) -> Result<Value> {
    crypto::core(value)?;
    Ok(object([
        ("context", context_value(&value.context)?),
        ("nonce_a", hex_value(&value.nonce_a)),
        ("nonce_b", hex_value(&value.nonce_b)),
        ("t_a_seconds", number(value.t_a_seconds)?),
        ("t_b_seconds", number(value.t_b_seconds)?),
        ("transcript", digest_value(value.transcript)),
        ("channels", channels_value(&value.channels)),
    ]))
}

fn side_value(value: Side) -> Value {
    text(match value {
        Side::A => "A",
        Side::B => "B",
    })
}

fn body_value(value: &FrameBody) -> Result<Value> {
    match value {
        FrameBody::Face(face) => Ok(object([
            ("type", text("FACE")),
            ("participant", participant_value(&face.participant)?),
            ("method", method_value(face.method)),
            ("required_layers", layers_value(face.required_layers)),
            ("nonce_commitment", digest_value(face.nonce_commitment)),
            ("t_seconds", number(face.t_seconds)?),
            ("frame_index", number(face.frame_index)?),
        ])),
        FrameBody::SeenYou(seen) => Ok(object([
            ("type", text("SEENYOU")),
            ("context", context_value(&seen.context)?),
            ("sender", side_value(seen.sender)),
            ("face_a", digest_value(seen.face_a)),
            ("face_b", digest_value(seen.face_b)),
            ("nonce", hex_value(&seen.nonce)),
            ("t_seconds", number(seen.t_seconds)?),
            ("frame_index", number(seen.frame_index)?),
        ])),
        FrameBody::Handshake(handshake) => Ok(object([
            ("type", text("HANDSHAKE")),
            ("core", core_value(&handshake.core)?),
            ("sig_b", hex_value(&handshake.sig_b.0)),
            ("t_seconds", number(handshake.t_seconds)?),
            ("frame_index", number(handshake.frame_index)?),
        ])),
        FrameBody::Bloom(bloom) => Ok(object([
            ("type", text("BLOOM")),
            ("context", digest_value(bloom.context)),
            ("core", digest_value(bloom.core)),
            ("sig_a", hex_value(&bloom.sig_a.0)),
            ("t_seconds", number(bloom.t_seconds)?),
            ("frame_index", number(bloom.frame_index)?),
        ])),
    }
}

pub(crate) fn unsigned(value: &FrameBody) -> Result<Vec<u8>> {
    canonical(&body_value(value)?)
}

pub(crate) fn encode_frame(frame: &SignedFrame) -> Result<Vec<u8>> {
    canonical(&object([
        ("schema", text(FRAME_SCHEMA)),
        (
            "body",
            object([
                ("body", body_value(&frame.body)?),
                ("signature", hex_value(&frame.signature.0)),
            ]),
        ),
    ]))
}

pub(crate) fn read_frame(bytes: &[u8]) -> Result<SignedFrame> {
    let value = read_hardened(bytes, HARDENED_LIMITS)?;
    fields(&value, &["schema", "body"])?;
    if string(get(&value, "schema")?)? != FRAME_SCHEMA {
        return Err(crypto::refusal("frame-schema"));
    }
    let signed = get(&value, "body")?;
    fields(signed, &["body", "signature"])?;
    let body = get(signed, "body")?;
    let frame = SignedFrame {
        body: parse_body(body)?,
        signature: SignatureBytes(raw(get(signed, "signature")?)?),
    };
    if encode_frame(&frame)? != bytes {
        return Err(crypto::refusal("frame-not-canonical"));
    }
    Ok(frame)
}

fn parse_body(value: &Value) -> Result<FrameBody> {
    match string(get(value, "type")?)?.as_str() {
        "FACE" => {
            fields(
                value,
                &[
                    "type",
                    "participant",
                    "method",
                    "required_layers",
                    "nonce_commitment",
                    "t_seconds",
                    "frame_index",
                ],
            )?;
            Ok(FrameBody::Face(Face {
                participant: participant(get(value, "participant")?)?,
                method: method(get(value, "method")?)?,
                required_layers: layers(get(value, "required_layers")?)?,
                nonce_commitment: digest(get(value, "nonce_commitment")?)?,
                t_seconds: uint(get(value, "t_seconds")?)?,
                frame_index: uint(get(value, "frame_index")?)?,
            }))
        }
        "SEENYOU" => {
            fields(
                value,
                &[
                    "type",
                    "context",
                    "sender",
                    "face_a",
                    "face_b",
                    "nonce",
                    "t_seconds",
                    "frame_index",
                ],
            )?;
            Ok(FrameBody::SeenYou(SeenYou {
                context: context(get(value, "context")?)?,
                sender: side(get(value, "sender")?)?,
                face_a: digest(get(value, "face_a")?)?,
                face_b: digest(get(value, "face_b")?)?,
                nonce: raw(get(value, "nonce")?)?,
                t_seconds: uint(get(value, "t_seconds")?)?,
                frame_index: uint(get(value, "frame_index")?)?,
            }))
        }
        "HANDSHAKE" => {
            fields(
                value,
                &["type", "core", "sig_b", "t_seconds", "frame_index"],
            )?;
            Ok(FrameBody::Handshake(Handshake {
                core: core(get(value, "core")?)?,
                sig_b: SignatureBytes(raw(get(value, "sig_b")?)?),
                t_seconds: uint(get(value, "t_seconds")?)?,
                frame_index: uint(get(value, "frame_index")?)?,
            }))
        }
        "BLOOM" => {
            fields(
                value,
                &[
                    "type",
                    "context",
                    "core",
                    "sig_a",
                    "t_seconds",
                    "frame_index",
                ],
            )?;
            Ok(FrameBody::Bloom(Bloom {
                context: digest(get(value, "context")?)?,
                core: digest(get(value, "core")?)?,
                sig_a: SignatureBytes(raw(get(value, "sig_a")?)?),
                t_seconds: uint(get(value, "t_seconds")?)?,
                frame_index: uint(get(value, "frame_index")?)?,
            }))
        }
        _ => Err(crypto::refusal("frame-type")),
    }
}

pub(crate) fn read_receipt(bytes: &[u8]) -> Result<ReceiptBody> {
    let value = read_hardened(bytes, HARDENED_LIMITS)?;
    fields(&value, &["schema", "body"])?;
    if string(get(&value, "schema")?)? != RECEIPT_SCHEMA {
        return Err(crypto::refusal("receipt-schema"));
    }
    let body = get(&value, "body")?;
    fields(body, &["core", "sig_a", "sig_b", "intent_ack"])?;
    if canonical(&value)? != bytes {
        return Err(crypto::refusal("receipt-not-canonical"));
    }
    let intent_ack = match get(body, "intent_ack")? {
        Value::Null => None,
        value => {
            fields(value, &["by", "intent", "core", "context", "signature"])?;
            Some(IntentAcknowledgement {
                by: side(get(value, "by")?)?,
                intent: digest(get(value, "intent")?)?,
                core: digest(get(value, "core")?)?,
                context: digest(get(value, "context")?)?,
                signature: SignatureBytes(raw(get(value, "signature")?)?),
            })
        }
    };
    Ok(ReceiptBody {
        core: core(get(body, "core")?)?,
        sig_a: SignatureBytes(raw(get(body, "sig_a")?)?),
        sig_b: SignatureBytes(raw(get(body, "sig_b")?)?),
        intent_ack,
    })
}

pub(crate) fn fields(value: &Value, expected: &[&str]) -> Result<()> {
    let Value::Object(entries) = value else {
        return Err(crypto::refusal("field-type"));
    };
    if entries.len() != expected.len() || expected.iter().any(|key| get(value, key).is_err()) {
        return Err(crypto::refusal("fields"));
    }
    Ok(())
}

pub(crate) fn get<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    let Value::Object(entries) = value else {
        return Err(crypto::refusal("field-type"));
    };
    let name: Vec<u16> = key.encode_utf16().collect();
    entries
        .iter()
        .find(|(key, _)| key == &name)
        .map(|(_, value)| value)
        .ok_or(crypto::refusal("field-missing"))
}

pub(crate) fn string(value: &Value) -> Result<String> {
    let Value::Text(units) = value else {
        return Err(crypto::refusal("field-type"));
    };
    String::from_utf16(units).map_err(|_| crypto::refusal("string"))
}

pub(crate) fn raw<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let value = string(value)?;
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crypto::refusal("hex"));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| crypto::refusal("hex"))?;
    Ok(bytes)
}

fn digest(value: &Value) -> Result<Digest32> {
    Ok(Digest32::from_bytes(raw(value)?))
}

fn optional_digest(value: &Value) -> Result<Option<Digest32>> {
    match value {
        Value::Null => Ok(None),
        value => digest(value).map(Some),
    }
}

pub(crate) fn uint(value: &Value) -> Result<u64> {
    if let Value::Integer(value) = value {
        crypto::integer(*value)?;
        return Ok(*value);
    }
    let Value::Number(value) = value else {
        return Err(crypto::refusal("field-type"));
    };
    if !value.is_finite()
        || value.is_sign_negative()
        || value.fract() != 0.0
        || *value > crypto::MAX_INTEGER as f64
    {
        return Err(crypto::refusal("integer-range"));
    }
    Ok(*value as u64)
}

fn boolean(value: &Value) -> Result<bool> {
    if let Value::Boolean(value) = value {
        Ok(*value)
    } else {
        Err(crypto::refusal("field-type"))
    }
}

fn method(value: &Value) -> Result<Method> {
    match string(value)?.as_str() {
        "screen-to-screen" => Ok(Method::ScreenToScreen),
        "remote" => Ok(Method::Remote),
        "relayed" => Ok(Method::Relayed),
        _ => Err(crypto::refusal("method")),
    }
}

fn side(value: &Value) -> Result<Side> {
    match string(value)?.as_str() {
        "A" => Ok(Side::A),
        "B" => Ok(Side::B),
        _ => Err(crypto::refusal("side")),
    }
}

fn layers(value: &Value) -> Result<RequiredLayers> {
    fields(value, &["sound", "motion", "intent_ack"])?;
    Ok(RequiredLayers {
        sound: boolean(get(value, "sound")?)?,
        motion: boolean(get(value, "motion")?)?,
        intent_ack: boolean(get(value, "intent_ack")?)?,
    })
}

fn participant(value: &Value) -> Result<Participant> {
    fields(
        value,
        &[
            "node",
            "device_key",
            "device_epoch",
            "session_id",
            "attempt_sequence",
        ],
    )?;
    let value = Participant {
        node: NodeId::from_bytes(raw(get(value, "node")?)?),
        device_key: PublicKeyBytes(raw(get(value, "device_key")?)?),
        device_epoch: uint(get(value, "device_epoch")?)?,
        session_id: raw(get(value, "session_id")?)?,
        attempt_sequence: uint(get(value, "attempt_sequence")?)?,
    };
    crypto::validate_participant(&value)?;
    Ok(value)
}

pub(crate) fn context(value: &Value) -> Result<Context> {
    fields(
        value,
        &["a", "b", "method", "required_layers", "purpose", "intent"],
    )?;
    let value = Context {
        a: participant(get(value, "a")?)?,
        b: participant(get(value, "b")?)?,
        method: method(get(value, "method")?)?,
        required_layers: layers(get(value, "required_layers")?)?,
        purpose: string(get(value, "purpose")?)?,
        intent: optional_digest(get(value, "intent")?)?,
    };
    crypto::validate_context(&value)?;
    Ok(value)
}

fn core(value: &Value) -> Result<CoreInput> {
    fields(
        value,
        &[
            "context",
            "nonce_a",
            "nonce_b",
            "t_a_seconds",
            "t_b_seconds",
            "transcript",
            "channels",
        ],
    )?;
    let channels = get(value, "channels")?;
    fields(channels, &["sound", "motion"])?;
    let value = CoreInput {
        context: context(get(value, "context")?)?,
        nonce_a: raw(get(value, "nonce_a")?)?,
        nonce_b: raw(get(value, "nonce_b")?)?,
        t_a_seconds: uint(get(value, "t_a_seconds")?)?,
        t_b_seconds: uint(get(value, "t_b_seconds")?)?,
        transcript: digest(get(value, "transcript")?)?,
        channels: ChannelCommitments {
            sound: optional_digest(get(channels, "sound")?)?,
            motion: optional_digest(get(channels, "motion")?)?,
        },
    };
    crypto::core(&value)?;
    Ok(value)
}

pub(crate) fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    write(value, &mut bytes)?;
    if bytes.len() > HARDENED_LIMITS.max_bytes {
        return Err(crypto::refusal("json-limit"));
    }
    Ok(bytes)
}

fn quoted(units: &[u16], bytes: &mut Vec<u8>) -> Result<()> {
    let value = String::from_utf16(units).map_err(|_| crypto::refusal("string"))?;
    bytes.push(b'"');
    for character in value.chars() {
        match character {
            '"' => bytes.extend_from_slice(b"\\\""),
            '\\' => bytes.extend_from_slice(b"\\\\"),
            '\u{8}' => bytes.extend_from_slice(b"\\b"),
            '\u{c}' => bytes.extend_from_slice(b"\\f"),
            '\n' => bytes.extend_from_slice(b"\\n"),
            '\r' => bytes.extend_from_slice(b"\\r"),
            '\t' => bytes.extend_from_slice(b"\\t"),
            character if character < ' ' => {
                bytes.extend_from_slice(format!("\\u{:04x}", character as u32).as_bytes())
            }
            character => {
                let mut buffer = [0; 4];
                bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    bytes.push(b'"');
    Ok(())
}

fn write(value: &Value, bytes: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => bytes.extend_from_slice(b"null"),
        Value::Boolean(value) => bytes.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(_) | Value::Integer(_) => {
            bytes.extend_from_slice(uint(value)?.to_string().as_bytes())
        }
        Value::Text(value) => quoted(value, bytes)?,
        Value::Array(values) => {
            bytes.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                write(value, bytes)?;
            }
            bytes.push(b']');
        }
        Value::Object(values) => {
            let mut values: Vec<_> = values.iter().collect();
            values.sort_by(|(a, _), (b, _)| a.cmp(b));
            bytes.push(b'{');
            for (index, (key, value)) in values.into_iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                quoted(key, bytes)?;
                bytes.push(b':');
                write(value, bytes)?;
            }
            bytes.push(b'}');
        }
    }
    Ok(())
}

/// Encodes the frozen receipt envelope without adding context fields.
pub(crate) fn encode_receipt(body: &ReceiptBody) -> Result<Vec<u8>> {
    let ack = match &body.intent_ack {
        None => Value::Null,
        Some(ack) => object([
            ("by", side_value(ack.by)),
            ("intent", digest_value(ack.intent)),
            ("core", digest_value(ack.core)),
            ("context", digest_value(ack.context)),
            ("signature", hex_value(&ack.signature.0)),
        ]),
    };
    canonical(&object([
        ("schema", text(RECEIPT_SCHEMA)),
        (
            "body",
            object([
                ("core", core_value(&body.core)?),
                ("sig_a", hex_value(&body.sig_a.0)),
                ("sig_b", hex_value(&body.sig_b.0)),
                ("intent_ack", ack),
            ]),
        ),
    ]))
}
