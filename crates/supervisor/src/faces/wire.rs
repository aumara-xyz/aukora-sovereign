// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{refuse, MAX_REPLY_BYTES};
use canon::{
    frame::{Frame, FrameId},
    json::{SafeInteger, Value, ValueView},
    provenance::{Provenance, Source},
    Result,
};

pub fn object(fields: impl IntoIterator<Item = (&'static str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
pub fn text(value: impl Into<String>) -> Result<Value> {
    Value::text(value.into())
}
pub fn number(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        value
            .try_into()
            .map_err(|_| refuse("face-number-invalid"))?,
    )?))
}
pub fn bounded(value: Value) -> Result<Value> {
    if canon::json::to_canonical(&value).len() > MAX_REPLY_BYTES {
        return Err(refuse("face-reply-too-large"));
    }
    Ok(value)
}
pub fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    let ValueView::Object(fields) = value.view() else {
        return Err(refuse("face-shape-invalid"));
    };
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
        .ok_or(refuse("face-shape-invalid"))
}
pub fn exact(value: &Value, names: &[&str]) -> Result<()> {
    let ValueView::Object(fields) = value.view() else {
        return Err(refuse("face-shape-invalid"));
    };
    if fields.len() != names.len()
        || fields
            .iter()
            .any(|(name, _)| !names.contains(&name.as_str()))
    {
        return Err(refuse("face-shape-invalid"));
    }
    Ok(())
}
pub fn string(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(refuse("face-shape-invalid")),
    }
}
pub fn unsigned(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(number) => number
            .get()
            .try_into()
            .map_err(|_| refuse("face-shape-invalid")),
        _ => Err(refuse("face-shape-invalid")),
    }
}
pub fn optional_string(value: &Value) -> Result<Option<&str>> {
    match value.view() {
        ValueView::Null => Ok(None),
        _ => string(value).map(Some),
    }
}
pub fn boolean(value: &Value) -> Result<bool> {
    match value.view() {
        ValueView::Boolean(value) => Ok(value),
        _ => Err(refuse("face-shape-invalid")),
    }
}
pub fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(values) => Ok(values),
        _ => Err(refuse("face-shape-invalid")),
    }
}
fn frame<T>(body: T) -> Result<Frame<T>> {
    Ok(Frame {
        v: 2,
        id: FrameId::new("face".into())?,
        provenance: Provenance {
            source: Source::Auma,
        },
        body,
    })
}
fn envelope(kind: &str, body: Value) -> Result<Vec<u8>> {
    Ok(canon::json::to_canonical(&object([
        ("v", number(2)?),
        ("id", text("face")?),
        ("kind", text(kind)?),
        ("provenance", object([("source", text("auma")?)])?),
        ("body", body),
    ])?))
}
pub fn request(kind: &str, body: Value) -> Result<canon::fd3::Request> {
    Ok(canon::fd3::decode_request(
        &envelope(kind, body)?,
        Provenance {
            source: Source::Auma,
        },
    )?
    .body)
}
pub fn command(kind: &str, body: Value) -> Result<canon::fd4::ChatCommand> {
    Ok(canon::fd4::decode_command(
        &envelope(kind, body)?,
        Provenance {
            source: Source::Auma,
        },
    )?
    .body)
}
fn body(bytes: &[u8]) -> Result<Value> {
    field(&canon::json::parse_strict(bytes)?, "body").cloned()
}
pub fn reply(reply: canon::fd3::Reply) -> Result<Value> {
    body(&canon::fd3::encode_reply(&frame(reply)?)?)
}
pub fn event(event: canon::fd4::SessionEvent) -> Result<Value> {
    body(&canon::fd4::encode_event(&frame(event)?)?)
}

/// The owner's scoped session read may retain entries with owner provenance.
pub fn owner_event(event: canon::fd4::SessionEvent) -> Result<Value> {
    if !matches!(
        event,
        canon::fd4::SessionEvent::Opened(_) | canon::fd4::SessionEvent::Listed(_)
    ) {
        return Err(refuse("face-operation-unknown"));
    }
    let mut event = frame(event)?;
    event.provenance = Provenance {
        source: Source::Owner,
    };
    body(&canon::fd4::encode_event(&event)?)
}
