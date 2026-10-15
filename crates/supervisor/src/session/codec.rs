// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stored bodies reuse the FD codec; no second session schema is interpreted here.

use canon::{
    codes,
    digest::Digest32,
    fd3::{self, Reply},
    frame::{Frame, FrameId},
    json::{self, Value, ValueView},
    provenance::{Provenance, Source},
    session::{SessionAppended, SessionEntry},
    Result,
};

fn source() -> Provenance {
    Provenance {
        source: Source::Auma,
    }
}

pub(super) fn frame(reply: Reply) -> Result<Vec<u8>> {
    fd3::encode_reply(&Frame {
        v: 2,
        id: FrameId::new("s".repeat(64))?,
        provenance: source(),
        body: reply,
    })
}

pub(super) fn record(reply: Reply) -> Result<Vec<u8>> {
    let encoded = frame(reply)?;
    let value = json::parse_strict(&encoded)?;
    Ok(value
        .get("body")
        .ok_or(codes::SUPERVISOR_STATE)?
        .canonical_bytes())
}

pub(super) fn decode(bytes: &[u8], kind: &str) -> Result<Reply> {
    let body = canon::frame::decode(bytes)?;
    let envelope = Value::checked_object(vec![
        ("body".into(), body),
        ("id".into(), Value::checked_text("store".into())?),
        ("kind".into(), Value::checked_text(kind.into())?),
        (
            "provenance".into(),
            Value::checked_object(vec![("source".into(), Value::checked_text("auma".into())?)])?,
        ),
        ("v".into(), Value::integer(json::SafeInteger::new(2)?)),
    ])?;
    Ok(fd3::decode_reply(&envelope.canonical_bytes(), source())?.body)
}

pub(super) fn entry_commitment(entry: &SessionEntry) -> Result<Digest32> {
    let encoded = record(Reply::SessionAppended(SessionAppended {
        entry: entry.clone(),
    }))?;
    let body = json::parse_strict(&encoded)?;
    let fields = match body.get("entry").ok_or(codes::SUPERVISOR_STATE)?.view() {
        ValueView::Object(fields) => fields,
        _ => return Err(codes::SUPERVISOR_STATE),
    };
    let content = Value::checked_object(
        fields
            .iter()
            .filter(|(key, _)| key != "commitment")
            .cloned()
            .collect(),
    )?;
    Ok(Digest32::sha256(&content.canonical_bytes()))
}
