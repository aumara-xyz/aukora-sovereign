// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::provenance::Source;

pub(in crate::fd3) fn parse_summary(value: &Value) -> Result<SessionSummary> {
    let o = Object::new(
        value,
        &[
            "algorithm",
            "archived",
            "created_at_ms",
            "mode",
            "sequence",
            "session_id",
            "thread_id",
            "title",
            "updated_at_ms",
            "v",
        ],
        &[],
    )?;
    let algorithm = record_algorithm(&o)?;
    let archived = o.boolean("archived")?;
    let created_at_ms = o.count("created_at_ms", 0, MAX)?;
    let mode = mode(o.get("mode")?)?;
    let sequence = o.count("sequence", 0, MAX)?;
    let session_id = sid(o.get("session_id")?)?;
    let thread_id = tid(o.get("thread_id")?)?;
    let title = txt(o.get("title")?)?;
    let updated_at_ms = o.count("updated_at_ms", 0, MAX)?;
    record_version(&o)?;
    Ok(SessionSummary {
        v: RECORD_VERSION,
        algorithm,
        session_id,
        thread_id,
        title,
        mode,
        archived,
        sequence,
        created_at_ms,
        updated_at_ms,
    })
}
pub(in crate::fd3) fn summary_body(p: &SessionSummary) -> Result<Value> {
    object(vec![
        ("algorithm", s(p.algorithm.wire_name())),
        ("archived", Value::boolean(p.archived)),
        ("created_at_ms", n(p.created_at_ms)?),
        ("mode", s(mode_name(p.mode))),
        ("sequence", n(p.sequence)?),
        ("session_id", s(p.session_id)),
        ("thread_id", s(p.thread_id)),
        ("title", s(p.title.as_str())),
        ("updated_at_ms", n(p.updated_at_ms)?),
        ("v", n(p.v as u64)?),
    ])
}
fn role(value: &Value) -> Result<SessionRole> {
    match text(value)? {
        "owner" => Ok(SessionRole::Owner),
        "auma" => Ok(SessionRole::Auma),
        "tool" => Ok(SessionRole::Tool),
        "context" => Ok(SessionRole::Context),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
fn role_name(role: SessionRole) -> &'static str {
    match role {
        SessionRole::Owner => "owner",
        SessionRole::Auma => "auma",
        SessionRole::Tool => "tool",
        SessionRole::Context => "context",
    }
}
pub(in crate::fd3) fn parse_entry(
    value: &Value,
    ingress: Option<&Provenance>,
) -> Result<SessionEntry> {
    let o = Object::new(
        value,
        &[
            "algorithm",
            "at_ms",
            "commitment",
            "content",
            "role",
            "sequence",
            "session_id",
            "tool_call_id",
            "v",
            "provenance",
            "tool_calls",
        ],
        &[],
    )?;
    let algorithm = record_algorithm(&o)?;
    let at_ms = o.count("at_ms", 0, MAX)?;
    let commitment = o.digest("commitment")?;
    let content = txt(o.get("content")?)?;
    let role = role(o.get("role")?)?;
    let sequence = o.count("sequence", 1, MAX)?;
    let session_id = sid(o.get("session_id")?)?;
    let tool_call_id = nullable(o.get("tool_call_id")?, txt)?;
    record_version(&o)?;
    let provenance = crate::fd3::parse_provenance(o.get("provenance")?)?;
    if provenance.source == Source::Stranger
        || ingress.is_some_and(|trusted| *trusted != provenance)
        || (role == SessionRole::Owner && provenance.source != Source::Owner)
        || (role == SessionRole::Auma && provenance.source != Source::Auma)
    {
        return Err(codes::FRAME_PROVENANCE);
    }
    let tool_calls = Items::new(list(o.get("tool_calls")?, crate::fd3::v1::parse_tool_call)?)?;
    Ok(SessionEntry {
        v: RECORD_VERSION,
        algorithm,
        session_id,
        sequence,
        role,
        content,
        tool_calls,
        tool_call_id,
        provenance,
        at_ms,
        commitment,
    })
}
pub(in crate::fd3) fn entry_body(p: &SessionEntry) -> Result<Value> {
    object(vec![
        ("algorithm", s(p.algorithm.wire_name())),
        ("at_ms", n(p.at_ms)?),
        ("commitment", s(p.commitment)),
        ("content", s(p.content.as_str())),
        ("role", s(role_name(p.role))),
        ("sequence", n(p.sequence)?),
        ("session_id", s(p.session_id)),
        (
            "tool_call_id",
            maybe(p.tool_call_id.as_ref(), |v| Ok(s(v.as_str())))?,
        ),
        ("v", n(p.v as u64)?),
        ("provenance", crate::fd3::provenance_body(&p.provenance)?),
        (
            "tool_calls",
            array(p.tool_calls.as_slice(), crate::fd3::v1::tool_call_body)?,
        ),
    ])
}
