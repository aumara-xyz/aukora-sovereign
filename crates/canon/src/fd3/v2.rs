// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{wire::*, Reply, Request};
use crate::{
    alg::AlgorithmId, codes, ids::*, json::Value, provenance::Provenance, session::*, Result,
};

mod models;
mod records;

pub(super) use records::{entry_body, parse_entry};

fn record_algorithm(o: &Object<'_>) -> Result<AlgorithmId> {
    let algorithm = AlgorithmId::from_wire(text(o.get("algorithm")?)?)
        .map_err(|_| codes::FRAME_INVALID_FIELD)?;
    if algorithm != AlgorithmId::Sha256 {
        return Err(codes::ALG_UNSUPPORTED);
    }
    Ok(algorithm)
}
fn record_version(o: &Object<'_>) -> Result<()> {
    if o.count("v", 0, MAX)? != RECORD_VERSION as u64 {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    Ok(())
}
fn mode(value: &Value) -> Result<SessionMode> {
    match text(value)? {
        "chat" => Ok(SessionMode::Chat),
        "build" => Ok(SessionMode::Build),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
fn mode_name(value: SessionMode) -> &'static str {
    match value {
        SessionMode::Chat => "chat",
        SessionMode::Build => "build",
    }
}
fn sid(value: &Value) -> Result<SessionId> {
    SessionId::from_hex(text(value)?).map_err(|_| codes::FRAME_INVALID_FIELD)
}
fn tid(value: &Value) -> Result<ThreadId> {
    ThreadId::from_hex(text(value)?).map_err(|_| codes::FRAME_INVALID_FIELD)
}
fn rid(value: &Value) -> Result<RequestId> {
    RequestId::from_hex(text(value)?).map_err(|_| codes::FRAME_INVALID_FIELD)
}
fn reservation(value: &Value) -> Result<ReservationId> {
    ReservationId::from_hex(text(value)?).map_err(|_| codes::FRAME_INVALID_FIELD)
}
fn txt<const N: usize>(value: &Value) -> Result<Text<N>> {
    Text::new(text(value)?.to_owned())
}

pub(super) fn parse_request(kind: &str, value: &Value, ingress: &Provenance) -> Result<Request> {
    Ok(match kind {
        "sites.propose" => Request::SitePropose(
            crate::fd3_payloads::sites::SiteProposal::from_fd3_body(value)?,
        ),
        "session.create" => {
            let o = Object::new(value, &["mode", "thread_id", "title"], &[])?;
            let mode = mode(o.get("mode")?)?;
            let thread_id = tid(o.get("thread_id")?)?;
            let title = txt(o.get("title")?)?;
            Request::SessionCreate(SessionCreate {
                thread_id,
                title,
                mode,
            })
        }
        "session.open" => {
            let o = Object::new(value, &["after_sequence", "limit", "session_id"], &[])?;
            let after_sequence = o.count("after_sequence", 0, MAX)?;
            let limit = o.count("limit", 1, MAX_SESSION_PAGE as u64)? as u16;
            let session_id = sid(o.get("session_id")?)?;
            Request::SessionOpen(SessionOpen {
                session_id,
                after_sequence,
                limit,
            })
        }
        "session.list" => {
            let o = Object::new(
                value,
                &["before", "include_archived", "limit", "thread_id"],
                &[],
            )?;
            let before = nullable(o.get("before")?, sid)?;
            let include_archived = o.boolean("include_archived")?;
            let limit = o.count("limit", 1, MAX_SESSION_PAGE as u64)? as u16;
            let thread_id = nullable(o.get("thread_id")?, tid)?;
            Request::SessionList(SessionList {
                thread_id,
                include_archived,
                before,
                limit,
            })
        }
        "session.append" => {
            let o = Object::new(value, &["expected_sequence", "session_id", "entry"], &[])?;
            let expected_sequence = o.count("expected_sequence", 0, MAX - 1)?;
            let session_id = sid(o.get("session_id")?)?;
            let entry = parse_entry(o.get("entry")?, Some(ingress))?;
            if entry.sequence != expected_sequence + 1 || entry.session_id != session_id {
                return Err(codes::SESSION_SEQUENCE);
            }
            Request::SessionAppend(SessionAppend {
                session_id,
                expected_sequence,
                entry,
            })
        }
        "session.flush" => {
            let o = Object::new(value, &["session_id", "through_sequence"], &[])?;
            let session_id = sid(o.get("session_id")?)?;
            let through_sequence = o.count("through_sequence", 0, MAX)?;
            Request::SessionFlush(SessionFlush {
                session_id,
                through_sequence,
            })
        }
        "model.start" => {
            let o = Object::new(
                value,
                &["max_pending_chunks", "request_id", "reservation_id", "call"],
                &[],
            )?;
            let max_pending_chunks =
                o.count("max_pending_chunks", 1, MAX_PENDING_CHUNKS as u64)? as u16;
            let request_id = rid(o.get("request_id")?)?;
            let reservation_id = reservation(o.get("reservation_id")?)?;
            let call = super::v1::parse_model_call(o.get("call")?)?;
            Request::ModelStart(ModelStart {
                request_id,
                reservation_id,
                call,
                max_pending_chunks,
            })
        }
        "model.cancel" => {
            let o = Object::new(value, &["request_id", "reservation_id"], &[])?;
            let request_id = rid(o.get("request_id")?)?;
            let reservation_id = reservation(o.get("reservation_id")?)?;
            Request::ModelCancel(ModelCancel {
                request_id,
                reservation_id,
            })
        }
        _ => return Err(codes::FRAME_UNKNOWN_KIND),
    })
}
pub(super) fn request_body(request: &Request) -> Result<Value> {
    match request {
        Request::SitePropose(proposal) => proposal.fd3_body(),
        Request::SessionCreate(p) => object(vec![
            ("mode", s(mode_name(p.mode))),
            ("thread_id", s(p.thread_id)),
            ("title", s(p.title.as_str())),
        ]),
        Request::SessionOpen(p) => object(vec![
            ("after_sequence", n(p.after_sequence)?),
            ("limit", n(p.limit as u64)?),
            ("session_id", s(p.session_id)),
        ]),
        Request::SessionList(p) => object(vec![
            ("before", maybe(p.before.as_ref(), |v| Ok(s(v)))?),
            ("include_archived", Value::boolean(p.include_archived)),
            ("limit", n(p.limit as u64)?),
            ("thread_id", maybe(p.thread_id.as_ref(), |v| Ok(s(v)))?),
        ]),
        Request::SessionAppend(p) => object(vec![
            ("expected_sequence", n(p.expected_sequence)?),
            ("session_id", s(p.session_id)),
            ("entry", entry_body(&p.entry)?),
        ]),
        Request::SessionFlush(p) => object(vec![
            ("session_id", s(p.session_id)),
            ("through_sequence", n(p.through_sequence)?),
        ]),
        Request::ModelStart(p) => object(vec![
            ("max_pending_chunks", n(p.max_pending_chunks as u64)?),
            ("request_id", s(p.request_id)),
            ("reservation_id", s(p.reservation_id)),
            ("call", super::v1::model_call_body(&p.call)?),
        ]),
        Request::ModelCancel(p) => object(vec![
            ("request_id", s(p.request_id)),
            ("reservation_id", s(p.reservation_id)),
        ]),
        _ => Err(codes::FRAME_UNKNOWN_KIND),
    }
}
pub(super) fn parse_reply(kind: &str, value: &Value, _ingress: &Provenance) -> Result<Reply> {
    match kind {
        "session.create" => Ok(Reply::SessionCreated(records::parse_summary(value)?)),
        "session.open" => {
            let o = Object::new(value, &["next_sequence", "entries", "summary"], &[])?;
            let next_sequence = nullable(o.get("next_sequence")?, |v| count(v, 1, MAX))?;
            let entries = Items::new(list(o.get("entries")?, |v| parse_entry(v, None))?)?;
            let summary = records::parse_summary(o.get("summary")?)?;
            let items = entries.as_slice();
            let expected_next = items
                .last()
                .filter(|last| last.sequence < summary.sequence)
                .map(|last| last.sequence);
            if items.iter().any(|entry| {
                entry.session_id != summary.session_id || entry.sequence > summary.sequence
            }) || items
                .windows(2)
                .any(|pair| pair[1].sequence != pair[0].sequence + 1)
                || next_sequence != expected_next
            {
                return Err(codes::SESSION_SEQUENCE);
            }
            Ok(Reply::SessionOpened(SessionOpened {
                summary,
                entries,
                next_sequence,
            }))
        }
        "session.list" => {
            let o = Object::new(value, &["next", "items"], &[])?;
            let next = nullable(o.get("next")?, sid)?;
            let items = Items::new(list(o.get("items")?, records::parse_summary)?)?;
            if next.is_some_and(|next| {
                items
                    .as_slice()
                    .last()
                    .is_none_or(|last| last.session_id != next)
            }) {
                return Err(codes::SESSION_SEQUENCE);
            }
            Ok(Reply::SessionList(SessionPage { items, next }))
        }
        "session.append" => {
            let o = Object::new(value, &["entry"], &[])?;
            Ok(Reply::SessionAppended(SessionAppended {
                entry: parse_entry(o.get("entry")?, None)?,
            }))
        }
        "session.flush" => {
            let o = Object::new(
                value,
                &["algorithm", "commitment", "sequence", "session_id", "v"],
                &[],
            )?;
            let algorithm = record_algorithm(&o)?;
            let commitment = o.digest("commitment")?;
            let sequence = o.count("sequence", 0, MAX)?;
            let session_id = sid(o.get("session_id")?)?;
            record_version(&o)?;
            Ok(Reply::SessionFlushed(SessionFlushed {
                v: RECORD_VERSION,
                algorithm,
                session_id,
                sequence,
                commitment,
            }))
        }
        _ => models::parse_reply(kind, value),
    }
}
pub(super) fn reply_body(reply: &Reply) -> Result<Value> {
    match reply {
        Reply::SessionCreated(p) => records::summary_body(p),
        Reply::SessionOpened(p) => object(vec![
            ("next_sequence", maybe(p.next_sequence.as_ref(), |v| n(*v))?),
            ("entries", array(p.entries.as_slice(), entry_body)?),
            ("summary", records::summary_body(&p.summary)?),
        ]),
        Reply::SessionList(p) => object(vec![
            ("next", maybe(p.next.as_ref(), |v| Ok(s(v)))?),
            ("items", array(p.items.as_slice(), records::summary_body)?),
        ]),
        Reply::SessionAppended(p) => object(vec![("entry", entry_body(&p.entry)?)]),
        Reply::SessionFlushed(p) => object(vec![
            ("algorithm", s(p.algorithm.wire_name())),
            ("commitment", s(p.commitment)),
            ("sequence", n(p.sequence)?),
            ("session_id", s(p.session_id)),
            ("v", n(p.v as u64)?),
        ]),
        _ => models::reply_body(reply),
    }
}
