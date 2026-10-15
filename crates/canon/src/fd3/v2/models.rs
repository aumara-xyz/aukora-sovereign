// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::fd3::v1::{parse_tool_call, parse_usage, tool_call_body, usage_body};

fn parse_receipt(value: &Value) -> Result<ModelReceipt> {
    let o = Object::new(
        value,
        &[
            "algorithm",
            "commitment",
            "model",
            "receipt_seq",
            "request_id",
            "reservation_id",
            "v",
            "usage",
        ],
        &[],
    )?;
    let algorithm = record(&o)?;
    let commitment = o.digest("commitment")?;
    let model = txt(o.get("model")?)?;
    let receipt_seq = o.count("receipt_seq", 1, MAX)?;
    let request_id = rid(o.get("request_id")?)?;
    let reservation_id = reservation(o.get("reservation_id")?)?;
    let usage = parse_usage(o.get("usage")?)?;
    Ok(ModelReceipt {
        v: RECORD_VERSION,
        algorithm,
        request_id,
        reservation_id,
        model,
        usage,
        receipt_seq,
        commitment,
    })
}
fn receipt_body(p: &ModelReceipt) -> Result<Value> {
    object(vec![
        ("algorithm", s(p.algorithm.wire_name())),
        ("commitment", s(p.commitment)),
        ("model", s(p.model.as_str())),
        ("receipt_seq", n(p.receipt_seq)?),
        ("request_id", s(p.request_id)),
        ("reservation_id", s(p.reservation_id)),
        ("v", n(p.v as u64)?),
        ("usage", usage_body(&p.usage)?),
    ])
}
fn check_receipt(
    receipt: &ModelReceipt,
    request: RequestId,
    reservation: ReservationId,
) -> Result<()> {
    if receipt.request_id != request || receipt.reservation_id != reservation {
        return Err(codes::FRAME_STREAM_ORDER);
    }
    Ok(())
}
pub(super) fn parse_reply(kind: &str, value: &Value) -> Result<Reply> {
    Ok(match kind {
        "model.start" => {
            let o = Object::new(
                value,
                &["max_pending_chunks", "request_id", "reservation_id"],
                &[],
            )?;
            let max_pending_chunks =
                o.count("max_pending_chunks", 1, MAX_PENDING_CHUNKS as u64)? as u16;
            let request_id = rid(o.get("request_id")?)?;
            let reservation_id = reservation(o.get("reservation_id")?)?;
            Reply::ModelStarted(ModelStarted {
                request_id,
                reservation_id,
                max_pending_chunks,
            })
        }
        "model.delta" => {
            let o = Object::new(
                value,
                &[
                    "algorithm",
                    "content",
                    "index",
                    "request_id",
                    "reservation_id",
                    "v",
                    "tool_calls",
                ],
                &[],
            )?;
            let algorithm = record(&o)?;
            let content = nullable(o.get("content")?, txt)?;
            let index = o.count("index", 0, MAX)?;
            let request_id = rid(o.get("request_id")?)?;
            let reservation_id = reservation(o.get("reservation_id")?)?;
            let tool_calls = Items::new(list(o.get("tool_calls")?, parse_tool_call)?)?;
            Reply::ModelDelta(ModelDelta {
                v: RECORD_VERSION,
                algorithm,
                request_id,
                reservation_id,
                index,
                content,
                tool_calls,
            })
        }
        "model.end" | "model.cancel" => {
            let o = Object::new(
                value,
                &[
                    "finish_reason",
                    "next_index",
                    "request_id",
                    "reservation_id",
                    "receipt",
                ],
                &[],
            )?;
            let finish_reason = nullable(o.get("finish_reason")?, txt)?;
            let next_index = o.count("next_index", 0, MAX)?;
            let request_id = rid(o.get("request_id")?)?;
            let reservation_id = reservation(o.get("reservation_id")?)?;
            let receipt = parse_receipt(o.get("receipt")?)?;
            check_receipt(&receipt, request_id, reservation_id)?;
            let end = ModelEnd {
                request_id,
                reservation_id,
                next_index,
                finish_reason,
                receipt,
            };
            if kind == "model.end" {
                Reply::ModelEnd(end)
            } else {
                Reply::ModelCancelled(end)
            }
        }
        "model.error" => {
            let o = Object::new(
                value,
                &[
                    "code",
                    "next",
                    "next_index",
                    "request_id",
                    "reservation_id",
                    "receipt",
                ],
                &[],
            )?;
            let code = codes::parse(text(o.get("code")?)?)?;
            let next = txt(o.get("next")?)?;
            let next_index = o.count("next_index", 0, MAX)?;
            let request_id = rid(o.get("request_id")?)?;
            let reservation_id = reservation(o.get("reservation_id")?)?;
            let receipt = parse_receipt(o.get("receipt")?)?;
            check_receipt(&receipt, request_id, reservation_id)?;
            Reply::ModelError(ModelError {
                request_id,
                reservation_id,
                next_index,
                code,
                next,
                receipt,
            })
        }
        _ => return Err(codes::FRAME_UNKNOWN_KIND),
    })
}
pub(super) fn reply_body(reply: &Reply) -> Result<Value> {
    match reply {
        Reply::ModelStarted(p) => object(vec![
            ("max_pending_chunks", n(p.max_pending_chunks as u64)?),
            ("request_id", s(p.request_id)),
            ("reservation_id", s(p.reservation_id)),
        ]),
        Reply::ModelDelta(p) => object(vec![
            ("algorithm", s(p.algorithm.wire_name())),
            ("content", maybe(p.content.as_ref(), |v| Ok(s(v.as_str())))?),
            ("index", n(p.index)?),
            ("request_id", s(p.request_id)),
            ("reservation_id", s(p.reservation_id)),
            ("v", n(p.v as u64)?),
            (
                "tool_calls",
                array(p.tool_calls.as_slice(), tool_call_body)?,
            ),
        ]),
        Reply::ModelEnd(p) | Reply::ModelCancelled(p) => object(vec![
            (
                "finish_reason",
                maybe(p.finish_reason.as_ref(), |v| Ok(s(v.as_str())))?,
            ),
            ("next_index", n(p.next_index)?),
            ("request_id", s(p.request_id)),
            ("reservation_id", s(p.reservation_id)),
            ("receipt", receipt_body(&p.receipt)?),
        ]),
        Reply::ModelError(p) => object(vec![
            ("code", s(p.code)),
            ("next", s(p.next.as_str())),
            ("next_index", n(p.next_index)?),
            ("request_id", s(p.request_id)),
            ("reservation_id", s(p.reservation_id)),
            ("receipt", receipt_body(&p.receipt)?),
        ]),
        _ => Err(codes::FRAME_UNKNOWN_KIND),
    }
}
