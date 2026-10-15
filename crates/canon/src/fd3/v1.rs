// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{wire::*, Reply, Request};
use crate::{
    codes,
    fd3_payloads::*,
    ids::{NoteId, ProposalId},
    json::{Value, ValueView},
    Result,
};

mod organs;

pub(super) fn parse_request(kind: &str, value: &Value) -> Result<Request> {
    Ok(match kind {
        "propose" => {
            let o = Object::new(
                value,
                &["base_sha256", "new_bytes_b64", "note", "target"],
                &["cell"],
            )?;
            let base_sha256 = o.digest("base_sha256")?;
            let new_bytes_b64 = b64(o.get("new_bytes_b64")?)?;
            let note = o.text("note")?;
            let target = o.text("target")?;
            let cell = o.optional("cell").map(parse_cell).transpose()?;
            Request::Propose(Propose {
                target,
                base_sha256,
                new_bytes_b64,
                note,
                cell,
            })
        }
        "read" => Request::Read(Read {
            target: Object::new(value, &["target"], &[])?.text("target")?,
        }),
        "model.call" => Request::ModelCall(parse_model_call(value)?),
        "memory.put" => {
            let o = Object::new(value, &["category", "statement", "cell"], &["quote"])?;
            let category = o.text("category")?;
            let quote = o
                .optional("quote")
                .map(|v| Ok(text(v)?.to_owned()))
                .transpose()?;
            let statement = o.text("statement")?;
            let cell = parse_cell(o.get("cell")?)?;
            Request::MemoryPut(MemoryPut {
                cell,
                statement,
                quote,
                category,
            })
        }
        "memory.recall" => {
            let o = Object::new(value, &["limit", "query"], &[])?;
            let limit = o.count("limit", 1, 100)? as u16;
            let query = o.text("query")?;
            Request::MemoryRecall(MemoryRecall { query, limit })
        }
        "memory.list" => {
            let o = Object::new(value, &["before", "tier"], &[])?;
            let before = nullable(o.get("before")?, note_id)?;
            let tier = parse_tier(o.get("tier")?)?;
            Request::MemoryList(MemoryList { tier, before })
        }
        "status" | "organs" => {
            Object::new(value, &[], &[])?;
            if kind == "status" {
                Request::Status
            } else {
                Request::Organs
            }
        }
        _ => return Err(codes::FRAME_UNKNOWN_KIND),
    })
}
fn parse_cell(value: &Value) -> Result<CellCommitments> {
    let o = Object::new(
        value,
        &["effect_sha256", "input_sha256", "module_sha256"],
        &[],
    )?;
    let effect_sha256 = o.digest("effect_sha256")?;
    let input_sha256 = o.digest("input_sha256")?;
    let module_sha256 = o.digest("module_sha256")?;
    Ok(CellCommitments {
        module_sha256,
        input_sha256,
        effect_sha256,
    })
}
pub(super) fn parse_model_call(value: &Value) -> Result<ModelCall> {
    let o = Object::new(
        value,
        &[
            "grant_id",
            "max_output_tokens",
            "model",
            "messages",
            "tools",
        ],
        &[],
    )?;
    let grant_id = o.text("grant_id")?;
    let max_output_tokens = o.count("max_output_tokens", 1, 32_768)? as u32;
    let model = o.text("model")?;
    let messages = list(o.get("messages")?, |value| {
        let m = Object::new(value, &["content", "role"], &["tool_call_id", "tool_calls"])?;
        let content = strings(m.get("content")?)?;
        let role = m.text("role")?;
        let tool_call_id = m
            .optional("tool_call_id")
            .map(|v| Ok(text(v)?.to_owned()))
            .transpose()?;
        let tool_calls = m
            .optional("tool_calls")
            .map(|v| list(v, parse_tool_call))
            .transpose()?;
        Ok(ModelMessage {
            role,
            content,
            tool_calls,
            tool_call_id,
        })
    })?;
    let tools = list(o.get("tools")?, |value| {
        let tool = Object::new(value, &["type", "function"], &[])?;
        if text(tool.get("type")?)? != "function" {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        let f = Object::new(
            tool.get("function")?,
            &["description", "name", "parameters"],
            &[],
        )?;
        let description = f.text("description")?;
        let name = f.text("name")?;
        let parameters = f.get("parameters")?;
        if !matches!(parameters.view(), ValueView::Object(_)) {
            return Err(codes::FRAME_NOT_OBJECT);
        }
        Ok(Tool {
            name,
            description,
            parameters: parameters.clone(),
        })
    })?;
    Ok(ModelCall {
        grant_id,
        model,
        messages,
        tools,
        max_output_tokens,
    })
}
pub(super) fn parse_tool_call(value: &Value) -> Result<ToolCall> {
    let o = Object::new(value, &["id", "type", "function"], &[])?;
    let id = o.text("id")?;
    if text(o.get("type")?)? != "function" {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let f = Object::new(o.get("function")?, &["arguments", "name"], &[])?;
    let arguments = f.text("arguments")?;
    let name = f.text("name")?;
    Ok(ToolCall {
        id,
        name,
        arguments,
    })
}
pub(super) fn parse_usage(value: &Value) -> Result<Usage> {
    let o = Object::new(
        value,
        &["completion_tokens", "cost_microusd", "prompt_tokens"],
        &[],
    )?;
    let completion_tokens = o.count("completion_tokens", 0, 32_768)? as u32;
    let cost_microusd = o.count("cost_microusd", 0, MAX)?;
    let prompt_tokens = o.count("prompt_tokens", 0, 32_768)? as u32;
    Ok(Usage {
        prompt_tokens,
        completion_tokens,
        cost_microusd,
    })
}
fn note_id(value: &Value) -> Result<NoteId> {
    NoteId::new(text(value)?.to_owned()).map_err(|_| codes::FRAME_INVALID_FIELD)
}
fn parse_tier(value: &Value) -> Result<MemoryTier> {
    match text(value)? {
        "remembered" => Ok(MemoryTier::Remembered),
        "forgotten" => Ok(MemoryTier::Forgotten),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
fn tier_name(tier: MemoryTier) -> &'static str {
    match tier {
        MemoryTier::Remembered => "remembered",
        MemoryTier::Forgotten => "forgotten",
    }
}
fn parse_state(value: &Value) -> Result<OutcomeState> {
    match text(value)? {
        "applied" => Ok(OutcomeState::Applied),
        "refused" => Ok(OutcomeState::Refused),
        "expired" => Ok(OutcomeState::Expired),
        "retired" => Ok(OutcomeState::Retired),
        "incomplete" => Ok(OutcomeState::Incomplete),
        "failed" => Ok(OutcomeState::Failed),
        "conflict" => Ok(OutcomeState::Conflict),
        "unknown" => Ok(OutcomeState::Unknown),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
fn state_name(state: OutcomeState) -> &'static str {
    match state {
        OutcomeState::Applied => "applied",
        OutcomeState::Refused => "refused",
        OutcomeState::Expired => "expired",
        OutcomeState::Retired => "retired",
        OutcomeState::Incomplete => "incomplete",
        OutcomeState::Failed => "failed",
        OutcomeState::Conflict => "conflict",
        OutcomeState::Unknown => "unknown",
    }
}
pub(super) fn parse_reply(kind: &str, value: &Value) -> Result<Reply> {
    Ok(match kind {
        "accepted" => {
            let proposal_id = Object::new(value, &["proposal_id"], &[])?.text("proposal_id")?;
            match ProposalId::from_hex(&proposal_id) {
                Ok(proposal_id) => Reply::Accepted(Accepted { proposal_id }),
                Err(_) => Reply::LegacyAccepted { proposal_id },
            }
        }
        "outcome" => {
            let o = Object::new(value, &["proposal_id", "state"], &[])?;
            let proposal_id = o.text("proposal_id")?;
            let state = parse_state(o.get("state")?)?;
            match ProposalId::from_hex(&proposal_id) {
                Ok(proposal_id) => Reply::Outcome(Outcome { proposal_id, state }),
                Err(_) => Reply::LegacyOutcome { proposal_id, state },
            }
        }
        "model.reply" => {
            let o = Object::new(
                value,
                &[
                    "content",
                    "finish_reason",
                    "receipt_seq",
                    "tool_calls",
                    "usage",
                ],
                &[],
            )?;
            let content = strings(o.get("content")?)?;
            let finish_reason = strings(o.get("finish_reason")?)?;
            let receipt_seq = o.count("receipt_seq", 1, MAX)?;
            let tool_calls = list(o.get("tool_calls")?, parse_tool_call)?;
            let usage = parse_usage(o.get("usage")?)?;
            Reply::ModelReply(ModelReply {
                content,
                tool_calls,
                finish_reason,
                usage,
                receipt_seq,
            })
        }
        "read.reply" => {
            let o = Object::new(value, &["bytes_b64", "sha256", "target"], &[])?;
            let bytes_b64 = b64(o.get("bytes_b64")?)?;
            let sha256 = o.digest("sha256")?;
            let target = o.text("target")?;
            Reply::ReadReply(ReadReply {
                target,
                sha256,
                bytes_b64,
            })
        }
        "recall" => {
            let o = Object::new(value, &["result", "items"], &[])?;
            let result = match text(o.get("result")?)? {
                "found" => RecallResult::Found,
                "empty" => RecallResult::Empty,
                "undetermined" => RecallResult::Undetermined,
                _ => return Err(codes::FRAME_INVALID_FIELD),
            };
            let items = list(o.get("items")?, |value| {
                let item = Object::new(value, &["cite_seq", "note_id", "text"], &[])?;
                let cite_seq = item.count("cite_seq", 1, MAX)?;
                let note_id = item.text("note_id")?;
                let text = item.text("text")?;
                Ok(RecallItem {
                    note_id,
                    text,
                    cite_seq,
                })
            })?;
            Reply::Recall(Recall { result, items })
        }
        "refusal" => {
            let o = Object::new(value, &["code", "next"], &[])?;
            let code = codes::parse(text(o.get("code")?)?)?;
            let next = o.text("next")?;
            Reply::Refusal(RefusalReply { code, next })
        }
        "status.reply" => {
            let o = Object::new(
                value,
                &["bound", "grant_id", "grant_remaining", "ready"],
                &[],
            )?;
            let bound = o.boolean("bound")?;
            let grant_id = strings(o.get("grant_id")?)?;
            let grant_remaining = nullable(o.get("grant_remaining")?, |v| count(v, 0, MAX))?;
            let ready = o.boolean("ready")?;
            Reply::StatusReply(StatusReply {
                ready,
                bound,
                grant_id,
                grant_remaining,
            })
        }
        "memory.list.reply" => Reply::MemoryListReply(parse_memory_list(value)?),
        "organs.reply" => Reply::OrgansReply(organs::parse(value)?),
        _ => return Err(codes::FRAME_UNKNOWN_KIND),
    })
}
fn parse_memory_list(value: &Value) -> Result<MemoryListReply> {
    let o = Object::new(value, &["next", "tier", "items"], &[])?;
    let next = nullable(o.get("next")?, note_id)?;
    let tier = parse_tier(o.get("tier")?)?;
    let items = list(o.get("items")?, |value| {
        let item = Object::new(
            value,
            &[
                "at",
                "category",
                "cite_seq",
                "demoted_at",
                "demoted_seq",
                "note_id",
                "text",
            ],
            &[],
        )?;
        let at = item.count("at", 0, MAX)?;
        let category = bounded(item.get("category")?, 1, 64)?;
        if !category
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        let cite_seq = item.count("cite_seq", 1, MAX)?;
        let demoted_at = nullable(item.get("demoted_at")?, |v| count(v, 0, MAX))?;
        let demoted_seq = nullable(item.get("demoted_seq")?, |v| count(v, 0, MAX))?;
        let note_id = note_id(item.get("note_id")?)?;
        let text = strings(item.get("text")?)?;
        let valid = match tier {
            MemoryTier::Remembered => {
                text.is_some() && demoted_at.is_none() && demoted_seq.is_none()
            }
            MemoryTier::Forgotten => {
                text.is_none() && demoted_at.is_some() && demoted_seq.is_some_and(|n| n > cite_seq)
            }
        };
        if !valid {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(MemoryListItem {
            note_id,
            category,
            at,
            cite_seq,
            text,
            demoted_seq,
            demoted_at,
        })
    })?;
    if items.len() > 100
        || items
            .windows(2)
            .any(|pair| pair[0].cite_seq <= pair[1].cite_seq)
    {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    Ok(MemoryListReply { tier, items, next })
}

fn cell_body(cell: &CellCommitments) -> Result<Value> {
    object(vec![
        ("effect_sha256", s(cell.effect_sha256)),
        ("input_sha256", s(cell.input_sha256)),
        ("module_sha256", s(cell.module_sha256)),
    ])
}
pub(super) fn tool_call_body(call: &ToolCall) -> Result<Value> {
    object(vec![
        ("id", s(&call.id)),
        ("type", s("function")),
        (
            "function",
            object(vec![
                ("arguments", s(&call.arguments)),
                ("name", s(&call.name)),
            ])?,
        ),
    ])
}
pub(super) fn usage_body(usage: &Usage) -> Result<Value> {
    object(vec![
        ("completion_tokens", n(usage.completion_tokens as u64)?),
        ("cost_microusd", n(usage.cost_microusd)?),
        ("prompt_tokens", n(usage.prompt_tokens as u64)?),
    ])
}
pub(super) fn model_call_body(call: &ModelCall) -> Result<Value> {
    let messages = array(&call.messages, |m| {
        let mut fields = vec![
            ("content", maybe(m.content.as_ref(), |v| Ok(s(v)))?),
            ("role", s(&m.role)),
        ];
        if let Some(id) = &m.tool_call_id {
            fields.push(("tool_call_id", s(id)));
        }
        if let Some(calls) = &m.tool_calls {
            fields.push(("tool_calls", array(calls, tool_call_body)?));
        }
        object(fields)
    })?;
    let tools = array(&call.tools, |tool| {
        object(vec![
            ("type", s("function")),
            (
                "function",
                object(vec![
                    ("description", s(&tool.description)),
                    ("name", s(&tool.name)),
                    ("parameters", tool.parameters.clone()),
                ])?,
            ),
        ])
    })?;
    object(vec![
        ("grant_id", s(&call.grant_id)),
        ("max_output_tokens", n(call.max_output_tokens as u64)?),
        ("model", s(&call.model)),
        ("messages", messages),
        ("tools", tools),
    ])
}
pub(super) fn request_body(request: &Request) -> Result<Value> {
    match request {
        Request::Propose(p) => {
            let mut fields = vec![
                ("base_sha256", s(p.base_sha256)),
                ("new_bytes_b64", s(&p.new_bytes_b64)),
                ("note", s(&p.note)),
                ("target", s(&p.target)),
            ];
            if let Some(cell) = &p.cell {
                fields.push(("cell", cell_body(cell)?));
            }
            object(fields)
        }
        Request::Read(p) => object(vec![("target", s(&p.target))]),
        Request::ModelCall(p) => model_call_body(p),
        Request::MemoryPut(p) => {
            let mut fields = vec![
                ("category", s(&p.category)),
                ("statement", s(&p.statement)),
                ("cell", cell_body(&p.cell)?),
            ];
            if let Some(quote) = &p.quote {
                fields.push(("quote", s(quote)));
            }
            object(fields)
        }
        Request::MemoryRecall(p) => {
            object(vec![("limit", n(p.limit as u64)?), ("query", s(&p.query))])
        }
        Request::MemoryList(p) => object(vec![
            ("before", maybe(p.before.as_ref(), |v| Ok(s(v)))?),
            ("tier", s(tier_name(p.tier))),
        ]),
        Request::Status | Request::Organs => object(vec![]),
        _ => Err(codes::FRAME_UNKNOWN_KIND),
    }
}
pub(super) fn reply_body(reply: &Reply) -> Result<Value> {
    match reply {
        Reply::Accepted(p) => object(vec![("proposal_id", s(p.proposal_id))]),
        Reply::LegacyAccepted { proposal_id } => object(vec![("proposal_id", s(proposal_id))]),
        Reply::Outcome(p) => object(vec![
            ("proposal_id", s(p.proposal_id)),
            ("state", s(state_name(p.state))),
        ]),
        Reply::LegacyOutcome { proposal_id, state } => object(vec![
            ("proposal_id", s(proposal_id)),
            ("state", s(state_name(*state))),
        ]),
        Reply::ModelReply(p) => object(vec![
            ("content", maybe(p.content.as_ref(), |v| Ok(s(v)))?),
            (
                "finish_reason",
                maybe(p.finish_reason.as_ref(), |v| Ok(s(v)))?,
            ),
            ("receipt_seq", n(p.receipt_seq)?),
            ("tool_calls", array(&p.tool_calls, tool_call_body)?),
            ("usage", usage_body(&p.usage)?),
        ]),
        Reply::ReadReply(p) => object(vec![
            ("bytes_b64", s(&p.bytes_b64)),
            ("sha256", s(p.sha256)),
            ("target", s(&p.target)),
        ]),
        Reply::Recall(p) => {
            let result = match p.result {
                RecallResult::Found => "found",
                RecallResult::Empty => "empty",
                RecallResult::Undetermined => "undetermined",
            };
            object(vec![
                ("result", s(result)),
                (
                    "items",
                    array(&p.items, |item| {
                        object(vec![
                            ("cite_seq", n(item.cite_seq)?),
                            ("note_id", s(&item.note_id)),
                            ("text", s(&item.text)),
                        ])
                    })?,
                ),
            ])
        }
        Reply::Refusal(p) => object(vec![("code", s(p.code)), ("next", s(&p.next))]),
        Reply::StatusReply(p) => object(vec![
            ("bound", Value::boolean(p.bound)),
            ("grant_id", maybe(p.grant_id.as_ref(), |v| Ok(s(v)))?),
            (
                "grant_remaining",
                maybe(p.grant_remaining.as_ref(), |v| n(*v))?,
            ),
            ("ready", Value::boolean(p.ready)),
        ]),
        Reply::MemoryListReply(p) => object(vec![
            ("next", maybe(p.next.as_ref(), |v| Ok(s(v)))?),
            ("tier", s(tier_name(p.tier))),
            (
                "items",
                array(&p.items, |item| {
                    object(vec![
                        ("at", n(item.at)?),
                        ("category", s(&item.category)),
                        ("cite_seq", n(item.cite_seq)?),
                        ("demoted_at", maybe(item.demoted_at.as_ref(), |v| n(*v))?),
                        ("demoted_seq", maybe(item.demoted_seq.as_ref(), |v| n(*v))?),
                        ("note_id", s(&item.note_id)),
                        ("text", maybe(item.text.as_ref(), |v| Ok(s(v)))?),
                    ])
                })?,
            ),
        ]),
        Reply::OrgansReply(p) => organs::body(p),
        _ => Err(codes::FRAME_UNKNOWN_KIND),
    }
}
