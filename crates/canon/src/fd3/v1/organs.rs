// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{codes, fd3::wire::*, fd3_payloads::*, json::Value, Result};

pub(super) fn parse(value: &Value) -> Result<OrgansReply> {
    let o = Object::new(
        value,
        &[
            "approvals_pending",
            "owner_origin",
            "aumlok",
            "aura",
            "kira",
            "nostr",
            "wasm",
        ],
        &[],
    )?;
    let approvals_pending = o.count("approvals_pending", 0, MAX)?;
    let owner_origin = bounded(o.get("owner_origin")?, 1, 2_048)?;
    let a = Object::new(o.get("aumlok")?, &["bound", "passkeys", "refresh_due"], &[])?;
    let bound = a.boolean("bound")?;
    let passkeys = a.count("passkeys", 0, MAX)?;
    let refresh_due = a.boolean("refresh_due")?;
    let aumlok = AumlokStatus {
        bound,
        passkeys,
        refresh_due,
    };
    let a = Object::new(o.get("aura")?, &["root", "sequence", "sources"], &[])?;
    let root = a.digest("root")?;
    let sequence = a.count("sequence", 0, MAX)?;
    let source_values = a.get("sources")?;
    if !matches!(source_values.view(), crate::json::ValueView::Array(items) if items.len() == 3) {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let mut index = 0;
    let sources = list(source_values, |value| {
        let source = parse_source(value, index)?;
        index += 1;
        Ok(source)
    })?
    .try_into()
    .map_err(|_| codes::FRAME_INVALID_FIELD)?;
    let aura = AuraStatus {
        root,
        sequence,
        sources,
    };
    let k = Object::new(o.get("kira")?, &["demoted", "notes"], &[])?;
    let demoted = k.count("demoted", 0, MAX)?;
    let notes = k.count("notes", 0, MAX)?;
    let kira = KiraStatus { notes, demoted };
    let n = Object::new(
        o.get("nostr")?,
        &["agent_npub", "node_npub", "witness_accepted"],
        &[],
    )?;
    let agent_npub = nullable(n.get("agent_npub")?, |v| bounded(v, 1, 128))?;
    let node_npub = nullable(n.get("node_npub")?, |v| bounded(v, 1, 128))?;
    let witness_accepted = n.count("witness_accepted", 0, MAX)?;
    let nostr = NostrStatus {
        node_npub,
        agent_npub,
        witness_accepted,
    };
    let wasm = WasmStatus {
        module_sha256: Object::new(o.get("wasm")?, &["module_sha256"], &[])?
            .digest("module_sha256")?,
    };
    Ok(OrgansReply {
        approvals_pending,
        aumlok,
        kira,
        aura,
        nostr,
        wasm,
        owner_origin,
    })
}
fn source_names(index: usize) -> Result<(AuraSourceName, SourceAbsence)> {
    match index {
        0 => Ok((AuraSourceName::GateLedger, SourceAbsence::GateLedgerEmpty)),
        1 => Ok((AuraSourceName::KiraChain, SourceAbsence::KiraLedgerEmpty)),
        2 => Ok((AuraSourceName::CodeChain, SourceAbsence::CodeRecordMissing)),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
fn name(value: AuraSourceName) -> &'static str {
    match value {
        AuraSourceName::GateLedger => "gate-ledger",
        AuraSourceName::KiraChain => "kira-chain",
        AuraSourceName::CodeChain => "code-chain",
    }
}
fn absence(value: SourceAbsence) -> &'static str {
    match value {
        SourceAbsence::GateLedgerEmpty => "gate-ledger-empty",
        SourceAbsence::KiraLedgerEmpty => "kira-ledger-empty",
        SourceAbsence::CodeRecordMissing => "code-record-missing",
    }
}
fn parse_source(value: &Value, index: usize) -> Result<AuraSource> {
    let o = Object::new(value, &["absence", "entries", "head", "name"], &[])?;
    let empty = strings(o.get("absence")?)?;
    let entries = o.count("entries", 0, MAX)?;
    let head = nullable(o.get("head")?, digest)?;
    let source = o.text("name")?;
    let (expected, reason) = source_names(index)?;
    if source != name(expected) {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let empty = match (head, entries, empty) {
        (None, 0, Some(text)) if text == absence(reason) => Some(reason),
        (Some(_), 1.., None) => None,
        _ => return Err(codes::FRAME_INVALID_FIELD),
    };
    Ok(AuraSource {
        name: expected,
        head,
        entries,
        absence: empty,
    })
}
pub(super) fn body(p: &OrgansReply) -> Result<Value> {
    object(vec![
        ("approvals_pending", n(p.approvals_pending)?),
        ("owner_origin", s(&p.owner_origin)),
        (
            "aumlok",
            object(vec![
                ("bound", Value::boolean(p.aumlok.bound)),
                ("passkeys", n(p.aumlok.passkeys)?),
                ("refresh_due", Value::boolean(p.aumlok.refresh_due)),
            ])?,
        ),
        (
            "aura",
            object(vec![
                ("root", s(p.aura.root)),
                ("sequence", n(p.aura.sequence)?),
                (
                    "sources",
                    array(&p.aura.sources, |source| {
                        object(vec![
                            (
                                "absence",
                                maybe(source.absence.as_ref(), |v| Ok(s(absence(*v))))?,
                            ),
                            ("entries", n(source.entries)?),
                            ("head", maybe(source.head.as_ref(), |v| Ok(s(v)))?),
                            ("name", s(name(source.name))),
                        ])
                    })?,
                ),
            ])?,
        ),
        (
            "kira",
            object(vec![
                ("demoted", n(p.kira.demoted)?),
                ("notes", n(p.kira.notes)?),
            ])?,
        ),
        (
            "nostr",
            object(vec![
                (
                    "agent_npub",
                    maybe(p.nostr.agent_npub.as_ref(), |v| Ok(s(v)))?,
                ),
                (
                    "node_npub",
                    maybe(p.nostr.node_npub.as_ref(), |v| Ok(s(v)))?,
                ),
                ("witness_accepted", n(p.nostr.witness_accepted)?),
            ])?,
        ),
        (
            "wasm",
            object(vec![("module_sha256", s(p.wasm.module_sha256))])?,
        ),
    ])
}
