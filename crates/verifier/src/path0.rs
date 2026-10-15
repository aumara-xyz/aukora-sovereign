//! Resolve the gate's signed review, consume and receipt references.

use super::{canonical, digest, field, integer, object, sha256, string, Row, Value};
use std::collections::BTreeMap;
mod standing;

const MODULE_SHA256: &str = "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438";

fn require(ok: bool) -> Result<(), String> {
    ok.then_some(()).ok_or("verifier:gate-evidence".into())
}

fn text<'a>(map: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a str, String> {
    string(field(map, name)?)
}

fn hex(text: &str, width: usize) -> bool {
    text.len() == width
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn content_digest(auth: &BTreeMap<String, Value>) -> Result<[u8; 32], String> {
    let fields = ["v", "node", "target", "base_sha256", "new_sha256", "cell"]
        .into_iter()
        .map(|name| Ok((name.to_owned(), field(auth, name)?.clone())))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let mut bytes = b"aukora:operation-content:v1\0".to_vec();
    bytes.extend(canonical(&Value::Object(fields)));
    Ok(sha256(&bytes))
}

fn current_auth(auth: &Value) -> Result<&BTreeMap<String, Value>, String> {
    let map = object(auth)?;
    let required = [
        "v",
        "node",
        "subject",
        "op",
        "proposal",
        "target",
        "base_sha256",
        "new_sha256",
        "cell",
        "display_sha256",
        "challenge",
        "expires_at",
        "epoch",
        "operation",
    ];
    let metadata = [
        "owner_epoch",
        "owner_root_id",
        "binding_sha256",
        "issued_at",
        "issued_at_ms",
        "gate",
        "pubkey_fp",
    ];
    require(
        required.iter().all(|name| map.contains_key(*name))
            && map
                .keys()
                .all(|name| required.contains(&name.as_str()) || metadata.contains(&name.as_str())),
    )?;
    require(
        map.get("v") == Some(&Value::Int(1))
            && hex(text(map, "node")?, 32)
            && hex(text(map, "proposal")?, 32)
            && hex(text(map, "challenge")?, 64)
            && text(map, "subject")?
                .strip_prefix("aukora:1:")
                .is_some_and(|s| hex(s, 64))
            && ["apply", "retire", "release", "grant", "permission"].contains(&text(map, "op")?)
            && !text(map, "target")?.is_empty()
            && integer(field(map, "epoch")?)? > 0
            && integer(field(map, "expires_at")?)? >= 0
            && (text(map, "base_sha256")? == "absent" || hex(text(map, "base_sha256")?, 64)),
    )?;
    for name in ["new_sha256", "display_sha256", "operation"] {
        digest(field(map, name)?)?;
    }
    require(digest(field(map, "operation")?)? == content_digest(map)?)?;
    require(matches!(
        field(map, "cell")?,
        Value::Null | Value::Object(_)
    ))?;
    for name in ["owner_epoch"] {
        if let Some(value) = map.get(name) {
            require(value == field(map, "epoch")?)?;
        }
    }
    for name in ["binding_sha256", "owner_root_id", "gate"] {
        if let Some(value) = map.get(name) {
            digest(value)?;
        }
    }
    if let (Some(left), Some(right)) = (map.get("binding_sha256"), map.get("owner_root_id")) {
        require(left == right)?;
    }
    for name in ["issued_at", "issued_at_ms"] {
        if let Some(value) = map.get(name) {
            require(integer(value)? >= 0 && integer(value)? < integer(field(map, "expires_at")?)?)?;
        }
    }
    if let (Some(left), Some(right)) = (map.get("issued_at"), map.get("issued_at_ms")) {
        require(left == right)?;
    }
    if let Some(value) = map.get("pubkey_fp") {
        require(string(value)? == &text(map, "gate")?[..16])?;
    }
    Ok(map)
}

fn row_fields(row: &Row) -> Result<&BTreeMap<String, Value>, String> {
    require(row.semantic_ok)?;
    object(&row.value)
}

fn body(row: &Row) -> Result<&BTreeMap<String, Value>, String> {
    object(field(row_fields(row)?, "body")?)
}

fn referenced<'a>(
    rows: &'a [Row],
    reference: &Value,
    before: usize,
    kind: &str,
    op: &str,
) -> Result<&'a Row, String> {
    let reference = object(reference)?;
    let seq = usize::try_from(integer(field(reference, "seq")?)?)
        .map_err(|_| "verifier:gate-reference")?;
    require(seq > 0 && seq < before)?;
    let row = rows.get(seq - 1).ok_or("verifier:gate-reference")?;
    let fields = row_fields(row)?;
    require(
        row.seq == seq
            && row.hash == digest(field(reference, "hash")?)?
            && text(fields, "kind")? == kind
            && text(fields, "op")? == op,
    )?;
    for (alias, name) in [("ledger_seq", "seq"), ("ledger_hash", "hash")] {
        if let Some(value) = reference.get(alias) {
            require(value == field(reference, name)?)?;
        }
    }
    Ok(row)
}

fn cell_and_bytes(
    auth: &BTreeMap<String, Value>,
    card: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let from_to = object(field(card, "from_to")?)?;
    let new = text(from_to, "new")?.as_bytes();
    require(sha256(new) == digest(field(auth, "new_sha256")?)?)?;
    match field(from_to, "base")? {
        Value::Null => require(text(auth, "base_sha256")? == "absent")?,
        Value::String(old) => {
            require(hex::encode(sha256(old.as_bytes())) == text(auth, "base_sha256")?)?
        }
        _ => return Err("verifier:gate-evidence".into()),
    }
    let Value::Object(cell) = field(auth, "cell")? else {
        return Ok(());
    };
    require(super::exact_keys(
        cell,
        &["module_sha256", "input_sha256", "effect_sha256"],
    ))?;
    require(
        text(cell, "module_sha256")? == MODULE_SHA256
            && digest(field(cell, "effect_sha256")?)? == sha256(new),
    )?;
    let input = new.strip_suffix(b"\n").ok_or("verifier:cell-effect")?;
    let parsed = super::json::parse_canonical(input)?;
    let arguments = object(&parsed)?;
    require(super::exact_keys(arguments, &["key", "value"]))?;
    let key = text(arguments, "key")?.as_bytes();
    require(
        (1..=128).contains(&key.len())
            && key[0].is_ascii_alphanumeric()
            && key[1..]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(b))
            && key.len() + canonical(field(arguments, "value")?).len() <= 65_536
            && sha256(input) == digest(field(cell, "input_sha256")?)?,
    )?;
    Ok(())
}

fn consume<'a>(rows: &'a [Row], row: &'a Row) -> Result<&'a BTreeMap<String, Value>, String> {
    let fields = row_fields(row)?;
    let op = text(fields, "op")?;
    require(text(fields, "kind")? == "gate.consume" && text(fields, "phase")? == "settle")?;
    let consumed = body(row)?;
    let authorization = field(consumed, "authorization")?;
    let auth = current_auth(authorization)?;
    require(["apply", "release", "grant", "permission"].contains(&text(auth, "op")?))?;
    require(text(auth, "proposal")? == op && field(consumed, "spent")? == &Value::Bool(true))?;
    let mut signed = b"aukora:owner-authorization:v1\0".to_vec();
    signed.extend(canonical(authorization));
    if sha256(&signed) != digest(field(consumed, "authorization_sha256")?)? {
        return Err("verifier:authorization-digest".into());
    }
    if !consumed.contains_key("standing_permission") {
        let proof_text = text(consumed, "proof_hex")?;
        require(
            !proof_text.is_empty()
                && hex(proof_text, proof_text.len())
                && proof_text.len() % 2 == 0,
        )?;
        let proof = hex::decode(proof_text).map_err(|_| "verifier:gate-proof")?;
        require(sha256(&proof) == digest(field(consumed, "proof_sha256")?)?)?;
    }
    let review = referenced(
        rows,
        field(consumed, "review_issue")?,
        row.seq,
        "gate.review",
        op,
    )?;
    require(text(row_fields(review)?, "phase")? == "fact")?;
    let reviewed = body(review)?;
    require(
        field(reviewed, "authorization")? == authorization
            && field(reviewed, "owner_state")? == field(consumed, "owner_state")?,
    )?;
    let owner = object(field(reviewed, "owner_state")?)?;
    require(
        field(owner, "subject")? == field(auth, "subject")?
            && field(owner, "epoch")? == field(auth, "epoch")?,
    )?;
    if let Some(binding) = auth.get("binding_sha256") {
        require(field(owner, "binding_sha256")? == binding)?;
    }
    let card = field(reviewed, "card")?;
    require(sha256(&canonical(card)) == digest(field(auth, "display_sha256")?)?)?;
    cell_and_bytes(auth, object(card)?)?;
    // The proposal is the one gate.propose intent for this operation. A release also carries the
    // immune organ's evidence as a gate.propose fact with the same op; that is not a second proposal.
    let proposals = rows[..review.seq - 1]
        .iter()
        .filter(|candidate| {
            row_fields(candidate).is_ok_and(|fields| {
                text(fields, "kind") == Ok("gate.propose")
                    && text(fields, "op") == Ok(op)
                    && text(fields, "phase") == Ok("intent")
            })
        })
        .collect::<Vec<_>>();
    require(proposals.len() == 1)?;
    let proposed = body(proposals[0])?;
    for name in ["target", "base_sha256", "new_sha256"] {
        require(field(proposed, name)? == field(auth, name)?)?;
    }
    require(field(proposed, "digest")? == field(auth, "operation")?)?;
    require(
        rows.iter()
            .filter(|candidate| {
                row_fields(candidate).is_ok_and(|fields| {
                    text(fields, "kind") == Ok("gate.consume") && text(fields, "op") == Ok(op)
                })
            })
            .count()
            == 1,
    )?;
    if consumed.contains_key("standing_permission") {
        standing::check(rows, row, integer(field(fields, "at")?)?, row.seq)?;
    }
    Ok(auth)
}

pub(super) fn has_evidence(row: &Row) -> bool {
    body(row).is_ok_and(|body| body.contains_key("authorization") || body.contains_key("receipt"))
}

pub(super) fn owner_binding(rows: &[Row], row: &Row) -> Result<bool, String> {
    let fields = row_fields(row)?;
    if text(fields, "kind")? == "gate.consume" {
        consume(rows, row)?;
        return Ok(true);
    }
    require(text(fields, "kind")? == "gate.apply" && text(fields, "phase")? == "terminal")?;
    let receipt = object(field(body(row)?, "receipt")?)?;
    let op = text(fields, "op")?;
    let consumption = field(receipt, "owner_consumption")?;
    let consumed_row = referenced(rows, consumption, row.seq, "gate.consume", op)?;
    let auth = consume(rows, consumed_row)?;
    let consumed = body(consumed_row)?;
    require(field(receipt, "v")? == &Value::Int(3) && text(receipt, "kind")? == "change")?;
    for name in ["proposal", "target", "node", "base_sha256", "new_sha256"] {
        require(field(receipt, name)? == field(auth, name)?)?;
    }
    require(field(receipt, "approver")? == field(auth, "subject")?)?;
    let receipt_review = field(object(consumption)?, "review_issue")?;
    let consume_review = object(field(consumed, "review_issue")?)?;
    let review_row = referenced(rows, receipt_review, consumed_row.seq, "gate.review", op)?;
    require(
        review_row.seq as i64 == integer(field(consume_review, "seq")?)?
            && review_row.hash == digest(field(consume_review, "hash")?)?,
    )?;
    let reference = object(field(receipt, "owner_authorization")?)?;
    let authorizing_digest = if let Some(permission) = consumed.get("standing_permission") {
        require(receipt.get("standing_permission") == Some(permission))?;
        let at = integer(field(fields, "at")?)?;
        require(integer(field(receipt, "applied_at")?)? == at)?;
        standing::check(rows, consumed_row, at, row.seq)?;
        field(object(permission)?, "authorization_sha256")?
    } else {
        require(matches!(
            receipt.get("standing_permission"),
            None | Some(Value::Null)
        ))?;
        field(consumed, "authorization_sha256")?
    };
    require(
        field(reference, "version")? == &Value::Int(1)
            && text(reference, "kind")? == "aukora-owner-authorization-ref/v1"
            && field(reference, "authorization_id")? == authorizing_digest
            && field(reference, "authorization_sha256")? == authorizing_digest
            && field(reference, "proof_sha256")? == field(consumed, "proof_sha256")?,
    )?;
    Ok(true)
}
