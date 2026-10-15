//! Standing authority resolves to an earlier normally approved permission.
use super::*;

const TARGET: &str = "gate/permission";

fn guard(ok: bool, code: &str) -> Result<(), String> {
    ok.then_some(()).ok_or_else(|| code.to_owned())
}

fn allowed_target(name: &str) -> bool {
    let parts = name.split('/').collect::<Vec<_>>();
    !name.is_empty()
        && name.encode_utf16().count() <= 200
        && !name.contains('\\')
        && !name.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
        && parts.len() >= 3
        && parts[0] == "plugins"
        && parts
            .iter()
            .all(|p| !p.is_empty() && *p != "." && *p != "..")
        && !name
            .to_ascii_lowercase()
            .split(['/', '.', '-', '_'])
            .any(|part| {
                [
                    "release",
                    "broker",
                    "grant",
                    "floor",
                    "identity",
                    "aumlok",
                    "gate",
                    "slider",
                    "permission",
                ]
                .contains(&part)
            })
        && !name.rsplit_once('.').is_some_and(|(_, suffix)| {
            ["js", "mjs", "cjs", "ts", "sh", "py", "node", "so"]
                .iter()
                .any(|code| suffix.eq_ignore_ascii_case(code))
        })
}

fn permission(bytes: &[u8]) -> Result<Value, String> {
    let parsed = super::super::json::parse_canonical(bytes)?;
    let value = object(&parsed)?;
    guard(
        super::super::exact_keys(
            value,
            &[
                "v",
                "mode",
                "targets",
                "kinds",
                "max_count",
                "expires_at",
                "nonce",
            ],
        ),
        "verifier:standing-permission",
    )?;
    let Value::Array(targets) = field(value, "targets")? else {
        return Err("verifier:standing-permission".into());
    };
    let mode = text(value, "mode")?;
    let count = integer(field(value, "max_count")?)?;
    guard(
        bytes.len() <= 4096
            && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
            && field(value, "v")? == &Value::Int(1)
            && ["ask", "risky", "limits"].contains(&mode)
            && targets.len() <= 32
            && targets
                .iter()
                .all(|target| string(target).is_ok_and(allowed_target))
            && field(value, "kinds")? == &Value::Array(vec![Value::String("put".into())])
            && (0..=1_000_000).contains(&count)
            && (if mode == "ask" {
                targets.is_empty() && count == 0
            } else {
                !targets.is_empty() && count > 0
            })
            && integer(field(value, "expires_at")?)? > 0
            && hex(text(value, "nonce")?, 32),
        "verifier:standing-permission",
    )?;
    Ok(parsed)
}

pub(super) fn check(rows: &[Row], row: &Row, at: i64, before: usize) -> Result<(), String> {
    let consumed = body(row)?;
    let auth = object(field(consumed, "authorization")?)?;
    let reference = object(field(consumed, "standing_permission")?)?;
    guard(
        super::super::exact_keys(
            reference,
            &[
                "v",
                "proposal",
                "authorization_sha256",
                "proof_sha256",
                "consume",
                "kind",
            ],
        ) && field(reference, "v")? == &Value::Int(1)
            && !consumed.contains_key("proof_hex"),
        "verifier:standing-reference",
    )?;
    let original = referenced(
        rows,
        field(reference, "consume")?,
        row.seq,
        "gate.consume",
        text(reference, "proposal")?,
    )
    .map_err(|_| "verifier:standing-reference")?;
    let approved = body(original)?;
    let permission_auth = object(field(approved, "authorization")?)?;
    guard(
        !approved.contains_key("standing_permission")
            && text(permission_auth, "target")? == TARGET
            && text(permission_auth, "op")? == "permission",
        "verifier:standing-permission",
    )?;
    let permission_auth = consume(rows, original)?;
    guard(
        field(reference, "authorization_sha256")? == field(approved, "authorization_sha256")?
            && field(reference, "proof_sha256")? == field(approved, "proof_sha256")?
            && field(consumed, "proof_sha256")? == field(approved, "proof_sha256")?,
        "verifier:standing-reference",
    )?;
    guard(
        field(consumed, "owner_state")? == field(approved, "owner_state")?
            && field(auth, "node")? == field(permission_auth, "node")?,
        "verifier:standing-owner",
    )?;
    let applications = rows[original.seq..row.seq - 1]
        .iter()
        .filter(|candidate| {
            row_fields(candidate).is_ok_and(|fields| {
                text(fields, "kind") == Ok("gate.apply")
                    && text(fields, "op") == text(reference, "proposal")
            })
        })
        .collect::<Vec<_>>();
    guard(applications.len() == 1, "verifier:standing-permission")?;
    owner_binding(rows, applications[0])?;
    // The latest consumed slider change disables all older permissions, even on failure.
    let latest = rows[..before - 1].iter().rev().find(|candidate| {
        row_fields(candidate).is_ok_and(|fields| text(fields, "kind") == Ok("gate.consume"))
            && body(candidate)
                .and_then(|body| object(field(body, "authorization")?))
                .is_ok_and(|auth| text(auth, "target") == Ok(TARGET))
    });
    guard(
        latest.map(|latest| latest.seq) == Some(original.seq),
        "verifier:standing-revoked",
    )?;
    let review = referenced(
        rows,
        field(approved, "review_issue")?,
        original.seq,
        "gate.review",
        text(reference, "proposal")?,
    )?;
    let card = object(field(body(review)?, "card")?)?;
    let from_to = object(field(card, "from_to")?)?;
    let value =
        permission(text(from_to, "new")?.as_bytes()).map_err(|_| "verifier:standing-permission")?;
    let value = object(&value)?;
    let Value::Array(targets) = field(value, "targets")? else {
        unreachable!()
    };
    guard(
        text(value, "mode")? != "ask"
            && text(auth, "op")? == "apply"
            && targets.contains(field(auth, "target")?)
            && text(reference, "kind")? == "put",
        "verifier:standing-scope",
    )?;
    let expires = integer(field(value, "expires_at")?)?;
    guard(
        at >= 0
            && at < expires
            && at < integer(field(auth, "expires_at")?)?
            && integer(field(auth, "expires_at")?)? <= expires,
        "verifier:standing-expired",
    )?;
    // A reservation consumes a count even if its later effect fails.
    let used = rows[..row.seq]
        .iter()
        .filter(|candidate| {
            row_fields(candidate).is_ok_and(|fields| text(fields, "kind") == Ok("gate.consume"))
                && body(candidate)
                    .and_then(|body| object(field(body, "standing_permission")?))
                    .is_ok_and(|standing| standing.get("proposal") == reference.get("proposal"))
        })
        .count();
    guard(
        used as i64 <= integer(field(value, "max_count")?)?,
        "verifier:standing-count",
    )?;
    let review = referenced(
        rows,
        field(consumed, "review_issue")?,
        row.seq,
        "gate.review",
        text(auth, "proposal")?,
    )?;
    let card = object(field(body(review)?, "card")?)?;
    let from_to = object(field(card, "from_to")?)?;
    guard(
        text(card, "risk")? == "routine"
            && match field(from_to, "base")? {
                Value::Null => true,
                Value::String(base) => base.len() <= 65_536,
                _ => false,
            },
        "verifier:standing-scope",
    )?;
    Ok(())
}
