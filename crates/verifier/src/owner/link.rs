// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained assertions commit to a specific direct owner operation in the ledger.

use crate::format::{digest, field, hex32, keys, refusal, text, uint};
use canon::{authority::OwnerAuthorization, ids::OperationId, json::Value, Result};

const WRAPPER: &str = "aukora-aura-authority-body-v1";

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(refusal("owner-assertion-link"))
    }
}

fn label<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    text(field(value, name)?)
}

pub(super) fn wrapped(body: &Value) -> bool {
    body.get("schema").is_some_and(|v| text(v) == Ok(WRAPPER))
}

fn payload(row: &Value) -> Result<&Value> {
    let body = field(row, "body")?;
    if wrapped(body) {
        keys(
            body,
            &[
                "schema",
                "algorithm",
                "epoch",
                "sequence",
                "previous_hash",
                "payload",
            ],
        )?;
        require(
            label(body, "algorithm")? == "sha256"
                && field(body, "sequence")? == field(row, "seq")?
                && field(body, "previous_hash")? == field(row, "prev")?,
        )?;
        uint(field(body, "epoch")?)?;
        let payload = field(body, "payload")?;
        require(matches!(payload.view(), canon::json::ValueView::Object(_)))?;
        Ok(payload)
    } else {
        Ok(body)
    }
}

/// Rows whose direct C5 assertion must occur exactly once in the export. A consume that names a standing grant is held
/// to `needs`, which checks the grant: a `standing` that is present is not by itself a reason to ask for no assertion.
pub(super) fn required(row: &Value) -> Result<bool> {
    let body = payload(row)?;
    Ok(match label(row, "kind")? {
        "gate.consume" => body.get("standing").is_none(),
        "gate.retire" | "floor.advance" => true,
        "gate.apply" => body
            .get("target")
            .is_some_and(|v| text(v) == Ok("gate/permission")),
        "aumlok.bind" => !body.get("schema").is_some_and(|v| {
            matches!(
                text(v),
                Ok("aukora-aumlok-initial-binding-v2" | "aukora-aumlok-envelope-refresh-v2")
            )
        }),
        _ => false,
    })
}

/// Whether the verdict needs this row's retained assertion. A consume is owner-free only when its `standing` is a
/// well-formed use of a prior owner-signed grant in these rows; null, malformed or unlinked is as good as absent.
pub(super) fn needs(rows: &[Value], row: &Value) -> Result<bool> {
    if label(row, "kind")? == "gate.consume" && payload(row)?.get("standing").is_some() {
        return Ok(standing(rows, row).is_err());
    }
    required(row)
}

/// A wrapped `gate.apply` that is not itself a permission grant changed state on the strength of exactly one consume of
/// the same operation, earlier in the ledger, and is the only apply of that operation. An apply with no consume, a
/// consume that came after it, a second apply, or an empty operation is not an effect the owner approved.
pub(super) fn effect(same: &[&Value], row: &Value) -> Result<()> {
    let body = payload(row)?;
    let permission = body.get("target").is_some_and(|v| text(v) == Ok("gate/permission"));
    if label(row, "kind")? != "gate.apply" || permission {
        return Ok(());
    }
    let (operation, sequence) = (label(row, "op")?, uint(field(row, "seq")?)?);
    let (mut consumes, mut applies) = (0, 0);
    for other in same {
        let kind = label(other, "kind")?;
        applies += usize::from(kind == "gate.apply");
        if kind != "gate.consume" || uint(field(other, "seq")?)? >= sequence {
            continue;
        }
        // A consume that cannot be read is not the consume of this apply.
        let linked = payload(other).is_ok_and(|earlier| {
            label(other, "phase") == Ok("settle")
                && label(earlier, "state") == Ok("consumed")
                && ["proposal", "target", "operation", "new_sha256"]
                    .iter()
                    .all(|name| earlier.get(name).is_some() && earlier.get(name) == body.get(name))
        });
        consumes += usize::from(linked);
    }
    if operation.is_empty() || consumes != 1 || applies != 1 {
        return Err(refusal("gate-reference"));
    }
    Ok(())
}

/// A standing use refers to a prior direct grant whose assertion is required above.
pub(super) fn standing(rows: &[Value], row: &Value) -> Result<()> {
    if label(row, "kind")? != "gate.consume" {
        return Ok(());
    }
    let body = payload(row)?;
    if body.get("standing_permission").is_some() {
        return Err(refusal("owner-standing-format"));
    }
    let Some(reference) = body.get("standing") else {
        return Ok(());
    };
    keys(
        reference,
        &[
            "permission",
            "permission_proposal",
            "permission_digest",
            "proposal",
            "operation",
            "use_number",
        ],
    )?;
    require(
        label(row, "phase")? == "settle"
            && label(row, "actor")? == "owner"
            && label(body, "state")? == "consumed"
            && uint(field(reference, "use_number")?)? > 0
            && field(reference, "proposal")? == field(body, "proposal")?
            && field(reference, "operation")? == field(body, "operation")?
            && digest(&reference.canonical_bytes()) == hex32(label(body, "consumed_approval")?)?,
    )?;
    let before = uint(field(row, "seq")?)?;
    let mut grants = 0;
    for grant in rows {
        if uint(field(grant, "seq")?)? >= before
            || label(grant, "kind")? != "gate.apply"
            || field(grant, "op")? != field(reference, "permission")?
        {
            continue;
        }
        let permission = payload(grant)?;
        require(
            required(grant)?
                && label(grant, "phase")? == "terminal"
                && label(grant, "actor")? == "owner"
                && label(permission, "state")? == "applied"
                && field(permission, "proposal")? == field(reference, "permission_proposal")?
                && field(permission, "new_sha256")? == field(reference, "permission_digest")?
                && field(field(grant, "body")?, "epoch")? == field(field(row, "body")?, "epoch")?,
        )?;
        grants += 1;
    }
    require(grants == 1)
}

/// Bind an independently checked assertion to the exported operation it describes.
pub(super) fn verify(rows: &[Value], entry: &Value, auth: &OwnerAuthorization) -> Result<()> {
    let sequence = uint(field(entry, "sequence")?)?;
    let index = sequence
        .checked_sub(1)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(refusal("owner-assertion-link"))?;
    let row = rows.get(index).ok_or(refusal("owner-assertion-link"))?;
    require(uint(field(row, "seq")?)? == sequence && required(row)?)?;
    let body = payload(row)?;
    let kind = label(row, "kind")?;
    let authorization = auth.canonical_bytes()?;
    let auth_value = canon::json::parse_strict(&authorization)?;
    require(auth.expires_at > 0 && uint(field(row, "at")?)? < auth.expires_at as u64)?;

    let wrapper = field(row, "body")?;
    require(label(wrapper, "schema")? == WRAPPER)?;
    let epoch = uint(field(wrapper, "epoch")?)?;
    let expected_epoch = if kind == "aumlok.bind" {
        canon::authority::verify_retained_binding_payload(
            body,
            auth,
            &OperationId::from_hex(label(row, "op")?)?,
        )?
    } else {
        auth.epoch
    };
    require(expected_epoch == epoch)?;
    require(
        label(row, "actor")?
            == if matches!(kind, "aumlok.bind" | "floor.advance") {
                label(&auth_value, "subject")?
            } else {
                "owner"
            },
    )?;
    let approval = digest(&authorization);

    match kind {
        "gate.consume" | "gate.retire" | "gate.apply" => {
            let (action, phase, state) = match kind {
                "gate.consume" => ("apply", "settle", "consumed"),
                "gate.retire" => ("retire", "terminal", "retired"),
                _ => ("permission", "terminal", "applied"),
            };
            require(
                auth.op.wire_name() == action
                    && label(row, "phase")? == phase
                    && label(body, "state")? == state
                    && hex32(label(body, "consumed_approval")?)? == approval,
            )?;
            for name in ["proposal", "target", "operation", "new_sha256"] {
                require(field(body, name)? == field(&auth_value, name)?)?;
            }
            if let Some(base) = body.get("base_sha256") {
                require(base == field(&auth_value, "base_sha256")?)?;
            }
            if kind == "gate.apply" {
                require(auth.target == "gate/permission")?;
            }
        }
        "floor.advance" => {
            keys(
                body,
                &["schema", "floor", "proposal", "authorization_sha256"],
            )?;
            require(
                auth.op.wire_name() == "release"
                    && auth.target == "release"
                    && label(row, "phase")? == "terminal"
                    && label(body, "schema")? == "aukora-floor-advance-v1"
                    && field(body, "proposal")? == field(&auth_value, "proposal")?
                    && hex32(label(body, "authorization_sha256")?)? == approval,
            )?;
            let floor = field(body, "floor")?;
            require(
                field(floor, "record")? == field(&auth_value, "new_sha256")?
                    && uint(field(floor, "signer_epoch")?)? == auth.epoch,
            )?;
        }
        "aumlok.bind" => {
            require(auth.op.wire_name() == "permission" && label(row, "phase")? == "terminal")?;
        }
        _ => return Err(refusal("owner-assertion-operation")),
    }
    proposal(rows, row, &auth_value)
}

fn proposal(rows: &[Value], consumed: &Value, auth: &Value) -> Result<()> {
    let mut found = 0;
    let before = uint(field(consumed, "seq")?)?;
    for row in rows {
        if uint(field(row, "seq")?)? >= before
            || label(row, "kind")? != "gate.propose"
            || label(row, "phase")? != "intent"
            || field(row, "op")? != field(consumed, "op")?
        {
            continue;
        }
        let body = payload(row)?;
        for name in ["proposal", "target", "operation"] {
            require(field(body, name)? == field(auth, name)?)?;
        }
        found += 1;
    }
    require(found == 1)
}
