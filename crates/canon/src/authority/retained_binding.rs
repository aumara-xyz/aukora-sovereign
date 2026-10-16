// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact-byte links for retained, versioned AUMLOK binding payloads.

use super::{OwnerAuthorization, OwnerOperation};
use crate::{
    digest::Digest32,
    ids::OperationId,
    json::{Value, ValueView},
    Result,
};

const KEY: &[&str] = &[
    "v",
    "algorithm",
    "key_id",
    "role",
    "material",
    "scope",
    "epoch",
    "operation_id",
];
const PAIRING: &[&str] = &[
    "v",
    "algorithm",
    "subject",
    "node",
    "epoch",
    "membership",
    "device_key",
    "scope",
    "copresence",
    "operation_id",
];
const DELEGATION: &[&str] = &[
    "v",
    "algorithm",
    "parent",
    "issuer",
    "delegate",
    "from",
    "to",
    "scope",
    "version",
    "id",
    "signatures",
];

fn bad() -> crate::Refusal {
    crate::codes::GATE_AUTHORIZATION_MISMATCH
}

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(bad())
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or_else(bad)
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match field(value, name)?.view() {
        ValueView::Text(value) => Ok(value),
        _ => Err(bad()),
    }
}

fn number(value: &Value, name: &str) -> Result<u64> {
    match field(value, name)?.view() {
        ValueView::Integer(value) => u64::try_from(value.get()).map_err(|_| bad()),
        _ => Err(bad()),
    }
}

fn shape(value: &Value, names: &[&str]) -> bool {
    matches!(value.view(), ValueView::Object(fields) if fields.len() == names.len()
        && names.iter().all(|name| value.get(name).is_some()))
}

fn version(value: &Value) -> Result<()> {
    require(number(value, "v")? == 1)
}

fn sha256(value: &Value) -> Result<()> {
    version(value)?;
    require(text(value, "algorithm")? == "sha256")
}

fn context(value: &Value, auth: &OwnerAuthorization) -> Result<()> {
    require(
        text(value, "subject")? == auth.subject.to_string()
            && text(value, "node")? == auth.node.to_string(),
    )
}

fn operation(value: &Value, id: &OperationId) -> Result<()> {
    require(text(value, "operation_id")? == id.to_string())
}

fn target(prefix: &str, value: &Value, key: &str) -> Result<String> {
    let digest = Digest32::from_hex(text(value, key)?)?;
    Ok(format!("{prefix}{digest}"))
}

fn key_binding(value: &Value, auth: &OwnerAuthorization, id: &OperationId) -> Result<String> {
    require(shape(value, KEY))?;
    version(value)?;
    operation(value, id)?;
    context(field(value, "scope")?, auth)?;
    require(number(value, "epoch")? == auth.epoch)?;
    target("aumlok:key:", value, "key_id")
}

fn device_membership(value: &Value, auth: &OwnerAuthorization) -> Result<u64> {
    require(shape(
        value,
        &["previous", "next", "expected", "next_epoch"],
    ))?;
    let expected = field(value, "expected")?;
    require(shape(expected, &["epoch", "sequence", "previous_hash"]))?;
    let epoch = auth.epoch.checked_add(1).ok_or_else(bad)?;
    require(number(expected, "epoch")? == auth.epoch && number(value, "next_epoch")? == epoch)?;
    Ok(epoch)
}

/// Check the one domain and target selected by a known frozen payload shape.
/// The operation id belongs to its Aura row; the caller separately checks its
/// unique prior proposal. Return the required authority epoch for that row.
pub fn verify_retained_binding_payload(
    payload: &Value,
    auth: &OwnerAuthorization,
    operation_id: &OperationId,
) -> Result<u64> {
    require(auth.op == OwnerOperation::Permission && auth.cell.is_none())?;
    auth.canonical_bytes()?;
    let (domain, expected_target, epoch) = if shape(payload, KEY) {
        (
            "aukora:aumlok-key-binding:v1",
            key_binding(payload, auth, operation_id)?,
            auth.epoch,
        )
    } else if shape(payload, &["schema", "epoch", "body"]) {
        require(
            text(payload, "schema")? == "aukora:aumlok-person-nostr-binding:v1"
                && number(payload, "epoch")? <= u64::from(u32::MAX),
        )?;
        let body = field(payload, "body")?;
        require(text(body, "role")? == "person-nostr")?;
        (
            "aukora:aumlok-person-nostr-binding:v1",
            key_binding(body, auth, operation_id)?,
            auth.epoch,
        )
    } else if shape(
        payload,
        &["v", "algorithm", "key_id", "epoch", "operation_id"],
    ) {
        sha256(payload)?;
        operation(payload, operation_id)?;
        require(number(payload, "epoch")? == auth.epoch)?;
        (
            "aukora:aumlok-key-revocation:v1",
            target("aumlok:key:", payload, "key_id")?,
            auth.epoch,
        )
    } else if shape(payload, &["v", "body", "possession"]) {
        version(payload)?;
        let body = field(payload, "body")?;
        require(shape(body, PAIRING))?;
        sha256(body)?;
        context(body, auth)?;
        context(field(body, "scope")?, auth)?;
        operation(body, operation_id)?;
        let epoch = device_membership(field(body, "membership")?, auth)?;
        require(number(body, "epoch")? == epoch)?;
        let key = field(body, "device_key")?;
        require(
            shape(key, KEY) && text(key, "role")? == "device" && number(key, "epoch")? == epoch,
        )?;
        version(key)?;
        context(field(key, "scope")?, auth)?;
        operation(key, operation_id)?;
        (
            "aukora:aumlok-device-approval:v1",
            format!("aumlok.devices:{}", auth.subject),
            epoch,
        )
    } else if shape(
        payload,
        &[
            "v",
            "algorithm",
            "subject",
            "node",
            "device",
            "membership",
            "operation_id",
        ],
    ) {
        sha256(payload)?;
        context(payload, auth)?;
        operation(payload, operation_id)?;
        Digest32::from_hex(text(payload, "device")?)?;
        let epoch = device_membership(field(payload, "membership")?, auth)?;
        (
            "aukora:aumlok-device-revocation:v1",
            format!("aumlok.devices:{}", auth.subject),
            epoch,
        )
    } else if shape(payload, DELEGATION) {
        sha256(payload)?;
        context(field(payload, "scope")?, auth)?;
        let version = field(payload, "version")?;
        require(
            shape(version, &["epoch", "sequence", "previous_hash"])
                && number(version, "epoch")? == auth.epoch,
        )?;
        (
            "aukora:aumlok-delegation:v1",
            target("aumlok:delegation:", payload, "id")?,
            auth.epoch,
        )
    } else if shape(
        payload,
        &["v", "algorithm", "delegation_id", "epoch", "operation_id"],
    ) {
        sha256(payload)?;
        operation(payload, operation_id)?;
        require(number(payload, "epoch")? == auth.epoch)?;
        (
            "aukora:aumlok-delegation-revocation:v1",
            target("aumlok:delegation:", payload, "delegation_id")?,
            auth.epoch,
        )
    } else {
        return Err(bad());
    };
    let mut approved = domain.as_bytes().to_vec();
    approved.push(0);
    approved.extend(payload.canonical_bytes());
    require(auth.target == expected_target && auth.new_sha256 == Digest32::sha256(&approved))?;
    Ok(epoch)
}
