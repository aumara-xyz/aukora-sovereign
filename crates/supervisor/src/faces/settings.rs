// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact settings projections; values come from the owning runtime source.
use super::{refuse, wire};
use canon::{
    digest::Digest32,
    json::{Value, ValueView, MAX_SAFE_INTEGER},
    Result,
};
use std::collections::BTreeSet;
use supervisor::ingress::PrincipalScope;

pub trait SettingsRead: Send + Sync {
    /// Sources return only non-secret state. The adapter validates the face contract again.
    fn read(&self, scope: PrincipalScope, method: &str) -> Result<Value>;
}

/// The digest and file count must come from the release actually loaded by frontdoor.
pub fn release(manifest_sha256: Digest32, assets: usize) -> Result<Value> {
    if !(2..=4096).contains(&assets) {
        return Err(refuse("settings-release-invalid"));
    }
    wire::object([(
        "release",
        wire::object([
            ("assets", wire::number(assets as u64)?),
            ("manifest_sha256", wire::text(manifest_sha256.to_string())?),
        ])?,
    )])
}

pub fn call(source: &dyn SettingsRead, scope: PrincipalScope, method: &str) -> Result<Value> {
    let value = source.read(scope, method)?;
    validate(method, &value)?;
    wire::bounded(value)
}

pub fn validate(method: &str, value: &Value) -> Result<()> {
    match method {
        "settings.general" => general(value),
        "settings.models" => models(value),
        "settings.plugins" => plugins(value),
        "settings.presets" => presets(value),
        _ => Err(refuse("face-operation-unknown")),
    }
}
fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    wire::field(value, key)
}
fn number(value: &Value, key: &str) -> Result<u64> {
    wire::unsigned(member(value, key)?)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    wire::string(member(value, key)?)
}
fn null(value: &Value) -> bool {
    matches!(value.view(), ValueView::Null)
}
fn check(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(refuse("settings-reply-invalid"))
    }
}
fn no_key(value: &str) -> bool {
    !value.to_ascii_lowercase().contains("sk-")
}
fn model(value: &Value) -> Result<()> {
    let value = wire::string(value)?;
    check(
        !value.is_empty()
            && value.len() <= 256
            && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            && no_key(value),
    )
}
fn digest(value: &Value) -> Result<()> {
    Digest32::from_hex(wire::string(value)?).map(|_| ())
}
fn general(value: &Value) -> Result<()> {
    wire::exact(value, &["release"])?;
    let release = member(value, "release")?;
    wire::exact(release, &["assets", "manifest_sha256"])?;
    check((2..=4096).contains(&number(release, "assets")?))?;
    digest(member(release, "manifest_sha256")?)
}
fn models(value: &Value) -> Result<()> {
    wire::exact(value, &["grant", "key", "last_reply", "model"])?;
    let chosen = member(value, "model")?;
    if !null(chosen) {
        wire::exact(chosen, &["name", "source"])?;
        model(member(chosen, "name")?)?;
        let source = member(chosen, "source")?;
        if source.get("provider").is_some() {
            wire::exact(source, &["provider"])?;
            check(matches!(
                text(source, "provider")?,
                "deepseek" | "openrouter"
            ))?;
        } else {
            wire::exact(source, &["artifact"])?;
            digest(member(source, "artifact")?)?;
        }
    }
    let key = member(value, "key")?;
    wire::exact(key, &["present"])?;
    wire::boolean(member(key, "present")?)?;
    let grant = member(value, "grant")?;
    if !null(grant) {
        wire::exact(
            grant,
            &[
                "completion_microusd_per_token",
                "expires_at_ms",
                "frozen",
                "max_requests",
                "per_request_cap_microusd",
                "prompt_microusd_per_token",
                "requests",
                "reserved_microusd",
                "spent_microusd",
                "total_cap_microusd",
            ],
        )?;
        let total = number(grant, "total_cap_microusd")?;
        let cap = number(grant, "per_request_cap_microusd")?;
        let requests = number(grant, "max_requests")?;
        check(
            total > 0
                && cap > 0
                && cap <= total
                && requests > 0
                && number(grant, "requests")? <= requests
                && number(grant, "expires_at_ms")? > 0,
        )?;
        let committed = number(grant, "spent_microusd")?
            .checked_add(number(grant, "reserved_microusd")?)
            .ok_or(refuse("settings-reply-invalid"))?;
        check(committed <= MAX_SAFE_INTEGER as u64)?;
        number(grant, "completion_microusd_per_token")?;
        number(grant, "prompt_microusd_per_token")?;
        wire::boolean(member(grant, "frozen")?)?;
    }
    let last = member(value, "last_reply")?;
    if !null(last) {
        wire::exact(
            last,
            &["charged_microusd", "cost_unknown", "identity", "outcome"],
        )?;
        number(last, "charged_microusd")?;
        wire::boolean(member(last, "cost_unknown")?)?;
        check(matches!(
            text(last, "outcome")?,
            "completed" | "cancelled" | "refused" | "unknown"
        ))?;
        let identity = member(last, "identity")?;
        wire::exact(identity, &["reported", "requested", "verified"])?;
        model(member(identity, "requested")?)?;
        if !null(member(identity, "reported")?) {
            model(member(identity, "reported")?)?;
        }
        let verified = member(identity, "verified")?;
        match text(verified, "status")? {
            "unverified" => wire::exact(verified, &["status"])?,
            "verified" => {
                wire::exact(verified, &["status", "model", "verifier"])?;
                model(member(verified, "model")?)?;
                let verifier = text(verified, "verifier")?;
                check(
                    !verifier.is_empty()
                        && verifier.chars().count() <= 256
                        && verifier.trim() == verifier
                        && !verifier.chars().any(unreadable)
                        && no_key(verifier),
                )?;
            }
            _ => return Err(refuse("settings-reply-invalid")),
        }
    }
    Ok(())
}
fn unreadable(value: char) -> bool {
    value.is_control()
        || matches!(value, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        })
}
fn code(value: &str) -> bool {
    let Some((organ, reason)) = value.split_once(':') else {
        return false;
    };
    !organ.is_empty()
        && organ.len() <= 32
        && organ.as_bytes()[0].is_ascii_lowercase()
        && organ
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
        && !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
fn plugins(value: &Value) -> Result<()> {
    wire::exact(value, &["plugins"])?;
    let values = wire::array(member(value, "plugins")?)?;
    check(values.len() <= 256)?;
    let mut ids = BTreeSet::new();
    for plugin in values {
        wire::exact(plugin, &["error", "id", "missing", "state"])?;
        let id = text(plugin, "id")?;
        check(identifier(id) && ids.insert(id))?;
        check(matches!(
            text(plugin, "state")?,
            "waiting" | "starting" | "active" | "stopping" | "failed" | "disposed"
        ))?;
        let missing = wire::array(member(plugin, "missing")?)?;
        check(missing.len() <= 16)?;
        for service in missing {
            check(identifier(wire::string(service)?))?;
        }
        if !null(member(plugin, "error")?) {
            check(code(text(plugin, "error")?))?;
        }
    }
    Ok(())
}
fn presets(value: &Value) -> Result<()> {
    wire::exact(value, &["presets"])?;
    let values = wire::array(member(value, "presets")?)?;
    check(values.len() <= 16)?;
    let mut ids = BTreeSet::new();
    for preset in values {
        wire::exact(preset, &["id", "max_output_tokens", "model", "operations"])?;
        let id = text(preset, "id")?;
        check(matches!(id, "chat" | "build") && ids.insert(id))?;
        check((1..=32768).contains(&number(preset, "max_output_tokens")?))?;
        model(member(preset, "model")?)?;
        let operations = wire::array(member(preset, "operations")?)?;
        check(operations.len() <= 8)?;
        let mut seen = BTreeSet::new();
        for operation in operations {
            let operation = wire::string(operation)?;
            check(
                matches!(
                    operation,
                    "chat"
                        | "threads"
                        | "sessions"
                        | "streaming"
                        | "compaction"
                        | "proposals"
                        | "memory_read"
                        | "memory_propose"
                ) && seen.insert(operation),
            )?;
        }
    }
    Ok(())
}
