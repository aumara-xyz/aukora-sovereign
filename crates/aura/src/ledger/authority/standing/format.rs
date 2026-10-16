// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standing scope formats are distinct from frozen permission target bytes.

use super::*;
use canon::json::{SafeInteger, ValueView};

pub(super) const USE_SCHEMA: &str = "aukora-aura-standing-use-v1";
pub(super) const REVOKE_SCHEMA: &str = "aukora-aura-standing-revocation-v1";
const STORAGE_SCHEMA: &str = "aukora-aura-standing-storage-v1";
const PERMISSION_V2: &str = "aukora-standing-permission-v2";
const DAY_MS: i64 = 86_400_000;

pub(super) struct StandingPermission {
    pub targets: Vec<String>,
    pub maximum: u64,
    pub starts: i64,
    pub expires: i64,
    pub rate_count: u64,
    pub window_ms: i64,
    pub enabled: bool,
    glob: bool,
}

impl StandingPermission {
    pub fn parse(bytes: &[u8], issued: i64) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 8_192 || issued < 0 {
            return Err(refusal("standing-permission-format"));
        }
        let value = json::parse_strict(bytes)?;
        if value.canonical_bytes() != bytes {
            return Err(refusal("standing-permission-format"));
        }
        let glob = text_field(&value, "schema").ok() == Some(PERMISSION_V2);
        let body = if glob {
            exact(&value, &["schema", "body"])?;
            let body = member(&value, "body")?;
            exact(
                body,
                &[
                    "mode",
                    "targets",
                    "kinds",
                    "max_count",
                    "not_before",
                    "expires_at",
                    "nonce",
                    "rate",
                ],
            )?;
            body
        } else {
            exact(
                &value,
                &[
                    "v",
                    "mode",
                    "targets",
                    "kinds",
                    "max_count",
                    "expires_at",
                    "nonce",
                ],
            )?;
            if integer(&value, "v")? != 1 {
                return Err(refusal("standing-permission-version"));
            }
            &value
        };
        let mode = text_field(body, "mode")?;
        let enabled = match mode {
            "ask" => false,
            "risky" | "limits" => true,
            _ => return Err(refusal("standing-permission-mode")),
        };
        let kinds = array(member(body, "kinds")?)?;
        if kinds.len() != 1 || !matches!(kinds[0].view(), ValueView::Text("put")) {
            return Err(refusal("standing-action"));
        }
        ProposalId::from_hex(text_field(body, "nonce")?)?;
        let maximum = unsigned_field(body, "max_count")?;
        let expires = integer(body, "expires_at")?;
        let starts = if glob {
            integer(body, "not_before")?
        } else {
            issued
        };
        if maximum > 1_000_000
            || starts < issued
            || starts >= expires
            || expires
                .checked_sub(issued)
                .is_none_or(|duration| duration <= 0 || duration > DAY_MS)
        {
            return Err(refusal("standing-window"));
        }
        let mut targets = Vec::new();
        let source = array(member(body, "targets")?)?;
        if source.len() > 32 {
            return Err(refusal("standing-scope"));
        }
        for entry in source {
            let ValueView::Text(target) = entry.view() else {
                return Err(refusal("standing-scope"));
            };
            if !valid_target(target, glob) || targets.iter().any(|prior| prior == target) {
                return Err(refusal("standing-scope"));
            }
            targets.push(target.to_owned());
        }
        if (enabled && (targets.is_empty() || maximum == 0))
            || (!enabled && (!targets.is_empty() || maximum != 0))
        {
            return Err(refusal("standing-scope"));
        }
        let (rate_count, window_ms) = if glob {
            let rate = member(body, "rate")?;
            exact(rate, &["max_count", "window_ms"])?;
            (
                unsigned_field(rate, "max_count")?,
                integer(rate, "window_ms")?,
            )
        } else {
            (maximum, expires - issued)
        };
        if rate_count > maximum
            || (enabled && rate_count == 0)
            || window_ms <= 0
            || window_ms > DAY_MS
        {
            return Err(refusal("standing-rate"));
        }
        Ok(Self {
            targets,
            maximum,
            starts,
            expires,
            rate_count,
            window_ms,
            enabled,
            glob,
        })
    }

    pub fn allows(&self, target: &str) -> bool {
        valid_target(target, false)
            && self.targets.iter().any(|pattern| {
                if self.glob {
                    glob_match(pattern, target)
                } else {
                    pattern == target
                }
            })
    }
}

fn valid_target(target: &str, glob: bool) -> bool {
    if target.is_empty()
        || target.len() > 128
        || target.starts_with('/')
        || target.contains("**")
        || !target.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || b"/._-".contains(&byte)
                || (glob && b"*?".contains(&byte))
        })
        || target
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return false;
    }
    !target
        .to_ascii_lowercase()
        .split(['/', '.', '-', '_'])
        .any(|part| {
            matches!(
                part,
                "release"
                    | "broker"
                    | "grant"
                    | "floor"
                    | "identity"
                    | "aumlok"
                    | "gate"
                    | "slider"
                    | "permission"
            )
        })
}

// Wildcards match only within a path component, with bounded dynamic programming.
fn glob_match(pattern: &str, target: &str) -> bool {
    let mut previous = vec![false; target.len() + 1];
    previous[0] = true;
    for token in pattern.bytes() {
        let mut next = vec![false; target.len() + 1];
        next[0] = token == b'*' && previous[0];
        for (index, byte) in target.bytes().enumerate() {
            next[index + 1] = if token == b'*' {
                previous[index + 1] || (byte != b'/' && next[index])
            } else {
                previous[index] && (token == byte || (token == b'?' && byte != b'/'))
            };
        }
        previous = next;
    }
    previous[target.len()]
}

pub(super) struct Stored {
    pub permission: ProposalId,
    pub digest: Digest32,
    pub approval: Digest32,
    pub sequence: u64,
    pub count: u64,
    pub revoked: bool,
}

impl Stored {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 2_048 {
            return Err(refusal("standing-storage"));
        }
        let value = json::parse_strict(bytes)?;
        exact(
            &value,
            &[
                "schema",
                "permission",
                "digest",
                "approval",
                "grant_sequence",
                "consumed_count",
                "revoked",
            ],
        )?;
        if value.canonical_bytes() != bytes || text_field(&value, "schema")? != STORAGE_SCHEMA {
            return Err(refusal("standing-storage"));
        }
        let ValueView::Boolean(revoked) = member(&value, "revoked")?.view() else {
            return Err(refusal("standing-storage"));
        };
        Ok(Self {
            permission: ProposalId::from_hex(text_field(&value, "permission")?)?,
            digest: Digest32::from_hex(text_field(&value, "digest")?)?,
            approval: Digest32::from_hex(text_field(&value, "approval")?)?,
            sequence: unsigned_field(&value, "grant_sequence")?,
            count: unsigned_field(&value, "consumed_count")?,
            revoked,
        })
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        Ok(object(vec![
            ("schema", text(STORAGE_SCHEMA)?),
            ("permission", text(self.permission)?),
            ("digest", text(self.digest)?),
            ("approval", text(self.approval)?),
            ("grant_sequence", number(self.sequence)?),
            ("consumed_count", number(self.count)?),
            ("revoked", Value::boolean(self.revoked)),
        ])?
        .canonical_bytes())
    }
}

pub(super) fn exact(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == names.len() && names.iter().all(|key| value.get(key).is_some()) =>
        {
            Ok(())
        }
        _ => Err(refusal("standing-format")),
    }
}

pub(super) fn member<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(refusal("standing-format"))
}

pub(super) fn text_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name).ok_or(refusal("standing-format"))
}

pub(super) fn integer(value: &Value, name: &str) -> Result<i64> {
    match member(value, name)?.view() {
        ValueView::Integer(number) => Ok(number.get()),
        _ => Err(refusal("standing-format")),
    }
}

pub(super) fn unsigned_field(value: &Value, name: &str) -> Result<u64> {
    u64::try_from(integer(value, name)?).map_err(|_| refusal("standing-format"))
}

fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(values) => Ok(values),
        _ => Err(refusal("standing-format")),
    }
}

pub(super) fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}

pub(super) fn number(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(sql_number(value)?)?))
}

pub(super) fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
