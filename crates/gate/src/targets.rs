use crate::{Error, Result};
use serde_json::Value;
use std::collections::BTreeSet;

pub const THEME_TARGET: &str = "plugins/auma-theme/theme.json";
pub const NOTE_TARGET: &str = "plugins/owner-note/note.md";
pub type ReviewFacts = fn(Option<&[u8]>, &[u8]) -> Result<Value>;

pub(crate) fn validate_release_evidence(new_sha256: &str, evidence: &Value) -> Result<()> {
    let hex_digest = |text: &str| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let fields = [
        "new_sha256",
        "antibody_corpus_sha256",
        "antibody_pass_count",
        "antibody_total",
        "antibody_ids",
    ];
    let optional = [
        "supervisor_binary_sha256",
        "proposal_id",
        "refusal_code",
        "failed_ids",
        "missing_ids",
    ];
    let object = evidence
        .as_object()
        .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
    let ids = evidence["antibody_ids"]
        .as_array()
        .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
    let total = evidence["antibody_total"].as_u64();
    let passed = evidence["antibody_pass_count"].as_u64();
    let mut seen = BTreeSet::new();
    if object
        .keys()
        .any(|field| !fields.contains(&field.as_str()) && !optional.contains(&field.as_str()))
        || fields.iter().any(|field| !object.contains_key(*field))
        || !hex_digest(new_sha256)
        || evidence["new_sha256"].as_str() != Some(new_sha256)
        || !evidence["antibody_corpus_sha256"]
            .as_str()
            .is_some_and(hex_digest)
        || total != Some(ids.len() as u64)
        || total == Some(0)
        || passed.is_none()
        || passed > total
        || ids.iter().any(|id| {
            !id.as_str().is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
                    && seen.insert(id)
            })
        })
    {
        return Err(Error::Refused("gate:review-facts-unavailable"));
    }
    if object
        .get("supervisor_binary_sha256")
        .is_some_and(|value| !value.as_str().is_some_and(hex_digest))
        || object.get("proposal_id").is_some_and(|value| {
            !value.as_str().is_some_and(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        })
        || object.get("refusal_code").is_some_and(|value| {
            !value.is_null()
                && !value.as_str().is_some_and(|code| {
                    code.starts_with("immune:")
                        && code.len() <= 80
                        && code
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b":-".contains(&byte))
                })
        })
    {
        return Err(Error::Refused("gate:review-facts-unavailable"));
    }
    for field in ["failed_ids", "missing_ids"] {
        if let Some(value) = object.get(field) {
            let mut seen = BTreeSet::new();
            if !value.as_array().is_some_and(|ids| {
                ids.iter().all(|id| {
                    id.as_str().is_some_and(|id| {
                        !id.is_empty()
                            && id.len() <= 128
                            && id
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
                            && seen.insert(id)
                    })
                })
            }) {
                return Err(Error::Refused("gate:review-facts-unavailable"));
            }
        }
    }
    crate::canonical(evidence).map_err(|_| Error::Refused("gate:review-facts-unavailable"))?;
    Ok(())
}

#[derive(Clone, Copy)]
pub enum Schema {
    Theme,
    Note,
    Release,
    BrokerKey,
    BrokerGrant,
    KiraPermission,
    Custom(fn(&[u8]) -> Result<()>),
}

#[derive(Clone)]
pub struct TargetSpec {
    pub name: String,
    pub max_bytes: usize,
    pub operator_only: bool,
    pub risk: &'static str,
    pub says: &'static str,
    pub schema: Schema,
    /// A longer pending lifetime is permitted only on an operator-only target.
    pub ttl_ms: Option<i64>,
    /// Independently read trusted target facts. Errors disable approval.
    pub review_facts: Option<ReviewFacts>,
    pub pinned_facts: Option<Value>,
}

impl TargetSpec {
    pub fn supervisor(name: &str) -> Result<Self> {
        let (schema, says) = match name {
            "gate/permission" => (
                Schema::Custom(crate::standing::validate),
                "Choose when proposals need your approval",
            ),
            "release" => (Schema::Release, "Start the agent runtime"),
            "broker/key" => (Schema::BrokerKey, "Use this model provider key"),
            "broker/grant" => (Schema::BrokerGrant, "Authorize this model spend grant"),
            "kira/permission" => (Schema::KiraPermission, "Permit memory in hosted context"),
            _ => return Err(Error::Refused("gate:target-not-allowed")),
        };
        Ok(Self {
            name: name.into(),
            max_bytes: 4096,
            operator_only: true,
            risk: "critical",
            says,
            schema,
            ttl_ms: Some(86_400_000),
            review_facts: Some(supervisor_facts),
            pinned_facts: None,
        })
    }
    pub fn theme() -> Self {
        Self {
            name: THEME_TARGET.into(),
            max_bytes: 256,
            operator_only: false,
            risk: "routine",
            says: "Change the app theme accent only.",
            schema: Schema::Theme,
            ttl_ms: None,
            review_facts: None,
            pinned_facts: None,
        }
    }

    pub fn note() -> Self {
        Self {
            name: NOTE_TARGET.into(),
            max_bytes: 2000,
            operator_only: false,
            risk: "routine",
            says: "Replace the owner-visible note only; its text grants no authority.",
            schema: Schema::Note,
            ttl_ms: None,
            review_facts: None,
            pinned_facts: None,
        }
    }

    pub fn custom(
        name: impl Into<String>,
        max_bytes: usize,
        validate: fn(&[u8]) -> Result<()>,
    ) -> Self {
        Self {
            name: name.into(),
            max_bytes,
            operator_only: true,
            risk: "critical",
            says: "Apply the exact stored change to this target; read the gate facts and diff.",
            schema: Schema::Custom(validate),
            ttl_ms: None,
            review_facts: None,
            pinned_facts: None,
        }
    }

    pub fn validate_name(&self) -> Result<()> {
        let name = &self.name;
        if name.is_empty() || name.encode_utf16().count() > 200 {
            return Err(Error::Refused("gate:target-name"));
        }
        if name.starts_with('/')
            || name.contains('\\')
            || name.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
        {
            return Err(Error::Refused("gate:target-name"));
        }
        let parts: Vec<_> = name.split('/').collect();
        let supervisor = matches!(
            name.as_str(),
            "release" | "broker/key" | "broker/grant" | "kira/permission" | "gate/permission"
        );
        if supervisor && !self.operator_only {
            return Err(Error::Refused("gate:operator-only"));
        }
        if !supervisor
            && (parts.len() < 3
                || parts[0] != "plugins"
                || parts
                    .iter()
                    .any(|p| p.is_empty() || *p == "." || *p == ".."))
        {
            return Err(Error::Refused("gate:target-name"));
        }
        if name.rsplit_once('.').is_some_and(|(_, suffix)| {
            ["js", "mjs", "cjs", "ts", "sh", "py", "node", "so"]
                .iter()
                .any(|code| suffix.eq_ignore_ascii_case(code))
        }) {
            return Err(Error::Refused("gate:code-target"));
        }
        if self.max_bytes == 0 || self.max_bytes > 4096 {
            return Err(Error::Refused("gate:target-limit"));
        }
        if self
            .ttl_ms
            .is_some_and(|ttl| !self.operator_only || ttl <= 0 || ttl > 24 * 60 * 60 * 1000)
        {
            return Err(Error::Refused("gate:target-ttl"));
        }
        Ok(())
    }

    pub fn validate(&self, bytes: &[u8]) -> Result<()> {
        self.validate_name()?;
        if bytes.len() > self.max_bytes {
            return Err(Error::Refused("gate:too-large"));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Refused("gate:invalid-utf8"))?;
        if self.name != NOTE_TARGET && !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return Err(Error::Refused("gate:non-ascii"));
        }
        match self.schema {
            Schema::Theme => validate_theme(bytes),
            Schema::Note => validate_note(text),
            Schema::Release => validate_supervisor(bytes, "release"),
            Schema::BrokerKey => validate_supervisor(bytes, "broker/key"),
            Schema::BrokerGrant => validate_supervisor(bytes, "broker/grant"),
            Schema::KiraPermission => validate_supervisor(bytes, "kira/permission"),
            Schema::Custom(validate) => validate(bytes),
        }
    }

    pub fn validate_at(&self, bytes: &[u8], now: i64) -> Result<()> {
        self.validate(bytes)?;
        if self.name == crate::standing::TARGET {
            let value: Value = serde_json::from_slice(bytes)?;
            let expires = value["expires_at"]
                .as_i64()
                .ok_or(Error::Refused("gate:record-schema"))?;
            if expires <= now || expires > now.saturating_add(crate::standing::DAY_MS) {
                return Err(Error::Refused("gate:record-schema"));
            }
        }
        if matches!(self.schema, Schema::BrokerGrant) {
            let record: Value = serde_json::from_slice(bytes)?;
            let expires = record["expires_at"]
                .as_i64()
                .ok_or(Error::Refused("broker:invalid-grant"))?;
            if expires <= now || expires > now.saturating_add(86_400_000) {
                return Err(Error::Refused("broker:invalid-grant"));
            }
        }
        Ok(())
    }
}

fn supervisor_facts(_: Option<&[u8]>, bytes: &[u8]) -> Result<Value> {
    let record: Value = serde_json::from_slice(bytes)?;
    let mut facts = Vec::new();
    if let Some(digest) = record.get("digest") {
        facts.push(serde_json::json!(["Runtime digest", digest]));
        for component in ["node", "harness", "guest"] {
            facts.push(serde_json::json!([
                component,
                record["components"][component]
            ]));
        }
    } else if let Some(key) = record["key_sha256"].as_str() {
        facts.push(serde_json::json!(["Key fingerprint", &key[..8]]));
    } else if record.get("cap_microusd").is_some() {
        facts.push(serde_json::json!([
            "Provider",
            provider_label(record["provider"].as_str())?
        ]));
        for (field, label) in [
            ("cap_microusd", "Total cap USD"),
            ("per_request_cap_microusd", "Per request cap USD"),
        ] {
            let value = record[field]
                .as_u64()
                .ok_or(Error::Refused("gate:record-schema"))?;
            facts.push(serde_json::json!([
                label,
                format!("{}.{:06}", value / 1_000_000, value % 1_000_000)
            ]));
        }
        for (field, label) in [
            ("model", "Model"),
            ("max_requests", "Maximum requests"),
            ("expires_at", "Expires at ms"),
        ] {
            facts.push(serde_json::json!([label, record[field].to_string()]));
        }
    } else if record.get("mode").is_some() {
        for (field, label) in [
            ("mode", "When to ask"),
            ("targets", "Exact targets"),
            ("kinds", "Change kinds"),
            ("max_count", "Maximum changes"),
            ("expires_at", "Expires at ms"),
        ] {
            facts.push(serde_json::json!([label, record[field].to_string()]));
        }
        facts.push(serde_json::json!([
            "Risk rule",
            "Risky changes always require a fresh approval"
        ]));
    } else {
        facts.push(serde_json::json!([
            "Purpose",
            format!(
                "Memory in {} hosted context",
                provider_label(record["model_provider"].as_str())?
            )
        ]));
    }
    Ok(
        serde_json::json!({"from_to":"Apply the exact supervisor record shown below", "facts":facts}),
    )
}

fn provider_label(provider: Option<&str>) -> Result<&'static str> {
    match provider {
        Some("openrouter") => Ok("OpenRouter"),
        Some("deepseek") => Ok("DeepSeek"),
        _ => Err(Error::Refused("gate:record-schema")),
    }
}

fn validate_supervisor(bytes: &[u8], target: &str) -> Result<()> {
    let value = canon::parse(bytes).map_err(|_| Error::Refused("gate:record-schema"))?;
    if canon::canonical_json(&value).map_err(|_| Error::Refused("gate:record-schema"))? != bytes {
        return Err(Error::Refused("gate:record-schema"));
    }
    let object: Value = serde_json::from_slice(bytes)?;
    let fields = object
        .as_object()
        .ok_or(Error::Refused("gate:record-schema"))?;
    let expected: &[&str] = match target {
        "release" => &["v", "digest", "components"],
        "broker/key" => &["v", "key_sha256"],
        "broker/grant" => &[
            "v",
            "provider",
            "model",
            "cap_microusd",
            "per_request_cap_microusd",
            "max_requests",
            "expires_at",
            "nonce",
        ],
        "kira/permission" => &["v", "purpose", "model_provider"],
        _ => return Err(Error::Refused("gate:record-schema")),
    };
    if fields.len() != expected.len()
        || expected.iter().any(|key| !fields.contains_key(*key))
        || object["v"] != 1
    {
        return Err(Error::Refused("gate:record-schema"));
    }
    let digest = |value: &Value, length| {
        value.as_str().is_some_and(|s| {
            s.len() == length
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    };
    let valid = match target {
        "release" => {
            digest(&object["digest"], 64)
                && object["components"].as_object().is_some_and(|c| {
                    c.len() == 3
                        && ["node", "harness", "guest"]
                            .iter()
                            .all(|k| c.get(*k).is_some_and(|v| digest(v, 64)))
                })
        }
        "broker/key" => digest(&object["key_sha256"], 64),
        "broker/grant" => {
            matches!(object["provider"].as_str(), Some("openrouter" | "deepseek"))
                && object["model"].as_str().is_some_and(|m| {
                    !m.is_empty()
                        && m.len() <= 200
                        && !m.contains("sk-or-")
                        && m.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
                })
                && [
                    "cap_microusd",
                    "per_request_cap_microusd",
                    "max_requests",
                    "expires_at",
                ]
                .iter()
                .all(|k| object[k].as_u64().is_some_and(|n| n > 0))
                && object["per_request_cap_microusd"].as_u64() <= object["cap_microusd"].as_u64()
                && digest(&object["nonce"], 32)
        }
        "kira/permission" => {
            object["purpose"] == "hosted-context"
                && matches!(
                    object["model_provider"].as_str(),
                    Some("openrouter" | "deepseek")
                )
        }
        _ => false,
    };
    if !valid {
        return Err(Error::Refused("gate:record-schema"));
    }
    Ok(())
}

fn validate_theme(bytes: &[u8]) -> Result<()> {
    let canonical = bytes == b"{\"accent\": \"default\"}"
        || (bytes.len() == 21
            && bytes.starts_with(b"{\"accent\": \"#")
            && bytes.ends_with(b"\"}")
            && bytes[13..19]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte)));
    if !canonical {
        return Err(Error::Refused("gate:theme-schema"));
    }
    Ok(())
}

fn validate_note(text: &str) -> Result<()> {
    if text.len() > 2000 {
        return Err(Error::Refused("gate:too-large"));
    }
    if text
        .chars()
        .any(|c| matches!(c, '\u{0}'..='\u{8}' | '\u{b}'..='\u{1f}' | '\u{7f}'))
    {
        return Err(Error::Refused("gate:note-plain-text"));
    }
    if text.trim_matches(js_whitespace).is_empty() {
        return Err(Error::Refused("gate:note-empty"));
    }
    Ok(())
}

fn js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | '\u{20}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(value: Value) -> Vec<u8> {
        crate::canonical(&value).unwrap().into_bytes()
    }
    #[test]
    fn supervisor_records_are_canonical_exact_and_operator_only() {
        let release = TargetSpec::supervisor("release").unwrap();
        let valid = record(
            serde_json::json!({"v":1,"digest":"a".repeat(64),"components":{"node":"b".repeat(64),"harness":"c".repeat(64),"guest":"d".repeat(64)}}),
        );
        release.validate(&valid).unwrap();
        let mut guest = release.clone();
        guest.operator_only = false;
        guest.ttl_ms = None;
        assert!(guest.validate(&valid).is_err());
        let mut spaced = valid.clone();
        spaced.push(b' ');
        assert!(release.validate(&spaced).is_err());
        let mut bad: Value = serde_json::from_slice(&valid).unwrap();
        bad["components"]["extra"] = serde_json::json!("e".repeat(64));
        assert!(release.validate(&record(bad)).is_err());
        let key = TargetSpec::supervisor("broker/key").unwrap();
        key.validate(&record(
            serde_json::json!({"v":1,"key_sha256":"a".repeat(64)}),
        ))
        .unwrap();
        for bad in [
            serde_json::json!({"v":2,"key_sha256":"a".repeat(64)}),
            serde_json::json!({"v":1,"key_sha256":"A".repeat(64)}),
            serde_json::json!({"v":1,"key_sha256":"a".repeat(64),"key":"secret"}),
        ] {
            assert!(key.validate(&record(bad)).is_err());
        }
        let permission = TargetSpec::supervisor("kira/permission").unwrap();
        permission
            .validate(&record(
                serde_json::json!({"v":1,"purpose":"hosted-context","model_provider":"openrouter"}),
            ))
            .unwrap();
        assert!(permission
            .validate(&record(
                serde_json::json!({"v":1,"purpose":"anything","model_provider":"openrouter"})
            ))
            .is_err());
        for name in ["broker/other", "kira/key", "release/old"] {
            assert!(TargetSpec::supervisor(name).is_err());
        }
    }
    #[test]
    fn spend_grant_values_are_positive_and_expiry_at_most_24_hours() {
        let target = TargetSpec::supervisor("broker/grant").unwrap();
        let now = 1_800_000_000_000i64;
        let valid = serde_json::json!({"v":1,"provider":"openrouter","model":"deepseek/deepseek-chat","cap_microusd":1000,"per_request_cap_microusd":100,"max_requests":10,"expires_at":now+86_400_000,"nonce":"a".repeat(32)});
        target.validate_at(&record(valid.clone()), now).unwrap();
        for key in ["cap_microusd", "per_request_cap_microusd", "max_requests"] {
            let mut bad = valid.clone();
            bad[key] = serde_json::json!(0);
            assert!(target.validate_at(&record(bad), now).is_err());
        }
        for expires in [now, now + 86_400_001] {
            let mut bad = valid.clone();
            bad["expires_at"] = serde_json::json!(expires);
            assert!(target.validate_at(&record(bad), now).is_err());
        }
        let mut bad = valid.clone();
        bad["provider"] = serde_json::json!("other");
        assert!(target.validate_at(&record(bad), now).is_err());
        let mut bad = valid;
        bad["per_request_cap_microusd"] = serde_json::json!(1001);
        assert!(target.validate_at(&record(bad), now).is_err());
    }

    #[test]
    fn builtins_are_bounded_declarative_targets() {
        // Prime checks/boundary.mjs: allowlist: theme, operator-only plugin-set approval and one fixed note; code targets refused.
        let theme = TargetSpec::theme();
        let note = TargetSpec::note();
        assert_eq!(theme.name, THEME_TARGET);
        assert_eq!(theme.max_bytes, 256);
        assert_eq!(note.name, NOTE_TARGET);
        assert_eq!(note.max_bytes, 2000);
        assert!(!theme.operator_only && !note.operator_only);
        assert_eq!(theme.risk, "routine");
        assert_eq!(note.risk, "routine");
        assert!(note.says.contains("grants no authority"));
    }

    #[test]
    fn paths_cannot_escape_plugins_or_address_code() {
        // Prime checks/boundary.mjs: allowlist: theme, operator-only plugin-set approval and one fixed note; code targets refused.
        for bad in [
            "",
            "/plugins/x/file.json",
            "plugins/x/../file.json",
            "plugins/./file.json",
            "plugins/x//file.json",
            "plugins/x/",
            "plugins/x",
            "plugins/x\\file.json",
            "other/x/file.json",
            "plugins/x/\0file.json",
            "plugins/x/\u{1f}file.json",
            "plugins/x/\u{7f}file.json",
            "plugins/x/file.js",
            "plugins/x/file.MJS",
            "plugins/x/file.cjs",
            "plugins/x/file.ts",
            "plugins/x/file.sh",
            "plugins/x/file.py",
            "plugins/x/file.node",
            "plugins/x/file.so",
        ] {
            let mut target = TargetSpec::theme();
            target.name = bad.into();
            assert!(target.validate_name().is_err(), "accepted {bad:?}");
            assert!(target.validate(b"{\"accent\": \"default\"}").is_err());
        }
        for good in [
            THEME_TARGET,
            NOTE_TARGET,
            "plugins/é/note.md",
            "plugins/x/a/b.json",
            "plugins/x/file.JS.json",
            "plugins/x/js",
        ] {
            let mut target = TargetSpec::theme();
            target.name = good.into();
            assert!(target.validate_name().is_ok(), "refused {good:?}");
        }
    }

    #[test]
    fn path_length_uses_javascript_utf16_units_and_limits_are_bounded() {
        // Prime src/targets.mjs: assertTargetName's length <= 200; allowlist's 0 < maxBytes <= 4096.
        let mut target = TargetSpec::theme();
        target.name = format!("plugins/x/{}", "a".repeat(190));
        assert!(target.validate_name().is_ok());
        target.name.push('a');
        assert!(target.validate_name().is_err());
        target.name = format!("plugins/x/{}", "😀".repeat(95));
        assert!(target.validate_name().is_ok());
        target.name.push('😀');
        assert!(target.validate_name().is_err());
        target.name = THEME_TARGET.into();
        for limit in [0, 4097] {
            target.max_bytes = limit;
            assert!(target.validate_name().is_err());
        }
        target.max_bytes = 4096;
        assert!(target.validate_name().is_ok());
    }

    #[test]
    fn theme_only_accepts_exact_canonical_bytes() {
        // Prime checks/gate.mjs: content rules: printable ASCII, size, schema, required and current base, no identical change.
        // Prime checks/boundary.mjs: theme schema: canonical bytes only (with a hint), and the harness reader falls back to default.
        let theme = TargetSpec::theme();
        for good in [
            b"{\"accent\": \"default\"}".as_slice(),
            b"{\"accent\": \"#1E90FF\"}",
            b"{\"accent\": \"#012ABC\"}",
        ] {
            assert!(theme.validate(good).is_ok(), "refused {good:?}");
        }
        for bad in [
            "{\"accent\": \"#1E90FF\"}\n",
            "{\"accent\": \"#1E90FF\"}\r\n",
            "{\"accent\":\"#1E90FF\"}",
            "{\"accent\": \"#1e90ff\"}",
            "{\"accent\": \"#1E90FF\", \"accent\": \"#FFD700\"}",
            "{\"accent\": \"\\u0023FFD700\"}",
            " {\"accent\": \"#1E90FF\"}",
            "{\"accent\": \"#1E90FG\"}",
            "{\"accent\": \"Default\"}",
            "{\"accent\": \"#1E90FF\"}\u{2007}",
            "{\"accent\": \"é\"}",
            "{\"accent\": \"#1E90FF\"}\0",
            "{\"accent\": \"#1E90F\"}",
        ] {
            assert!(theme.validate(bad.as_bytes()).is_err(), "accepted {bad:?}");
        }
        assert!(theme.validate(&[0xff]).is_err());
        assert!(theme.validate(&vec![b'x'; 257]).is_err());
    }

    #[test]
    fn note_requires_utf8_plain_nonempty_bytes_with_a_byte_limit() {
        // Prime checks/note.mjs: note schema has the door character rules and a UTF-8 byte cap, without normalization.
        // Prime src/targets.mjs: noteTarget.validate permits TAB and LF only among C0 controls.
        let note = TargetSpec::note();
        for good in [
            "A note",
            "café 😀",
            "one\ttwo\nthree",
            "\u{85}",
            "\u{200b}",
            "�",
        ] {
            assert!(note.validate(good.as_bytes()).is_ok(), "refused {good:?}");
        }
        assert!(note.validate("é".repeat(1000).as_bytes()).is_ok());
        assert!(note.validate("é".repeat(1001).as_bytes()).is_err());
        assert!(note.validate(&vec![b'a'; 2000]).is_ok());
        assert!(note.validate(&vec![b'a'; 2001]).is_err());
        let mut wider_spec = note.clone();
        wider_spec.max_bytes = 4096;
        assert!(wider_spec.validate(&vec![b'a'; 2001]).is_err());
        for empty in [
            "",
            " \t\n",
            "\u{a0}\u{2007}",
            "\u{feff}",
            "\u{2028}\u{2029}",
        ] {
            assert!(
                note.validate(empty.as_bytes()).is_err(),
                "accepted blank {empty:?}"
            );
        }
        for control in (0u8..=31).chain([127]) {
            if control != b'\t' && control != b'\n' {
                assert!(
                    note.validate(&[b'a', control, b'b']).is_err(),
                    "accepted control {control}"
                );
            }
        }
        for invalid in [
            b"\xff".as_slice(),
            b"\xed\xa0\x80",
            b"\xc0\xaf",
            b"\xf0\x9f\x98",
        ] {
            assert!(
                note.validate(invalid).is_err(),
                "accepted malformed UTF-8 {invalid:?}"
            );
        }
    }

    #[test]
    fn custom_validator_cannot_bypass_limits_or_plain_ascii() {
        // Prime checks/note.mjs: the UTF-8 exception cannot widen other targets even with a permissive schema.
        let target = TargetSpec::custom("plugins/example/data.json", 3, |_| Ok(()));
        assert_eq!(target.risk, "critical");
        assert!(target.operator_only);
        assert!(target.validate(b"abc").is_ok());
        for bad in [b"abcd".as_slice(), b"a\nb", "é".as_bytes(), b"\xff"] {
            assert!(target.validate(bad).is_err());
        }
        let target = TargetSpec::custom("plugins/example/data.json", 3, |_| {
            Err(Error::Refused("gate:custom-schema"))
        });
        assert!(target.validate(b"abc").is_err());
        let mut renamed_note = TargetSpec::note();
        renamed_note.name = "plugins/example/data.json".into();
        assert!(renamed_note.validate("é".as_bytes()).is_err());
    }

    #[test]
    fn operator_ttl_is_positive_bounded_and_cannot_widen_guest_targets() {
        let mut operator = TargetSpec::custom("plugins/example/data.json", 256, |_| Ok(()));
        for ttl in [1, 86_400_000] {
            operator.ttl_ms = Some(ttl);
            assert!(operator.validate_name().is_ok());
        }
        for ttl in [0, -1, 86_400_001] {
            operator.ttl_ms = Some(ttl);
            assert!(operator.validate_name().is_err());
        }
        let mut guest = TargetSpec::theme();
        guest.ttl_ms = Some(1);
        assert!(guest.validate_name().is_err());
    }
}
