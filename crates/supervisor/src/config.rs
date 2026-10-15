// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::{bail, Result};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub boot_probe: bool,
    /// Enforce the root-owned release floor after the root install step enables it.
    #[serde(default)]
    pub release_floor: bool,
    #[serde(default)]
    pub nostr: Nostr,
    #[serde(default)]
    pub openviking: OpenViking,
    #[serde(default)]
    pub invite: Option<crate::invites::Admission>,
    pub node_id: String,
    pub state_dir: PathBuf,
    pub listen: SocketAddr,
    pub chat_hostname: String,
    pub owner_hostname: String,
    pub chat_origin: String,
    pub owner_origin: String,
    pub trusted_proxy: TrustedProxy,
    pub guest: Guest,
    pub cgroup_root: PathBuf,
    pub broker: Broker,
    pub webauthn: WebAuthn,
    pub limits: Limits,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenViking {
    pub enabled: bool,
    pub command: PathBuf,
    pub port: u16,
    pub embedding_port: u16,
    pub data_dir: PathBuf,
    pub timeout_ms: u64,
    /// How long a fresh openviking-server may take to report healthy before it is restarted.
    pub start_grace_ms: u64,
    pub account: String,
    pub user: String,
}
impl Default for OpenViking {
    fn default() -> Self {
        Self {
            enabled: false,
            command: "/opt/aukora/openviking/venv/bin/openviking-server".into(),
            port: 1933,
            embedding_port: 1934,
            data_dir: "/var/lib/aukora/openviking/data".into(),
            timeout_ms: 1000,
            // A real 0.4.21 cold start reported healthy after 10.1 s on S2 (2026-10-15); 5 s killed every start.
            start_grace_ms: 60_000,
            account: "aukora".into(),
            user: "owner".into(),
        }
    }
}
impl OpenViking {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0
            || self.embedding_port == 0
            || self.port == self.embedding_port
            || !(10..=2000).contains(&self.timeout_ms)
            || !(1_000..=300_000).contains(&self.start_grace_ms)
            || [&self.account, &self.user].iter().any(|s| {
                s.is_empty()
                    || s.len() > 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            })
        {
            bail!("supervisor:openviking-config");
        }
        for path in [&self.command, &self.data_dir] {
            if !path.is_absolute()
                || path.components().any(|p| {
                    matches!(
                        p,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                bail!("supervisor:openviking-path");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nostr {
    #[serde(default)]
    pub relays: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProxy {
    pub peers: Vec<IpAddr>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    pub node_dir: PathBuf,
    pub harness_dir: PathBuf,
    pub bundle_dir: PathBuf,
    pub subordinate_uid: u32,
    pub subordinate_gid: u32,
    /// The guest's workspace and sandbox root live here, outside the private state
    /// directory: the sandbox child already runs as the guest's uid when it resolves
    /// them, so this directory is traversable (0711) while the state stays 0700.
    #[serde(default = "default_guest_work_dir")]
    pub work_dir: PathBuf,
}
fn default_guest_work_dir() -> PathBuf {
    PathBuf::from("/var/lib/aukora-guest")
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Broker {
    pub provider_base_url: String,
    pub allowed_models: Vec<String>,
    pub default_model: String,
    pub prices: BTreeMap<String, broker::PriceBasis>,
}
impl Broker {
    /// The label grants and memory permissions name; the base URL is validated at load.
    pub fn provider_name(&self) -> &'static str {
        broker::provider_name(&self.provider_base_url).unwrap_or("openrouter")
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthn {
    pub rp_id: String,
    pub origin: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub pids_max: u64,
    pub memory_max_bytes: u64,
    #[serde(default = "default_file_size_max_bytes")]
    pub file_size_max_bytes: u64,
    #[serde(default = "default_workspace_max_bytes")]
    pub workspace_max_bytes: u64,
    pub cpu_max: String,
    pub max_connections: usize,
    pub max_body_bytes: usize,
    pub session_seconds: u64,
    pub request_seconds: u64,
}
fn default_file_size_max_bytes() -> u64 {
    launcher::DEFAULT_FILE_SIZE_MAX_BYTES
}
fn default_workspace_max_bytes() -> u64 {
    4 * 1024 * 1024 * 1024
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        canon::parse(&bytes)?;
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        self.openviking.validate()?;
        if let Some(invite) = &self.invite {
            crate::invites::validate_admission(invite)?;
        }
        if self.nostr.relays.len() > 8 {
            bail!("supervisor:nostr-relay-limit");
        }
        for url in &self.nostr.relays {
            relay::validate_url(url)?;
        }
        if !hex_value(&self.node_id, 32) {
            bail!("supervisor:invalid-node");
        }
        if self.chat_hostname == self.owner_hostname
            || !hostname(&self.chat_hostname)
            || !hostname(&self.owner_hostname)
            || self.chat_origin != format!("https://{}", self.chat_hostname)
            || self.owner_origin != format!("https://{}", self.owner_hostname)
            || self.webauthn.rp_id != self.owner_hostname
            || self.webauthn.origin != self.owner_origin
        {
            bail!("supervisor:origin-mismatch");
        }
        if self.trusted_proxy.peers.is_empty() || !self.listen.ip().is_loopback() {
            bail!("supervisor:proxy-required");
        }
        for path in [
            &self.state_dir,
            &self.cgroup_root,
            &self.guest.node_dir,
            &self.guest.harness_dir,
            &self.guest.bundle_dir,
        ] {
            if !path.is_absolute()
                || path.components().any(|p| {
                    matches!(
                        p,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                bail!("supervisor:invalid-path");
            }
        }
        if self.guest.subordinate_uid < 100_000 || self.guest.subordinate_gid < 100_000 {
            bail!("supervisor:subordinate-required");
        }
        if !matches!(
            self.broker.provider_base_url.as_str(),
            "https://openrouter.ai/api/v1" | "https://api.deepseek.com"
        ) {
            bail!("broker:provider-fixed");
        }
        if self.broker.allowed_models.is_empty()
            || !self
                .broker
                .allowed_models
                .contains(&self.broker.default_model)
            || self.broker.allowed_models.iter().any(|m| !model_id(m))
            || self
                .broker
                .allowed_models
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.broker.allowed_models.len()
            || self
                .broker
                .prices
                .keys()
                .any(|m| !self.broker.allowed_models.contains(m))
            || self
                .broker
                .prices
                .values()
                .any(|p| p.prompt_microusd_per_token == 0 || p.completion_microusd_per_token == 0)
        {
            bail!("broker:invalid-models");
        }
        if self.limits.pids_max == 0
            || self.limits.memory_max_bytes == 0
            || !(1..=canon::MAX_SAFE_INTEGER as u64).contains(&self.limits.file_size_max_bytes)
            || !(1..=canon::MAX_SAFE_INTEGER as u64).contains(&self.limits.workspace_max_bytes)
            || self.limits.max_connections == 0
            || !(1..=1_048_576).contains(&self.limits.max_body_bytes)
            || !(1..=86_400).contains(&self.limits.session_seconds)
            || !(1..=300).contains(&self.limits.request_seconds)
        {
            bail!("supervisor:invalid-limits");
        }
        let cpu: Vec<_> = self.limits.cpu_max.split_whitespace().collect();
        if cpu.len() != 2
            || cpu
                .iter()
                .any(|n| n.parse::<u64>().is_err() || n.parse::<u64>() == Ok(0))
        {
            bail!("supervisor:invalid-limits");
        }
        Ok(())
    }
}
pub fn hex_value(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && !value.contains("sk-or-")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn antibody_boot_probe_defaults_off_and_accepts_only_boolean_switch() {
        let source = include_str!("../../../deploy/node.example.json");
        let default: Config = serde_json::from_str(source).unwrap();
        assert!(!default.boot_probe);
        let mut value: serde_json::Value = serde_json::from_str(source).unwrap();
        value["boot_probe"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<Config>(value.clone())
                .unwrap()
                .boot_probe
        );
        for invalid in [
            serde_json::json!("true"),
            serde_json::json!(1),
            serde_json::Value::Null,
        ] {
            value["boot_probe"] = invalid;
            assert!(serde_json::from_value::<Config>(value.clone()).is_err());
        }
    }
    #[test]
    fn antibody_openviking_start_grace_covers_a_real_cold_start() {
        // openviking-server 0.4.21 took 10.1 s to report healthy on S2; a 5 s grace restarted it forever.
        let default = OpenViking::default();
        assert!(default.start_grace_ms >= 30_000);
        default.validate().unwrap();
        for bad in [0, 999, 300_001] {
            let config = OpenViking {
                start_grace_ms: bad,
                ..OpenViking::default()
            };
            assert!(config.validate().is_err());
        }
    }
    #[test]
    fn antibody_openviking_config_defaults_off_and_restricts_endpoints_and_limits() {
        let source = include_str!("../../../deploy/node.example.json");
        let default: Config = serde_json::from_str(source).unwrap();
        assert!(!default.openviking.enabled);
        let mut value: serde_json::Value = serde_json::from_str(source).unwrap();
        value["openviking"] = serde_json::json!({"enabled":true});
        let enabled: Config = serde_json::from_value(value.clone()).unwrap();
        enabled.validate().unwrap();
        for (field, bad) in [
            ("enabled", serde_json::json!("true")),
            ("host", serde_json::json!("0.0.0.0")),
            (
                "embedding_url",
                serde_json::json!("https://provider.example"),
            ),
            ("args", serde_json::json!(["--host", "0.0.0.0"])),
        ] {
            let mut changed = value.clone();
            changed["openviking"][field] = bad;
            assert!(serde_json::from_value::<Config>(changed).is_err());
        }
        for (field, bad) in [
            ("port", serde_json::json!(0)),
            ("embedding_port", serde_json::json!(1933)),
            ("timeout_ms", serde_json::json!(0)),
            ("timeout_ms", serde_json::json!(2001)),
            ("command", serde_json::json!("relative-command")),
            ("data_dir", serde_json::json!("/private/tmp/../escape")),
            ("user", serde_json::json!("../../escape")),
        ] {
            let mut changed = value.clone();
            changed["openviking"][field] = bad;
            assert!(
                serde_json::from_value::<Config>(changed)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn config_rejects_unrecognized_fields_wrong_origins_provider_and_limits() {
        let source = include_str!("../../../deploy/node.example.json");
        let good: Config = serde_json::from_str(source).unwrap();
        good.validate().unwrap();
        let value: serde_json::Value = serde_json::from_str(source).unwrap();
        for (path, bad) in [
            ("unknown", serde_json::json!(true)),
            ("guest/unknown", serde_json::json!(0)),
            ("broker/unknown", serde_json::json!(0)),
            ("trusted_proxy/unknown", serde_json::json!(0)),
            ("limits/unknown", serde_json::json!(0)),
            ("webauthn/unknown", serde_json::json!(0)),
        ] {
            let mut changed = value.clone();
            let mut parts = path.split('/');
            let first = parts.next().unwrap();
            if let Some(second) = parts.next() {
                changed[first][second] = bad;
            } else {
                changed[first] = bad;
            }
            assert!(serde_json::from_value::<Config>(changed).is_err(), "{path}");
        }
        let mut bad = good.clone();
        bad.broker.provider_base_url = "https://other.example/api/v1".into();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.chat_hostname = bad.owner_hostname.clone();
        bad.chat_origin = bad.owner_origin.clone();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.webauthn.origin = bad.chat_origin.clone();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.trusted_proxy.peers.clear();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.listen = "0.0.0.0:18080".parse().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.guest.subordinate_uid = 0;
        assert!(bad.validate().is_err());
        let mut bad = good;
        bad.limits.session_seconds = 0;
        assert!(bad.validate().is_err());
    }
    #[test]
    fn config_loader_refuses_duplicate_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node.json");
        let valid = include_str!("../../../deploy/node.example.json");
        std::fs::write(&path, valid).unwrap();
        Config::load(&path).unwrap();
        let duplicate =
            valid.replacen('{', "{\"node_id\":\"00000000000000000000000000000000\",", 1);
        std::fs::write(path.clone(), duplicate).unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn antibody_node_json_refuses_twin_and_kdf_choices() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node.json");
        let mut valid: serde_json::Value =
            serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
        valid["broker"]["prices"]["deepseek/deepseek-chat"] = serde_json::json!({
            "prompt_microusd_per_token": 1,
            "completion_microusd_per_token": 1,
        });
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        Config::load(&path).unwrap();

        for parent in [
            "",
            "/trusted_proxy",
            "/guest",
            "/broker",
            "/broker/prices/deepseek~1deepseek-chat",
            "/webauthn",
            "/limits",
        ] {
            for (field, value) in [
                ("twin", serde_json::json!(true)),
                ("is_twin", serde_json::json!(true)),
                ("twin_mode", serde_json::json!(true)),
                ("replay_twin", serde_json::json!(true)),
                ("cheap_kdf", serde_json::json!(true)),
                ("use_cheap_kdf", serde_json::json!(true)),
                ("kdf", serde_json::json!("twin")),
                ("kdf_choice", serde_json::json!("twin")),
                ("kdf_mode", serde_json::json!("twin")),
                (
                    "kdf_params",
                    serde_json::json!({"memory_kib": 8, "time_cost": 1, "parallelism": 1}),
                ),
                ("kdf_memory_kib", serde_json::json!(8)),
                ("kdf_iterations", serde_json::json!(1)),
            ] {
                let mut changed = valid.clone();
                changed
                    .pointer_mut(parent)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), value);
                std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
                let error = match Config::load(&path) {
                    Ok(_) => panic!("node.json accepted {parent}/{field}"),
                    Err(error) => error.to_string(),
                };
                assert!(
                    error.contains("unknown field") && error.contains(field),
                    "{parent}/{field}: {error}"
                );
            }
        }
    }

    #[test]
    fn antibody_file_size_limit_refuses_zero_and_unbounded_values() {
        // Expected refusal: supervisor:invalid-limits.
        let valid: Config =
            serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
        for bytes in [0, canon::MAX_SAFE_INTEGER as u64 + 1, u64::MAX] {
            let mut changed = valid.clone();
            changed.limits.file_size_max_bytes = bytes;
            assert_eq!(
                changed.validate().unwrap_err().to_string(),
                "supervisor:invalid-limits",
                "file_size_max_bytes={bytes}"
            );
        }
    }

    #[test]
    fn antibody_workspace_limit_refuses_zero_and_unbounded_values() {
        // Expected refusal: supervisor:invalid-limits.
        let valid: Config =
            serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
        for bytes in [0, canon::MAX_SAFE_INTEGER as u64 + 1, u64::MAX] {
            let mut changed = valid.clone();
            changed.limits.workspace_max_bytes = bytes;
            assert_eq!(
                changed.validate().unwrap_err().to_string(),
                "supervisor:invalid-limits",
                "workspace_max_bytes={bytes}"
            );
        }
    }

    #[test]
    fn antibody_disk_limits_default_and_remain_owner_configurable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node.json");
        let source = include_str!("../../../deploy/node.example.json");
        std::fs::write(&path, source).unwrap();
        let default = Config::load(&path).unwrap();
        assert_eq!(default.limits.file_size_max_bytes, 256 * 1024 * 1024);
        assert_eq!(default.limits.workspace_max_bytes, 4 * 1024 * 1024 * 1024);

        let mut configured: serde_json::Value = serde_json::from_str(source).unwrap();
        configured["limits"]["file_size_max_bytes"] = serde_json::json!(1024 * 1024 * 1024_u64);
        configured["limits"]["workspace_max_bytes"] =
            serde_json::json!(16 * 1024 * 1024 * 1024_u64);
        std::fs::write(&path, serde_json::to_vec(&configured).unwrap()).unwrap();
        let changed = Config::load(&path).unwrap();
        assert_eq!(changed.limits.file_size_max_bytes, 1024 * 1024 * 1024);
        assert_eq!(changed.limits.workspace_max_bytes, 16 * 1024 * 1024 * 1024);
        let mut largest = changed;
        largest.limits.file_size_max_bytes = canon::MAX_SAFE_INTEGER as u64;
        largest.limits.workspace_max_bytes = canon::MAX_SAFE_INTEGER as u64;
        largest.validate().unwrap();
    }
}
