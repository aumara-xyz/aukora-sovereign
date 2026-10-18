// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decode deployment inputs without treating their observations as owner authority.

mod disk;
mod gate;
mod relay_policy;

use canon::{
    digest::Digest32,
    json::{self, Value, ValueView},
    Refusal, Result,
};
use frontdoor::tls::{CaddyBoundary, Origin};
use relay::egress::{EgressPolicy, RelayRule, ValidatedRelay};
use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Component, Path, PathBuf},
};

const NODE_FIELDS: &[&str] = &[
    "v",
    "kind",
    "node",
    "listen",
    "shell_origin",
    "owner_origin",
    "registered_site",
    "proxy_peers",
    "public_ip",
    "state_root",
    "approved_release_root",
    "cage_root",
    "cage_uid",
    "cage_gid",
    "claim_commitment",
    "egress_policy",
    "egress_status",
    "release_state",
];

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub node: String,
    pub listen: SocketAddr,
    pub shell_origin: String,
    pub owner_origin: String,
    pub registered_site: String,
    pub proxy_peers: Vec<IpAddr>,
    pub public_ip: Option<IpAddr>,
    pub state_root: PathBuf,
    pub approved_release_root: PathBuf,
    pub cage_root: PathBuf,
    pub cage_uid: u32,
    pub cage_gid: u32,
    pub claim_commitment: PathBuf,
    pub egress_policy: PathBuf,
    pub egress_status: PathBuf,
    pub release_state: PathBuf,
    directory: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ProviderPin {
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
pub struct EgressConfig {
    pub policy: EgressPolicy,
    pub providers: Vec<ProviderPin>,
}

impl NodeConfig {
    /// The host writes canonical node configuration before starting the service.
    /// Claim issuance happens later and is read separately by the claim service.
    pub fn load(path: &Path) -> Result<Self> {
        checked_path(path)?;
        if path.file_name().and_then(|name| name.to_str()) != Some("node.json") {
            return Err(refused("config-path"));
        }
        let directory = path.parent().ok_or(refused("config-path"))?.to_owned();
        let raw = disk::read_host_file(path, 16_384)?;
        let value = canonical(&raw)?;
        exact(&value, NODE_FIELDS)?;
        if number(&value, "v")? != 1 || text(&value, "kind")? != "aukora-node-config-v1" {
            return Err(refused("config-version"));
        }
        let node = text(&value, "node")?.to_owned();
        if !node_name(&node) {
            return Err(refused("config-node"));
        }
        let listen = text(&value, "listen")?
            .parse::<SocketAddr>()
            .map_err(|_| refused("config-listen"))?;
        if listen != SocketAddr::from((Ipv4Addr::LOCALHOST, 18_080)) {
            return Err(refused("config-listen"));
        }
        let shell_origin = text(&value, "shell_origin")?.to_owned();
        let owner_origin = text(&value, "owner_origin")?.to_owned();
        let registered_site = text(&value, "registered_site")?.to_owned();
        let shell = Origin::parse(&shell_origin)?;
        if !hostname(shell.host())
            || owner_origin != format!("https://owner.{}", shell.host())
            || registered_site != shell_origin
        {
            return Err(refused("config-origin"));
        }
        let proxy_peers = addresses(member(&value, "proxy_peers")?, false)?;
        if proxy_peers.iter().any(|ip| !ip.is_loopback()) || !proxy_peers.contains(&listen.ip()) {
            return Err(refused("config-proxy"));
        }
        let public_ip = match member(&value, "public_ip")?.view() {
            ValueView::Null => None,
            ValueView::Text(raw) => {
                let ip = raw.parse::<Ipv4Addr>().map_err(|_| refused("config-ip"))?;
                if ip.to_string() != raw {
                    return Err(refused("config-ip"));
                }
                validate_addresses("deployment.invalid", 443, &[IpAddr::V4(ip)])?;
                Some(IpAddr::V4(ip))
            }
            _ => return Err(refused("config-ip")),
        };
        let config = Self {
            node,
            listen,
            shell_origin,
            owner_origin,
            registered_site,
            proxy_peers,
            public_ip,
            state_root: path_value(&value, "state_root")?,
            approved_release_root: path_value(&value, "approved_release_root")?,
            cage_root: path_value(&value, "cage_root")?,
            cage_uid: nonzero_u32(&value, "cage_uid")?,
            cage_gid: nonzero_u32(&value, "cage_gid")?,
            claim_commitment: path_value(&value, "claim_commitment")?,
            egress_policy: path_value(&value, "egress_policy")?,
            egress_status: path_value(&value, "egress_status")?,
            release_state: path_value(&value, "release_state")?,
            directory,
        };
        if config.claim_commitment != config.directory.join("claim.sha256")
            || config.egress_policy != config.directory.join("egress.json")
        {
            return Err(refused("config-path"));
        }
        let roots = [
            &config.state_root,
            &config.approved_release_root,
            &config.cage_root,
        ];
        for (index, root) in roots.iter().enumerate() {
            if roots
                .iter()
                .skip(index + 1)
                .any(|other| root.starts_with(other) || other.starts_with(root))
            {
                return Err(refused("config-path"));
            }
        }
        config.boundary()?.validate()?;
        Ok(config)
    }

    pub fn runtime_config(&self) -> supervisor::runtime::RuntimeConfig {
        supervisor::runtime::RuntimeConfig {
            state_root: self.state_root.clone(),
            approved_release_root: self.approved_release_root.clone(),
            cage_root: self.cage_root.clone(),
        }
    }

    pub fn boundary(&self) -> Result<CaddyBoundary> {
        Ok(CaddyBoundary {
            shell: Origin::parse(&self.shell_origin)?,
            owner: Origin::parse(&self.owner_origin)?,
            registered_site: Origin::parse(&self.registered_site)?,
            allowed_proxy_peers: self.proxy_peers.clone(),
        })
    }

    pub fn config_directory(&self) -> Result<File> {
        disk::open_host_directory(&self.directory)
    }

    /// Every public address and relay URL is checked by the relay organ.
    pub fn load_egress(&self) -> Result<EgressConfig> {
        let raw = disk::read_host_file(&self.egress_policy, 262_144)?;
        let value = canonical(&raw)?;
        exact(&value, &["v", "epoch", "relays", "providers"])?;
        let epoch = number(&value, "epoch")?;
        if number(&value, "v")? != 1 || epoch == 0 {
            return Err(refused("egress-version"));
        }
        let rows = array(member(&value, "relays")?)?;
        if rows.len() > relay::egress::MAX_RELAYS {
            return Err(refused("egress-config"));
        }
        let mut relays = Vec::with_capacity(rows.len());
        for row in rows {
            exact(row, &["url", "port", "addresses"])?;
            relays.push(RelayRule {
                url: text(row, "url")?.to_owned(),
                port: port(row)?,
                addresses: addresses(member(row, "addresses")?, true)?,
            });
        }
        let policy = EgressPolicy {
            v: relay::egress::EGRESS_POLICY_VERSION,
            epoch,
            host_policy_digest: Digest32::sha256(&raw),
            relays,
        };
        for rule in &policy.relays {
            ValidatedRelay::from_policy(&policy, &rule.url)?;
        }
        let rows = array(member(&value, "providers")?)?;
        // The model provider plus the door's allowlisted web_fetch hosts (NODE.md O10, section 12 P3): at most 16, as
        // deploy/spawn/core.py's MAX_PROVIDERS.
        if rows.len() > 16 {
            return Err(refused("egress-config"));
        }
        let mut providers: Vec<ProviderPin> = Vec::with_capacity(rows.len());
        for row in rows {
            exact(row, &["host", "port", "addresses"])?;
            let host = text(row, "host")?.to_owned();
            if !hostname(&host) || providers.iter().any(|pin| pin.host == host) {
                return Err(refused("egress-config"));
            }
            let port = port(row)?;
            let addresses = addresses(member(row, "addresses")?, true)?;
            validate_addresses(&host, port, &addresses)?;
            providers.push(ProviderPin {
                host,
                port,
                addresses,
            });
        }
        Ok(EgressConfig { policy, providers })
    }
}

fn validate_addresses(host: &str, port: u16, addresses: &[IpAddr]) -> Result<()> {
    let url = format!("wss://{host}:{port}");
    let policy = EgressPolicy {
        v: relay::egress::EGRESS_POLICY_VERSION,
        epoch: 1,
        host_policy_digest: Digest32::sha256(&[]),
        relays: vec![RelayRule {
            url: url.clone(),
            port,
            addresses: addresses.to_vec(),
        }],
    };
    ValidatedRelay::from_policy(&policy, &url).map(|_| ())
}

fn canonical(raw: &[u8]) -> Result<Value> {
    let value = json::parse_strict(raw).map_err(|_| refused("config-json"))?;
    if json::to_canonical(&value) != raw {
        return Err(refused("config-canonical"));
    }
    Ok(value)
}

fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    let ValueView::Object(fields) = value.view() else {
        return Err(refused("config-shape"));
    };
    if fields.len() != keys.len() || fields.iter().any(|(key, _)| !keys.contains(&key.as_str())) {
        return Err(refused("config-shape"));
    }
    Ok(())
}

fn member<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    let ValueView::Object(fields) = value.view() else {
        return Err(refused("config-shape"));
    };
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or(refused("config-shape"))
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match member(value, name)?.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(refused("config-shape")),
    }
}

fn number(value: &Value, name: &str) -> Result<u64> {
    match member(value, name)?.view() {
        ValueView::Integer(value) => {
            u64::try_from(value.get()).map_err(|_| refused("config-shape"))
        }
        _ => Err(refused("config-shape")),
    }
}

fn nonzero_u32(value: &Value, name: &str) -> Result<u32> {
    u32::try_from(number(value, name)?)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(refused("config-id"))
}

fn port(value: &Value) -> Result<u16> {
    u16::try_from(number(value, "port")?)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(refused("egress-port"))
}

fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(items) => Ok(items),
        _ => Err(refused("config-shape")),
    }
}

fn addresses(value: &Value, bounded: bool) -> Result<Vec<IpAddr>> {
    let items = array(value)?;
    if items.is_empty() || items.len() > 16 {
        return Err(refused("config-address"));
    }
    let mut result = Vec::with_capacity(items.len());
    for value in items {
        let ValueView::Text(raw) = value.view() else {
            return Err(refused("config-address"));
        };
        let ip = raw
            .parse::<IpAddr>()
            .map_err(|_| refused("config-address"))?;
        if (bounded && ip.to_string() != raw) || result.contains(&ip) {
            return Err(refused("config-address"));
        }
        result.push(ip);
    }
    Ok(result)
}

fn path_value(value: &Value, name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(text(value, name)?);
    checked_path(&path)?;
    Ok(path)
}

fn checked_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path.file_name().is_none()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(refused("config-path"));
    }
    Ok(())
}

fn node_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=21).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (*byte == b'-' && bytes.get(index + 1).is_some_and(u8::is_ascii_lowercase))
        })
}

fn hostname(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().any(|byte| byte.is_ascii_lowercase()))
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn refused(reason: &'static str) -> Refusal {
    Refusal {
        organ: "supervisor",
        reason,
    }
}
