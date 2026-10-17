// SPDX-License-Identifier: AGPL-3.0-or-later
//! The door's policy file: one action per crossing class, the peers that may call, and what the executors may reach.
//!
//! Strict by construction: unknown fields are refused, every class defaults to deny, and a policy that asks for
//! something the door cannot do safely (allow `fs-outside`; allow a class that has no executor) does not load.

use super::classify::Class;
use super::files;
use canon::{Refusal, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_POLICY_BYTES: u64 = 64 << 10;
/// The only ports a fetch may use: the door fetches web pages, not arbitrary services.
const WEB_PORTS: [u16; 4] = [80, 443, 8080, 8443];

fn refuse() -> Refusal {
    Refusal { organ: "supervisor", reason: "door-policy" }
}

/// What to do with a crossing of one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Ask,
    Deny,
}

/// How callers are identified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerRule {
    /// Only these uids (kernel `SO_PEERCRED`; Linux).
    Uids(Vec<u32>),
    /// The socket's own file permissions are the only gate (development on a platform without peer credentials).
    SocketPermissions,
}

/// Which hosts the door may fetch for the engine, and how.
#[derive(Clone, Debug)]
pub struct NetPolicy {
    pub hosts: Vec<String>,
    pub ports: Vec<u16>,
    pub max_bytes: usize,
    pub timeout_ms: u64,
    pub allow_http: bool,
    /// Tests only: let the fetch reach loopback.
    #[cfg(test)]
    pub allow_private: bool,
}

impl NetPolicy {
    /// Whether fetches may reach non-public addresses. Only test builds ever say yes.
    pub fn private_ok(&self) -> bool {
        #[cfg(test)]
        {
            self.allow_private
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

/// Where the Kira 2 service is and where the door's own token for it lives (only the door holds it).
#[derive(Clone, Debug)]
pub struct MemoryPolicy {
    pub socket: PathBuf,
    pub token_file: PathBuf,
}

/// The loaded policy.
#[derive(Clone, Debug)]
pub struct Policy {
    pub peers: PeerRule,
    pub workspace_roots: Vec<String>,
    pub state_dir: PathBuf,
    pub classes: BTreeMap<Class, Action>,
    pub net: Option<NetPolicy>,
    pub memory: Option<MemoryPolicy>,
    pub max_frame_bytes: usize,
    /// Sustained requests per second the door will look at, and the burst it tolerates.
    pub rate_per_second: u32,
    pub rate_burst: u32,
    /// Where the door listens when the node runs it (`door serve --socket` overrides this one).
    pub socket: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    v: u64,
    peers: RawPeers,
    #[serde(default)]
    workspace_roots: Vec<String>,
    state_dir: String,
    #[serde(default)]
    classes: BTreeMap<String, String>,
    net: Option<RawNet>,
    memory: Option<RawMemory>,
    max_frame_bytes: Option<usize>,
    rate_per_second: Option<u32>,
    rate_burst: Option<u32>,
    socket: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeers {
    mode: String,
    #[serde(default)]
    uids: Vec<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNet {
    hosts: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
    max_bytes: Option<usize>,
    timeout_ms: Option<u64>,
    #[serde(default)]
    allow_http: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMemory {
    socket: String,
    token_file: String,
}

fn absolute(path: &str) -> bool {
    path.starts_with('/') && !path.contains('\0') && path.len() <= 4096
}

fn host_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels.last().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

impl Policy {
    /// Parse and validate policy text.
    pub fn parse(text: &str) -> Result<Policy> {
        let raw: RawPolicy = serde_json::from_str(text).map_err(|_| refuse())?;
        if raw.v != 1 {
            return Err(refuse());
        }
        let peers = match raw.peers.mode.as_str() {
            "peercred" if !raw.peers.uids.is_empty() && raw.peers.uids.len() <= 16 => PeerRule::Uids(raw.peers.uids),
            "socket-permissions" if raw.peers.uids.is_empty() => PeerRule::SocketPermissions,
            _ => return Err(refuse()),
        };
        if !raw.workspace_roots.iter().all(|root| absolute(root)) || raw.workspace_roots.len() > 16 || !absolute(&raw.state_dir) {
            return Err(refuse());
        }
        let mut classes = BTreeMap::new();
        for (name, action) in &raw.classes {
            let class = Class::parse(name).ok_or_else(refuse)?;
            let action = match action.as_str() {
                "allow" => Action::Allow,
                "ask" => Action::Ask,
                "deny" => Action::Deny,
                _ => return Err(refuse()),
            };
            let has_executor = matches!(class, Class::Net | Class::Memory);
            if action == Action::Allow && !has_executor {
                return Err(refuse());
            }
            classes.insert(class, action);
        }
        let net = raw
            .net
            .map(|net| {
                let hosts: Vec<String> = net.hosts.iter().map(|h| h.to_ascii_lowercase()).collect();
                let ports = if net.ports.is_empty() { vec![if net.allow_http { 80 } else { 443 }] } else { net.ports };
                let max_bytes = net.max_bytes.unwrap_or(1 << 20);
                let timeout_ms = net.timeout_ms.unwrap_or(15_000);
                if hosts.is_empty() || hosts.len() > 64 || !hosts.iter().all(|h| host_name(h)) || !ports.iter().all(|p| WEB_PORTS.contains(p)) {
                    return Err(refuse());
                }
                if !(1_024..=(8 << 20)).contains(&max_bytes) || !(100..=60_000).contains(&timeout_ms) {
                    return Err(refuse());
                }
                Ok(NetPolicy {
                    hosts,
                    ports,
                    max_bytes,
                    timeout_ms,
                    allow_http: net.allow_http,
                    #[cfg(test)]
                    allow_private: false,
                })
            })
            .transpose()?;
        let memory = match raw.memory {
            Some(memory) if absolute(&memory.socket) && absolute(&memory.token_file) => {
                Some(MemoryPolicy { socket: memory.socket.into(), token_file: memory.token_file.into() })
            }
            Some(_) => return Err(refuse()),
            None => None,
        };
        if classes.get(&Class::Net) == Some(&Action::Allow) && net.is_none() {
            return Err(refuse());
        }
        if classes.get(&Class::Memory) == Some(&Action::Allow) && memory.is_none() {
            return Err(refuse());
        }
        let max_frame_bytes = raw.max_frame_bytes.unwrap_or(1 << 20);
        if !(1_024..=(16 << 20)).contains(&max_frame_bytes) {
            return Err(refuse());
        }
        let rate_per_second = raw.rate_per_second.unwrap_or(20);
        let rate_burst = raw.rate_burst.unwrap_or(100);
        if !(1..=1_000).contains(&rate_per_second) || !(1..=10_000).contains(&rate_burst) {
            return Err(refuse());
        }
        let socket = match raw.socket {
            Some(socket) if absolute(&socket) => Some(PathBuf::from(socket)),
            Some(_) => return Err(refuse()),
            None => None,
        };
        Ok(Policy {
            peers,
            workspace_roots: raw.workspace_roots,
            state_dir: raw.state_dir.into(),
            classes,
            net,
            memory,
            max_frame_bytes,
            rate_per_second,
            rate_burst,
            socket,
        })
    }

    /// Read a policy file: a regular file of ours (or root's), small, not writable by group or others, opened without
    /// following a final symlink and checked on the open descriptor.
    pub fn load(path: &Path) -> Result<Policy> {
        let mut file = files::open_trusted(path, MAX_POLICY_BYTES, 0o022, "door-policy")?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(|_| refuse())?;
        Policy::parse(&text)
    }

    /// A uid allowlist that includes root or the door's own user would give the engine the door's authority.
    pub fn check_peer_uids(&self, effective: u32) -> Result<()> {
        match &self.peers {
            PeerRule::Uids(uids) if uids.iter().any(|uid| *uid == 0 || *uid == effective) => Err(refuse()),
            _ => Ok(()),
        }
    }

    /// The action for a class; anything not listed is denied.
    pub fn action(&self, class: Class) -> Action {
        self.classes.get(&class).copied().unwrap_or(Action::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{"v":1,"peers":{"mode":"peercred","uids":[1001]},"workspace_roots":["/sandbox"],"state_dir":"/var/lib/aukora-door"}"#;

    fn with(extra: &str) -> String {
        format!("{},{}}}", BASE.trim_end_matches('}'), extra)
    }

    #[test]
    fn every_class_defaults_to_deny() {
        let policy = Policy::parse(BASE).unwrap();
        for class in Class::ALL {
            assert_eq!(policy.action(class), Action::Deny);
        }
    }

    #[test]
    fn a_full_policy_loads() {
        let text = with(
            r#""classes":{"net":"allow","memory":"allow","plugin":"ask","fs-outside":"deny"},
               "net":{"hosts":["Docs.rs","example.org"],"ports":[443]},
               "memory":{"socket":"/run/kira.sock","token_file":"/etc/aukora/door-kira.token"}"#,
        );
        let policy = Policy::parse(&text).unwrap();
        assert_eq!(policy.action(Class::Net), Action::Allow);
        assert_eq!(policy.action(Class::Plugin), Action::Ask);
        assert_eq!(policy.action(Class::Unknown), Action::Deny);
        assert_eq!(policy.net.as_ref().unwrap().hosts, vec!["docs.rs".to_owned(), "example.org".to_owned()]);
        assert_eq!(policy.peers, PeerRule::Uids(vec![1001]));
    }

    #[test]
    fn a_policy_that_asks_for_something_unsafe_does_not_load() {
        // Allowing a class that has no executor, or fs-outside at all.
        for class in ["fs-outside", "unknown", "mcp", "plugin", "persist", "delegate", "shell-interactive"] {
            assert!(Policy::parse(&with(&format!("\"classes\":{{\"{class}\":\"allow\"}}"))).is_err(), "{class}");
        }
        // Allowing an executor that has no configuration.
        assert!(Policy::parse(&with("\"classes\":{\"net\":\"allow\"}")).is_err());
        assert!(Policy::parse(&with("\"classes\":{\"memory\":\"allow\"}")).is_err());
        // Unknown class, unknown action, unknown field, wrong version.
        assert!(Policy::parse(&with("\"classes\":{\"quantum\":\"deny\"}")).is_err());
        assert!(Policy::parse(&with("\"classes\":{\"net\":\"sometimes\"}")).is_err());
        assert!(Policy::parse(&with("\"extra\":1")).is_err());
        assert!(Policy::parse(&BASE.replace("\"v\":1", "\"v\":2")).is_err());
    }

    #[test]
    fn the_socket_the_node_listens_on_is_an_absolute_path() {
        assert_eq!(Policy::parse(BASE).unwrap().socket, None);
        let policy = Policy::parse(&with("\"socket\":\"/run/aukora/door.sock\"")).unwrap();
        assert_eq!(policy.socket, Some(PathBuf::from("/run/aukora/door.sock")));
        assert!(Policy::parse(&with("\"socket\":\"door.sock\"")).is_err());
    }

    #[test]
    fn peers_need_a_rule() {
        assert!(Policy::parse(&BASE.replace("[1001]", "[]")).is_err());
        assert!(Policy::parse(&BASE.replace("peercred", "anyone")).is_err());
        let dev = BASE.replace("\"mode\":\"peercred\",\"uids\":[1001]", "\"mode\":\"socket-permissions\"");
        assert_eq!(Policy::parse(&dev).unwrap().peers, PeerRule::SocketPermissions);
    }

    #[test]
    fn the_engine_may_not_be_root_or_the_door() {
        let policy = Policy::parse(BASE).unwrap();
        assert!(policy.check_peer_uids(1000).is_ok());
        assert!(policy.check_peer_uids(1001).is_err());
        let root = Policy::parse(&BASE.replace("[1001]", "[1001,0]")).unwrap();
        assert!(root.check_peer_uids(1000).is_err());
        let dev = Policy::parse(&BASE.replace("\"mode\":\"peercred\",\"uids\":[1001]", "\"mode\":\"socket-permissions\"")).unwrap();
        assert!(dev.check_peer_uids(0).is_ok());
    }

    #[test]
    fn fetch_ports_are_web_ports_and_the_rate_is_bounded() {
        let net = |ports: &str| with(&format!("\"net\":{{\"hosts\":[\"docs.rs\"],\"ports\":{ports}}}"));
        assert!(Policy::parse(&net("[443,8443]")).is_ok());
        for bad in ["[22]", "[25]", "[443,5432]", "[0]"] {
            assert!(Policy::parse(&net(bad)).is_err(), "{bad}");
        }
        let defaults = Policy::parse(BASE).unwrap();
        assert_eq!((defaults.rate_per_second, defaults.rate_burst), (20, 100));
        assert!(Policy::parse(&with("\"rate_per_second\":0")).is_err());
        assert!(Policy::parse(&with("\"rate_per_second\":5000")).is_err());
        assert!(Policy::parse(&with("\"rate_burst\":0")).is_err());
        assert_eq!(Policy::parse(&with("\"rate_per_second\":5,\"rate_burst\":7")).unwrap().rate_burst, 7);
    }

    #[test]
    fn hosts_are_plain_names() {
        let net = |hosts: &str| with(&format!("\"net\":{{\"hosts\":{hosts}}}"));
        assert!(Policy::parse(&net("[\"docs.rs\"]")).is_ok());
        for bad in ["[]", "[\"localhost\"]", "[\"127.0.0.1\"]", "[\"a b.com\"]", "[\"-x.com\"]", "[\"x..com\"]", "[\"*.example.com\"]"] {
            assert!(Policy::parse(&net(bad)).is_err(), "{bad}");
        }
    }
}
