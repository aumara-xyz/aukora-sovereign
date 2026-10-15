// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::{self, Config};
use crate::node::Node;
use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{connect_info::Connected, ConnectInfo};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use frontdoor::{Backend, Frontdoor};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NODE_ID: &str = "00000000000000000000000000000001";
const OWNER_HOST: &str = "owner-test.example";
const CHAT_HOST: &str = "chat-test.example";
const CREDENTIAL: &[u8] = b"immune-disposable-credential";
const MAX_STEPS: usize = 64;
// Measured on the Linux host under parallel test load: twin setup, not Argon2, dominates there.
pub(crate) const REPLAY_BUDGET: Duration = Duration::from_secs(120);

#[cfg(test)]
#[path = "twin_kdf_tests.rs"]
mod twin_kdf_tests;

pub fn replay(
    corpus: &::immune::Corpus,
    budget: Duration,
    _handle: tokio::runtime::Handle,
) -> Result<::immune::Report> {
    // A separate runtime prevents nested block_on in the supervisor's runtime.
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<::immune::Report> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("immune:replay-unavailable")?;
                let directory = replay_directory()?;
                let root =
                    std::fs::canonicalize(directory.path()).context("immune:replay-unavailable")?;
                let started = Instant::now();
                let mut unavailable = None;
                let report = ::immune::run(corpus, budget, |vector| {
                    if unavailable.is_some() {
                        return Err("immune:replay-unavailable".into());
                    }
                    let remaining = budget.saturating_sub(started.elapsed());
                    runtime.block_on(async {
                        match tokio::time::timeout(remaining, replay_vector(vector, &root)).await {
                            Ok(Ok(observed)) => Ok(observed),
                            Ok(Err(error)) if error.to_string() == "immune:replay-unavailable" => {
                                unavailable = Some(error);
                                Err("immune:replay-unavailable".into())
                            }
                            Ok(Err(error)) => Err(error.to_string()),
                            Err(_) => Err("immune:budget-exhausted".into()),
                        }
                    })
                });
                match unavailable {
                    Some(error) => Err(error),
                    None => Ok(report),
                }
            })
            .join()
            .map_err(|_| anyhow!("immune:runner-panicked"))?
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    #[serde(default = "session_seconds")]
    session_seconds: u64,
    steps: Vec<Step>,
}
fn session_seconds() -> u64 {
    3_600
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    NewClaim { save: String },
    RevokeSession,
    Wait { milliseconds: u64 },
    Http(Box<HttpStep>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpStep {
    method: String,
    path: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    fetch_site: Option<String>,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    cookie: bool,
    #[serde(default)]
    body: Value,
    #[serde(default)]
    raw_body: Option<String>,
    #[serde(default)]
    save: Option<String>,
    #[serde(default)]
    expect: Option<String>,
}

struct Reply {
    status: u16,
    cookie: Option<String>,
    body: Value,
}
impl Reply {
    fn outcome(&self) -> String {
        self.body["error"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if self.status == 200 {
                    "ok".into()
                } else {
                    format!("http:{}", self.status)
                }
            })
    }
}
struct Door {
    connections: tokio::sync::mpsc::Sender<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Drop for Door {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Listener {
    connections: tokio::sync::mpsc::Receiver<tokio::io::DuplexStream>,
    address: SocketAddr,
}
impl axum::serve::Listener for Listener {
    type Io = tokio::io::DuplexStream;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.connections.recv().await {
            Some(stream) => (stream, self.address),
            None => std::future::pending().await,
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.address)
    }
}
#[derive(Clone, Copy)]
struct Peer(SocketAddr);
impl Connected<axum::serve::IncomingStream<'_, Listener>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, Listener>) -> Self {
        Self(*stream.remote_addr())
    }
}
async fn listener_peer(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(ConnectInfo(Peer(peer))) = request.extensions().get::<ConnectInfo<Peer>>().copied()
    {
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    next.run(request).await
}
impl Door {
    fn start(node: &Arc<Node>, seconds: u64) -> Result<Self> {
        let config = &node.config;
        let mut settings = frontdoor::Config::behind_proxy(
            config.node_id.clone(),
            config.owner_hostname.clone(),
            config.chat_hostname.clone(),
            config.state_dir.join("sockets/ui.sock"),
            config.trusted_proxy.peers.clone(),
        );
        settings.session_lifetime = Duration::from_secs(seconds);
        // Allow scheduling and storage delays on a loaded 2-vCPU node.
        settings.request_timeout = Duration::from_secs(30);
        let frontdoor =
            Frontdoor::new(settings, node.clone()).map_err(|error| anyhow!(error.code))?;
        *node.frontdoor.lock().map_err(|_| anyhow!("immune:lock"))? = Arc::downgrade(&frontdoor);
        let (connections, incoming) = tokio::sync::mpsc::channel(1);
        let listener = Listener {
            connections: incoming,
            address: "127.0.0.1:3000".parse()?,
        };
        let router = frontdoor
            .router()
            .layer(axum::middleware::from_fn(listener_peer))
            .into_make_service_with_connect_info::<Peer>();
        let task = tokio::spawn(async move { axum::serve(listener, router).await });
        Ok(Self { connections, task })
    }
    async fn request(&self, request: Vec<u8>) -> Result<Reply> {
        let (mut client, server) = tokio::io::duplex(131_072);
        self.connections
            .send(server)
            .await
            .map_err(|_| anyhow!("immune:transport-closed"))?;
        client.write_all(&request).await?;
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await?;
        let boundary = bytes
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .ok_or_else(|| anyhow!("immune:invalid-http"))?;
        let headers = std::str::from_utf8(&bytes[..boundary])?;
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| anyhow!("immune:invalid-http"))?
            .parse()?;
        let header = |name: &str| {
            headers.lines().skip(1).find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
        };
        let body = &bytes[boundary + 4..];
        if header("content-length").and_then(|n| n.parse::<usize>().ok()) != Some(body.len()) {
            bail!("immune:invalid-http");
        }
        Ok(Reply {
            status,
            cookie: header("set-cookie"),
            body: serde_json::from_slice(body).context("immune:invalid-http-json")?,
        })
    }
}

fn replay_directory() -> Result<tempfile::TempDir> {
    replay_directory_in(&std::env::temp_dir())
}

fn replay_directory_in(parent: &Path) -> Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("aukora-immune-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .context("immune:replay-unavailable")
}

fn open_twin(root: &Path) -> Result<Arc<Node>> {
    Node::open_twin(twin_config(root), tokio::runtime::Handle::current())
        .context("immune:replay-unavailable")
}

async fn replay_vector(vector: &::immune::Vector, replay_root: &Path) -> Result<String> {
    let scenario: Scenario =
        serde_json::from_value(vector.scenario.clone()).context("immune:invalid-scenario")?;
    if scenario.steps.is_empty()
        || scenario.steps.len() > MAX_STEPS
        || !(1..=86_400).contains(&scenario.session_seconds)
        || !matches!(scenario.steps.last(), Some(Step::Http(_)))
    {
        bail!("immune:scenario-budget");
    }
    let directory = tempfile::Builder::new()
        .prefix("twin-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(replay_root)
        .context("immune:replay-unavailable")?;
    let root = std::fs::canonicalize(directory.path()).context("immune:replay-unavailable")?;
    let node = open_twin(&root)?;
    let door = Door::start(&node, scenario.session_seconds)?;
    let mut values = BTreeMap::new();
    let mut owner_cookie = None;
    let mut observed = None;
    for (index, step) in scenario.steps.iter().enumerate() {
        match step {
            Step::NewClaim { save } => {
                let claim = node
                    .owner
                    .lock()
                    .map_err(|_| anyhow!("immune:lock"))?
                    .create_claim()
                    .map_err(|error| anyhow!(error.code))?;
                values.insert(save.clone(), Value::String(claim));
            }
            Step::RevokeSession => {
                let digest = session_digest(
                    owner_cookie
                        .as_deref()
                        .ok_or_else(|| anyhow!("immune:cookie-required"))?,
                )?;
                node.revoke_session(digest)
                    .await
                    .map_err(|error| anyhow!(error.code))?;
            }
            Step::Wait { milliseconds } => {
                if *milliseconds > 1_500 {
                    bail!("immune:scenario-budget");
                }
                tokio::time::sleep(Duration::from_millis(*milliseconds)).await;
            }
            Step::Http(request) => {
                let HttpStep {
                    method,
                    path,
                    host,
                    origin,
                    fetch_site,
                    proto,
                    cookie,
                    body,
                    raw_body,
                    save,
                    expect,
                } = request.as_ref();
                if !matches!(method.as_str(), "GET" | "POST")
                    || !path.starts_with('/')
                    || path.len() > 2_048
                {
                    bail!("immune:invalid-request");
                }
                let host = host.as_deref().unwrap_or(OWNER_HOST);
                let default_origin = format!("https://{host}");
                let origin = origin.as_deref().unwrap_or(&default_origin);
                let fetch_site = fetch_site.as_deref().unwrap_or("same-origin");
                let proto = proto.as_deref().unwrap_or("https");
                let payload = match raw_body {
                    Some(raw) => raw.as_bytes().to_vec(),
                    None => serde_json::to_vec(&resolve(body, &values)?)?,
                };
                if payload.len() > 65_536
                    || [method.as_str(), path, host, origin, fetch_site, proto]
                        .iter()
                        .any(|value| value.contains(['\r', '\n']))
                {
                    bail!("immune:invalid-request");
                }
                let cookie_header = if *cookie {
                    format!(
                        "Cookie: {}\r\n",
                        owner_cookie
                            .as_deref()
                            .ok_or_else(|| anyhow!("immune:cookie-required"))?
                    )
                } else {
                    String::new()
                };
                let headers = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nSec-Fetch-Site: {fetch_site}\r\nX-Forwarded-Proto: {proto}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{cookie_header}\r\n", payload.len());
                let reply = door
                    .request([headers.as_bytes(), payload.as_slice()].concat())
                    .await?;
                if let Some(cookie) = &reply.cookie {
                    if let Some(value) = cookie
                        .split(';')
                        .next()
                        .filter(|value| !value.ends_with('='))
                    {
                        owner_cookie = Some(value.to_owned());
                    }
                }
                let outcome = reply.outcome();
                let wanted = expect
                    .as_deref()
                    .unwrap_or(if index + 1 == scenario.steps.len() {
                        &vector.expected_refusal
                    } else {
                        "ok"
                    });
                if outcome != wanted {
                    if index + 1 != scenario.steps.len() {
                        bail!("immune:setup-failed:{outcome}");
                    }
                    return Ok(outcome);
                }
                if let Some(save) = save {
                    values.insert(save.clone(), reply.body);
                }
                observed = Some(outcome);
            }
        }
    }
    observed.ok_or_else(|| anyhow!("immune:no-outcome"))
}

fn session_digest(cookie: &str) -> Result<[u8; 32]> {
    Ok(Sha256::digest(
        cookie
            .split_once('=')
            .ok_or_else(|| anyhow!("immune:invalid-cookie"))?
            .1
            .as_bytes(),
    )
    .into())
}
fn resolve(value: &Value, values: &BTreeMap<String, Value>) -> Result<Value> {
    if let Some(fields) = value.as_object() {
        if fields.len() == 1 {
            if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                let (name, pointer) = reference
                    .split_once('/')
                    .map_or((reference, String::new()), |(name, pointer)| {
                        (name, format!("/{pointer}"))
                    });
                return values
                    .get(name)
                    .and_then(|value| value.pointer(&pointer))
                    .cloned()
                    .ok_or_else(|| anyhow!("immune:unknown-reference"));
            }
            if let Some(challenge) = fields.get("$registration") {
                return registration(
                    resolve(challenge, values)?
                        .as_str()
                        .ok_or_else(|| anyhow!("immune:invalid-challenge"))?,
                );
            }
            if let Some(material) = fields.get("$assertion") {
                let material = resolve(material, values)?;
                let challenge = material["challenge"]
                    .as_str()
                    .ok_or_else(|| anyhow!("immune:invalid-challenge"))?;
                let counter = material["counter"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| anyhow!("immune:invalid-counter"))?;
                return Ok(assertion(
                    challenge,
                    counter,
                    material["invalid_signature"] == true,
                ));
            }
            if let Some(words) = fields.get("$wrong_words") {
                let mut words = resolve(words, values)?;
                if words.as_array().is_none_or(|words| words.len() != 7) {
                    bail!("immune:invalid-words");
                }
                words[0] = Value::String("immune-wrong-word".into());
                return Ok(words);
            }
            if let Some(words) = fields.get("$phrase") {
                let words = resolve(words, values)?;
                let words = words
                    .as_array()
                    .ok_or_else(|| anyhow!("immune:invalid-words"))?
                    .iter()
                    .map(|word| word.as_str().ok_or_else(|| anyhow!("immune:invalid-words")))
                    .collect::<Result<Vec<_>>>()?;
                return Ok(Value::String(words.join(" ")));
            }
        }
        return fields
            .iter()
            .map(|(key, value)| Ok((key.clone(), resolve(value, values)?)))
            .collect::<Result<serde_json::Map<_, _>>>()
            .map(Value::Object);
    }
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .map(|value| resolve(value, values))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array);
    }
    Ok(value.clone())
}
fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = if bytes.len() < 24 {
        vec![0x40 + bytes.len() as u8]
    } else if bytes.len() < 256 {
        vec![0x58, bytes.len() as u8]
    } else {
        vec![0x59, (bytes.len() >> 8) as u8, bytes.len() as u8]
    };
    encoded.extend(bytes);
    encoded
}
fn registration(challenge: &str) -> Result<Value> {
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
    cose.extend(cbor_bytes(key.verifying_key().as_bytes()));
    let mut auth = Sha256::digest(OWNER_HOST).to_vec();
    auth.push(0x45);
    auth.extend(0_u32.to_be_bytes());
    auth.extend([0; 16]);
    auth.extend((CREDENTIAL.len() as u16).to_be_bytes());
    auth.extend(CREDENTIAL);
    auth.extend(cose);
    let mut attestation = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData".to_vec();
    attestation.extend(cbor_bytes(&auth));
    Ok(
        json!({"kind":"passkey-registration","id":URL_SAFE_NO_PAD.encode(CREDENTIAL),"raw_id":URL_SAFE_NO_PAD.encode(CREDENTIAL),"client_data_json":URL_SAFE_NO_PAD.encode(json!({"type":"webauthn.create","challenge":challenge,"origin":format!("https://{OWNER_HOST}"),"crossOrigin":false}).to_string()),"attestation_object":URL_SAFE_NO_PAD.encode(attestation),"client_extension_results":{}}),
    )
}
fn assertion(challenge: &str, counter: u32, invalid_signature: bool) -> Value {
    let client = json!({"type":"webauthn.get","challenge":challenge,"origin":format!("https://{OWNER_HOST}"),"crossOrigin":false}).to_string();
    let mut auth = Sha256::digest(OWNER_HOST).to_vec();
    auth.push(5);
    auth.extend(counter.to_be_bytes());
    let signed = [
        auth.as_slice(),
        Sha256::digest(client.as_bytes()).as_slice(),
    ]
    .concat();
    let mut signature = SigningKey::from_bytes(&[9; 32]).sign(&signed).to_bytes();
    if invalid_signature {
        signature[0] ^= 1;
    }
    json!({"kind":"passkey","credential_id":URL_SAFE_NO_PAD.encode(CREDENTIAL),"client_data_json":URL_SAFE_NO_PAD.encode(client),"authenticator_data":URL_SAFE_NO_PAD.encode(auth),"signature":URL_SAFE_NO_PAD.encode(signature),"user_handle":URL_SAFE_NO_PAD.encode(NODE_ID.as_bytes())})
}
fn twin_config(path: &Path) -> Config {
    Config {
        boot_probe: false,
        release_floor: false,
        nostr: config::Nostr::default(),
        openviking: config::OpenViking::default(),
        invite: None,
        node_id: NODE_ID.into(),
        state_dir: path.join("state"),
        listen: "127.0.0.1:3000".parse().expect("fixed address"),
        chat_hostname: CHAT_HOST.into(),
        owner_hostname: OWNER_HOST.into(),
        chat_origin: format!("https://{CHAT_HOST}"),
        owner_origin: format!("https://{OWNER_HOST}"),
        trusted_proxy: config::TrustedProxy {
            peers: vec!["127.0.0.1".parse().expect("fixed address")],
        },
        guest: config::Guest {
            node_dir: path.join("runtime-node"),
            harness_dir: path.join("runtime-harness"),
            bundle_dir: path.join("runtime-bundle"),
            subordinate_uid: 100_000,
            subordinate_gid: 100_000,
            work_dir: path.join("guest-work"),
        },
        cgroup_root: path.join("cgroup"),
        broker: config::Broker {
            provider_base_url: "https://openrouter.ai/api/v1".into(),
            allowed_models: vec!["deepseek/deepseek-chat".into()],
            default_model: "deepseek/deepseek-chat".into(),
            prices: BTreeMap::new(),
        },
        webauthn: config::WebAuthn {
            rp_id: OWNER_HOST.into(),
            origin: format!("https://{OWNER_HOST}"),
        },
        limits: config::Limits {
            pids_max: 512,
            memory_max_bytes: 2 * 1024 * 1024 * 1024,
            file_size_max_bytes: launcher::DEFAULT_FILE_SIZE_MAX_BYTES,
            workspace_max_bytes: 4 * 1024 * 1024 * 1024,
            cpu_max: "200000 100000".into(),
            max_connections: 64,
            max_body_bytes: 65_536,
            session_seconds: 3_600,
            request_seconds: 5,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn corpus_for(id: &str) -> ::immune::Corpus {
        let bytes = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../immune/corpus")
                .join(format!("{id}.json")),
        )
        .unwrap();
        ::immune::Corpus::from_bytes([bytes]).unwrap()
    }
    fn assert_vector(id: &str) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let report = replay(
            &corpus_for(id),
            Duration::from_secs(10),
            runtime.handle().clone(),
        )
        .unwrap();
        assert!(report.successful(), "{report:?}");
        assert_eq!(report.passed, 1);
    }
    #[test]
    fn antibody_replay_twins_live_in_private_system_temporary_directory() {
        let directory = replay_directory().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        assert_eq!(
            root.parent().unwrap(),
            std::fs::canonicalize(std::env::temp_dir()).unwrap()
        );
        assert_ne!(root.parent().unwrap(), std::env::current_dir().unwrap());
        assert!(root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("aukora-immune-"));
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::write(root.join("disposable-twin"), b"test").unwrap();
        drop(directory);
        assert!(!root.exists());
    }
    #[test]
    fn antibody_replay_environment_error_is_not_an_antibody_failure() {
        let directory = tempfile::tempdir().unwrap();
        let unavailable = directory.path().join("unavailable");
        std::fs::write(&unavailable, b"not a directory").unwrap();
        let error = replay_directory_in(&unavailable).unwrap_err();
        assert_eq!(error.to_string(), "immune:replay-unavailable");
        let vector = ::immune::Vector {
            id: "unavailable-twin".into(),
            guarded_issue: "#41".into(),
            organ: "frontdoor".into(),
            expected_refusal: "frontdoor:session-required".into(),
            scenario: json!({"steps":[
                {"action":"http","method":"GET","path":"/api/approvals"}
            ]}),
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            assert_eq!(
                replay_vector(&vector, &unavailable)
                    .await
                    .unwrap_err()
                    .to_string(),
                "immune:replay-unavailable"
            );
            let error = match open_twin(&unavailable) {
                Err(error) => error,
                Ok(_) => panic!("twin must refuse an unavailable state directory"),
            };
            assert_eq!(error.to_string(), "immune:replay-unavailable");
            assert!(error.chain().any(|cause| cause.is::<std::io::Error>()));
        });
    }
    #[test]
    fn antibody_replay_twins_are_contained_and_removed_when_cancelled() {
        let directory = replay_directory().unwrap();
        let root = directory.path().to_owned();
        let vector = ::immune::Vector {
            id: "cancelled-replay".into(),
            guarded_issue: "#41".into(),
            organ: "frontdoor".into(),
            expected_refusal: "frontdoor:session-required".into(),
            scenario: json!({"steps":[
                {"action":"wait","milliseconds":1_500},
                {"action":"http","method":"GET","path":"/api/approvals"}
            ]}),
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let twin_root = root.clone();
            let task = tokio::spawn(async move { replay_vector(&vector, &twin_root).await });
            let twins = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let twins = std::fs::read_dir(&root)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .collect::<Vec<_>>();
                    if twins.len() == 1
                        && twins[0].join("state/node.ed25519").is_file()
                        && twins[0].join("state/node.sqlite3").is_file()
                    {
                        break twins;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("replay must create its twin in the dedicated directory");
            assert_eq!(twins.len(), 1);
            assert_eq!(
                std::fs::metadata(&twins[0]).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert!(twins[0].join("state/node.ed25519").is_file());
            assert!(twins[0].join("state/node.sqlite3").is_file());
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        });
    }
    #[test]
    fn antibody_claim_single_use_corpus_replay() {
        assert_vector("claim-single-use");
    }
    #[test]
    fn antibody_revoked_session_corpus_replay() {
        assert_vector("session-revoked");
    }
    #[test]
    fn antibody_expired_session_corpus_replay() {
        assert_vector("session-expired");
    }
    #[test]
    fn antibody_corpus_setup_refusal_cannot_count_as_final_refusal() {
        let vector = ::immune::Vector {
            id: "setup-refusal".into(),
            guarded_issue: "#41".into(),
            organ: "frontdoor".into(),
            expected_refusal: "frontdoor:session-required".into(),
            scenario: json!({"steps":[
                {"action":"http","method":"GET","path":"/api/approvals"},
                {"action":"http","method":"GET","path":"/api/approvals"}
            ]}),
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let directory = replay_directory().unwrap();
        let error = runtime
            .block_on(replay_vector(&vector, directory.path()))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "immune:setup-failed:frontdoor:session-required"
        );
    }
    #[test]
    fn antibody_embedded_corpus_replays_through_real_node_http() {
        let corpus = ::immune::Corpus::embedded().unwrap();
        assert!(corpus.vectors().len() >= 12);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let report = replay(&corpus, REPLAY_BUDGET, runtime.handle().clone()).unwrap();
        assert!(report.successful(), "{report:?}");
        assert_eq!(report.passed, corpus.vectors().len());
    }
    #[test]
    fn antibody_replay_zero_budget_never_passes() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let report = replay(
            &::immune::Corpus::embedded().unwrap(),
            Duration::ZERO,
            runtime.handle().clone(),
        )
        .unwrap();
        assert!(!report.successful());
        assert_eq!(report.passed, 0);
        assert!(report.budget_exhausted);
    }
}
