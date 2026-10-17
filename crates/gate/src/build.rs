// SPDX-License-Identifier: AGPL-3.0-or-later
//! The build manifest: every input of one build, written down before the owner is asked.
//!
//! The owner's passkey approves these exact canonical bytes (a content proposal on `build/manifest.json`). A throwaway
//! builder then rebuilds from exactly this manifest, and only the artifact that rebuild produces can be offered for
//! release. The manifest names the source (commit, tree and a digest over the exported files), the lockfiles, the
//! toolchain, the recipe (the exact command and the digest of its script), the environment it starts with, the
//! target, the network it gets (none), the builder's sandbox policy and the release it replaces. It is made by trusted
//! code from an export that code made itself; nothing in it is a claim the engine can make.
//!
//! Canonical JSON with exactly these members: `base_release_sha256`, `builder`, `env`, `kind`, `locks`, `network`,
//! `node`, `recipe`, `source`, `target`, `toolchain`, `v`.

use canon::json::{parse_strict, to_canonical, SafeInteger, Value, ValueView};
use canon::Result;

/// Builds are approved on this one target; the applied bytes are the current approval.
pub const TARGET: &str = "build/manifest.json";
/// Targets under this prefix belong to the build path; the guest can neither propose to them nor rename them.
pub const TARGET_PREFIX: &str = "build/";
/// The `kind` member.
pub const KIND: &str = "aukora-build-manifest-v1";
/// A manifest is refused above this size, so it always fits the target's `max_bytes` (16,384 as installed).
pub const MAX_MANIFEST_BYTES: usize = 12_288;
/// The only target v1 builds for (the node's binaries).
pub const TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";

/// Environment variables a build may start with, and what their values may look like. Everything else is cleared by
/// the builder; its own paths (`PATH`, `HOME`, `CARGO_HOME`, `TMPDIR`, ...) are part of the builder's policy digest.
const ENV_ALLOWED: [&str; 15] = [
    "CARGO_INCREMENTAL",
    "CARGO_NET_OFFLINE",
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
    "CARGO_PROFILE_RELEASE_DEBUG",
    "CARGO_PROFILE_RELEASE_INCREMENTAL",
    "CARGO_PROFILE_RELEASE_LTO",
    "CARGO_PROFILE_RELEASE_OPT_LEVEL",
    "CARGO_PROFILE_RELEASE_PANIC",
    "CARGO_PROFILE_RELEASE_STRIP",
    "LC_ALL",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "RUSTUP_AUTO_INSTALL",
    "SOURCE_DATE_EPOCH",
    "TZ",
];

/// Which variables must be empty (a wrapper would run arbitrary code around every compiler call).
const ENV_EMPTY: [&str; 2] = ["RUSTC_WORKSPACE_WRAPPER", "RUSTC_WRAPPER"];

/// Variables whose value is one of a few exact strings, not a free pattern: a `TZ` of `:/etc/passwd` names a file, a
/// locale names a directory of code the C library loads.
const ENV_EXACT: [(&str, &[&str]); 3] = [("CARGO_NET_OFFLINE", &["true"]), ("LC_ALL", &["C", "C.UTF-8"]), ("TZ", &["UTC"])];

/// The variable that makes cargo refuse the network. A builder with no network of its own still gets it set, so a
/// build that reaches for a registry fails loudly instead of fetching.
const ENV_OFFLINE: &str = "CARGO_NET_OFFLINE";

fn env_value_ok(name: &str, value: &str) -> bool {
    match ENV_EXACT.iter().find(|(known, _)| *known == name) {
        Some((_, allowed)) => allowed.contains(&value),
        None => {
            value.len() <= 64
                && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b',' | b':' | b'=' | b'+' | b'/' | b'-' | b'_'))
                && (!ENV_EMPTY.contains(&name) || value.is_empty())
        }
    }
}

/// What network the build gets. A closed enum with one member: v1 builds never have any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    /// No network at all (the builder's wall); dependencies come from the pinned, read-only cache.
    None,
}

impl Network {
    /// The word on the card and in the manifest.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

fn bad() -> canon::Refusal {
    crate::refuse("build-manifest")
}

/// A lowercase hex string of exactly `len` digits.
fn hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn printable(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && text.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// One argument of the command: printable ASCII with no space, so the card's line for it is the argument and nothing else.
fn argument(text: &str) -> bool {
    printable(text, 256) && !text.contains(' ')
}

fn name(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !text.starts_with('-')
}

/// A path inside the export: relative, no `..`, no empty or `.` part, printable ASCII without spaces.
pub fn relative_path(text: &str) -> bool {
    printable(text, 256)
        && !text.contains(' ')
        && !text.starts_with('/')
        && text.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Where the sources came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    /// The commit (40 hex).
    pub commit: String,
    /// The commit's tree object (40 hex).
    pub tree: String,
    /// The digest over the exported files (`supervisor::build::closure`): paths, modes and content, 64 hex.
    pub export_sha256: String,
}

/// One lockfile and the digest of its exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lock {
    pub path: String,
    pub sha256: String,
}

/// The toolchain, as the tools themselves report it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Toolchain {
    /// `rustc -Vv`, the whole text (version, commit, host, LLVM).
    pub rustc: String,
    /// `cargo -V`.
    pub cargo: String,
    /// `node --version`.
    pub node: String,
}

/// The one command the builder runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipe {
    /// Literal arguments; the first is a script path inside the export. No shell is involved.
    pub argv: Vec<String>,
    /// The digest of that script's bytes (it is also inside `source.export_sha256`; stated so the card shows it).
    pub script_sha256: String,
}

/// The sandbox the build ran in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Builder {
    /// A name for the profile (`launcher-builder`, `openshell-build`).
    pub profile: String,
    /// The digest of the effective policy document (mounts, network, syscalls, limits, uid), not the policy's name.
    pub policy_sha256: String,
}

/// Everything one build depends on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    /// The release this build replaces (64 hex), or `None` for a node's first.
    pub base_release_sha256: Option<String>,
    pub builder: Builder,
    /// Name and value, sorted by name, names from the allowlist.
    pub env: Vec<(String, String)>,
    /// Sorted by path.
    pub locks: Vec<Lock>,
    /// The network the build gets: none. The builder is handed it in its request, not left to infer it.
    pub network: Network,
    /// The node the approval is for (the gate binds the proposal to the node too).
    pub node: String,
    pub recipe: Recipe,
    pub source: Source,
    pub toolchain: Toolchain,
}

fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}

fn object(members: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(members.into_iter().map(|(key, value)| (key.to_owned(), value)).collect())
}

impl Manifest {
    /// Check every field; the manifest is only ever built or read through this.
    pub fn validate(&self) -> Result<()> {
        let env_ok = self.env.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && self.env.len() <= 32
            && self.env.iter().all(|(key, value)| ENV_ALLOWED.contains(&key.as_str()) && env_value_ok(key, value))
            // Cargo must be told to stay offline, whatever the builder's own walls are.
            && self.env.iter().any(|(key, value)| key == ENV_OFFLINE && value == "true");
        let locks_ok = !self.locks.is_empty()
            && self.locks.len() <= 16
            && self.locks.windows(2).all(|pair| pair[0].path < pair[1].path)
            && self.locks.iter().all(|lock| relative_path(&lock.path) && hex(&lock.sha256, 64));
        let argv_ok = (1..=16).contains(&self.recipe.argv.len())
            && relative_path(&self.recipe.argv[0])
            && self.recipe.argv.iter().all(|arg| argument(arg))
            && hex(&self.recipe.script_sha256, 64);
        let toolchain_ok = printable(&self.toolchain.cargo, 128)
            && printable(&self.toolchain.node, 64)
            // `rustc -Vv` is several lines.
            && !self.toolchain.rustc.is_empty()
            && self.toolchain.rustc.len() <= 512
            && self.toolchain.rustc.bytes().all(|b| (0x20..=0x7e).contains(&b) || b == b'\n');
        let ok = self.base_release_sha256.as_deref().is_none_or(|digest| hex(digest, 64))
            && name(&self.builder.profile)
            && hex(&self.builder.policy_sha256, 64)
            && env_ok
            && locks_ok
            && name(&self.node)
            && argv_ok
            && hex(&self.source.commit, 40)
            && hex(&self.source.tree, 40)
            && hex(&self.source.export_sha256, 64)
            && toolchain_ok;
        if ok {
            Ok(())
        } else {
            Err(bad())
        }
    }

    /// The lines of the owner's card, in order: a label and its text. One line per input, nothing summarized.
    pub fn card_lines(&self) -> Vec<(String, String)> {
        let mut lines = vec![
            ("node".to_owned(), self.node.clone()),
            ("replaces_release".to_owned(), self.base_release_sha256.clone().unwrap_or_else(|| "none (first release)".to_owned())),
            ("commit".to_owned(), self.source.commit.clone()),
            ("tree".to_owned(), self.source.tree.clone()),
            ("source_files_sha256".to_owned(), self.source.export_sha256.clone()),
        ];
        lines.extend(self.locks.iter().map(|lock| (format!("lock {}", lock.path), lock.sha256.clone())));
        lines.push(("rustc".to_owned(), self.toolchain.rustc.clone()));
        lines.push(("cargo".to_owned(), self.toolchain.cargo.clone()));
        lines.push(("node_js".to_owned(), self.toolchain.node.clone()));
        // One line per argument: a space-joined command would show `build --skip` and `build`, `--skip` the same.
        lines.extend(self.recipe.argv.iter().enumerate().map(|(at, arg)| (format!("argv {at}"), arg.clone())));
        lines.push(("script_sha256".to_owned(), self.recipe.script_sha256.clone()));
        lines.extend(self.env.iter().map(|(name, value)| (format!("env {name}"), value.clone())));
        lines.push(("network".to_owned(), self.network.as_str().to_owned()));
        lines.push(("builder".to_owned(), self.builder.profile.clone()));
        lines.push(("builder_policy_sha256".to_owned(), self.builder.policy_sha256.clone()));
        lines
    }

    /// The canonical bytes the owner approves.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = object(vec![
            ("base_release_sha256", text(self.base_release_sha256.as_deref().unwrap_or("none"))?),
            (
                "builder",
                object(vec![("policy_sha256", text(&self.builder.policy_sha256)?), ("profile", text(&self.builder.profile)?)])?,
            ),
            (
                "env",
                object(self.env.iter().map(|(key, value)| Ok((key.as_str(), text(value)?))).collect::<Result<Vec<_>>>()?)?,
            ),
            ("kind", text(KIND)?),
            (
                "locks",
                Value::array(
                    self.locks
                        .iter()
                        .map(|lock| object(vec![("path", text(&lock.path)?), ("sha256", text(&lock.sha256)?)]))
                        .collect::<Result<Vec<_>>>()?,
                )?,
            ),
            ("network", text(self.network.as_str())?),
            ("node", text(&self.node)?),
            (
                "recipe",
                object(vec![
                    ("argv", Value::array(self.recipe.argv.iter().map(|arg| text(arg)).collect::<Result<Vec<_>>>()?)?),
                    ("script_sha256", text(&self.recipe.script_sha256)?),
                ])?,
            ),
            (
                "source",
                object(vec![
                    ("commit", text(&self.source.commit)?),
                    ("export_sha256", text(&self.source.export_sha256)?),
                    ("tree", text(&self.source.tree)?),
                ])?,
            ),
            ("target", text(TARGET_TRIPLE)?),
            (
                "toolchain",
                object(vec![
                    ("cargo", text(&self.toolchain.cargo)?),
                    ("node", text(&self.toolchain.node)?),
                    ("rustc", text(&self.toolchain.rustc)?),
                ])?,
            ),
            ("v", Value::integer(SafeInteger::new(1)?)),
        ])?;
        let bytes = to_canonical(&value);
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(crate::refuse("build-manifest-too-large"));
        }
        Ok(bytes)
    }

    /// Read a manifest back, refusing anything that is not exactly what `to_bytes` writes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let root = parse_strict(bytes).map_err(|_| bad())?;
        if to_canonical(&root) != bytes || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(bad());
        }
        let members = |value: &Value, keys: &[&str]| match value.view() {
            ValueView::Object(found) if found.len() == keys.len() && keys.iter().all(|key| value.get(key).is_some()) => Ok(()),
            _ => Err(bad()),
        };
        let field = |value: &Value, key: &str| match value.get(key).map(Value::view) {
            Some(ValueView::Text(found)) => Ok(found.to_owned()),
            _ => Err(bad()),
        };
        members(
            &root,
            &["base_release_sha256", "builder", "env", "kind", "locks", "network", "node", "recipe", "source", "target", "toolchain", "v"],
        )?;
        if !matches!(root.get("v").map(Value::view), Some(ValueView::Integer(version)) if version.get() == 1)
            || field(&root, "kind")? != KIND
            || field(&root, "target")? != TARGET_TRIPLE
        {
            return Err(bad());
        }
        let child = |key: &str, keys: &[&str]| -> Result<&Value> {
            let value = root.get(key).ok_or_else(bad)?;
            members(value, keys)?;
            Ok(value)
        };
        let builder = child("builder", &["policy_sha256", "profile"])?;
        let source = child("source", &["commit", "export_sha256", "tree"])?;
        let toolchain = child("toolchain", &["cargo", "node", "rustc"])?;
        let recipe = child("recipe", &["argv", "script_sha256"])?;
        let strings = |value: Option<&Value>| match value.map(Value::view) {
            Some(ValueView::Array(items)) => items
                .iter()
                .map(|item| match item.view() {
                    ValueView::Text(found) => Ok(found.to_owned()),
                    _ => Err(bad()),
                })
                .collect::<Result<Vec<_>>>(),
            _ => Err(bad()),
        };
        let env = match root.get("env").map(Value::view) {
            Some(ValueView::Object(found)) => found
                .iter()
                .map(|(key, value)| match value.view() {
                    ValueView::Text(found) => Ok((key.clone(), found.to_owned())),
                    _ => Err(bad()),
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(bad()),
        };
        let locks = match root.get("locks").map(Value::view) {
            Some(ValueView::Array(items)) => items
                .iter()
                .map(|item| {
                    members(item, &["path", "sha256"])?;
                    Ok(Lock { path: field(item, "path")?, sha256: field(item, "sha256")? })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(bad()),
        };
        let network = Network::parse(&field(&root, "network")?).ok_or_else(bad)?;
        let base = field(&root, "base_release_sha256")?;
        let manifest = Manifest {
            base_release_sha256: if base == "none" { None } else { Some(base) },
            builder: Builder { profile: field(builder, "profile")?, policy_sha256: field(builder, "policy_sha256")? },
            env,
            locks,
            network,
            node: field(&root, "node")?,
            recipe: Recipe { argv: strings(recipe.get("argv"))?, script_sha256: field(recipe, "script_sha256")? },
            source: Source { commit: field(source, "commit")?, tree: field(source, "tree")?, export_sha256: field(source, "export_sha256")? },
            toolchain: Toolchain { rustc: field(toolchain, "rustc")?, cargo: field(toolchain, "cargo")?, node: field(toolchain, "node")? },
        };
        manifest.validate()?;
        if manifest.to_bytes()? != bytes {
            return Err(bad());
        }
        Ok(manifest)
    }
}

#[cfg(test)]
pub(crate) fn sample() -> Manifest {
    let digest = |n: u8| format!("{n:02x}").repeat(32);
    Manifest {
        base_release_sha256: Some(digest(0xaa)),
        builder: Builder { profile: "launcher-builder".into(), policy_sha256: digest(0xbb) },
        env: vec![
            ("CARGO_NET_OFFLINE".into(), "true".into()),
            ("LC_ALL".into(), "C".into()),
            ("RUSTC_WRAPPER".into(), String::new()),
            ("SOURCE_DATE_EPOCH".into(), "1760000000".into()),
            ("TZ".into(), "UTC".into()),
        ],
        locks: vec![
            Lock { path: "Cargo.lock".into(), sha256: digest(0x01) },
            Lock { path: "app/package-lock.json".into(), sha256: digest(0x02) },
        ],
        network: Network::None,
        node: "t1".into(),
        recipe: Recipe {
            argv: ["scripts/reproduce.sh", "build", "0123456789abcdef0123456789abcdef01234567", "/out", "--twice"].map(String::from).to_vec(),
            script_sha256: digest(0xcc),
        },
        source: Source { commit: "0123456789abcdef0123456789abcdef01234567".into(), tree: "fedcba9876543210fedcba9876543210fedcba98".into(), export_sha256: digest(0xdd) },
        toolchain: Toolchain {
            rustc: "rustc 1.91.0 (abcdef012 2026-08-01)\nbinary: rustc\nhost: x86_64-unknown-linux-gnu".into(),
            cargo: "cargo 1.91.0 (abcdef012 2026-08-01)".into(),
            node: "v24.11.1".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_reads_back_as_what_it_says() {
        let manifest = sample();
        let bytes = manifest.to_bytes().unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().starts_with("{\"base_release_sha256\":"));
        assert_eq!(Manifest::parse(&bytes).unwrap(), manifest);
        let first = Manifest { base_release_sha256: None, ..sample() };
        assert_eq!(Manifest::parse(&first.to_bytes().unwrap()).unwrap().base_release_sha256, None);
    }

    #[test]
    fn what_is_not_exactly_a_manifest_is_refused() {
        let good = String::from_utf8(sample().to_bytes().unwrap()).unwrap();
        for changed in [
            good.replace("\"v\":1", "\"v\": 1"),
            good.replace("\"v\":1", "\"v\":2"),
            good.replace(KIND, "other"),
            good.replace("\"network\":\"none\"", "\"network\":\"open\""),
            good.replace(TARGET_TRIPLE, "aarch64-apple-darwin"),
            good.replace("\"v\":1}", "\"v\":1,\"z\":0}"),
            good.replace("\"node\":\"t1\"", "\"node\":\"T1\""),
            good.replace("0123456789abcdef0123456789abcdef01234567\",\"export", "0123\",\"export"),
        ] {
            assert!(Manifest::parse(changed.as_bytes()).is_err(), "{changed}");
        }
        assert!(Manifest::parse(b"{}").is_err() && Manifest::parse(b"nope").is_err());
    }

    /// The sample's environment with one more (or replaced) variable, still sorted.
    fn env_with(name: &str, value: &str) -> Vec<(String, String)> {
        let mut env: Vec<_> = sample().env.into_iter().filter(|(key, _)| key != name).collect();
        env.push((name.to_owned(), value.to_owned()));
        env.sort();
        env
    }

    #[test]
    fn the_environment_is_a_closed_list_with_closed_values() {
        let mut manifest = sample();
        for (name, value) in [("LD_PRELOAD", "/x"), ("PATH", "/bin"), ("RUSTC_WRAPPER", "evil"), ("TZ", "a b"), ("TZ", "$(id)")] {
            manifest.env = env_with(name, value);
            assert!(manifest.to_bytes().is_err(), "{name}={value}");
        }
        // Unsorted or repeated names are refused rather than reordered.
        manifest.env = vec![("CARGO_NET_OFFLINE".into(), "true".into()), ("TZ".into(), "UTC".into()), ("LC_ALL".into(), "C".into())];
        assert!(manifest.to_bytes().is_err());
        manifest.env = vec![("CARGO_NET_OFFLINE".into(), "true".into()), ("TZ".into(), "UTC".into()), ("TZ".into(), "UTC".into())];
        assert!(manifest.to_bytes().is_err());
    }

    #[test]
    fn the_build_is_told_to_stay_offline_and_its_locale_and_zone_name_no_file() {
        // Review: `network` was parsed and dropped, `CARGO_NET_OFFLINE=false` was allowed, and `TZ=:/etc/passwd` passed.
        let mut manifest = sample();
        assert_eq!(manifest.network, Network::None);
        manifest.env = env_with("CARGO_NET_OFFLINE", "false");
        assert!(manifest.to_bytes().is_err(), "offline=false");
        manifest.env = sample().env.into_iter().filter(|(key, _)| key != "CARGO_NET_OFFLINE").collect();
        assert!(manifest.to_bytes().is_err(), "offline missing");
        manifest.env = vec![];
        assert!(manifest.to_bytes().is_err(), "env empty");
        for (name, value) in [("TZ", ":/etc/passwd"), ("TZ", "Europe/Oslo"), ("TZ", "utc"), ("TZ", ""), ("LC_ALL", "en_US.UTF-8"), ("LC_ALL", "/tmp/locale"), ("LC_ALL", "")] {
            manifest.env = env_with(name, value);
            assert!(manifest.to_bytes().is_err(), "{name}={value}");
        }
        manifest.env = env_with("LC_ALL", "C.UTF-8");
        let bytes = manifest.to_bytes().unwrap();
        assert_eq!(Manifest::parse(&bytes).unwrap(), manifest);
        // The same refusals on the read path: bytes the owner would be shown, edited to carry them, do not parse.
        let good = String::from_utf8(sample().to_bytes().unwrap()).unwrap();
        for changed in [good.replace("\"CARGO_NET_OFFLINE\":\"true\"", "\"CARGO_NET_OFFLINE\":\"false\""), good.replace("\"TZ\":\"UTC\"", "\"TZ\":\":/etc/passwd\"")] {
            assert!(Manifest::parse(changed.as_bytes()).is_err(), "{changed}");
        }
    }

    #[test]
    fn the_recipe_is_a_script_inside_the_export() {
        for first in ["/bin/sh", "../x.sh", "a//b.sh", "./x.sh", "a b.sh", ""] {
            let mut manifest = sample();
            manifest.recipe.argv[0] = first.into();
            assert!(manifest.to_bytes().is_err(), "{first:?}");
        }
        let mut manifest = sample();
        manifest.recipe.argv.push("tab\there".into());
        assert!(manifest.to_bytes().is_err());
        // A space in any slot is refused, not just the first: `["build --skip"]` must not read as `["build", "--skip"]`.
        for arg in ["build --skip", " build", "build ", "a\nb", "a\u{a0}b", "a\u{7f}b", ""] {
            let mut manifest = sample();
            manifest.recipe.argv[1] = arg.into();
            assert!(manifest.to_bytes().is_err(), "{arg:?}");
        }
        manifest.recipe.argv = vec![];
        assert!(manifest.to_bytes().is_err());
    }

    #[test]
    fn locks_and_digests_are_checked() {
        let mut manifest = sample();
        manifest.locks.clear();
        assert!(manifest.to_bytes().is_err());
        let mut manifest = sample();
        manifest.locks.reverse();
        assert!(manifest.to_bytes().is_err(), "unsorted");
        let mut manifest = sample();
        manifest.source.export_sha256 = "AB".repeat(32);
        assert!(manifest.to_bytes().is_err(), "uppercase");
        let mut manifest = sample();
        manifest.base_release_sha256 = Some("none".into());
        assert!(manifest.to_bytes().is_err());
    }

    #[test]
    fn the_card_shows_every_input_on_its_own_line() {
        let lines = sample().card_lines();
        let label = |name: &str| lines.iter().find(|(label, _)| label == name).map(|(_, text)| text.as_str());
        assert_eq!(label("node"), Some("t1"));
        assert_eq!(label("commit"), Some("0123456789abcdef0123456789abcdef01234567"));
        assert_eq!(label("lock Cargo.lock"), Some(&*"01".repeat(32)));
        assert_eq!(label("lock app/package-lock.json"), Some(&*"02".repeat(32)));
        assert_eq!(label("env RUSTC_WRAPPER"), Some(""));
        assert_eq!(label("env TZ"), Some("UTC"));
        assert_eq!(label("command"), None, "the command is no longer one joined line");
        let argv: Vec<_> = lines.iter().filter(|(label, _)| label.starts_with("argv ")).map(|(label, text)| (label.as_str(), text.as_str())).collect();
        assert_eq!(
            argv,
            [
                ("argv 0", "scripts/reproduce.sh"),
                ("argv 1", "build"),
                ("argv 2", "0123456789abcdef0123456789abcdef01234567"),
                ("argv 3", "/out"),
                ("argv 4", "--twice"),
            ]
        );
        assert_eq!(label("env CARGO_NET_OFFLINE"), Some("true"));
        assert_eq!(label("network"), Some("none"));
        assert_eq!(Manifest { base_release_sha256: None, ..sample() }.card_lines()[1].1, "none (first release)");
        // Labels are unique, so none can hide another.
        let mut names: Vec<_> = lines.iter().map(|(label, _)| label.clone()).collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn two_different_commands_never_show_the_same_card() {
        // Review: `["build --skip", ...]` and `["build", "--skip", ...]` both rendered `build --skip`. The first is now
        // refused; and where two argument lists are both valid, their cards differ line for line.
        let mut spaced = sample();
        spaced.recipe.argv = ["scripts/reproduce.sh", "build --skip", "0123456789abcdef0123456789abcdef01234567", "/out"].map(String::from).to_vec();
        assert!(spaced.to_bytes().is_err());
        let mut split = sample();
        split.recipe.argv = ["scripts/reproduce.sh", "build", "--skip", "0123456789abcdef0123456789abcdef01234567", "/out"].map(String::from).to_vec();
        let mut joined = sample();
        joined.recipe.argv = ["scripts/reproduce.sh", "build--skip", "0123456789abcdef0123456789abcdef01234567", "/out"].map(String::from).to_vec();
        assert_ne!(split.card_lines(), joined.card_lines());
        assert_ne!(split.to_bytes().unwrap(), joined.to_bytes().unwrap());
    }

    #[test]
    fn the_target_slot_is_a_valid_target_name() {
        assert_eq!(crate::target::TargetId::new(TARGET.to_owned()).unwrap().as_str(), TARGET);
        assert!(TARGET.starts_with(TARGET_PREFIX));
    }
}
