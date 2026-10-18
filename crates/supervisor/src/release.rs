// SPDX-License-Identifier: AGPL-3.0-or-later
//! Release files remain data until floor and Aura agree on the installed digest.

mod owner;
pub(crate) mod pointer;
pub(crate) mod probe;
pub(crate) use owner::ReleaseApproval;

use crate::adapters::HostLedger;
use canon::{
    authority::{AuthorityRecord, AuthorityTxn, OwnerAssertion, OwnerOperation, VerifiedProof},
    digest::Digest32,
    ids::{NodeId, ProposalId},
    json::{self, Value, ValueView},
    Result,
};
use frontdoor::assets::{ReleaseCandidate, ReleaseSource};
use rustix::fs::{flock, open, openat, FlockOperation, Mode, OFlags};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

pub struct ReleaseFiles {
    directory: File,
    manifest: Vec<u8>,
    manifest_digest: Digest32,
    pub release_digest: Digest32,
    pub binary_digest: Digest32,
    floor_directory: PathBuf,
    ledger: Arc<HostLedger>,
    /// Root's record of the floor it last accepted (`/var/lib/aukora-release/anchor.json`, written by
    /// `node_release.py follow`). A floor behind it is a restored snapshot, never served (Codex review, B30).
    anchor: Option<PathBuf>,
}

impl ReleaseFiles {
    pub fn open(root: &Path, floor_directory: PathBuf, ledger: Arc<HostLedger>) -> Result<Self> {
        // Deployment owns the one current-release symlink. Its resolved tree is immutable to this user.
        let resolved = std::fs::canonicalize(root).map_err(|_| refuse("release-directory"))?;
        let directory = trusted_directory(&resolved)?;
        let tree = verify_tree(&directory)?;
        let running = std::env::current_exe().map_err(|_| refuse("running-executable"))?;
        let file: File = open(
            &running,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| refuse("running-executable"))?
        .into();
        let metadata = file.metadata().map_err(|_| refuse("running-executable"))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
            || metadata.len() != tree.binary_len as u64
        {
            return Err(refuse("running-executable"));
        }
        let mut running_bytes = Vec::new();
        file.take(256 * 1024 * 1024 + 1)
            .read_to_end(&mut running_bytes)
            .map_err(|_| refuse("running-executable"))?;
        if running_bytes.len() != tree.binary_len
            || Digest32::sha256(&running_bytes) != tree.binary_digest
        {
            return Err(refuse("running-release-mismatch"));
        }
        Ok(Self {
            directory,
            manifest: tree.manifest,
            manifest_digest: tree.manifest_digest,
            release_digest: tree.release_digest,
            binary_digest: tree.binary_digest,
            floor_directory,
            ledger,
            anchor: None,
        })
    }

    /// The root anchor beside the release state (`release_state` is `/var/lib/aukora-release/active.json`).
    pub fn with_anchor(mut self, release_state: &Path) -> Self {
        self.anchor = release_state.parent().map(|folder| folder.join(ANCHOR_FILE));
        self
    }

    pub fn approval(&self) -> Result<()> {
        let floor = floor::service::FloorService::open(&self.floor_directory)?;
        self.ledger.transaction(|transaction| {
            floor.probe_release_guard(transaction)?;
            let state = floor.snapshot()?;
            check_anchor(self.anchor.as_deref(), &state)?;
            if state.floor.digest != self.release_digest {
                return Err(refuse("release-not-approved"));
            }
            Ok(())
        })
    }

    /// Whether the owner's passkey approved this running release: the floor names it AND the floor is one the owner
    /// advanced, not the install's own starting floor (`is_install_genesis`), which the shell accepts before the
    /// first card but which nobody approved. `Err` is "cannot read the floor now" (`floor:locked` while another
    /// reader holds it, I/O, a staged transition), never "no": callers keep the two apart (NODE.md O11).
    pub fn owner_approved(&self) -> Result<bool> {
        let floor = floor::service::FloorService::open(&self.floor_directory)?;
        self.ledger.transaction(|transaction| {
            floor.probe_release_guard(transaction)?;
            let state = floor.snapshot()?;
            check_anchor(self.anchor.as_deref(), &state)?;
            Ok(state.floor.digest == self.release_digest && !state.is_install_genesis())
        })
    }

    /// Consume a release assertion only for this verified, running release. The
    /// caller supplies the assertion, not a pointer hash or an approval receipt.
    pub fn advance_approved(
        &self,
        proposal: ProposalId,
        assertion: OwnerAssertion,
        order: &floor::ReleaseOrder,
    ) -> Result<AuthorityRecord> {
        if order.digest != self.release_digest {
            return Err(refuse("release-not-approved"));
        }
        order.validate()?;
        let mut floor = floor::service::FloorService::open(&self.floor_directory)?;
        self.ledger
            .transaction(|transaction| floor.reconcile(transaction))?;
        let record = self.ledger.transaction(|transaction| {
            let installed = floor.snapshot()?;
            if installed.floor.digest == self.release_digest {
                floor.probe_release_guard(transaction)?;
                require_release_order(&installed.floor, order)?;
                if installed.high_water.spent.iter().any(|spent| {
                    spent.authority == installed.authority && spent.proposal == proposal
                }) {
                    return floor
                        .retry_installed(
                            transaction,
                            proposal,
                            assertion,
                            order,
                            self.release_digest,
                        )
                        .map_err(|_| refuse("release-not-approved"));
                }
            }
            let proof =
                VerifiedProof::verify(transaction, &proposal, OwnerOperation::Release, assertion)
                    .map_err(|error| {
                        if installed.floor.digest == self.release_digest {
                            refuse("release-not-approved")
                        } else {
                            error
                        }
                    })?;
            floor
                .advance_installed(transaction, proof, order, self.release_digest)
                .map_err(|error| {
                    if installed.floor.digest == self.release_digest {
                        refuse("release-not-approved")
                    } else {
                        error
                    }
                })
        })?;
        // The floor stage is not readable until a fresh transaction authenticates
        // its committed receipt.
        self.ledger
            .transaction(|transaction| floor.reconcile(transaction))?;
        self.ledger.transaction(|transaction| {
            floor.probe_release_guard(transaction)?;
            let installed = floor.snapshot()?;
            require_release_order(&installed.floor, order)?;
            if installed.authority != record.authority {
                return Err(refuse("release-not-approved"));
            }
            Ok(())
        })?;
        Ok(record)
    }

    /// An absent first floor may come only from the verified install before claim.
    pub fn initialize_floor(
        &self,
        sessions: &File,
        node: NodeId,
        shell_origin: &str,
        owner_origin: &str,
    ) -> Result<()> {
        let mut floor = floor::service::FloorService::open(&self.floor_directory)?;
        match self
            .ledger
            .transaction(|transaction| floor.reconcile(transaction))
        {
            Ok(_) => return Ok(()),
            Err(error)
                if error
                    == (canon::Refusal {
                        organ: "floor",
                        reason: "absent",
                    }) => {}
            Err(error) => return Err(error),
        }
        let _claim_lock = unclaimed_sessions(sessions, node, shell_origin, owner_origin)?;
        let installed = read(&self.directory, ".verified", 65)?;
        if installed != format!("{}\n", self.release_digest).as_bytes() {
            return Err(refuse("release-not-verified"));
        }
        self.ledger.transaction(|transaction| {
            if transaction.pending_owner_credential()?.is_some()
                || transaction.bound_owner_identity()?.is_some()
            {
                return Err(refuse("genesis-owner-present"));
            }
            floor.initialize_from_install(transaction, self.release_digest)?;
            Ok(())
        })?;
        self.ledger
            .transaction(|transaction| floor.reconcile(transaction))?;
        Ok(())
    }

    pub fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }
}

struct VerifiedTree {
    manifest: Vec<u8>,
    manifest_digest: Digest32,
    release_digest: Digest32,
    binary_digest: Digest32,
    binary_len: usize,
}

/// Everything `ReleaseFiles::open` checks of a release tree except that it is the running binary: the manifest, the
/// shell's browser manifest and every leaf it names, the supervisor binary and the Pentora cell.
fn verify_tree(directory: &File) -> Result<VerifiedTree> {
    let bytes = read(directory, "release.json", 4 * 1024 * 1024)?;
    let release_digest = Digest32::sha256(&bytes);
    let value = json::parse_strict(&bytes)?;
    if value.canonical_bytes() != bytes || text(&value, "schema")? != "aukora-release-v1" {
        return Err(refuse("release-manifest"));
    }
    let files = validate_manifest(&value)?;
    let manifest = read(
        directory,
        "www/release-manifest.json",
        frontdoor::assets::MAX_MANIFEST_BYTES,
    )?;
    let manifest_digest = Digest32::sha256(&manifest);
    verify_entry(files, "www/release-manifest.json", &manifest)?;
    let executable = read(directory, "bin/sovereign", 256 * 1024 * 1024)?;
    verify_entry(files, "bin/sovereign", &executable)?;
    let binary_digest = Digest32::sha256(&executable);
    let browser = json::parse_strict(&manifest)?;
    let Some(ValueView::Array(assets)) = browser.get("assets").map(Value::view) else {
        return Err(refuse("release-manifest"));
    };
    if !assets
        .iter()
        .any(|asset| text(asset, "path").ok() == Some("app/core/pentora.wasm"))
    {
        return Err(refuse("pentora-asset-missing"));
    }
    let pentora = read(
        directory,
        "www/app/core/pentora.wasm",
        frontdoor::assets::MAX_ASSET_BYTES,
    )?;
    verify_entry(files, "www/app/core/pentora.wasm", &pentora)?;
    // Every browser manifest leaf must also occur in the installed release commitment.
    for asset in assets {
        let path = text(asset, "path")?;
        let entry = files
            .get(&format!("www/{path}"))
            .ok_or(refuse("release-manifest"))?;
        if entry.get("bytes") != asset.get("bytes")
            || entry.get("sha256") != asset.get("sha256")
        {
            return Err(refuse("release-manifest"));
        }
    }
    Ok(VerifiedTree {
        manifest,
        manifest_digest,
        release_digest,
        binary_digest,
        binary_len: executable.len(),
    })
}

/// The release the operator offered for an upgrade (`/opt/aukora/offered`, a root-made link to a staged release),
/// verified as a whole tree exactly as the running one is, plus the staging tool's own `.verified` marker. Its
/// release digest (the SHA-256 of `release.json`) is what the owner's card names. `None`: nothing is offered.
pub(crate) fn verify_candidate(link: &Path) -> Result<Option<(PathBuf, Digest32)>> {
    match std::fs::symlink_metadata(link) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(refuse("release-offer")),
        Ok(metadata) if !metadata.file_type().is_symlink() || metadata.uid() != 0 => {
            return Err(refuse("release-offer"))
        }
        Ok(_) => {}
    }
    let resolved = std::fs::canonicalize(link).map_err(|_| refuse("release-offer"))?;
    let directory = trusted_directory(&resolved)?;
    let tree = verify_tree(&directory)?;
    let marker = read(&directory, ".verified", 65)?;
    if marker != format!("{}\n", tree.release_digest).as_bytes() {
        return Err(refuse("release-not-verified"));
    }
    Ok(Some((resolved, tree.release_digest)))
}

/// `sovereign release floor --config PATH`, run by the supervisor's root pre-start step as the service user while the
/// supervisor is stopped (it takes the state lock): print the owner's floor anchor JSON, after the floor
/// is reconciled with Aura and its history checked, or refuse. The install's own starting floor is nobody's approval
/// and prints nothing (exit 3). This is the only answer `node_release.py follow` switches on.
pub(crate) fn floor_cli(arguments: &[std::ffi::OsString]) -> Result<()> {
    let [flag, path] = arguments else {
        return Err(refuse("release-floor-usage"));
    };
    if flag != "--config" {
        return Err(refuse("release-floor-usage"));
    }
    let config = crate::config::NodeConfig::load(Path::new(path))?;
    // A node with no floor yet (a fresh install, before the supervisor's first start) has nothing to follow, and this
    // step must never create the node's identity or its ledger: only `serve` does that.
    if std::fs::symlink_metadata(config.state_root.join("floor").join("floor-state.json")).is_err() {
        std::process::exit(3);
    }
    let state = crate::state::HostState::open(&config.state_root, &config.node)?;
    let ledger = HostLedger::open(
        &config.state_root.join("aura.sqlite3"),
        state.signer.clone(),
        Arc::new(crate::adapters::HostClock),
    )?;
    let mut floor = floor::service::FloorService::open(&config.state_root.join("floor"))?;
    let current = ledger.transaction(|transaction| {
        let current = floor.reconcile(transaction)?;
        floor.probe_release_guard(transaction)?;
        Ok(current)
    })?;
    if current.is_install_genesis() {
        std::process::exit(3);
    }
    println!("{}", floor_anchor(&current));
    Ok(())
}

/// The anchor file root keeps beside `active.json`.
pub(crate) const ANCHOR_FILE: &str = "anchor.json";

/// What root anchors of an owner's floor: the release it names, its authority version, its head receipt, its display
/// history and every approval it has spent (`epoch:sequence:authorization_sha256`, never pruned). A later floor
/// extends `spent` and moves the version forward; a restored older snapshot does neither.
pub(crate) fn floor_anchor(state: &floor::ProtectedState) -> serde_json::Value {
    serde_json::json!({
        "digest": state.floor.digest.to_string(),
        "epoch": state.authority.epoch,
        "sequence": state.authority.sequence,
        "head": state.high_water.head.to_string(),
        "history": state.floor.history.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "spent": state.high_water.spent.iter().map(spent_text).collect::<Vec<_>>(),
    })
}

fn spent_text(spent: &floor::SpentApproval) -> String {
    format!("{}:{}:{}", spent.authority.epoch, spent.authority.sequence, spent.authorization_sha256)
}

static ANCHOR_SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Fail closed when the floor is behind the floor root last accepted: an older version, the same version with another
/// head, or a spent list that does not extend root's. No anchor yet (a node before its first owner floor was
/// followed): nothing to compare. An anchor that cannot be read refuses.
pub(crate) fn check_anchor(path: Option<&Path>, state: &floor::ProtectedState) -> Result<()> {
    let Some(path) = path else { return Ok(()) };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(refuse("release-anchor")),
    };
    let anchored = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| value.get("floor").cloned())
        .ok_or(refuse("release-anchor"))?;
    if !anchor_is_behind_or_equal(&anchored, &floor_anchor(state)) {
        if !ANCHOR_SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("release: the floor is behind the floor root accepted (a restored or divergent state); refusing to serve it");
        }
        return Err(refuse("floor-behind-anchor"));
    }
    ANCHOR_SAID.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Whether `current` is `anchored` or a successor of it (pure).
pub(crate) fn anchor_is_behind_or_equal(anchored: &serde_json::Value, current: &serde_json::Value) -> bool {
    let version = |value: &serde_json::Value| (value["epoch"].as_u64(), value["sequence"].as_u64());
    let (Some(a_epoch), Some(a_sequence)) = version(anchored) else { return false };
    let (Some(c_epoch), Some(c_sequence)) = version(current) else { return false };
    let (Some(a_spent), Some(c_spent)) = (anchored["spent"].as_array(), current["spent"].as_array()) else {
        return false;
    };
    if (c_epoch, c_sequence) == (a_epoch, a_sequence) {
        return anchored["head"] == current["head"] && a_spent == c_spent;
    }
    (c_epoch, c_sequence) > (a_epoch, a_sequence) && c_spent.len() > a_spent.len() && c_spent.starts_with(a_spent)
}

fn require_release_order(published: &floor::Floor, order: &floor::ReleaseOrder) -> Result<()> {
    if published.digest != order.digest
        || published.record != order.record
        || published.signer_epoch != order.signer_epoch
        || published.ledger_seq != order.ledger_seq
        || published.signer_key_sha256 != order.signer_key_sha256
        || published.ledger_hash != order.ledger_hash
    {
        return Err(refuse("release-not-approved"));
    }
    Ok(())
}

impl ReleaseSource for ReleaseFiles {
    fn candidate(&mut self) -> Result<ReleaseCandidate> {
        Ok(ReleaseCandidate {
            manifest_bytes: self.manifest.clone(),
            manifest_sha256: self.manifest_digest,
        })
    }

    fn require_current_approval(&mut self, manifest: Digest32) -> Result<()> {
        if manifest != self.manifest_digest {
            return Err(refuse("manifest-changed"));
        }
        self.approval()
    }

    fn read_exact_asset(&mut self, path: &str, maximum: usize) -> Result<Vec<u8>> {
        read(&self.directory, &format!("www/{path}"), maximum)
    }
}

fn unclaimed_sessions(
    sessions_dir: &File,
    node: NodeId,
    shell_origin: &str,
    owner_origin: &str,
) -> Result<File> {
    let flags = OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let lock: File = openat(
        sessions_dir,
        "sessions.lock",
        flags | OFlags::RDWR,
        Mode::empty(),
    )
    .map_err(|_| refuse("genesis-session-lock"))?
    .into();
    private_session_file(&lock)?;
    flock(&lock, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| refuse("genesis-session-lock"))?;
    let state: File = openat(
        sessions_dir,
        "sessions-v1.json",
        flags | OFlags::RDONLY,
        Mode::empty(),
    )
    .map_err(|_| refuse("genesis-session-state"))?
    .into();
    private_session_file(&state)?;
    let mut bytes = Vec::new();
    state
        .take(2_097_153)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse("genesis-session-state"))?;
    if bytes.len() > 2_097_152 {
        return Err(refuse("genesis-session-state"));
    }
    let state = json::parse_strict(&bytes).map_err(|_| refuse("genesis-session-state"))?;
    exact_keys(
        &state,
        &[
            "format", "node", "shell", "owner", "epoch", "binding", "subject", "records",
        ],
    )
    .map_err(|_| refuse("genesis-session-state"))?;
    if text(&state, "format")? != "frontdoor-sessions-v1"
        || text(&state, "node")? != node.to_string()
        || text(&state, "shell")? != shell_origin
        || text(&state, "owner")? != owner_origin
        || text(&state, "binding")? != "unclaimed"
        || !matches!(state.get("epoch").map(Value::view), Some(ValueView::Integer(epoch)) if epoch.get() == 0)
        || !matches!(state.get("subject").map(Value::view), Some(ValueView::Null))
        || !matches!(state.get("records").map(Value::view), Some(ValueView::Array(records)) if records.is_empty())
    {
        return Err(refuse("genesis-claim-spent"));
    }
    Ok(lock)
}

fn private_session_file(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| refuse("genesis-session-state"))?;
    if metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o077 == 0 {
        Ok(())
    } else {
        Err(refuse("genesis-session-state"))
    }
}

pub fn trusted_directory(path: &Path) -> Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current: File = open(std::path::MAIN_SEPARATOR_STR, flags, Mode::empty())
        .map_err(|_| refuse("release-directory"))?
        .into();
    if !path.is_absolute() {
        return Err(refuse("release-directory"));
    }
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = openat(&current, name, flags, Mode::empty())
                    .map_err(|_| refuse("release-directory"))?
                    .into();
                let meta = current
                    .metadata()
                    .map_err(|_| refuse("release-directory"))?;
                if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                    return Err(refuse("release-permissions"));
                }
            }
            _ => return Err(refuse("release-directory")),
        }
    }
    Ok(current)
}

fn read(directory: &File, path: &str, maximum: usize) -> Result<Vec<u8>> {
    if path.is_empty() || path.starts_with('/') {
        return Err(refuse("release-path"));
    }
    let mut directory = directory
        .try_clone()
        .map_err(|_| refuse("release-directory"))?;
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
            return Err(refuse("release-path"));
        }
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let file: File = openat(
            &directory,
            part,
            if parts.peek().is_some() {
                flags | OFlags::DIRECTORY
            } else {
                flags
            },
            Mode::empty(),
        )
        .map_err(|_| refuse("release-read"))?
        .into();
        let meta = file.metadata().map_err(|_| refuse("release-read"))?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(refuse("release-permissions"));
        }
        if parts.peek().is_some() {
            directory = file;
            continue;
        }
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > maximum as u64 {
            return Err(refuse("release-file"));
        }
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refuse("release-read"))?;
        if bytes.len() > maximum || bytes.len() as u64 != meta.len() {
            return Err(refuse("release-file"));
        }
        return Ok(bytes);
    }
    Err(refuse("release-path"))
}

fn verify_entry(files: &Value, path: &str, bytes: &[u8]) -> Result<()> {
    let entry = files.get(path).ok_or(refuse("release-manifest"))?;
    if text(entry, "sha256")? != Digest32::sha256(bytes).to_string()
        || !matches!(entry.get("bytes").map(Value::view), Some(ValueView::Integer(size)) if size.get() >= 0 && size.get() as usize == bytes.len())
    {
        return Err(refuse("release-file-mismatch"));
    }
    Ok(())
}

fn validate_manifest(manifest: &Value) -> Result<&Value> {
    exact_keys(
        manifest,
        &["schema", "commit", "target", "toolchain", "files"],
    )?;
    let commit = text(manifest, "commit")?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || text(manifest, "target")?.len() > 64
        || text(manifest, "toolchain")?.len() > 512
    {
        return Err(refuse("release-manifest"));
    }
    let files = manifest.get("files").ok_or(refuse("release-manifest"))?;
    let ValueView::Object(entries) = files.view() else {
        return Err(refuse("release-manifest"));
    };
    if entries.is_empty() || entries.len() > 8192 {
        return Err(refuse("release-manifest"));
    }
    let mut total = 0_u64;
    for (path, entry) in entries {
        exact_keys(entry, &["bytes", "mode", "sha256"])?;
        if path.is_empty()
            || path.len() > 240
            || !path.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(refuse("release-path"));
        }
        if !matches!(text(entry, "mode")?, "0644" | "0755") {
            return Err(refuse("release-manifest"));
        }
        Digest32::from_hex(text(entry, "sha256")?).map_err(|_| refuse("release-manifest"))?;
        let Some(ValueView::Integer(bytes)) = entry.get("bytes").map(Value::view) else {
            return Err(refuse("release-manifest"));
        };
        let bytes = u64::try_from(bytes.get()).map_err(|_| refuse("release-manifest"))?;
        total = total.checked_add(bytes).ok_or(refuse("release-manifest"))?;
        if total > 512 * 1024 * 1024 {
            return Err(refuse("release-manifest"));
        }
    }
    for path in [
        "bin/sovereign",
        "bin/auma",
        "bin/aukora-verify",
        "www/release-manifest.json",
    ] {
        if files.get(path).is_none() {
            return Err(refuse("release-file-missing"));
        }
    }
    Ok(files)
}

fn exact_keys(value: &Value, expected: &[&str]) -> Result<()> {
    let ValueView::Object(fields) = value.view() else {
        return Err(refuse("release-manifest"));
    };
    if fields.len() != expected.len()
        || fields
            .iter()
            .any(|(key, _)| !expected.contains(&key.as_str()))
    {
        return Err(refuse("release-manifest"));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refuse("release-manifest")),
    }
}
fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "supervisor",
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::anchor_is_behind_or_equal;
    use serde_json::json;

    fn floor(sequence: u64, spent: &[u64]) -> serde_json::Value {
        json!({"epoch": 1, "sequence": sequence, "head": format!("{sequence:064x}"),
               "spent": spent.iter().map(|n| format!("1:{n}:e")).collect::<Vec<_>>()})
    }

    #[test]
    fn a_floor_behind_or_beside_roots_anchor_is_refused() {
        let anchored = floor(20, &[10, 20]);
        assert!(anchor_is_behind_or_equal(&anchored, &floor(20, &[10, 20])), "the anchored floor itself");
        assert!(anchor_is_behind_or_equal(&anchored, &floor(30, &[10, 20, 30])), "a successor");
        assert!(!anchor_is_behind_or_equal(&anchored, &floor(10, &[10])), "a restored older snapshot");
        assert!(!anchor_is_behind_or_equal(&anchored, &floor(30, &[10, 29])), "divergent");
        let mut other_head = floor(20, &[10, 20]);
        other_head["head"] = json!("0");
        assert!(!anchor_is_behind_or_equal(&anchored, &other_head), "same version, other head");
        assert!(!anchor_is_behind_or_equal(&json!({}), &floor(20, &[10, 20])), "an unreadable anchor");
    }
}
