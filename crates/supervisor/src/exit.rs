// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 61: versioned exports of sealed keys, encrypted memory and verified receipts.
//!
//! `build_export` produces the export `aukora-member-exit-v1`: the passkey-bound key file AUMLOK
//! offers for download, Kira's tables as the `aukora-kira-archive-v1` archive, and Aura's whole
//! signed history as a cold proof, tied together by a manifest of sizes and SHA-256 digests. The
//! file list, the checks a stranger can make with standard tools and the verifier that reads it
//! with no node and no key are documented in `verifier::restore`; the names and schemas here are
//! the same constants. `write_export` puts it in a private folder. `restore_export` takes an export
//! into an empty node with every note under its original id.
//!
//! What this module decides and what it does not:
//! - Leaving is authorized by a standing `Export` grant for the exact scope `member-exit`, which
//!   only the owner's passkey can create or revoke, checked again inside the transaction of each
//!   export. Nothing a guest, a message or a model says can start one.
//! - Restoring writes into the node, so it needs the owner's passkey over the exact manifest
//!   digest (`RestoreApproval`), and only an empty node accepts it.
//! - Spent approvals stay spent: the history carries every consumed and retired operation, and a
//!   restore refuses unless the target reports its floor covers them all.
//! - An export holds ciphertext, wrapped keys and public data only. It never holds the phrase,
//!   the identity root, a PRF output or a plaintext note.
//! - C3 has no row kind for an export, so none is appended; a new kind needs an issue.
//!
//! The ports below require supervisor adapters over the organs; each adapter must run inside
//! the caller's Aura transaction and commit nothing. A restore that returns an
//! error must be rolled back by its caller.

use aumlok::{backup::BackupEnvelopeV2, envelope::EnvelopeV1};
use canon::{
    authority::{
        AuthorityRecord, AuthorityTxn, BaseDigest, Kind, OwnerAssertion, OwnerOperation, Phase,
        VerifiedProof,
    },
    codes,
    digest::Digest32,
    ids::NodeId,
    ids::OperationId,
    ids::ProposalId,
    json::Value,
    json::MAX_SAFE_INTEGER,
    Refusal, Result,
};
use kira::{
    anchor::AnchorClaim,
    backup::MemoryArchive,
    permissions::{
        self, MemoryPermissions, Permission, PermissionAction, PermissionContext,
        PermissionRequest, PermissionScope,
    },
};
use std::{collections::BTreeSet, path::Path};

mod disk;
mod wire;

/// The `schema` of `manifest.json`.
pub const EXIT_SCHEMA: &str = "aukora-member-exit-v1";
/// The exact `Export` permission scope that authorizes an export; there is no wildcard.
pub const EXIT_SCOPE: &str = "member-exit";
/// The longest `receipts.json` the stranger verifier reads: its input cap, shared with
/// `aukora-verify --bundle`. Larger histories can still be exported and restored, but the
/// stranger verifier refuses them until its byte cap is raised.
pub const RECEIPTS_READER_LIMIT: usize = 8_388_608;
/// The `schema` of `keys/public.json`.
pub const PUBLIC_KEYS_SCHEMA: &str = "aukora-exit-public-keys-v1";
/// File names of an export.
pub const MANIFEST: &str = "manifest.json";
pub const BACKUP: &str = "keys/backup-v2.json";
pub const ENVELOPE: &str = "keys/envelope-v1.json";
pub const PUBLIC_KEYS: &str = "keys/public.json";
pub const MEMORY: &str = "memory.jsonl";
pub const RECEIPTS: &str = "receipts.json";

/// (file, manifest role) for every file the manifest lists, sorted by file name.
pub(crate) const MANIFEST_ROLES: [(&str, &str); 5] = [
    (BACKUP, "backup"),
    (ENVELOPE, "envelope"),
    (PUBLIC_KEYS, "public"),
    (MEMORY, "memory"),
    (RECEIPTS, "receipts"),
];

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "supervisor",
        reason,
    }
}

/// An export file violates its closed format.
pub const EXIT_FORMAT: Refusal = refusal("exit-format");
/// The parts of an export disagree with each other, with the manifest or with the owner.
pub const EXIT_INCONSISTENT: Refusal = refusal("exit-inconsistent");
/// The standing grant for the exit is missing, revoked, stale or for another scope.
pub const EXIT_NOT_PERMITTED: Refusal = refusal("exit-not-permitted");
/// A restore was attempted into a node that already holds history or notes.
pub const EXIT_NOT_EMPTY: Refusal = refusal("exit-not-empty");
/// The restored floor does not cover every spent approval in the history.
pub const EXIT_REVIVAL: Refusal = refusal("exit-revival");

/// Everything the organs hand over for one export, as bytes and typed archives, read inside one
/// Aura transaction so the memory and the history describe the same instant.
#[derive(Debug)]
pub struct ExitMaterial {
    /// Kira's tables at its verified head, with no receipts inside (they are their own file).
    pub archive: MemoryArchive,
    /// Aura's canonical `aukora-aura-cold-proof-v2` bytes with retained owner assertions.
    pub receipts: Vec<u8>,
    /// Phrase-only envelope bytes, emitted only by an explicit ExportKeyPolicy choice.
    pub envelope_v1: Vec<u8>,
    /// Passkey-bound backup bytes; export refuses when no v2 backup is available.
    pub backup_v2: Option<Vec<u8>>,
    /// The public key that signs the history.
    pub aura_signing_key: Digest32,
    /// This node's id.
    pub node: NodeId,
}

/// The organs' read side. An implementation reads only inside `txn`, returns no phrase, root,
/// PRF output or plaintext, and fails rather than returning a partial history.
pub trait ExitSource {
    fn gather<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
    ) -> Result<ExitMaterial>;
}

/// The files of one export, manifest first, each with its exact bytes.
pub struct ExportFiles {
    entries: Vec<(&'static str, Vec<u8>)>,
}

impl ExportFiles {
    /// `(name, bytes)` in write order, `manifest.json` first.
    pub fn files(&self) -> impl Iterator<Item = (&'static str, &[u8])> + '_ {
        self.entries
            .iter()
            .map(|(name, bytes)| (*name, bytes.as_slice()))
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.files()
            .find(|(n, _)| *n == name)
            .map(|(_, bytes)| bytes)
    }

    /// False when `receipts.json` is longer than `RECEIPTS_READER_LIMIT`, so the owner can be told
    /// that the export cannot yet be checked offline.
    pub fn receipts_verifiable_offline(&self) -> bool {
        self.get(RECEIPTS)
            .is_some_and(|bytes| bytes.len() <= RECEIPTS_READER_LIMIT)
    }

    /// The digest an owner approves to restore this export.
    pub fn manifest_sha256(&self) -> Result<Digest32> {
        Ok(Digest32::sha256(self.get(MANIFEST).ok_or(EXIT_FORMAT)?))
    }
}

fn consistent(archive: &MemoryArchive, facts: &wire::Facts, signing: &Digest32) -> Result<()> {
    if facts.tip != (archive.aura_sequence, archive.aura_hash)
        || facts.kira_head != archive.head
        || facts.saves != archive.counts.saved
        || facts.demotes != archive.counts.demoted
        || facts.signing_key != *signing
    {
        return Err(EXIT_INCONSISTENT);
    }
    Ok(())
}

fn manifest_bytes(
    context: &PermissionContext,
    material: &ExitMaterial,
    created_at_ms: u64,
    parts: &[(&'static str, Vec<u8>)],
) -> Result<Vec<u8>> {
    use wire::{head_value, integer, obj, string};
    let archive = &material.archive;
    let mut listed = Vec::with_capacity(parts.len());
    for (name, bytes) in parts {
        let role = MANIFEST_ROLES
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, role)| *role)
            .ok_or(EXIT_FORMAT)?;
        listed.push(obj(vec![
            ("name", string(*name)?),
            ("role", string(role)?),
            ("bytes", integer(bytes.len() as u64)?),
            ("sha256", string(Digest32::sha256(bytes).to_string())?),
        ])?);
    }
    Ok(obj(vec![
        ("schema", string(EXIT_SCHEMA)?),
        (
            "body",
            obj(vec![
                ("owner", string(context.owner_subject.to_string())?),
                ("epoch", integer(context.owner_epoch)?),
                ("node", string(material.node.to_string())?),
                ("created_at", integer(created_at_ms)?),
                (
                    "aura",
                    obj(vec![
                        ("sequence", integer(archive.aura_sequence)?),
                        ("hash", string(archive.aura_hash.to_string())?),
                    ])?,
                ),
                (
                    "memory",
                    obj(vec![
                        ("head", head_value(archive.head)?),
                        ("notes", integer(archive.counts.saved)?),
                        ("demoted", integer(archive.counts.demoted)?),
                        ("quarantined", integer(archive.counts.quarantined)?),
                    ])?,
                ),
                ("files", Value::checked_array(listed)?),
            ])?,
        ),
    ])?
    .canonical_bytes())
}

/// Explicitly choosing the phrase-only envelope adds it alongside the required v2 backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportKeyPolicy {
    PasskeyBound,
    IncludePhraseEnvelopeV1,
}

/// Build a v2-key export; no phrase-only envelope is included by default.
pub fn build_export<S, P, T>(
    source: &S,
    permissions: &P,
    txn: &mut T,
    context: &PermissionContext,
    created_at_ms: u64,
) -> Result<ExportFiles>
where
    S: ExitSource + ?Sized,
    P: MemoryPermissions + ?Sized,
    T: AuthorityTxn + ?Sized,
{
    build_export_with_key_policy(
        source,
        permissions,
        txn,
        context,
        created_at_ms,
        ExportKeyPolicy::PasskeyBound,
    )
}

/// Build the export for the owner in `context`.
///
/// The standing `Export` grant for `EXIT_SCOPE` is required and rechecked here, in this
/// transaction. The parts are then cross-checked before anything is emitted: the archive is the
/// owner's at this epoch, the key files are well-formed AUMLOK envelopes, and the history's tip,
/// Kira head, save and demotion counts and signing key match the archive. Any disagreement
/// refuses, so the supervisor never writes an export it could not stand behind.
pub fn build_export_with_key_policy<S, P, T>(
    source: &S,
    permissions: &P,
    txn: &mut T,
    context: &PermissionContext,
    created_at_ms: u64,
    key_policy: ExportKeyPolicy,
) -> Result<ExportFiles>
where
    S: ExitSource + ?Sized,
    P: MemoryPermissions + ?Sized,
    T: AuthorityTxn + ?Sized,
{
    context.validate()?;
    if created_at_ms > MAX_SAFE_INTEGER as u64 {
        return Err(codes::SUPERVISOR_STATE);
    }
    permissions::verify_context(txn, context)?;
    let request = PermissionRequest {
        permission: Permission::Export,
        scope: PermissionScope::new(EXIT_SCOPE.to_owned())?,
    };
    let grant = permissions.require(txn, context, &request)?;
    if grant.change.context != *context
        || grant.change.action != PermissionAction::Grant
        || grant.change.request != request
        || grant.record.authority.epoch != context.owner_epoch
        || grant.record.authority.sequence == 0
    {
        return Err(EXIT_NOT_PERMITTED);
    }
    let material = source.gather(txn, context)?;
    aura::export::ColdProofV2::parse(
        &material.receipts,
        aura::export::ExportLimits {
            max_bytes: material.receipts.len(),
            max_rows: material.receipts.len(),
        },
    )
    .map_err(|_| EXIT_FORMAT)?;
    let archive = &material.archive;
    archive.validate()?;
    if archive.owner != context.owner_subject
        || archive.key_epoch != context.owner_epoch
        || archive.receipts.is_some()
        || grant.record.authority.sequence > archive.aura_sequence
    {
        return Err(EXIT_INCONSISTENT);
    }
    let backup = material.backup_v2.as_ref().ok_or(EXIT_FORMAT)?;
    BackupEnvelopeV2::from_canonical_bytes(backup)?;
    if key_policy == ExportKeyPolicy::IncludePhraseEnvelopeV1 {
        EnvelopeV1::from_canonical_bytes(&material.envelope_v1)?;
    }
    let facts = wire::facts(&material.receipts)?;
    consistent(archive, &facts, &material.aura_signing_key)?;
    let public = wire::public_keys_bytes(
        &context.owner_subject,
        context.owner_epoch,
        &material.node,
        &facts.signing_key,
    )?;
    let mut parts: Vec<(&'static str, Vec<u8>)> = vec![
        (BACKUP, backup.clone()),
        (PUBLIC_KEYS, public),
        (MEMORY, archive.to_bytes()?.to_vec()),
        (RECEIPTS, material.receipts.clone()),
    ];
    if key_policy == ExportKeyPolicy::IncludePhraseEnvelopeV1 {
        parts.push((ENVELOPE, material.envelope_v1.clone()));
    }
    parts.sort_by_key(|(name, _)| *name);
    let manifest = manifest_bytes(context, &material, created_at_ms, &parts)?;
    let mut entries = Vec::with_capacity(parts.len() + 1);
    entries.push((MANIFEST, manifest));
    entries.extend(parts);
    Ok(ExportFiles { entries })
}

/// Write the export into the relative private folder `parent` (it must exist, be owned by the supervisor's
/// user and have mode 0700). Returns the new folder's name, 32 random hex digits. Nothing is
/// overwritten and nothing is followed through a symlink.
pub fn write_export(parent: &Path, files: &ExportFiles) -> Result<String> {
    disk::write(parent, files)
}

/// Remove the half-written folders (`<32 hex digits>.pending`) a crash left in `parent`, and
/// nothing else. Run it before the next export; returns how many it removed.
pub fn discard_unfinished(parent: &Path) -> Result<u32> {
    disk::discard_unfinished(parent)
}

// ---- restore -----------------------------------------------------------------------------------

/// Verify the owner's passkey over the gate's exact manifest digest inside `txn`.
/// The returned capability is consumed and retained through finalization by restore_export.
pub trait RestoreApproval {
    fn approved<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        manifest_sha256: &Digest32,
    ) -> Result<VerifiedProof>;
}

/// Exact gate target used by the passkey restore adapter.
pub const RESTORE_TARGET: &str = "member-exit.restore";

/// Retained browser assertion; verification and consumption happen only inside restore's lock.
pub struct PasskeyRestoreApproval {
    node: NodeId,
    proposal: ProposalId,
    assertion: OwnerAssertion,
}

impl PasskeyRestoreApproval {
    pub fn new(node: NodeId, proposal: ProposalId, assertion: OwnerAssertion) -> Self {
        Self {
            node,
            proposal,
            assertion,
        }
    }
}

impl RestoreApproval for PasskeyRestoreApproval {
    fn approved<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        manifest_sha256: &Digest32,
    ) -> Result<VerifiedProof> {
        permissions::verify_context(txn, context)?;
        let proof = VerifiedProof::verify(
            txn,
            &self.proposal,
            OwnerOperation::Apply,
            self.assertion.clone(),
        )?;
        let authorization = proof.authorization();
        if authorization.node != self.node
            || authorization.subject != context.owner_subject
            || authorization.epoch != context.owner_epoch
            || authorization.target != RESTORE_TARGET
            || authorization.base_sha256 != BaseDigest::Absent
            || authorization.new_sha256 != *manifest_sha256
            || authorization.cell.is_some()
        {
            return Err(EXIT_NOT_PERMITTED);
        }
        Ok(proof)
    }
}

/// The organs' write side of a restore. Each call runs in `txn` and commits nothing.
pub trait RestoreTarget {
    /// True only when the destination history, memory tables and key slots are empty.
    /// The enrolled control transaction is separate and must retain its approval records.
    fn is_empty<T: AuthorityTxn + ?Sized>(&self, txn: &mut T) -> Result<bool>;

    /// Preserve the original node id; this stages no unrelated configuration or release change.
    fn import_node_id<T: AuthorityTxn + ?Sized>(&self, txn: &mut T, node: &NodeId) -> Result<()>;

    /// AUMLOK keeps the sealed key files. They are ciphertext; nothing is opened here.
    fn import_keys<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        envelope: Option<&EnvelopeV1>,
        backup: &BackupEnvelopeV2,
    ) -> Result<()>;

    /// Aura verifies every row and signature under `signing_key` and the contiguity of the whole
    /// chain, then keeps it as this node's history. Returns the sequence and hash of the last row.
    fn import_history<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        cold_proof: &[u8],
        signing_key: &Digest32,
    ) -> Result<(u64, Digest32)>;

    /// True only when the floor and the consumed-approval high-water marks mark every one of
    /// these operations spent or retired. A restore never lowers them.
    fn floor_covers<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        spent: &BTreeSet<OperationId>,
        retired: &BTreeSet<OperationId>,
    ) -> Result<bool>;

    /// Append the consumed proof as a GateConsume settlement and exactly one GateApply terminal.
    /// Retain the full owner assertion in the control ledger; never replace it with imported rows.
    /// Return the verified terminal record. Nothing commits independently of the containing transaction.
    fn finish_restore<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        proof: VerifiedProof,
    ) -> Result<AuthorityRecord>;

    /// Kira restores the archive against the history imported above.
    fn import_memory<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        archive: &MemoryArchive,
    ) -> Result<AnchorClaim>;
}

/// Restore an export into an empty node, every note under its original id.
///
/// Before any effect: every listed file must be exactly the one the manifest names, the archive
/// and history must agree with each other and with the manifest, the owner must be the one the
/// export names, and the target must be empty. Then, in order, the owner's approval of the
/// manifest digest is taken and the keys, history and memory are imported. The history's tip,
/// the floor and the resulting Kira head are checked against the export before success is
/// reported. A forgotten note stays forgotten because Kira refuses an archive whose demotions
/// differ from the imported history.
///
/// The signing key comes from the export itself, so it proves nothing about who made the history.
/// The trust anchor is the owner: the approval covers the exact manifest digest, which the owner
/// should have checked offline with `verifier::restore` against a key and head kept apart from the
/// export. Aura's cold-proof reader checks the complete receipt chain before any import.
pub fn restore_export<R, A, T>(
    target: &R,
    approval: &A,
    txn: &mut T,
    context: &PermissionContext,
    files: &[(&str, &[u8])],
) -> Result<AnchorClaim>
where
    R: RestoreTarget + ?Sized,
    A: RestoreApproval + ?Sized,
    T: AuthorityTxn + ?Sized,
{
    context.validate()?;
    let mut names = BTreeSet::new();
    if files.iter().any(|(name, _)| !names.insert(*name)) {
        return Err(EXIT_FORMAT);
    }
    let find = |name: &str| files.iter().find(|(n, _)| *n == name).map(|(_, b)| *b);
    let manifest_file = find(MANIFEST).ok_or(EXIT_FORMAT)?;
    let manifest = wire::read_manifest(manifest_file)?;
    if files.len() != manifest.files.len() + 1
        || files.iter().any(|(name, _)| {
            *name != MANIFEST && !manifest.files.iter().any(|(listed, _, _)| listed == name)
        })
    {
        return Err(EXIT_FORMAT);
    }
    for (name, size, sha256) in &manifest.files {
        let bytes = find(name).ok_or(EXIT_FORMAT)?;
        if bytes.len() as u64 != *size || Digest32::sha256(bytes) != *sha256 {
            return Err(EXIT_INCONSISTENT);
        }
    }
    let listed = |name: &str| manifest.files.iter().any(|(n, _, _)| n == name);
    if ![BACKUP, PUBLIC_KEYS, MEMORY, RECEIPTS]
        .into_iter()
        .all(listed)
    {
        return Err(EXIT_FORMAT);
    }
    let required = |name: &str| find(name).ok_or(EXIT_FORMAT);
    let receipts = required(RECEIPTS)?;
    let archive = MemoryArchive::parse(required(MEMORY)?)?;
    if archive.receipts.is_some() {
        return Err(EXIT_FORMAT);
    }
    let facts = wire::facts(receipts)?;
    let (subject, epoch, node, signing) = wire::read_public_keys(required(PUBLIC_KEYS)?)?;
    if manifest.owner != context.owner_subject
        || subject != manifest.owner
        || epoch != manifest.epoch
        || node != manifest.node
        || archive.key_epoch != manifest.epoch
        || archive.owner != manifest.owner
        || manifest.head != archive.head
        || manifest.counts != archive.counts
        || manifest.aura != facts.tip
    {
        return Err(EXIT_INCONSISTENT);
    }
    consistent(&archive, &facts, &signing)?;
    let envelope = find(ENVELOPE)
        .map(EnvelopeV1::from_canonical_bytes)
        .transpose()?;
    let backup = BackupEnvelopeV2::from_canonical_bytes(required(BACKUP)?)?;
    if !target.is_empty(txn)? {
        return Err(EXIT_NOT_EMPTY);
    }
    let manifest_sha256 = Digest32::sha256(manifest_file);
    let proof = approval.approved(txn, context, &manifest_sha256)?;
    let authorization = proof.authorization();
    if proof.transaction_id() != txn.transaction_id()
        || authorization.subject != context.owner_subject
        || authorization.epoch != context.owner_epoch
        || authorization.op != OwnerOperation::Apply
        || authorization.target != RESTORE_TARGET
        || authorization.base_sha256 != BaseDigest::Absent
        || authorization.new_sha256 != manifest_sha256
        || authorization.cell.is_some()
    {
        return Err(EXIT_NOT_PERMITTED);
    }
    let append = txn.authority_append_context(&proof)?;
    txn.persist_counter(&proof)?;
    txn.consume(&proof)?;
    target.import_node_id(txn, &manifest.node)?;
    target.import_keys(txn, envelope.as_ref(), &backup)?;
    if target.import_history(txn, receipts, &signing)? != facts.tip {
        return Err(EXIT_INCONSISTENT);
    }
    if !target.floor_covers(txn, &facts.spent, &facts.retired)? {
        return Err(EXIT_REVIVAL);
    }
    let anchor = target.import_memory(txn, context, &archive)?;
    anchor.validate()?;
    if anchor.owner != archive.owner
        || anchor.head != archive.head
        || anchor.counts != archive.counts
        || anchor.aura_sequence < archive.aura_sequence
        || (anchor.aura_sequence == archive.aura_sequence && anchor.aura_hash != archive.aura_hash)
    {
        return Err(EXIT_INCONSISTENT);
    }
    let terminal = target.finish_restore(txn, proof)?;
    if terminal.kind != Kind::GateApply
        || terminal.phase != Phase::Terminal
        || terminal.operation != Some(append.operation_id)
        || terminal.authority.epoch != context.owner_epoch
        || terminal.authority.sequence <= append.authority.sequence
    {
        return Err(EXIT_INCONSISTENT);
    }
    Ok(anchor)
}
