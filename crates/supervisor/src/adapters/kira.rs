// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scoped memory operations and capture of durable, ingress-labelled conversation entries.

use super::HostLedger;
use canon::{
    authority::{AuthorityTxn, CellCommitment, Kind},
    codes,
    digest::Digest32,
    fd3_payloads::{
        Accepted, MemoryList, MemoryListReply, MemoryPut, MemoryRecall, Outcome, Recall,
    },
    frame::FrameId,
    ids::{ProposalId, SessionId},
    provenance::{Provenance, Source},
    session::{SessionEntry, SessionRole},
    Result,
};
use kira::{
    embed::{EmbedInput, EmbedPurpose},
    notes::{MemoryOrigin, NoteContent, NoteForm, SaveCell, SaveReceipt, SaveRequest},
    permissions::{
        LedgerPermissions, MemoryPermissions, Permission, PermissionContext, PermissionRequest,
        PermissionScope,
    },
    recall::{CitedRecall, MAX_RECALL_ITEMS},
};
use std::sync::Arc;
use supervisor::{
    ingress::PrincipalScope,
    services::{KiraService, ServiceFuture},
};

pub struct KiraAdapter {
    ledger: Arc<HostLedger>,
    cell: MemoryCell,
    backend: Option<Arc<dyn KiraBackend>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedChunk {
    pub cell: CellCommitment,
    pub receipt: SaveReceipt,
}

/// Content-free binding of an ordered set of saves to one durable entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureCheckpoint {
    pub session_id: SessionId,
    pub entry_sequence: u64,
    pub entry_commitment: Digest32,
    pub chunks: Vec<CapturedChunk>,
}

/// Implementations use the supplied Aura transaction for encrypted note storage,
/// citations and capture checkpoints together. No method may commit independently.
/// Keys must come from AUMLOK for the current subject and root epoch.
pub trait KiraBackend: Send + Sync {
    fn save(
        &self,
        transaction: &mut aura::LedgerTxn<'_>,
        context: &PermissionContext,
        cell: &dyn SaveCell,
        request: SaveRequest,
    ) -> Result<SaveReceipt>;

    /// Read an authenticated checkpoint keyed by subject, session and entry sequence.
    /// Verify its binding to the retained chunk notes and refuse a different entry
    /// commitment at the same position. Absence must not hide a partial capture.
    fn captured(
        &self,
        transaction: &mut aura::LedgerTxn<'_>,
        context: &PermissionContext,
        entry: &SessionEntry,
    ) -> Result<Option<CaptureCheckpoint>>;

    /// Retain the exact entry/chunk commitments and citations, never transcript text.
    /// The checkpoint and every chunk must commit in this same transaction.
    fn record_capture(
        &self,
        transaction: &mut aura::LedgerTxn<'_>,
        context: &PermissionContext,
        checkpoint: &CaptureCheckpoint,
    ) -> Result<()>;

    fn recall(
        &self,
        transaction: &mut aura::LedgerTxn<'_>,
        context: &PermissionContext,
        request: MemoryRecall,
    ) -> Result<Recall>;

    fn list(
        &self,
        transaction: &mut aura::LedgerTxn<'_>,
        context: &PermissionContext,
        request: MemoryList,
    ) -> Result<MemoryListReply>;

    fn outcome(
        &self,
        transaction: &mut aura::LedgerTxn<'_>,
        context: &PermissionContext,
        proposal: ProposalId,
    ) -> Result<Option<Outcome>>;
}

impl KiraAdapter {
    pub fn new(ledger: Arc<HostLedger>) -> Result<Self> {
        Ok(Self {
            ledger,
            cell: MemoryCell(wasmcell::Runner::new()?),
            backend: None,
        })
    }

    pub fn with_backend(ledger: Arc<HostLedger>, backend: Arc<dyn KiraBackend>) -> Result<Self> {
        Ok(Self {
            ledger,
            cell: MemoryCell(wasmcell::Runner::new()?),
            backend: Some(backend),
        })
    }

    /// Capture an entry already flushed by the trusted session store. Its stored
    /// provenance is compared with the independently supplied ingress label.
    /// Returns citations only after HostLedger commits every chunk and checkpoint.
    pub fn capture_entry(
        &self,
        scope: PrincipalScope,
        ingress: &Provenance,
        entry: &SessionEntry,
    ) -> Result<Vec<SaveReceipt>> {
        let Some(category) = capture_category(ingress, entry)? else {
            return Ok(Vec::new());
        };
        self.ledger.scoped(scope, |transaction| {
            let backend = self.backend.as_ref().ok_or(codes::KIRA_STORE_UNAVAILABLE)?;
            let context = context(scope);
            LedgerPermissions.require(
                transaction,
                &context,
                &PermissionRequest {
                    permission: Permission::Store,
                    scope: PermissionScope::local_memory(),
                },
            )?;
            let now = transaction.observation_context()?.at;
            let now = u64::try_from(now).map_err(|_| codes::KIRA_INVALID_FIELD)?;
            let requests = capture_requests(&self.cell, ingress, entry, category, now)?;
            let cells: Vec<_> = requests
                .iter()
                .map(|request| request.put.cell.clone())
                .collect();
            if let Some(checkpoint) = backend.captured(transaction, &context, entry)? {
                let receipts = checkpoint_receipts(&context, entry, &cells, &checkpoint)?;
                verify_citations(transaction, &context, &receipts, None)?;
                return Ok(receipts);
            }
            let count = requests.len();
            let first_sequence = transaction.current_version()?.sequence;
            let mut receipts = Vec::with_capacity(requests.len());
            for request in requests {
                receipts.push(backend.save(transaction, &context, &self.cell, request)?);
            }
            validate_capture(&context, count, &receipts)?;
            verify_citations(transaction, &context, &receipts, Some(first_sequence))?;
            let checkpoint = CaptureCheckpoint {
                session_id: entry.session_id,
                entry_sequence: entry.sequence,
                entry_commitment: entry.commitment,
                chunks: cells
                    .into_iter()
                    .zip(receipts.iter().cloned())
                    .map(|(cell, receipt)| CapturedChunk { cell, receipt })
                    .collect(),
            };
            backend.record_capture(transaction, &context, &checkpoint)?;
            if backend.captured(transaction, &context, entry)?.as_ref() != Some(&checkpoint) {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
            Ok(receipts)
        })
    }
}

impl KiraService for KiraAdapter {
    fn put<'a>(
        &'a self,
        scope: PrincipalScope,
        _: &'a FrameId,
        request: MemoryPut,
    ) -> ServiceFuture<'a, Accepted> {
        Box::pin(async move {
            self.ledger.scoped(scope, |_| {
                let content = NoteContent::new(request.category, request.statement, request.quote)?;
                if self.cell.replay(&content)? != request.cell {
                    return Err(codes::WASMCELL_EVIDENCE_MISMATCH);
                }
                // C4 accepted requires an owner queue; automatic capture is separate.
                Err(codes::KIRA_STORE_UNAVAILABLE)
            })
        })
    }

    fn recall(&self, scope: PrincipalScope, request: MemoryRecall) -> ServiceFuture<'_, Recall> {
        Box::pin(async move {
            self.ledger.scoped(scope, |transaction| {
                if request.limit == 0 || usize::from(request.limit) > MAX_RECALL_ITEMS {
                    return Err(codes::KIRA_INVALID_FIELD);
                }
                EmbedInput::new(EmbedPurpose::Query, &request.query)
                    .map_err(|_| codes::KIRA_INVALID_FIELD)?;
                disclose(transaction, scope)?;
                if let Some(backend) = &self.backend {
                    return backend.recall(transaction, &context(scope), request);
                }
                require_no_retained_notes(transaction)?;
                Ok(CitedRecall::empty().c4_body())
            })
        })
    }

    fn list(
        &self,
        scope: PrincipalScope,
        request: MemoryList,
    ) -> ServiceFuture<'_, MemoryListReply> {
        Box::pin(async move {
            self.ledger.scoped(scope, |transaction| {
                disclose(transaction, scope)?;
                if let Some(backend) = &self.backend {
                    return backend.list(transaction, &context(scope), request);
                }
                require_no_retained_notes(transaction)?;
                if request.before.is_some() {
                    return Err(codes::KIRA_INVALID_FIELD);
                }
                Ok(MemoryListReply {
                    tier: request.tier,
                    items: Vec::new(),
                    next: None,
                })
            })
        })
    }

    fn outcome(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
    ) -> ServiceFuture<'_, Option<Outcome>> {
        Box::pin(async move {
            self.ledger.scoped(scope, |transaction| {
                disclose(transaction, scope)?;
                if let Some(backend) = &self.backend {
                    return backend.outcome(transaction, &context(scope), proposal);
                }
                require_no_retained_notes(transaction)?;
                Ok(None)
            })
        })
    }
}

fn context(scope: PrincipalScope) -> PermissionContext {
    PermissionContext {
        owner_subject: scope.subject,
        current_principal: scope.subject,
        owner_epoch: scope.epoch,
    }
}

fn disclose(transaction: &mut aura::LedgerTxn<'_>, scope: PrincipalScope) -> Result<()> {
    LedgerPermissions
        .require(
            transaction,
            &context(scope),
            &PermissionRequest {
                permission: Permission::Disclose,
                scope: PermissionScope::hosted_model_context(),
            },
        )
        .map(|_| ())
}

fn require_no_retained_notes(transaction: &aura::LedgerTxn<'_>) -> Result<()> {
    if !transaction.kira_retention_tables_empty()? {
        return Err(codes::KIRA_STORE_UNAVAILABLE);
    }
    let version = transaction.current_version()?;
    let mut previous = None;
    for sequence in 1..version.sequence {
        let record = transaction
            .floor_record_at_sequence(sequence)?
            .ok_or(codes::KIRA_LEDGER_UNVERIFIED)?;
        if record.authority.previous_hash != previous {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        previous = Some(record.hash);
        if matches!(record.kind, Kind::KiraSave | Kind::KiraDemote) {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
    }
    if previous != version.previous_hash {
        return Err(codes::KIRA_LEDGER_UNVERIFIED);
    }
    Ok(())
}

struct MemoryCell(wasmcell::Runner);
impl SaveCell for MemoryCell {
    fn replay(&self, content: &NoteContent) -> Result<canon::authority::CellCommitment> {
        let bytes = content.canonical_value()?;
        let input = wasmcell::CellInput::new(
            wasmcell::CellKey::new(format!(
                "memory:{}",
                canon::digest::Digest32::sha256(&bytes)
            ))?,
            canon::json::parse_strict(&bytes)?,
        )?;
        Ok(self.0.run(&input)?.commitments())
    }
}

fn capture_category(ingress: &Provenance, entry: &SessionEntry) -> Result<Option<&'static str>> {
    if ingress != &entry.provenance || matches!(ingress.source, Source::Stranger) {
        return Err(codes::FRAME_PROVENANCE);
    }
    if entry.v != canon::session::RECORD_VERSION
        || entry.algorithm != canon::alg::AlgorithmId::Sha256
        || entry.sequence == 0
        || entry.sequence > canon::json::MAX_SAFE_INTEGER as u64
        || supervisor::session::entry_commitment(entry)? != entry.commitment
    {
        return Err(codes::KIRA_INVALID_FIELD);
    }
    match (&ingress.source, entry.role) {
        (Source::Owner, SessionRole::Owner) => Ok(Some("owner_turn")),
        (Source::Auma, SessionRole::Auma) => Ok(Some("auma_reply")),
        (_, SessionRole::Owner | SessionRole::Auma) => Err(codes::FRAME_PROVENANCE),
        (_, SessionRole::Tool | SessionRole::Context) => Ok(None),
    }
}

fn capture_requests(
    cell: &dyn SaveCell,
    ingress: &Provenance,
    entry: &SessionEntry,
    category: &str,
    now_ms: u64,
) -> Result<Vec<SaveRequest>> {
    let chunks = capture_chunks(entry);
    let mut requests = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let marker = format!(
            "session {} entry {} part {}/{} commitment {}",
            entry.session_id,
            entry.sequence,
            index + 1,
            chunks.len(),
            entry.commitment
        );
        let (statement, quote) = if chunk.trim().is_empty() {
            (
                format!("{category}: {marker}; text in quote"),
                (*chunk).to_owned(),
            )
        } else {
            ((*chunk).to_owned(), marker)
        };
        let content = NoteContent::new(category.to_owned(), statement, Some(quote))?;
        requests.push(SaveRequest {
            put: MemoryPut {
                cell: cell.replay(&content)?,
                category: content.category().into(),
                statement: content.statement().into(),
                quote: content.quote().map(str::to_owned),
            },
            origin: MemoryOrigin::from_ingress(ingress.clone())?,
            form: NoteForm::Original,
            at_ms: now_ms,
            review_by: None,
        });
    }
    Ok(requests)
}

fn capture_chunks(entry: &SessionEntry) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut rest = entry.content.as_str();
    loop {
        let mut end = rest.len().min(kira::notes::MAX_STATEMENT_BYTES);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(&rest[..end]);
        rest = &rest[end..];
        if rest.is_empty() {
            break;
        }
    }
    chunks
}

fn checkpoint_receipts(
    context: &PermissionContext,
    entry: &SessionEntry,
    cells: &[CellCommitment],
    checkpoint: &CaptureCheckpoint,
) -> Result<Vec<SaveReceipt>> {
    if checkpoint.session_id != entry.session_id
        || checkpoint.entry_sequence != entry.sequence
        || checkpoint.entry_commitment != entry.commitment
        || checkpoint.chunks.len() != cells.len()
        || checkpoint
            .chunks
            .iter()
            .zip(cells)
            .any(|(chunk, cell)| &chunk.cell != cell)
    {
        return Err(codes::KIRA_LEDGER_UNVERIFIED);
    }
    let receipts: Vec<_> = checkpoint
        .chunks
        .iter()
        .map(|chunk| chunk.receipt.clone())
        .collect();
    validate_capture(context, cells.len(), &receipts)?;
    Ok(receipts)
}

fn validate_capture(
    context: &PermissionContext,
    count: usize,
    receipts: &[SaveReceipt],
) -> Result<()> {
    if count == 0 || receipts.len() != count {
        return Err(codes::KIRA_LEDGER_UNVERIFIED);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut previous = 0;
    for receipt in receipts {
        receipt.validate()?;
        if receipt.anchor.owner != context.owner_subject
            || receipt.cite_seq != receipt.anchor.head.sequence
            || receipt.cite_seq <= previous
            || !ids.insert(receipt.commitment.note_id.clone())
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        previous = receipt.cite_seq;
    }
    Ok(())
}

fn verify_citations(
    transaction: &aura::LedgerTxn<'_>,
    context: &PermissionContext,
    receipts: &[SaveReceipt],
    first_sequence: Option<u64>,
) -> Result<()> {
    for receipt in receipts {
        let record = transaction
            .floor_record_at_sequence(receipt.cite_seq)?
            .ok_or(codes::KIRA_LEDGER_UNVERIFIED)?;
        let body = aura::record::AuthorityBodyV1::parse(&record.body)?;
        if record.kind != Kind::KiraSave
            || record.phase != canon::authority::Phase::Fact
            || record.operation.is_some()
            || body.authority != record.authority
            || body.algorithm != record.algorithm
            || record.authority.epoch > context.owner_epoch
            || first_sequence.is_some_and(|first| {
                receipt.cite_seq < first || record.authority.epoch != context.owner_epoch
            })
            || receipt.anchor.head.hash != Some(record.hash)
            || receipt.anchor.aura_sequence != receipt.cite_seq
            || receipt.anchor.aura_hash != record.hash
            || body.payload.get("schema")
                != Some(&canon::json::Value::checked_text(
                    "aukora-kira-retained-save-v2".into(),
                )?)
            || body
                .payload
                .get("body")
                .and_then(|body| body.get("commitment"))
                != Some(&receipt.commitment.canonical_body()?)
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
    }
    Ok(())
}

/// A backend can use this bridge to the existing encrypted MemoryStore without
/// requesting a passkey. Its enclosing Aura transaction supplies durability.
pub fn save_with_store<T, M>(
    transaction: &mut T,
    store: &mut M,
    context: &PermissionContext,
    cell: &dyn SaveCell,
    request: SaveRequest,
) -> Result<SaveReceipt>
where
    T: AuthorityTxn + ?Sized,
    M: kira::notes::MemoryStore,
{
    struct BorrowedCell<'a>(&'a dyn SaveCell);
    impl SaveCell for BorrowedCell<'_> {
        fn replay(&self, content: &NoteContent) -> Result<canon::authority::CellCommitment> {
            self.0.replay(content)
        }
    }
    store.save(
        transaction,
        &mut LedgerPermissions,
        context,
        &BorrowedCell(cell),
        request,
    )
}

use canon::session::{
    SessionAppend, SessionAppended, SessionCreate, SessionFlush, SessionFlushed, SessionList,
    SessionOpen, SessionOpened, SessionPage, SessionSummary,
};
use supervisor::session::{DispatchFence, SessionStore, TailRecovery};

type CaptureCursors =
    std::collections::BTreeMap<(canon::ids::SubjectId, u64, SessionId), SessionFlushed>;

/// Transcript persistence precedes capture; capture failure prevents acknowledgement
/// and model dispatch. A retry reopens the exact retained entry before recapturing.
pub struct CapturingSessions {
    sessions: Arc<dyn SessionStore>,
    kira: Arc<KiraAdapter>,
    writer: tokio::sync::Mutex<CaptureCursors>,
}

impl CapturingSessions {
    pub fn new(sessions: Arc<dyn SessionStore>, kira: Arc<KiraAdapter>) -> Result<Self> {
        if kira.backend.is_none() {
            return Err(codes::KIRA_STORE_UNAVAILABLE);
        }
        Ok(Self {
            sessions,
            kira,
            writer: tokio::sync::Mutex::new(CaptureCursors::new()),
        })
    }

    /// Reconcile the durable prefix, including turns retained before a crash between
    /// transcript flush and memory commit. Backend checkpoints make retries idempotent.
    async fn capture_prefix(
        &self,
        scope: PrincipalScope,
        session_id: SessionId,
        through_sequence: u64,
        cursors: &mut CaptureCursors,
    ) -> Result<SessionFlushed> {
        let flushed = self
            .sessions
            .flush(
                scope,
                SessionFlush {
                    session_id,
                    through_sequence,
                },
            )
            .await?;
        if flushed.v != canon::session::RECORD_VERSION
            || flushed.algorithm != canon::alg::AlgorithmId::Sha256
            || flushed.session_id != session_id
            || flushed.sequence != through_sequence
        {
            return Err(codes::SESSION_SEQUENCE);
        }
        let mut after_sequence = 0;
        let key = (scope.subject, scope.epoch, session_id);
        if let Some(prior) = cursors
            .get(&key)
            .filter(|prior| prior.sequence <= through_sequence)
        {
            let retained = if prior.sequence == through_sequence {
                flushed.clone()
            } else {
                self.sessions
                    .flush(
                        scope,
                        SessionFlush {
                            session_id,
                            through_sequence: prior.sequence,
                        },
                    )
                    .await?
            };
            if &retained != prior {
                return Err(codes::SESSION_SEQUENCE);
            }
            after_sequence = prior.sequence;
        }
        while after_sequence < through_sequence {
            let page = self
                .sessions
                .open(
                    scope,
                    SessionOpen {
                        session_id,
                        after_sequence,
                        limit: canon::session::MAX_SESSION_PAGE as u16,
                    },
                )
                .await?;
            if page.summary.session_id != session_id || page.entries.as_slice().is_empty() {
                return Err(codes::SESSION_SEQUENCE);
            }
            for entry in page.entries.as_slice() {
                if entry.session_id != session_id || entry.sequence != after_sequence + 1 {
                    return Err(codes::SESSION_SEQUENCE);
                }
                if entry.sequence > through_sequence {
                    break;
                }
                self.kira.capture_entry(scope, &entry.provenance, entry)?;
                after_sequence = entry.sequence;
            }
        }
        // This cache only skips work after checking the same durable prefix again.
        // Restart or eviction replays the backend's durable capture checkpoints.
        if !cursors.contains_key(&key) && cursors.len() >= 256 {
            cursors.pop_first();
        }
        cursors.insert(key, flushed.clone());
        Ok(flushed)
    }
}

impl SessionStore for CapturingSessions {
    fn create(
        &self,
        scope: PrincipalScope,
        request: SessionCreate,
    ) -> ServiceFuture<'_, SessionSummary> {
        self.sessions.create(scope, request)
    }

    fn open(
        &self,
        scope: PrincipalScope,
        request: SessionOpen,
    ) -> ServiceFuture<'_, SessionOpened> {
        self.sessions.open(scope, request)
    }

    fn list(&self, scope: PrincipalScope, request: SessionList) -> ServiceFuture<'_, SessionPage> {
        self.sessions.list(scope, request)
    }

    fn append(
        &self,
        scope: PrincipalScope,
        origin: Provenance,
        request: SessionAppend,
    ) -> ServiceFuture<'_, SessionAppended> {
        Box::pin(async move {
            let mut cursors = self.writer.lock().await;
            capture_category(&origin, &request.entry)?;
            if request.entry.session_id != request.session_id
                || request.expected_sequence.checked_add(1) != Some(request.entry.sequence)
            {
                return Err(codes::SESSION_SEQUENCE);
            }
            let appended = match self.sessions.append(scope, origin, request.clone()).await {
                Ok(appended) => appended,
                Err(code) if code == codes::SESSION_SEQUENCE => {
                    let retained = self
                        .sessions
                        .open(
                            scope,
                            SessionOpen {
                                session_id: request.session_id,
                                after_sequence: request.expected_sequence,
                                limit: 1,
                            },
                        )
                        .await?;
                    if retained.entries.as_slice().first() != Some(&request.entry) {
                        return Err(code);
                    }
                    SessionAppended {
                        entry: request.entry.clone(),
                    }
                }
                Err(code) => return Err(code),
            };
            if appended.entry != request.entry {
                return Err(codes::SESSION_SEQUENCE);
            }
            self.capture_prefix(
                scope,
                appended.entry.session_id,
                appended.entry.sequence,
                &mut cursors,
            )
            .await?;
            Ok(appended)
        })
    }

    fn flush(
        &self,
        scope: PrincipalScope,
        request: SessionFlush,
    ) -> ServiceFuture<'_, SessionFlushed> {
        Box::pin(async move {
            let mut cursors = self.writer.lock().await;
            self.capture_prefix(
                scope,
                request.session_id,
                request.through_sequence,
                &mut cursors,
            )
            .await
        })
    }

    fn recover(
        &self,
        scope: PrincipalScope,
        session_id: SessionId,
    ) -> ServiceFuture<'_, TailRecovery> {
        Box::pin(async move {
            let mut cursors = self.writer.lock().await;
            let recovered = self.sessions.recover(scope, session_id).await?;
            self.capture_prefix(
                scope,
                session_id,
                recovered.last_complete_sequence,
                &mut cursors,
            )
            .await?;
            Ok(recovered)
        })
    }

    fn before_dispatch(
        &self,
        scope: PrincipalScope,
        session_id: SessionId,
        sequence: u64,
    ) -> ServiceFuture<'_, DispatchFence> {
        Box::pin(async move {
            let mut cursors = self.writer.lock().await;
            self.capture_prefix(scope, session_id, sequence, &mut cursors)
                .await?;
            self.sessions
                .before_dispatch(scope, session_id, sequence)
                .await
        })
    }
}
