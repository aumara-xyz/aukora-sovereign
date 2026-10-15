// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cited data for Auma; v1 serialization continues to use canon's C4 payloads.

use canon::{
    authority::AuthorityTxn,
    digest::Digest32,
    fd3_payloads::{MemoryList, MemoryListReply, MemoryRecall, Recall, RecallItem, RecallResult},
    frame::FrameId,
    ids::NoteId,
    provenance::{Provenance, Source},
    Result,
};

use crate::{
    anchor::{AuraAnchors, MemoryHead},
    embed::LocalEmbedder,
    notes::MemoryOrigin,
    openviking::{OpenViking, SemanticError},
    permissions::{MemoryPermissions, PermissionContext},
};

pub const MAX_RECALL_ITEMS: usize = 100;

/// These fields describe the read, never authorize a later disclosure.
/// An undetermined reply with permission_sequence zero has no verified disclosure;
/// its EMPTY head is an unavailable sentinel, not a claim of empty memory history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallReceipt {
    pub request_id: FrameId,
    pub head: MemoryHead,
    pub permission_sequence: u64,
    pub permission_epoch: u64,
    pub cited_save_sequences: Vec<u64>,
    pub reply_sha256: Digest32,
}

/// Original source attribution accompanies every recalled note outside frozen C4 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CitedMemory {
    item: RecallItem,
    origin: MemoryOrigin,
}

impl CitedMemory {
    /// Shape checking only. The reader must verify the retained save, AEAD and
    /// current permission before returning this data to a caller.
    pub fn new(note_id: NoteId, text: String, cite_seq: u64, origin: MemoryOrigin) -> Result<Self> {
        if text.trim().is_empty()
            || text.len() > crate::notes::MAX_NOTE_BYTES
            || cite_seq == 0
            || cite_seq > canon::json::MAX_SAFE_INTEGER as u64
        {
            return Err(canon::codes::KIRA_INVALID_FIELD);
        }
        Ok(Self {
            item: RecallItem {
                note_id: note_id.as_str().to_owned(),
                text,
                cite_seq,
            },
            origin,
        })
    }

    pub fn item(&self) -> &RecallItem {
        &self.item
    }
    pub fn origin(&self) -> &MemoryOrigin {
        &self.origin
    }
    pub fn delivery_source(&self) -> Provenance {
        Provenance {
            source: Source::Memory,
        }
    }
    pub const fn grants_authority(&self) -> bool {
        false
    }
}

/// Undetermined does not become empty when an index, key, ledger or permission is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecallGap {
    Ledger,
    Locked,
    Permission,
    StaleIndex,
    IncompleteIndex,
    SemanticMiss,
    Unavailable,
    Integrity,
}

impl From<SemanticError> for RecallGap {
    fn from(error: SemanticError) -> Self {
        match error {
            SemanticError::IndexStale => Self::StaleIndex,
            SemanticError::IndexIncomplete => Self::IncompleteIndex,
            SemanticError::Response | SemanticError::Model => Self::Integrity,
            _ => Self::Unavailable,
        }
    }
}

/// Internal context accompanies C4's unchanged `{result,items}` object.
/// Constructors enforce that only found contains plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CitedRecall {
    result: RecallResult,
    items: Vec<CitedMemory>,
    gap: Option<RecallGap>,
}

impl CitedRecall {
    pub fn found(items: Vec<CitedMemory>) -> Result<Self> {
        if items.is_empty() || items.len() > MAX_RECALL_ITEMS {
            return Err(canon::codes::KIRA_INVALID_FIELD);
        }
        let ids: std::collections::BTreeSet<_> =
            items.iter().map(|item| &item.item.note_id).collect();
        if ids.len() != items.len() {
            return Err(canon::codes::KIRA_INVALID_FIELD);
        }
        Ok(Self {
            result: RecallResult::Found,
            items,
            gap: None,
        })
    }

    /// Use only after a complete verified search of the current permitted snapshot.
    pub fn empty() -> Self {
        Self {
            result: RecallResult::Empty,
            items: Vec::new(),
            gap: None,
        }
    }
    pub fn undetermined(gap: RecallGap) -> Self {
        Self {
            result: RecallResult::Undetermined,
            items: Vec::new(),
            gap: Some(gap),
        }
    }
    pub const fn gap(&self) -> Option<RecallGap> {
        self.gap
    }
    pub fn items(&self) -> &[CitedMemory] {
        &self.items
    }
    pub fn delivery_source(&self) -> Provenance {
        Provenance {
            source: Source::Memory,
        }
    }

    /// The codec still enforces the 65,536-byte envelope bound and correlation id.
    pub fn c4_body(&self) -> Recall {
        Recall {
            result: self.result,
            items: self.items.iter().map(|item| item.item.clone()).collect(),
        }
    }
}

/// Worker 12's read interface. Recall and remembered listing recheck the current
/// principal and disclose-to-context permission inside the same locked snapshot.
/// A verified Aura anchor precedes decryption. Every OpenViking hit is only a
/// candidate: re-read its retained ciphertext, authenticate it, compare its save
/// commitment and exclude demoted/quarantined notes. Index/model/head mismatch,
/// authentication failure or incomplete coverage yields undetermined without text.
/// A semantic miss alone never proves empty. No read raises a note's confidence.
pub trait MemoryRecallService {
    fn recall<T: AuthorityTxn + ?Sized, P: MemoryPermissions, A: AuraAnchors>(
        &mut self,
        transaction: &mut T,
        permissions: &mut P,
        anchors: &A,
        context: &PermissionContext,
        request_id: &FrameId,
        request: &MemoryRecall,
        index: &mut dyn OpenViking,
        embedder: &mut dyn LocalEmbedder,
    ) -> Result<(CitedRecall, RecallReceipt)>;

    /// Newest save sequence first, exclusive same-tier cursor, at most 100 items
    /// and one C4 frame. Forgotten is retained metadata only: text is null, no
    /// cold plaintext or reason is decrypted, and demoted_seq exceeds cite_seq.
    /// Remembered text has memory provenance and requires disclosure permission.
    fn list<T: AuthorityTxn + ?Sized, P: MemoryPermissions, A: AuraAnchors>(
        &mut self,
        transaction: &mut T,
        permissions: &mut P,
        anchors: &A,
        context: &PermissionContext,
        request: &MemoryList,
    ) -> Result<MemoryListReply>;
}

use crate::{
    anchor::{MemoryLedger, RetainedNote, SqliteMemory},
    embed::{EmbedInput, EmbedPurpose},
    notes::{sha256, SaveCommitment},
    openviking::recall_candidates,
    permissions::{
        Permission, PermissionAction, PermissionReceipt, PermissionRequest, PermissionScope,
    },
};
use canon::{
    codes,
    fd3_payloads::{MemoryListItem, MemoryTier},
    json::{SafeInteger, Value, MAX_SAFE_INTEGER},
};
use std::collections::BTreeSet;

impl<L: MemoryLedger> MemoryRecallService for SqliteMemory<'_, L> {
    fn recall<T: AuthorityTxn + ?Sized, P: MemoryPermissions, A: AuraAnchors>(
        &mut self,
        transaction: &mut T,
        permissions: &mut P,
        anchors: &A,
        context: &PermissionContext,
        request_id: &FrameId,
        request: &MemoryRecall,
        index: &mut dyn OpenViking,
        embedder: &mut dyn LocalEmbedder,
    ) -> Result<(CitedRecall, RecallReceipt)> {
        context.validate()?;
        if request.limit == 0 || usize::from(request.limit) > MAX_RECALL_ITEMS {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        EmbedInput::new(EmbedPurpose::Query, &request.query)
            .map_err(|_| codes::KIRA_INVALID_FIELD)?;
        let unavailable = |gap| {
            finish_recall(
                request_id,
                MemoryHead::EMPTY,
                None,
                CitedRecall::undetermined(gap),
            )
        };
        if crate::permissions::verify_context(transaction, context).is_err() {
            return unavailable(RecallGap::Permission);
        }
        let snapshot = match self.snapshot(transaction, context) {
            Ok(snapshot) => snapshot,
            Err(error) => return unavailable(read_gap(error)),
        };
        if anchors.verify(transaction, &snapshot.anchor).is_err() {
            return unavailable(RecallGap::Ledger);
        }
        let grant = match disclosure(permissions, transaction, context) {
            Ok(grant) => grant,
            Err(_) => return unavailable(RecallGap::Permission),
        };
        if grant.record.authority.sequence > snapshot.anchor.aura_sequence {
            return unavailable(RecallGap::Permission);
        }
        let finish = |result| finish_recall(request_id, snapshot.anchor.head, Some(&grant), result);
        let active: BTreeSet<_> = snapshot
            .notes
            .iter()
            .filter(|(_, note)| note.demotion.is_none() && !note.quarantined)
            .map(|(id, _)| id.clone())
            .collect();
        if active.is_empty() {
            return finish(CitedRecall::empty());
        }
        let candidates = match recall_candidates(
            index,
            embedder,
            snapshot.anchor.head,
            &request.query,
            usize::from(request.limit).min(crate::openviking::MAX_CANDIDATES),
        ) {
            Ok(reply) => reply,
            Err(error) => return finish(CitedRecall::undetermined(error.into())),
        };
        if candidates.state.eligible_notes != active.len() as u64
            || candidates.state.indexed_notes != active.len() as u64
        {
            return finish(CitedRecall::undetermined(RecallGap::IncompleteIndex));
        }
        if candidates.candidates().is_empty() {
            return finish(CitedRecall::undetermined(RecallGap::SemanticMiss));
        }
        let mut seen = BTreeSet::new();
        let mut items = Vec::new();
        for candidate in candidates.candidates() {
            let id = candidate.note_id();
            if !seen.insert(id) || !active.contains(id) {
                return finish(CitedRecall::undetermined(RecallGap::Integrity));
            }
            let Some(note) = snapshot.notes.get(id) else {
                return finish(CitedRecall::undetermined(RecallGap::Integrity));
            };
            if verify_note(id, note, context).is_err() {
                return finish(CitedRecall::undetermined(RecallGap::Integrity));
            }
            let payload = match self.decrypt(note) {
                Ok(payload) => payload,
                Err(error) => return finish(CitedRecall::undetermined(read_gap(error))),
            };
            if payload.content.category() != note.category
                || payload.at_ms != note.at_ms
                || payload.root_epoch != note.encrypted.root_epoch
            {
                return finish(CitedRecall::undetermined(RecallGap::Integrity));
            }
            items.push(CitedMemory::new(
                id.clone(),
                payload.content.statement().to_owned(),
                note.receipt.cite_seq,
                payload.origin,
            )?);
        }
        // Every ranked hit is authenticated before frame-size truncation.
        loop {
            let result = CitedRecall::found(items.clone())?;
            if recall_frame(request_id, &result)?.len() <= canon::frame::MAX_FRAME_BYTES {
                return finish(result);
            }
            items.pop();
            if items.is_empty() {
                return finish(CitedRecall::undetermined(RecallGap::Integrity));
            }
        }
    }

    fn list<T: AuthorityTxn + ?Sized, P: MemoryPermissions, A: AuraAnchors>(
        &mut self,
        transaction: &mut T,
        permissions: &mut P,
        anchors: &A,
        context: &PermissionContext,
        request: &MemoryList,
    ) -> Result<MemoryListReply> {
        crate::permissions::verify_context(transaction, context)?;
        let snapshot = self.snapshot(transaction, context)?;
        anchors.verify(transaction, &snapshot.anchor)?;
        if request.tier == MemoryTier::Remembered {
            let grant = disclosure(permissions, transaction, context)?;
            if grant.record.authority.sequence > snapshot.anchor.aura_sequence {
                return Err(codes::KIRA_LEDGER_UNVERIFIED);
            }
        }
        let mut notes: Vec<_> = snapshot
            .notes
            .iter()
            .filter(|(_, note)| match request.tier {
                MemoryTier::Remembered => note.demotion.is_none() && !note.quarantined,
                MemoryTier::Forgotten => note.demotion.is_some(),
            })
            .collect();
        notes.sort_by(|(left_id, left), (right_id, right)| {
            right
                .receipt
                .cite_seq
                .cmp(&left.receipt.cite_seq)
                .then_with(|| left_id.cmp(right_id))
        });
        let start = match &request.before {
            Some(before) => {
                notes
                    .iter()
                    .position(|(id, _)| *id == before)
                    .ok_or(codes::KIRA_INVALID_FIELD)?
                    + 1
            }
            None => 0,
        };
        let remaining = &notes[start..];
        let mut reply = MemoryListReply {
            tier: request.tier,
            items: Vec::new(),
            next: None,
        };
        for (id, note) in remaining.iter().take(MAX_RECALL_ITEMS) {
            verify_note(id, note, context)?;
            let (text, demoted_seq, demoted_at) = match request.tier {
                MemoryTier::Remembered => {
                    let payload = self.decrypt(note)?;
                    if payload.content.category() != note.category
                        || payload.at_ms != note.at_ms
                        || payload.root_epoch != note.encrypted.root_epoch
                    {
                        return Err(codes::KIRA_STORE_CORRUPT);
                    }
                    (Some(payload.content.statement().to_owned()), None, None)
                }
                MemoryTier::Forgotten => {
                    let demotion = note.demotion.as_ref().ok_or(codes::KIRA_STORE_CORRUPT)?;
                    if demotion.note_id != **id
                        || demotion.save_sequence != note.receipt.cite_seq
                        || demotion.demoted_sequence <= note.receipt.cite_seq
                        || demotion.demoted_sequence > MAX_SAFE_INTEGER as u64
                        || demotion.demoted_at_ms > MAX_SAFE_INTEGER as u64
                    {
                        return Err(codes::KIRA_STORE_CORRUPT);
                    }
                    (
                        None,
                        Some(demotion.demoted_sequence),
                        Some(demotion.demoted_at_ms),
                    )
                }
            };
            reply.items.push(MemoryListItem {
                note_id: (*id).clone(),
                category: note.category.clone(),
                at: note.at_ms,
                cite_seq: note.receipt.cite_seq,
                text,
                demoted_seq,
                demoted_at,
            });
            reply.next = (reply.items.len() < remaining.len()).then(|| (*id).clone());
            if list_frame(&reply)?.len() > canon::frame::MAX_FRAME_BYTES {
                reply.items.pop();
                reply.next = Some(
                    reply
                        .items
                        .last()
                        .ok_or(codes::KIRA_INVALID_FIELD)?
                        .note_id
                        .clone(),
                );
                break;
            }
        }
        Ok(reply)
    }
}

fn disclosure<T: AuthorityTxn + ?Sized, P: MemoryPermissions>(
    permissions: &P,
    transaction: &mut T,
    context: &PermissionContext,
) -> Result<PermissionReceipt> {
    let request = PermissionRequest {
        permission: Permission::Disclose,
        scope: PermissionScope::hosted_model_context(),
    };
    let receipt = permissions.require(transaction, context, &request)?;
    if receipt.change.context != *context
        || receipt.change.request != request
        || receipt.change.action != PermissionAction::Grant
        || receipt.record.authority.sequence == 0
        || receipt.record.authority.sequence > MAX_SAFE_INTEGER as u64
        || receipt.record.authority.epoch != context.owner_epoch
    {
        return Err(codes::KIRA_DISCLOSURE_NOT_PERMITTED);
    }
    Ok(receipt)
}

fn verify_note(id: &NoteId, note: &RetainedNote, context: &PermissionContext) -> Result<()> {
    if note.encrypted.note_id != *id
        || note.encrypted.owner != context.owner_subject
        || note.receipt.commitment != SaveCommitment::from_encrypted(&note.encrypted)?
        || note.receipt.cite_seq == 0
        || note.receipt.cite_seq > MAX_SAFE_INTEGER as u64
        || note.at_ms > MAX_SAFE_INTEGER as u64
        || note.category.is_empty()
        || note.category.len() > crate::notes::MAX_CATEGORY_BYTES
        || !note
            .category
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    Ok(())
}

fn read_gap(error: canon::Refusal) -> RecallGap {
    if error == codes::KIRA_LEDGER_UNVERIFIED {
        RecallGap::Ledger
    } else if error == codes::KIRA_STORE_UNAVAILABLE {
        RecallGap::Unavailable
    } else if error == codes::KIRA_AUTHENTICATION_FAILED {
        RecallGap::Locked
    } else {
        RecallGap::Integrity
    }
}

fn finish_recall(
    id: &FrameId,
    head: MemoryHead,
    permission: Option<&PermissionReceipt>,
    recall: CitedRecall,
) -> Result<(CitedRecall, RecallReceipt)> {
    let bytes = recall_frame(id, &recall)?;
    if bytes.len() > canon::frame::MAX_FRAME_BYTES {
        return Err(codes::KIRA_INVALID_FIELD);
    }
    let receipt = RecallReceipt {
        request_id: id.clone(),
        head,
        permission_sequence: permission.map_or(0, |p| p.record.authority.sequence),
        permission_epoch: permission.map_or(0, |p| p.change.context.owner_epoch),
        cited_save_sequences: recall.items.iter().map(|item| item.item.cite_seq).collect(),
        reply_sha256: sha256(&bytes),
    };
    Ok((recall, receipt))
}

fn number(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        i64::try_from(value).map_err(|_| codes::KIRA_INVALID_FIELD)?,
    )?))
}

fn text(value: &str) -> Result<Value> {
    Value::checked_text(value.to_owned())
}

fn envelope(id: &str, kind: &str, body: Value) -> Result<Vec<u8>> {
    Ok(Value::checked_object(vec![
        ("v".into(), number(1)?),
        ("id".into(), text(id)?),
        ("kind".into(), text(kind)?),
        ("body".into(), body),
    ])?
    .canonical_bytes())
}

/// Exact frozen C4 envelope bytes, without the transport length prefix.
pub(crate) fn recall_frame(id: &FrameId, recall: &CitedRecall) -> Result<Vec<u8>> {
    let items = recall
        .items
        .iter()
        .map(|item| {
            Value::checked_object(vec![
                ("note_id".into(), text(&item.item.note_id)?),
                ("text".into(), text(&item.item.text)?),
                ("cite_seq".into(), number(item.item.cite_seq)?),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    let result = match recall.result {
        RecallResult::Found => "found",
        RecallResult::Empty => "empty",
        RecallResult::Undetermined => "undetermined",
    };
    envelope(
        id.as_str(),
        "recall",
        Value::checked_object(vec![
            ("result".into(), text(result)?),
            ("items".into(), Value::checked_array(items)?),
        ])?,
    )
}

/// The list signature has no request id; reserve its maximum frozen C4 length.
pub(crate) fn list_frame(reply: &MemoryListReply) -> Result<Vec<u8>> {
    let items = reply
        .items
        .iter()
        .map(|item| {
            Value::checked_object(vec![
                ("note_id".into(), text(item.note_id.as_str())?),
                ("category".into(), text(&item.category)?),
                ("at".into(), number(item.at)?),
                ("cite_seq".into(), number(item.cite_seq)?),
                (
                    "text".into(),
                    item.text
                        .as_deref()
                        .map(text)
                        .transpose()?
                        .unwrap_or_else(Value::null),
                ),
                (
                    "demoted_seq".into(),
                    item.demoted_seq
                        .map(number)
                        .transpose()?
                        .unwrap_or_else(Value::null),
                ),
                (
                    "demoted_at".into(),
                    item.demoted_at
                        .map(number)
                        .transpose()?
                        .unwrap_or_else(Value::null),
                ),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    let tier = match reply.tier {
        MemoryTier::Remembered => "remembered",
        MemoryTier::Forgotten => "forgotten",
    };
    envelope(
        &"r".repeat(64),
        "memory.list.reply",
        Value::checked_object(vec![
            ("tier".into(), text(tier)?),
            ("items".into(), Value::checked_array(items)?),
            (
                "next".into(),
                reply
                    .next
                    .as_ref()
                    .map(|id| text(id.as_str()))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
        ])?,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecallProbe {
    Checked,
    NotChecked,
    Unreachable,
    Violation,
    Disagreement,
}

pub(crate) struct RecallObservation {
    pub permissions: RecallProbe,
    pub citations: RecallProbe,
    pub provenance: RecallProbe,
    pub receipt: RecallProbe,
}

impl RecallObservation {
    fn unavailable(probe: RecallProbe) -> Self {
        Self {
            permissions: probe,
            citations: probe,
            provenance: probe,
            receipt: probe,
        }
    }
}

/// Measure the actual recall path using the caller's index and embedder. The
/// expected grant comes from an independent read in the same Aura transaction.
pub(crate) fn inspect_recall<T, L>(
    store: &mut SqliteMemory<'_, L>,
    transaction: &mut T,
    principal: &PermissionContext,
    snapshot: &crate::anchor::MemorySnapshot,
    expected_grant: Option<&PermissionReceipt>,
    disclosure_expected: Option<bool>,
    request_id: &FrameId,
    request: &MemoryRecall,
    index: &mut dyn OpenViking,
    embedder: &mut dyn LocalEmbedder,
) -> RecallObservation
where
    T: AuthorityTxn + ?Sized,
    L: MemoryLedger,
{
    use RecallProbe::{Checked, Disagreement, NotChecked, Violation};
    if principal.validate().is_err()
        || request.limit == 0
        || usize::from(request.limit) > MAX_RECALL_ITEMS
        || EmbedInput::new(EmbedPurpose::Query, &request.query).is_err()
    {
        return RecallObservation::unavailable(NotChecked);
    }
    let anchors = SqliteMemory::new(store.sql, store.ledger, store.keys);
    let (reply, receipt) = match store.recall(
        transaction,
        &mut crate::permissions::LedgerPermissions,
        &anchors,
        principal,
        request_id,
        request,
        index,
        embedder,
    ) {
        Ok(observed) => observed,
        Err(error) => return RecallObservation::unavailable(observation_error(error)),
    };
    let mut measured = RecallObservation::unavailable(NotChecked);
    let frame = match recall_frame(request_id, &reply) {
        Ok(frame) => frame,
        Err(_) => return RecallObservation::unavailable(Violation),
    };
    if receipt.request_id != *request_id
        || receipt.reply_sha256 != sha256(&frame)
        || frame.len() > canon::frame::MAX_FRAME_BYTES
        || receipt.cited_save_sequences
            != reply
                .items
                .iter()
                .map(|item| item.item.cite_seq)
                .collect::<Vec<_>>()
    {
        return RecallObservation::unavailable(Violation);
    }
    let sentinel = receipt.permission_sequence == 0
        && receipt.permission_epoch == 0
        && receipt.head == MemoryHead::EMPTY;
    let bound = expected_grant.is_some_and(|grant| {
        grant.change.context == *principal
            && grant.change.request.permission == Permission::Disclose
            && grant.change.request.scope == PermissionScope::hosted_model_context()
            && grant.change.action == PermissionAction::Grant
            && grant.record.authority.epoch == principal.owner_epoch
            && grant.record.authority.sequence > 0
            && grant.record.authority.sequence <= snapshot.anchor.aura_sequence
            && receipt.head == snapshot.anchor.head
            && receipt.permission_sequence == grant.record.authority.sequence
            && receipt.permission_epoch == principal.owner_epoch
    });
    if !sentinel && !bound {
        measured.receipt = if expected_grant.is_some() {
            Disagreement
        } else {
            NotChecked
        };
        if disclosure_expected.is_some() {
            measured.permissions = Disagreement;
        }
    } else if bound {
        measured.receipt = Checked;
    }
    let active = snapshot
        .notes
        .values()
        .filter(|note| note.demotion.is_none() && !note.quarantined)
        .count();
    match reply.result {
        RecallResult::Found => {
            if reply.items.is_empty()
                || reply.items.len() > usize::from(request.limit)
                || reply.gap.is_some()
                || sentinel
            {
                return RecallObservation::unavailable(Violation);
            }
            let mut seen = BTreeSet::new();
            for item in &reply.items {
                let id = match NoteId::new(item.item.note_id.clone()) {
                    Ok(id) => id,
                    Err(_) => return RecallObservation::unavailable(Violation),
                };
                let Some(note) = snapshot.notes.get(&id) else {
                    return RecallObservation::unavailable(Violation);
                };
                if !seen.insert(id.clone())
                    || note.demotion.is_some()
                    || note.quarantined
                    || item.item.cite_seq != note.receipt.cite_seq
                    || verify_note(&id, note, principal).is_err()
                {
                    return RecallObservation::unavailable(Violation);
                }
                let payload = match store.decrypt(note) {
                    Ok(payload) => payload,
                    Err(error) => return RecallObservation::unavailable(observation_error(error)),
                };
                if item.item.text != payload.content.statement() {
                    return RecallObservation::unavailable(Violation);
                }
                if item.origin != payload.origin
                    || item.delivery_source().source != Source::Memory
                    || item.grants_authority()
                    || reply.delivery_source().source != Source::Memory
                {
                    measured.provenance = Violation;
                }
            }
            if measured.provenance != Violation {
                measured.provenance = Checked;
            }
            measured.permissions = match disclosure_expected {
                Some(false) => Violation,
                Some(true) if bound => Checked,
                Some(true) => Disagreement,
                None => NotChecked,
            };
            measured.citations = measured.permissions;
        }
        RecallResult::Empty => {
            if active != 0 || !reply.items.is_empty() || reply.gap.is_some() || sentinel {
                return RecallObservation::unavailable(Violation);
            }
            if bound && disclosure_expected == Some(true) {
                measured.permissions = Checked;
            } else if disclosure_expected == Some(false) {
                measured.permissions = Violation;
            }
        }
        RecallResult::Undetermined => {
            if !reply.items.is_empty() || reply.gap.is_none() {
                return RecallObservation::unavailable(Violation);
            }
            if reply.gap == Some(RecallGap::Permission) {
                if !sentinel {
                    return RecallObservation::unavailable(Violation);
                }
                measured.permissions = match disclosure_expected {
                    Some(false) => Checked,
                    Some(true) => Disagreement,
                    None => NotChecked,
                };
            }
        }
    }
    measured
}

fn observation_error(error: canon::Refusal) -> RecallProbe {
    if error == codes::KIRA_STORE_UNAVAILABLE {
        RecallProbe::Unreachable
    } else if error == codes::KIRA_LEDGER_UNVERIFIED || error == codes::KIRA_AUTHENTICATION_FAILED {
        RecallProbe::NotChecked
    } else {
        RecallProbe::Violation
    }
}
