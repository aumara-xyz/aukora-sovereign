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
    notes::{refuse, MemoryOrigin},
    openviking::{OpenViking, SemanticError},
    permissions::{MemoryPermissions, PermissionContext},
};

pub const MAX_RECALL_ITEMS: usize = 100;

/// These fields describe the verified read, never authorize a later disclosure.
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
            return Err(refuse("citation-invalid"));
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
            return Err(refuse("recall-bounds"));
        }
        let ids: std::collections::BTreeSet<_> =
            items.iter().map(|item| &item.item.note_id).collect();
        if ids.len() != items.len() {
            return Err(refuse("citation-invalid"));
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
