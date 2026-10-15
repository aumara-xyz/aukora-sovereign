//! Incremental verification: one entry, an RFC 6962 frontier, bounded terminal state.

use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{digest, entry_hash, merkle, Entry, Error, RetainedHead, DOMAIN, MAX_BUFFER_BYTES};

#[derive(Default)]
struct Frontier(Vec<Option<merkle::Hash>>);

impl Frontier {
    fn push(&mut self, mut hash: merkle::Hash) {
        let mut height = 0;
        loop {
            if height == self.0.len() {
                self.0.push(Some(hash));
                break;
            }
            if let Some(left) = self.0[height].take() {
                hash = merkle::node_hash(&left, &hash);
                height += 1;
            } else {
                self.0[height] = Some(hash);
                break;
            }
        }
    }

    fn root(&self) -> merkle::Hash {
        self.0
            .iter()
            .flatten()
            .fold(None, |right, left| {
                Some(match right {
                    None => *left,
                    Some(right) => merkle::node_hash(left, &right),
                })
            })
            .unwrap_or_else(|| Sha256::digest([]).into())
    }
}

pub(crate) struct Verification<'a> {
    key: &'a VerifyingKey,
    retained: Option<&'a RetainedHead>,
    next: u64,
    prev: String,
    terminals: HashSet<String>,
    track_terminals: bool,
    terminal_bytes: usize,
    frontier: Frontier,
}

impl<'a> Verification<'a> {
    pub(crate) fn new(
        key: &'a VerifyingKey,
        retained: Option<&'a RetainedHead>,
    ) -> Result<Self, Error> {
        if retained.is_some_and(|head| head.sequence == 0 || head.tree_size == 0) {
            return Err(Error::new("aura:empty-retained"));
        }
        Ok(Self {
            key,
            retained,
            next: 1,
            prev: DOMAIN.into(),
            terminals: HashSet::new(),
            track_terminals: true,
            terminal_bytes: 0,
            frontier: Frontier::default(),
        })
    }

    pub(crate) fn for_database(
        key: &'a VerifyingKey,
        retained: Option<&'a RetainedHead>,
    ) -> Result<Self, Error> {
        let mut verification = Self::new(key, retained)?;
        verification.track_terminals = false;
        Ok(verification)
    }

    pub(crate) fn push(&mut self, entry: &Entry) -> Result<merkle::Hash, Error> {
        self.check(entry).map_err(|error| error.at(self.next))
    }

    fn check(&mut self, entry: &Entry) -> Result<merkle::Hash, Error> {
        if entry.sequence != self.next {
            return Err(Error::new("aura:sequence-gap"));
        }
        if entry.prev != self.prev {
            return Err(Error::new("aura:broken-link"));
        }
        let hash = entry_hash(&self.prev, &entry.fields(), self.next)?;
        if digest(&entry.hash)? != hash {
            return Err(Error::new("aura:hash-mismatch"));
        }
        let signature = STANDARD
            .decode(&entry.sig)
            .map_err(|_| Error::new("aura:invalid-signature"))?;
        let signature =
            Signature::from_slice(&signature).map_err(|_| Error::new("aura:invalid-signature"))?;
        self.key
            .verify_strict(&hash, &signature)
            .map_err(|_| Error::new("aura:invalid-signature"))?;
        if entry.phase == "terminal" && self.track_terminals {
            self.terminal_bytes = self.terminal_bytes.saturating_add(entry.op.len() + 128);
            if self.terminal_bytes > MAX_BUFFER_BYTES {
                return Err(Error::new("aura:memory-limit"));
            }
            if !self.terminals.insert(entry.op.clone()) {
                return Err(Error::new("aura:duplicate-terminal"));
            }
        }
        self.frontier.push(merkle::leaf_hash(&hash));
        self.prev.clone_from(&entry.hash);
        if let Some(head) = self.retained {
            if self.next == head.sequence as u64 {
                let actual = RetainedHead {
                    schema: "aukora-aura-retained-head-v1".into(),
                    leaf_convention: merkle::LEAF_CONVENTION.into(),
                    sequence: head.sequence,
                    hash: self.prev.clone(),
                    tree_size: head.sequence,
                    root: hex::encode(self.frontier.root()),
                };
                // Compare the retained prefix before interpreting any later entry.
                if actual != *head {
                    return Err(Error::new("aura:retained-head-mismatch"));
                }
            }
        }
        self.next += 1;
        Ok(hash)
    }

    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self
            .retained
            .is_some_and(|head| self.next - 1 < head.sequence as u64)
        {
            return Err(Error::new("aura:shorter-than-retained").at(self.next));
        }
        Ok(())
    }
}
