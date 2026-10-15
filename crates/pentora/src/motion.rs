// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fail-closed fingerprint frames with a generation guard and hidden moving digests.

use crate::fingerprint::{pentora_expand, Expansion, FingerprintTrit, TRIT_COUNT};
use crate::snapshot::{absence_text, source_name, AuraDisplaySnapshot};
use crate::Geometry;
use canon::{digest::Digest32, Result};

pub const TRANSITION_MS: u64 = 400;
pub const SETTLE_MS: u64 = 1_200;
pub const FINGERPRINT_LABEL: &str = "Fingerprint — display only";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MotionState {
    Moving,
    Settled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLabel {
    pub name: &'static str,
    pub entries: u64,
    pub absence: Option<&'static str>,
    /// Omitted for every source until the fingerprint has settled.
    pub head_text: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FingerprintFrame {
    pub label: &'static str,
    pub trits: [FingerprintTrit; TRIT_COUNT],
    pub state: MotionState,
    pub changed: [bool; TRIT_COUNT],
    pub head_text: Option<String>,
    pub digest_text: Option<String>,
    pub sources: [SourceLabel; 3],
}

#[derive(Clone, Debug)]
struct Transition {
    previous: Expansion,
    next: Expansion,
    snapshot: AuraDisplaySnapshot,
    started_ms: u64,
    changed_head: bool,
}

/// Only this display's latest observation ticket can publish or fail its frame.
#[derive(Debug, Eq, PartialEq)]
pub struct ObservationTicket(u64);

#[derive(Debug)]
pub struct FingerprintDisplay {
    generation: u64,
    pending: bool,
    transition: Option<Transition>,
}

impl FingerprintDisplay {
    pub fn new() -> Result<Self> {
        Geometry::pinned()?;
        Ok(Self {
            generation: 0,
            pending: false,
            transition: None,
        })
    }

    /// A pending observation suppresses rendering until it completes successfully.
    pub fn begin(&mut self) -> Result<ObservationTicket> {
        let Some(next) = self.generation.checked_add(1) else {
            self.transition = None;
            self.pending = true;
            return Err(crate::refusal("generation-exhausted"));
        };
        self.generation = next;
        self.pending = true;
        Ok(ObservationTicket(next))
    }

    pub fn complete(
        &mut self,
        ticket: ObservationTicket,
        snapshot: AuraDisplaySnapshot,
        observed_ms: u64,
    ) -> Result<()> {
        self.require_ticket(ticket)?;
        let next = pentora_expand(snapshot.head().as_bytes())?;
        let previous = self
            .transition
            .as_ref()
            .map(|old| old.next.clone())
            .unwrap_or_else(|| next.clone());
        let unchanged = self
            .transition
            .as_ref()
            .is_some_and(|old| old.snapshot.head() == snapshot.head());
        let changed_head = self.transition.is_some() && !unchanged;
        let started_ms = if unchanged {
            self.transition
                .as_ref()
                .map_or(observed_ms, |old| old.started_ms)
        } else {
            observed_ms
        };
        if started_ms > observed_ms {
            self.transition = None;
            self.pending = false;
            return Err(crate::refusal("time-invalid"));
        }
        // Retain an in-progress transition across repeated observations of the same head.
        if unchanged {
            if let Some(old) = &mut self.transition {
                old.snapshot = snapshot;
            }
        } else {
            self.transition = Some(Transition {
                previous,
                next,
                snapshot,
                started_ms,
                changed_head,
            });
        }
        self.pending = false;
        Ok(())
    }

    pub fn fail(&mut self, ticket: ObservationTicket) -> Result<()> {
        self.require_ticket(ticket)?;
        self.transition = None;
        self.pending = false;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        let ticket = self.begin()?;
        self.fail(ticket)
    }

    fn require_ticket(&self, ticket: ObservationTicket) -> Result<()> {
        if !self.pending || ticket.0 != self.generation {
            return Err(crate::refusal("stale-observation"));
        }
        Ok(())
    }

    pub fn frame(&self, now_ms: u64, reduced_motion: bool) -> Result<FingerprintFrame> {
        if self.pending {
            return Err(crate::refusal("display-unavailable"));
        }
        let transition = self
            .transition
            .as_ref()
            .ok_or_else(|| crate::refusal("display-unavailable"))?;
        let elapsed = now_ms
            .checked_sub(transition.started_ms)
            .ok_or_else(|| crate::refusal("time-invalid"))?;
        let settled = reduced_motion || !transition.changed_head || elapsed >= SETTLE_MS;
        let cut = if settled {
            TRIT_COUNT
        } else {
            ((elapsed.min(TRANSITION_MS) * TRIT_COUNT as u64) / TRANSITION_MS) as usize
        };
        let sources = std::array::from_fn(|index| {
            let source = &transition.snapshot.sources()[index];
            SourceLabel {
                name: source_name(source.name),
                entries: source.entries,
                absence: source.absence.map(absence_text),
                head_text: if settled {
                    source.head.map(|head| head.to_string())
                } else {
                    None
                },
            }
        });
        Ok(FingerprintFrame {
            label: FINGERPRINT_LABEL,
            trits: std::array::from_fn(|i| {
                if i < cut {
                    transition.next.trits()[i]
                } else {
                    transition.previous.trits()[i]
                }
            }),
            state: if settled {
                MotionState::Settled
            } else {
                MotionState::Moving
            },
            changed: std::array::from_fn(|i| {
                transition.next.trits()[i] != transition.previous.trits()[i]
            }),
            head_text: settled.then(|| transition.snapshot.head().to_string()),
            digest_text: settled.then(|| transition.next.digest().to_string()),
            sources,
        })
    }

    /// A settled root may be named in the display; it never verifies identity.
    pub fn settled_head(&self, now_ms: u64, reduced_motion: bool) -> Result<Option<Digest32>> {
        let frame = self.frame(now_ms, reduced_motion)?;
        Ok(if frame.state == MotionState::Settled {
            self.transition.as_ref().map(|t| t.snapshot.head())
        } else {
            None
        })
    }
}
