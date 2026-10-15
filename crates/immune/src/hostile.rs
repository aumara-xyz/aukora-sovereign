// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded attack jobs; only the supervisor/launcher implementation runs a guest.

use canon::{digest::Digest32, Refusal, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub wall_ms: u64,
    pub cpu_us: u64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub output_bytes: u32,
    pub cases: u32,
}

impl Limits {
    pub fn validate(self) -> Result<Self> {
        if self.wall_ms == 0
            || self.wall_ms > 60_000
            || self.cpu_us == 0
            || self.cpu_us > 10_000_000
            || self.memory_bytes == 0
            || self.memory_bytes > 256 * 1024 * 1024
            || self.io_bytes == 0
            || self.io_bytes > 16 * 1024 * 1024
            || self.output_bytes == 0
            || self.output_bytes > 65_536
            || self.cases == 0
            || self.cases > 16_384
        {
            return Err(Refusal {
                organ: "immune",
                reason: "attack-budget",
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    ReadHostSecret,
    ExecuteCommand,
    OpenSocket,
    WriteOutsideCage,
    ForgedOwnerFrame,
    ModelKeyDisclosure,
    OverspendRace,
    RouteDisabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Blocked,
    ReachedTarget,
    Unavailable,
    BudgetExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairedProbe {
    pub probe: Probe,
    pub confined: Outcome,
    pub unconfined_control: Outcome,
    pub input_digest: Digest32,
}

impl PairedProbe {
    pub fn contained(&self) -> bool {
        self.confined == Outcome::Blocked && self.unconfined_control == Outcome::ReachedTarget
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CageRun {
    pub run_id: Digest32,
    pub candidate: Digest32,
    pub release: Digest32,
    pub cage: Digest32,
    pub challenge: Digest32,
    pub grants_at_start: u32,
    pub grants_at_end: u32,
    pub candidate_drove_guest: bool,
    pub parent_cgroup: u64,
    pub attack_cgroup: u64,
    pub probes: Vec<PairedProbe>,
    pub budget_exhausted: bool,
}

pub trait CageDriver {
    fn drive(&mut self, request: &crate::boot_attack::Request) -> Result<CageRun>;
}
