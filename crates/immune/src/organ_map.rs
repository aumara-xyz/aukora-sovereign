// SPDX-License-Identifier: AGPL-3.0-or-later
//! Health-to-geometry projection; a fingerprint cannot be passed to this interface.
//!
//! Level 1: the five cubes are the five organs, each cube's 18 private cells are
//! that organ's own checks and each pair's 2 shared corners are its cross-checks.
//! The map is evidence on its own labelled canvas; it grants nothing.

use canon::health::{Cell, HealthSnapshot, OrganId, CHECKS, CORNERS};
use canon::{Refusal, Result};
use pentora::geometry::Geometry;
use pentora::CellIndex;

pub const LABEL: &str = "Organ health";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganMap {
    pub cells: [Cell; 110],
    pub epoch: u64,
    pub sequence: u64,
}

/// Projects a snapshot's 90 private and 20 corner cells onto the pinned geometry.
/// Refuses a snapshot whose cells differ from canon's reduction of its evidence,
/// a private check whose owner is not its id's organ, a corner whose registered
/// owners are not the geometry pair holding its cell, and any projection that does
/// not write each of the 110 cells exactly once.
pub fn project(snapshot: &HealthSnapshot, geometry: &Geometry) -> Result<OrganMap> {
    let reduced = HealthSnapshot::reduce(
        snapshot.epoch,
        snapshot.sequence,
        snapshot.observed_at_ms,
        snapshot.commitment,
        snapshot.evidence.clone(),
    )?;
    if snapshot != &reduced {
        return Err(refusal("health-snapshot-mismatch"));
    }
    let mut cells = [Cell::Failed; 110];
    let mut written = [false; 110];
    let mut place = |index: CellIndex, cell: Cell| {
        let digit = index.digit();
        if written[digit] {
            return Err(refusal("organ-map-geometry"));
        }
        written[digit] = true;
        cells[digit] = cell;
        Ok(())
    };
    for (definition, cell) in CHECKS.iter().zip(snapshot.private_cells.iter()) {
        if definition.owner != definition.id.organ() {
            return Err(refusal("organ-map-geometry"));
        }
        place(geometry.private_cell(definition.id), *cell)?;
    }
    for (definition, cell) in CORNERS.iter().zip(snapshot.corner_cells.iter()) {
        let pair = &geometry.pairs()[usize::from(definition.id.index() - 1) / 2];
        if pair.owners != definition.owners {
            return Err(refusal("organ-map-geometry"));
        }
        place(geometry.corner_cell(definition.id), *cell)?;
    }
    if written.contains(&false) {
        return Err(refusal("organ-map-geometry"));
    }
    Ok(OrganMap {
        cells,
        epoch: snapshot.epoch,
        sequence: snapshot.sequence,
    })
}

/// Cell counts for one group. An undetermined cell is never counted as verified.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Tally {
    pub verified: u8,
    pub undetermined: u8,
    pub failed: u8,
}

impl Tally {
    fn count(cells: impl IntoIterator<Item = Cell>) -> Self {
        cells.into_iter().fold(Self::default(), |mut tally, cell| {
            match cell {
                Cell::Verified => tally.verified += 1,
                Cell::Undetermined => tally.undetermined += 1,
                Cell::Failed => tally.failed += 1,
            }
            tally
        })
    }

    /// True only when every counted cell is verified.
    pub const fn whole(&self) -> bool {
        self.undetermined == 0 && self.failed == 0
    }
}

/// One cube: an organ's 18 own checks and the 8 corners it shares with the others.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrganHealth {
    pub organ: OrganId,
    pub private: Tally,
    pub corners: Tally,
}

/// One organ pair's two shared corners, lower global index first. A failed corner
/// localises the fault to this pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairHealth {
    pub owners: [OrganId; 2],
    pub corners: [Cell; 2],
}

impl OrganMap {
    pub const fn cell(&self, index: CellIndex) -> Cell {
        self.cells[index.digit()]
    }

    /// The five cubes in organ order.
    pub fn organs(&self, geometry: &Geometry) -> [OrganHealth; 5] {
        geometry.cubes().each_ref().map(|cube| OrganHealth {
            organ: cube.owner,
            private: Tally::count(cube.private.iter().map(|index| self.cell(*index))),
            corners: Tally::count(cube.corners.iter().map(|index| self.cell(*index))),
        })
    }

    /// The ten organ pairs in the pinned geometry's intersection order.
    pub fn pairs(&self, geometry: &Geometry) -> [PairHealth; 10] {
        geometry.pairs().map(|pair| PairHealth {
            owners: pair.owners,
            corners: pair.corners.map(|index| self.cell(index)),
        })
    }

    /// True only when all 110 cells are verified.
    pub fn whole(&self) -> bool {
        self.cells.iter().all(|cell| *cell == Cell::Verified)
    }
}

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
