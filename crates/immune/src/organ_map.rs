// SPDX-License-Identifier: AGPL-3.0-or-later
//! Health-to-geometry projection; a fingerprint cannot be passed to this interface.

use canon::health::{Cell, HealthSnapshot, CHECKS, CORNERS};
use canon::Result;
use pentora::geometry::Geometry;

pub const LABEL: &str = "Organ health";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganMap {
    pub cells: [Cell; 110],
    pub epoch: u64,
    pub sequence: u64,
}

pub fn project(snapshot: &HealthSnapshot, geometry: &Geometry) -> Result<OrganMap> {
    let reduced = HealthSnapshot::reduce(
        snapshot.epoch,
        snapshot.sequence,
        snapshot.observed_at_ms,
        snapshot.commitment,
        snapshot.evidence.clone(),
    )?;
    if snapshot != &reduced {
        return Err(canon::Refusal {
            organ: "immune",
            reason: "health-snapshot-mismatch",
        });
    }
    let mut cells = [Cell::Failed; 110];
    for (definition, cell) in CHECKS.iter().zip(snapshot.private_cells.iter()) {
        cells[geometry.private_cell(definition.id).digit()] = *cell;
    }
    for (definition, cell) in CORNERS.iter().zip(snapshot.corner_cells.iter()) {
        cells[geometry.corner_cell(definition.id).digit()] = *cell;
    }
    Ok(OrganMap {
        cells,
        epoch: snapshot.epoch,
        sequence: snapshot.sequence,
    })
}
