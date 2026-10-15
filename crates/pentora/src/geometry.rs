// SPDX-License-Identifier: AGPL-3.0-or-later
//! Geometry is decoded only after its exact pinned bytes pass SHA-256.

use canon::health::{CheckId, CornerId, OrganId};
use canon::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CENTRE_INDEX: usize = 55;
pub const POINT_COUNT: usize = 111;
pub const GEOMETRY_SHA256: &str =
    "96b27c9b4de41cd961612be5b1e88d40e973a2fded16bd320415b3e15e3b8c61";
pub const PINNED_GEOMETRY: &[u8] = include_bytes!("../vectors/geometry_index_table_v1.json");

/// A non-centre global cell index. It names a position, never a state or grant.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CellIndex(u8);

impl CellIndex {
    pub fn new(global: usize) -> Result<Self> {
        if global >= POINT_COUNT || global == CENTRE_INDEX {
            return Err(crate::refusal("cell-index"));
        }
        Ok(Self(global as u8))
    }

    pub const fn global(self) -> usize {
        self.0 as usize
    }

    /// Zero-based index into the 110 trits, with the centre omitted.
    pub const fn digit(self) -> usize {
        let global = self.global();
        if global > CENTRE_INDEX {
            global - 1
        } else {
            global
        }
    }
}

#[derive(Clone, Debug)]
pub struct Cube {
    pub owner: OrganId,
    pub cells: [CellIndex; 26],
    pub private: [CellIndex; 18],
    pub corners: [CellIndex; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pair {
    pub owners: [OrganId; 2],
    /// Lower global index first; pair order follows the pinned table.
    pub corners: [CellIndex; 2],
}

#[derive(Clone, Debug)]
pub struct Geometry {
    cubes: [Cube; 5],
    pairs: [Pair; 10],
    edges: [[CellIndex; 2]; 60],
    points: [[f64; 3]; POINT_COUNT],
}

impl Geometry {
    pub fn pinned() -> Result<Self> {
        Self::from_pinned_bytes(PINNED_GEOMETRY)
    }

    /// Unknown or modified tables refuse even when their geometry is isomorphic.
    pub fn from_pinned_bytes(bytes: &[u8]) -> Result<Self> {
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if canon::digest::Digest32::from_bytes(actual).to_string() != GEOMETRY_SHA256 {
            return Err(crate::refusal("geometry-pin"));
        }
        let table: Value =
            serde_json::from_slice(bytes).map_err(|_| crate::refusal("geometry-invalid"))?;
        if index(&table["centre_index"])? != CENTRE_INDEX
            || index(&table["centre_local_index"])? != 13
            || index(&table["centre_fixed_value"])? != 0
        {
            return invalid();
        }
        let raw_cubes = array(&table["cubes"], 5)?;
        let mut members = Vec::<BTreeSet<usize>>::new();
        let mut multiplicities = [0_u8; POINT_COUNT];
        let mut edges = BTreeSet::new();
        for (cube_number, cube) in raw_cubes.iter().enumerate() {
            if index(&cube["cube_id"])? != cube_number {
                return invalid();
            }
            let slots = array(&cube["slots"], 27)?;
            let mut cells = BTreeSet::new();
            for (local, slot) in slots.iter().enumerate() {
                let global = index(&slot["global_index"])?;
                if global >= POINT_COUNT
                    || index(&slot["local_index"])? != local
                    || !cells.insert(global)
                    || (local == 13) != (global == CENTRE_INDEX)
                {
                    return invalid();
                }
                if global != CENTRE_INDEX {
                    multiplicities[global] += 1;
                }
            }
            for edge in array(&cube["edges_global_indices"], 12)? {
                let ends = array(edge, 2)?;
                let a = CellIndex::new(index(&ends[0])?)?;
                let b = CellIndex::new(index(&ends[1])?)?;
                if a >= b
                    || !cells.contains(&a.global())
                    || !cells.contains(&b.global())
                    || !edges.insert([a, b])
                {
                    return invalid();
                }
            }
            cells.remove(&CENTRE_INDEX);
            members.push(cells);
        }
        for (global, count) in multiplicities.iter().enumerate() {
            if (global == CENTRE_INDEX && *count != 0)
                || (global != CENTRE_INDEX && !(1..=2).contains(count))
            {
                return invalid();
            }
        }
        compare_indices(
            &table["mutable_indices"],
            (0..POINT_COUNT).filter(|i| *i != CENTRE_INDEX),
        )?;
        compare_indices(
            &table["private_indices"],
            (0..POINT_COUNT).filter(|i| multiplicities[*i] == 1),
        )?;
        compare_indices(
            &table["double_corner_indices"],
            (0..POINT_COUNT).filter(|i| multiplicities[*i] == 2),
        )?;
        let mut cubes = Vec::new();
        for (number, cells) in members.iter().enumerate() {
            cubes.push(Cube {
                owner: OrganId::ALL[number],
                cells: collect_cells(cells.iter().copied())?,
                private: collect_cells(cells.iter().copied().filter(|i| multiplicities[*i] == 1))?,
                corners: collect_cells(cells.iter().copied().filter(|i| multiplicities[*i] == 2))?,
            });
        }
        let pair_rows = array(&table["pair_intersections"], 10)?;
        let mut pairs = Vec::new();
        for left in 0..5 {
            for right in left + 1..5 {
                let shared: Vec<usize> = members[left]
                    .intersection(&members[right])
                    .copied()
                    .collect();
                if shared.len() != 2 {
                    return Err(crate::refusal("pair-intersection"));
                }
                let row = &pair_rows[pairs.len()];
                compare_indices(&row["cube_ids"], [left, right])?;
                compare_indices(&row["noncentre_corner_indices"], shared.iter().copied())?;
                let mut including_centre = shared.clone();
                including_centre.push(CENTRE_INDEX);
                including_centre.sort_unstable();
                compare_indices(&row["global_indices"], including_centre)?;
                if index(&row["centre_index"])? != CENTRE_INDEX {
                    return invalid();
                }
                pairs.push(Pair {
                    owners: [OrganId::ALL[left], OrganId::ALL[right]],
                    corners: collect_cells(shared)?,
                });
            }
        }
        let mut degree = [0_u8; POINT_COUNT];
        for [a, b] in &edges {
            if multiplicities[a.global()] != 2 || multiplicities[b.global()] != 2 {
                return invalid();
            }
            degree[a.global()] += 1;
            degree[b.global()] += 1;
        }
        if (0..POINT_COUNT).any(|i| degree[i] != if multiplicities[i] == 2 { 6 } else { 0 }) {
            return invalid();
        }
        let mut points = Vec::new();
        for (global, point) in array(&table["points"], POINT_COUNT)?.iter().enumerate() {
            if index(&point["global_index"])? != global {
                return invalid();
            }
            let coordinates = array(&point["coordinates"], 3)?;
            let mut position = [0.0; 3];
            for (axis, coordinate) in coordinates.iter().enumerate() {
                let a = rational(&coordinate["a"])?;
                let b = rational(&coordinate["b"])?;
                position[axis] = (a + b * (1.0 + 5.0_f64.sqrt()) / 2.0) / 3.0_f64.sqrt();
            }
            points.push(position);
        }
        Ok(Self {
            cubes: fixed(cubes)?,
            pairs: fixed(pairs)?,
            edges: fixed(edges.into_iter().collect())?,
            points: fixed(points)?,
        })
    }

    pub const fn cubes(&self) -> &[Cube; 5] {
        &self.cubes
    }
    pub const fn pairs(&self) -> &[Pair; 10] {
        &self.pairs
    }
    pub const fn edges(&self) -> &[[CellIndex; 2]; 60] {
        &self.edges
    }
    pub const fn points(&self) -> &[[f64; 3]; POINT_COUNT] {
        &self.points
    }

    pub fn private_cell(&self, check: CheckId) -> CellIndex {
        self.cubes[organ_index(check.organ())].private[usize::from(check.index() - 1)]
    }

    pub fn corner_cell(&self, corner: CornerId) -> CellIndex {
        let index = usize::from(corner.index() - 1);
        self.pairs[index / 2].corners[index % 2]
    }
}

pub const fn organ_index(organ: OrganId) -> usize {
    match organ {
        OrganId::Aumlok => 0,
        OrganId::GateAura => 1,
        OrganId::Kira => 2,
        OrganId::Network => 3,
        OrganId::Body => 4,
    }
}

fn invalid<T>() -> Result<T> {
    Err(crate::refusal("geometry-invalid"))
}

fn array(value: &Value, size: usize) -> Result<&[Value]> {
    value
        .as_array()
        .filter(|items| items.len() == size)
        .map(Vec::as_slice)
        .ok_or_else(|| crate::refusal("geometry-invalid"))
}

fn index(value: &Value) -> Result<usize> {
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| crate::refusal("geometry-invalid"))
}

fn rational(value: &Value) -> Result<f64> {
    let parts = array(value, 2)?;
    let a = parts[0]
        .as_i64()
        .ok_or_else(|| crate::refusal("geometry-invalid"))?;
    let b = parts[1]
        .as_i64()
        .filter(|b| *b > 0)
        .ok_or_else(|| crate::refusal("geometry-invalid"))?;
    Ok(a as f64 / b as f64)
}

fn fixed<T, const N: usize>(values: Vec<T>) -> Result<[T; N]> {
    values
        .try_into()
        .map_err(|_| crate::refusal("geometry-invalid"))
}

fn collect_cells<const N: usize>(
    indices: impl IntoIterator<Item = usize>,
) -> Result<[CellIndex; N]> {
    fixed(
        indices
            .into_iter()
            .map(CellIndex::new)
            .collect::<Result<Vec<_>>>()?,
    )
}

fn compare_indices(value: &Value, expected: impl IntoIterator<Item = usize>) -> Result<()> {
    let expected: Vec<usize> = expected.into_iter().collect();
    let supplied = array(value, expected.len())?
        .iter()
        .map(index)
        .collect::<Result<Vec<_>>>()?;
    if supplied != expected {
        return invalid();
    }
    Ok(())
}
