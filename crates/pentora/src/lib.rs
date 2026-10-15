// SPDX-License-Identifier: AGPL-3.0-or-later

use sha2::{Digest, Sha256};
use std::fmt;

pub const DOMAIN: &[u8; 18] = b"pentora.display.v1";
pub const ROOT_LEN: usize = 32;
pub const DIGEST_LEN: usize = 32;
pub const TRIT_COUNT: usize = 110;
pub const CENTRE_INDEX: usize = 55;
pub const TRANSITION_MS: i64 = 400;
pub const SETTLE_MS: i64 = 1_200;

pub const MUTABLE_INDICES: [usize; TRIT_COUNT] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
    75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98,
    99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
];

pub const DOUBLE_CORNER_INDICES: [usize; 20] = [
    0, 1, 10, 12, 16, 18, 27, 28, 52, 53, 57, 58, 82, 83, 92, 94, 98, 100, 109, 110,
];

pub const EDGES: [[usize; 2]; 60] = [
    [10, 12],
    [10, 16],
    [10, 92],
    [12, 18],
    [12, 94],
    [16, 18],
    [16, 98],
    [18, 100],
    [92, 94],
    [92, 98],
    [94, 100],
    [98, 100],
    [10, 57],
    [1, 10],
    [10, 82],
    [53, 100],
    [100, 109],
    [28, 100],
    [1, 53],
    [53, 82],
    [57, 109],
    [28, 57],
    [82, 109],
    [1, 28],
    [12, 58],
    [0, 12],
    [12, 82],
    [52, 98],
    [98, 110],
    [28, 98],
    [0, 52],
    [52, 82],
    [58, 110],
    [28, 58],
    [0, 28],
    [82, 110],
    [16, 52],
    [1, 16],
    [16, 83],
    [58, 94],
    [94, 109],
    [27, 94],
    [52, 109],
    [27, 52],
    [1, 58],
    [58, 83],
    [83, 109],
    [1, 27],
    [18, 53],
    [0, 18],
    [18, 83],
    [57, 92],
    [92, 110],
    [27, 92],
    [53, 110],
    [27, 53],
    [0, 57],
    [57, 83],
    [0, 27],
    [83, 110],
];

pub const CUBES: [[usize; 27]; 5] = [
    [
        10, 49, 92, 13, 54, 95, 16, 59, 98, 11, 50, 93, 14, 55, 96, 17, 60, 99, 12, 51, 94, 15, 56,
        97, 18, 61, 100,
    ],
    [
        10, 45, 82, 2, 30, 67, 1, 22, 53, 31, 68, 101, 24, 55, 86, 9, 42, 79, 57, 88, 109, 43, 80,
        108, 28, 65, 100,
    ],
    [
        12, 46, 82, 3, 29, 66, 0, 19, 52, 32, 69, 102, 25, 55, 85, 8, 41, 78, 58, 91, 110, 44, 81,
        107, 28, 64, 98,
    ],
    [
        16, 47, 83, 4, 36, 73, 1, 26, 58, 33, 70, 103, 20, 55, 90, 7, 40, 77, 52, 84, 109, 37, 74,
        106, 27, 63, 94,
    ],
    [
        18, 48, 83, 5, 35, 72, 0, 23, 57, 34, 71, 104, 21, 55, 89, 6, 39, 76, 53, 87, 110, 38, 75,
        105, 27, 62, 92,
    ],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PentoraError {
    HeadInvalid,
    TritsInvalid,
    TimeInvalid,
}

impl PentoraError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::HeadInvalid => "pentora:head-invalid",
            Self::TritsInvalid => "pentora:trits-invalid",
            Self::TimeInvalid => "pentora:time-invalid",
        }
    }
}

impl fmt::Display for PentoraError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PentoraError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expansion {
    pub digest: [u8; DIGEST_LEN],
    pub trits: [u8; TRIT_COUNT],
}

pub fn pentora_digest(root: &[u8]) -> Result<[u8; DIGEST_LEN], PentoraError> {
    if root.len() != ROOT_LEN {
        return Err(PentoraError::HeadInvalid);
    }

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update([0]);
    hasher.update(root);
    Ok(hasher.finalize().into())
}

pub fn expand_digest(digest: [u8; DIGEST_LEN]) -> [u8; TRIT_COUNT] {
    let mut quotient = digest;
    let mut trits = [0; TRIT_COUNT];
    for trit in &mut trits {
        let mut remainder = 0_u16;
        for byte in &mut quotient {
            let value = remainder * 256 + u16::from(*byte);
            *byte = (value / 3) as u8;
            remainder = value % 3;
        }
        *trit = remainder as u8;
    }
    trits
}

pub fn pentora_digits(root: &[u8]) -> Result<[u8; TRIT_COUNT], PentoraError> {
    Ok(expand_digest(pentora_digest(root)?))
}

// Prime's pentoraCells returns raw trits, not balanced values.
pub fn pentora_cells(root: &[u8]) -> Result<[u8; TRIT_COUNT], PentoraError> {
    pentora_digits(root)
}

pub fn balanced_cells(trits: &[u8]) -> Result<[i8; TRIT_COUNT], PentoraError> {
    let trits: &[u8; TRIT_COUNT] = trits.try_into().map_err(|_| PentoraError::TritsInvalid)?;
    if trits.iter().any(|&trit| trit > 2) {
        return Err(PentoraError::TritsInvalid);
    }
    Ok(trits.map(|trit| trit as i8 - 1))
}

pub fn expand(root: &[u8]) -> Result<Expansion, PentoraError> {
    let digest = pentora_digest(root)?;
    Ok(Expansion {
        digest,
        trits: expand_digest(digest),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MotionStatus {
    InMotion,
    Solid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PentoraMotion {
    previous_root: [u8; ROOT_LEN],
    next_root: [u8; ROOT_LEN],
    previous_cells: [u8; TRIT_COUNT],
    next_cells: [u8; TRIT_COUNT],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MotionFrame {
    pub cells: [u8; TRIT_COUNT],
    pub changed_cells: [bool; TRIT_COUNT],
    pub status: MotionStatus,
    pub root: Option<[u8; ROOT_LEN]>,
    pub moved_cells: usize,
}

impl PentoraMotion {
    pub fn new(previous_root: &[u8], next_root: &[u8]) -> Result<Self, PentoraError> {
        let previous_root = copy_root(previous_root)?;
        let next_root = copy_root(next_root)?;
        let previous_cells = pentora_cells(&previous_root)?;
        let next_cells = if previous_root == next_root {
            previous_cells
        } else {
            pentora_cells(&next_root)?
        };
        Ok(Self {
            previous_root,
            next_root,
            previous_cells,
            next_cells,
        })
    }

    pub fn frame(
        &self,
        elapsed_ms: i64,
        reduced_motion: bool,
    ) -> Result<MotionFrame, PentoraError> {
        if elapsed_ms < 0 {
            return Err(PentoraError::TimeInvalid);
        }

        let changed = self.previous_root != self.next_root;
        let moved_cells = if reduced_motion || !changed {
            TRIT_COUNT
        } else {
            let transition_elapsed = elapsed_ms.min(TRANSITION_MS) as usize;
            TRIT_COUNT * transition_elapsed / TRANSITION_MS as usize
        };
        let solid = reduced_motion || !changed || elapsed_ms >= SETTLE_MS;
        let cells = std::array::from_fn(|index| {
            if index < moved_cells {
                self.next_cells[index]
            } else {
                self.previous_cells[index]
            }
        });
        let changed_cells =
            std::array::from_fn(|index| self.next_cells[index] != self.previous_cells[index]);

        Ok(MotionFrame {
            cells,
            changed_cells,
            status: if solid {
                MotionStatus::Solid
            } else {
                MotionStatus::InMotion
            },
            root: solid.then_some(self.next_root),
            moved_cells,
        })
    }
}

fn copy_root(root: &[u8]) -> Result<[u8; ROOT_LEN], PentoraError> {
    root.try_into().map_err(|_| PentoraError::HeadInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn malformed_roots_have_a_named_refusal() {
        for length in [0, 1, 31, 33, 64] {
            let error = pentora_digest(&vec![0; length]).unwrap_err();
            assert_eq!(error.code(), "pentora:head-invalid");
            assert_eq!(pentora_digits(&vec![0; length]), Err(error));
        }
    }

    #[test]
    fn malformed_wire_trits_have_a_named_refusal() {
        for trits in [vec![0; 109], vec![0; 111], vec![3; TRIT_COUNT]] {
            let error = balanced_cells(&trits).unwrap_err();
            assert_eq!(error.code(), "pentora:trits-invalid");
        }
    }

    #[test]
    fn index_state_matches_the_display_tables() {
        assert_eq!(MUTABLE_INDICES.len(), TRIT_COUNT);
        assert_eq!(
            MUTABLE_INDICES,
            std::array::from_fn(|i| i + usize::from(i >= 55))
        );
        assert!(!MUTABLE_INDICES.contains(&CENTRE_INDEX));
        assert_eq!(EDGES.len(), 60);
        assert_eq!(CUBES.len(), 5);
        assert!(CUBES.iter().all(|cube| cube[13] == CENTRE_INDEX));

        let edges: HashSet<_> = EDGES.iter().copied().collect();
        assert_eq!(edges.len(), EDGES.len());
        assert!(EDGES.iter().all(|[left, right]| left < right));

        let mut uses = [0_u8; 111];
        for index in CUBES.into_iter().flatten() {
            uses[index] += 1;
        }
        assert_eq!(uses[CENTRE_INDEX], 5);
        assert_eq!(uses.iter().filter(|&&count| count == 1).count(), 90);
        assert_eq!(uses.iter().filter(|&&count| count == 2).count(), 20);
        assert_eq!(
            uses.iter()
                .enumerate()
                .filter_map(|(index, &count)| (count == 2).then_some(index))
                .collect::<Vec<_>>(),
            DOUBLE_CORNER_INDICES
        );
    }

    #[test]
    fn motion_uses_integer_prime_boundaries() {
        assert_eq!(TRANSITION_MS, 400);
        assert_eq!(SETTLE_MS, 1_200);
        let previous = [0_u8; ROOT_LEN];
        let next = [1_u8; ROOT_LEN];
        let motion = PentoraMotion::new(&previous, &next).unwrap();
        for elapsed in [0, 40, 199, 399, 400, 800, 1_199, 1_200, 1_800] {
            let frame = motion.frame(elapsed, false).unwrap();
            let expected_moved =
                TRIT_COUNT * elapsed.min(TRANSITION_MS) as usize / TRANSITION_MS as usize;
            assert_eq!(frame.moved_cells, expected_moved);
            assert_eq!(
                frame.status,
                if elapsed < SETTLE_MS {
                    MotionStatus::InMotion
                } else {
                    MotionStatus::Solid
                }
            );
            assert_eq!(frame.root, (elapsed >= SETTLE_MS).then_some(next));
            if frame.status == MotionStatus::Solid {
                assert_eq!(frame.cells, pentora_cells(&next).unwrap());
            }
        }
    }

    #[test]
    fn unchanged_and_reduced_motion_are_immediately_solid() {
        let root = [7_u8; ROOT_LEN];
        let same = PentoraMotion::new(&root, &root).unwrap();
        let same_frame = same.frame(0, false).unwrap();
        assert_eq!(same_frame.status, MotionStatus::Solid);
        assert_eq!(same_frame.root, Some(root));
        assert_eq!(same_frame.moved_cells, TRIT_COUNT);

        let changed = PentoraMotion::new(&[0; ROOT_LEN], &root).unwrap();
        let reduced_frame = changed.frame(0, true).unwrap();
        assert_eq!(reduced_frame.status, MotionStatus::Solid);
        assert_eq!(reduced_frame.root, Some(root));
        assert_eq!(reduced_frame.cells, pentora_cells(&root).unwrap());
    }

    #[test]
    fn negative_motion_time_has_a_named_refusal() {
        let motion = PentoraMotion::new(&[0; ROOT_LEN], &[1; ROOT_LEN]).unwrap();
        let error = motion.frame(-1, false).unwrap_err();
        assert_eq!(error.code(), "pentora:time-invalid");
    }
}
