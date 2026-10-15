// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sole root-to-fingerprint derivation; trits are not health cells.

use canon::domain::PENTORA_DISPLAY_DOMAIN;
use canon::{digest::Digest32, Result};
use sha2::{Digest, Sha256};

/// One trit for each non-centre cell of the pinned geometry.
pub const TRIT_COUNT: usize = 110;

/// Raw base-three digit. Zero maps to -1, one to 0 and two to +1 in the display.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FingerprintTrit {
    Zero = 0,
    One = 1,
    Two = 2,
}

impl FingerprintTrit {
    pub fn from_digit(digit: u8) -> Result<Self> {
        match digit {
            0 => Ok(Self::Zero),
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err(crate::refusal("trits-invalid")),
        }
    }

    pub const fn digit(self) -> u8 {
        self as u8
    }

    pub const fn balanced(self) -> i8 {
        self as i8 - 1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expansion {
    digest: Digest32,
    trits: [FingerprintTrit; TRIT_COUNT],
}

impl Expansion {
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    pub const fn trits(&self) -> &[FingerprintTrit; TRIT_COUNT] {
        &self.trits
    }

    /// The frozen expansion wire is 110 bytes, each exactly 0, 1 or 2.
    pub fn wire(&self) -> [u8; TRIT_COUNT] {
        self.trits.map(FingerprintTrit::digit)
    }
}

/// Accept exactly the 32 raw bytes of an Aura root, never health state or hexadecimal text.
///
/// The digest is `sha256("pentora.display.v1" || 0x00 || root)`. Trit `i` is
/// `floor(N / 3^i) mod 3` for `i` in `0..110`, `N` being the big-endian integer of that
/// digest. Trit `i` belongs to the `i`-th non-centre cell (`CellIndex::digit`).
pub fn pentora_expand(root32: &[u8]) -> Result<Expansion> {
    let root: &[u8; 32] = root32
        .try_into()
        .map_err(|_| crate::refusal("head-invalid"))?;
    let digest: [u8; 32] = Sha256::new()
        .chain_update(PENTORA_DISPLAY_DOMAIN.as_bytes())
        .chain_update([0])
        .chain_update(root)
        .finalize()
        .into();

    // Four big-endian limbs preserve the quotient while extracting low trits.
    let mut limbs = [0_u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(digest.chunks_exact(8)) {
        for byte in bytes {
            *limb = (*limb << 8) | u64::from(*byte);
        }
    }
    let mut trits = [FingerprintTrit::Zero; TRIT_COUNT];
    for trit in &mut trits {
        let mut remainder = 0_u128;
        for limb in &mut limbs {
            let dividend = (remainder << 64) | u128::from(*limb);
            *limb = (dividend / 3) as u64;
            remainder = dividend % 3;
        }
        *trit = match remainder {
            0 => FingerprintTrit::Zero,
            1 => FingerprintTrit::One,
            _ => FingerprintTrit::Two,
        };
    }
    Ok(Expansion {
        digest: Digest32::from_bytes(digest),
        trits,
    })
}
