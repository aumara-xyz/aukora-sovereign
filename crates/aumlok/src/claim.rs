// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compare a bootstrap candidate with the host's SHA-256 claim commitment.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{codes::AUMLOK_CLAIM_UNKNOWN, digest::Digest32, Result};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Host configuration supplies this commitment; request bodies never do.
pub struct HostClaimCommitment(Digest32);

impl HostClaimCommitment {
    /// Load only spawn's root-owned commitment beneath the host directory descriptor.
    #[cfg(unix)]
    pub fn from_host(directory: &std::fs::File) -> Result<Self> {
        use rustix::fs::{openat, Mode, OFlags};
        use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

        let parent = directory.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let mut source = File::from(
            openat(
                directory,
                "claim.sha256",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?,
        );
        let metadata = source.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o440
            || metadata.nlink() != 1
            || metadata.len() != 65
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let mut contents = [0u8; 65];
        source
            .read_exact(&mut contents)
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        let mut trailing = [0u8; 1];
        if contents[64] != b'\n'
            || source
                .read(&mut trailing)
                .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?
                != 0
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let text = std::str::from_utf8(&contents[..64]).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        Digest32::from_hex(text)
            .map(Self)
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)
    }

    /// Spawn encodes 32 random bytes without padding and hashes those raw bytes.
    pub fn verify(&self, token: &[u8]) -> Result<()> {
        if token.len() != 43 {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let secret = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?,
        );
        if secret.len() != 32 {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice()));
        if encoded.as_bytes() != token {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let actual = Digest32::sha256(secret.as_slice());
        if !bool::from(self.0.as_bytes().ct_eq(actual.as_bytes())) {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        Ok(())
    }
}
