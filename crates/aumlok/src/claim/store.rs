// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recoverable claim admission; enrolled credentials in Aura close bootstrap.

use super::HostClaimCommitment;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    authority::AuthorityTxn,
    codes::{AUMLOK_CLAIM_SPENT, AUMLOK_CLAIM_UNKNOWN},
    digest::Digest32,
    ids::NodeId,
    Result,
};
use hkdf::hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{fs::File, os::unix::fs::MetadataExt, path::Path};
use zeroize::Zeroizing;

pub struct ClaimAdmission {
    node: NodeId,
    session_digest: Digest32,
    origin: String,
    expires_at_ms: u64,
    directory_identity: (u64, u64),
}

impl ClaimAdmission {
    /// The key is the decoded spawn token; node has a fixed sixteen-byte width.
    pub fn derive_session_secret(
        token: &[u8],
        node: NodeId,
        origin: &str,
    ) -> Result<Zeroizing<String>> {
        let key = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?,
        );
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(key.as_slice()));
        if key.len() != 32 || encoded.as_bytes() != token {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key.as_slice()).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        mac.update(b"aukora:claim-session:v1");
        mac.update(node.as_bytes());
        mac.update(origin.as_bytes());
        let bytes = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        Ok(Zeroizing::new(hex::encode(bytes.as_slice())))
    }

    pub fn matches_directory(&self, directory: &File) -> Result<bool> {
        let metadata = directory.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        Ok(metadata.is_dir() && (metadata.dev(), metadata.ino()) == self.directory_identity)
    }

    pub fn into_parts(self) -> (NodeId, Digest32, String, u64) {
        (
            self.node,
            self.session_digest,
            self.origin,
            self.expires_at_ms,
        )
    }
}

pub trait ClaimStore {
    /// Keep the authority transaction open until the session save completes.
    #[allow(clippy::too_many_arguments)]
    fn claim(
        &mut self,
        commitment: &HostClaimCommitment,
        token: &[u8],
        node: NodeId,
        session_digest: Digest32,
        origin: &str,
        expires_at_ms: u64,
        now_ms: u64,
        authority: &mut impl AuthorityTxn,
    ) -> Result<ClaimAdmission>;
}

/// Retains the former store's API name; the legacy database is never authoritative.
pub struct SqliteClaimStore {
    directory: File,
    node: NodeId,
}

impl SqliteClaimStore {
    pub fn open(
        path: &Path,
        directory: &File,
        node: NodeId,
        _commitment: &HostClaimCommitment,
        _bootstrap_allowed: bool,
    ) -> Result<Self> {
        let parent = directory.metadata().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        if !parent.is_dir()
            || parent.mode() & 0o077 != 0
            || path.file_name() != Some(std::ffi::OsStr::new("claim-v1.sqlite3"))
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        Ok(Self {
            directory: directory.try_clone().map_err(|_| AUMLOK_CLAIM_UNKNOWN)?,
            node,
        })
    }
}

impl ClaimStore for SqliteClaimStore {
    fn claim(
        &mut self,
        commitment: &HostClaimCommitment,
        token: &[u8],
        node: NodeId,
        session_digest: Digest32,
        origin: &str,
        expires_at_ms: u64,
        now_ms: u64,
        authority: &mut impl AuthorityTxn,
    ) -> Result<ClaimAdmission> {
        commitment.verify(token)?;
        let maximum = canon::json::MAX_SAFE_INTEGER as u64;
        if node != self.node
            || origin.is_empty()
            || origin.len() > 2048
            || origin.chars().any(char::is_control)
            || now_ms > maximum
            || expires_at_ms > maximum
            || !expires_at_ms
                .checked_sub(now_ms)
                .is_some_and(|duration| (1..=86_400_000).contains(&duration))
        {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let secret = ClaimAdmission::derive_session_secret(token, node, origin)?;
        if Digest32::sha256(secret.as_bytes()) != session_digest {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        if authority.pending_owner_credential()?.is_some()
            || authority.bound_owner_identity()?.is_some()
        {
            return Err(AUMLOK_CLAIM_SPENT);
        }
        let metadata = self
            .directory
            .metadata()
            .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?;
        Ok(ClaimAdmission {
            node,
            session_digest,
            origin: origin.to_owned(),
            expires_at_ms,
            directory_identity: (metadata.dev(), metadata.ino()),
        })
    }
}
