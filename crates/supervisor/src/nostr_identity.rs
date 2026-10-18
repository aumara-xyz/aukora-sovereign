// SPDX-License-Identifier: AGPL-3.0-or-later
//! A persistent Nostr node key, held only in the supervisor's private state.

use canon::{Refusal, Result};
use nostr::{PublicKey, SecretKey};
use std::fs::File;
use zeroize::Zeroizing;

const KEY_FILE: &str = "nostr-node-v1.key";
const PUBLIC_FILE: &str = "nostr-node-v1.npub";

pub struct NodeIdentity {
    key: SecretKey,
    public: PublicKey,
    npub: String,
}

impl NodeIdentity {
    pub fn open(directory: &File) -> Result<Self> {
        let saved_public = match crate::state::read_private(directory, PUBLIC_FILE, 128) {
            Ok(bytes) => Some(bytes),
            Err(rustix::io::Errno::NOENT) => None,
            Err(_) => return Err(refuse("nostr-public-file")),
        };
        let mut existing = match crate::state::read_private(directory, KEY_FILE, 32) {
            Ok(bytes) => Some(Zeroizing::new(bytes)),
            Err(rustix::io::Errno::NOENT) => None,
            Err(_) => return Err(refuse("nostr-key-file")),
        };
        // A crash between creating the key file and syncing its 32 bytes leaves a short file and no public companion:
        // that key was never used or published, so it is replaced. With a public companion it is never replaced.
        if saved_public.is_none() && existing.as_ref().is_some_and(|bytes| !importable(bytes)) {
            rustix::fs::unlinkat(directory, KEY_FILE, rustix::fs::AtFlags::empty())
                .map_err(|_| refuse("nostr-key-file"))?;
            existing = None;
        }
        let bytes = match existing {
            Some(bytes) => bytes,
            None if saved_public.is_none() => {
                // There is no export operation on SecretKey: fill and import a zeroizing seed.
                // Invalid secp256k1 scalars are retried before any bytes reach disk.
                let mut seed = Zeroizing::new([0; 32]);
                loop {
                    getrandom::fill(&mut seed[..]).map_err(|_| refuse("randomness"))?;
                    if SecretKey::import(seed.clone()).is_ok() {
                        break;
                    }
                }
                crate::state::write_new(directory, KEY_FILE, &seed[..])?;
                Zeroizing::new(seed.to_vec())
            }
            None => return Err(refuse("nostr-key-file")),
        };
        let seed = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| refuse("nostr-key-file"))?,
        );
        let key = SecretKey::import(seed).map_err(|_| refuse("nostr-key-file"))?;
        let public = key.public_key()?;
        let npub = public.to_npub()?.as_str().to_owned();
        if let Some(saved) = saved_public {
            if saved != npub.as_bytes() {
                return Err(refuse("nostr-key-mismatch"));
            }
        } else {
            // A crash after the durable key write resumes with that key, never a new one.
            crate::state::write_new(directory, PUBLIC_FILE, npub.as_bytes())?;
        }
        Ok(Self { key, public, npub })
    }

    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn npub(&self) -> &str {
        &self.npub
    }
}

fn importable(bytes: &[u8]) -> bool {
    <[u8; 32]>::try_from(bytes).is_ok_and(|seed| SecretKey::import(Zeroizing::new(seed)).is_ok())
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "supervisor",
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
    };

    struct Directory(PathBuf, File);
    impl Directory {
        fn new() -> Self {
            let mut suffix = [0; 16];
            getrandom::fill(&mut suffix).unwrap();
            let path =
                std::env::temp_dir().join(format!("sovereign-nostr-{}", hex::encode(suffix)));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = File::open(&path).unwrap();
            Self(path, file)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn node_key_is_private_persistent_and_distinct() {
        let a = Directory::new();
        let b = Directory::new();
        let first = NodeIdentity::open(&a.1).unwrap();
        assert_eq!(first.npub(), NodeIdentity::open(&a.1).unwrap().npub());
        assert_ne!(first.npub(), NodeIdentity::open(&b.1).unwrap().npub());
        let metadata = std::fs::metadata(a.0.join(KEY_FILE)).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.len(), 32);
        assert_eq!(
            PublicKey::from_npub(first.npub()).unwrap(),
            first.public_key()
        );
        std::fs::remove_file(a.0.join(KEY_FILE)).unwrap();
        assert!(
            NodeIdentity::open(&a.1).is_err(),
            "missing key must never rotate a known npub"
        );
    }

    #[test]
    fn node_key_refuses_symlinks_and_public_permissions() {
        let a = Directory::new();
        std::os::unix::fs::symlink("elsewhere", a.0.join(KEY_FILE)).unwrap();
        assert!(NodeIdentity::open(&a.1).is_err());
        std::fs::remove_file(a.0.join(KEY_FILE)).unwrap();
        NodeIdentity::open(&a.1).unwrap();
        std::fs::set_permissions(a.0.join(KEY_FILE), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(NodeIdentity::open(&a.1).is_err());
    }

    #[test]
    fn a_short_key_file_from_an_interrupted_first_write_is_replaced_only_while_unpublished() {
        let a = Directory::new();
        std::fs::write(a.0.join(KEY_FILE), [7; 5]).unwrap();
        std::fs::set_permissions(a.0.join(KEY_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        let fresh = NodeIdentity::open(&a.1).unwrap();
        assert_eq!(std::fs::metadata(a.0.join(KEY_FILE)).unwrap().len(), 32);
        assert_eq!(fresh.npub(), NodeIdentity::open(&a.1).unwrap().npub());
        // Once the npub exists, a damaged key file refuses instead of rotating the identity.
        std::fs::remove_file(a.0.join(KEY_FILE)).unwrap();
        std::fs::write(a.0.join(KEY_FILE), [7; 5]).unwrap();
        std::fs::set_permissions(a.0.join(KEY_FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(NodeIdentity::open(&a.1).is_err());
    }

    #[test]
    fn interrupted_public_write_recovers_existing_key() {
        let a = Directory::new();
        let first = NodeIdentity::open(&a.1).unwrap();
        std::fs::remove_file(a.0.join(PUBLIC_FILE)).unwrap();
        assert_eq!(first.npub(), NodeIdentity::open(&a.1).unwrap().npub());
    }
}
