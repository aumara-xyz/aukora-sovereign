// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who is on the other end of the Kira socket, and whether the service lets it in (the door's `door/peer.rs` pattern).
//!
//! Linux: the kernel reports the connecting process's uid and gid (`SO_PEERCRED`). With `--peer-uids` or `--peer-gids`
//! set, a peer whose uid is not listed and whose gid is not listed is refused (`kira:peer-refused`) before it can send
//! a line, and the socket is opened to mode 0666 so the kernel check, not the file mode, is the gate.
//! macOS (Phase M): there are no peer credentials without unsafe code, so the gate stays same-uid trust: the socket is
//! 0600 inside the 0700 state folder, which keeps out other users, not other processes of the owner's own user (see the
//! trust boundary in mod.rs). A peer set on macOS is refused at start, because it could not be enforced and would
//! silently admit everyone.

use std::os::unix::net::UnixStream;

/// The caller of one connection, as the kernel reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// `SO_PEERCRED` uid and gid (Linux).
    #[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
    Cred { uid: u32, gid: u32 },
    /// The platform cannot say.
    Unknown,
}

/// Read the connecting process's credentials from the kernel.
#[cfg(target_os = "linux")]
pub fn of(stream: &UnixStream) -> Peer {
    match rustix::net::sockopt::socket_peercred(stream) {
        Ok(credentials) => Peer::Cred { uid: credentials.uid.as_raw(), gid: credentials.gid.as_raw() },
        Err(_) => Peer::Unknown,
    }
}

/// Only Linux reports peer credentials without unsafe code.
#[cfg(not(target_os = "linux"))]
pub fn of(_stream: &UnixStream) -> Peer {
    Peer::Unknown
}

/// Whether this platform can enforce a peer set.
pub const fn supported() -> bool {
    cfg!(target_os = "linux")
}

/// The peers the service admits: everyone who can open the socket (nothing configured), or only these uids and gids.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Admission {
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
}

impl Admission {
    pub fn configured(&self) -> bool {
        !self.uids.is_empty() || !self.gids.is_empty()
    }

    /// With a set configured, only a peer the kernel names with a listed uid or gid; an unknown peer never.
    pub fn admits(&self, peer: Peer) -> bool {
        if !self.configured() {
            return true;
        }
        match peer {
            Peer::Cred { uid, gid } => self.uids.contains(&uid) || self.gids.contains(&gid),
            Peer::Unknown => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_set_admits_only_listed_peers_and_never_an_unknown_one() {
        let open = Admission::default();
        assert!(open.admits(Peer::Unknown) && open.admits(Peer::Cred { uid: 7, gid: 7 }));
        let set = Admission { uids: vec![1001], gids: vec![2000] };
        assert!(set.admits(Peer::Cred { uid: 1001, gid: 5 }));
        assert!(set.admits(Peer::Cred { uid: 5, gid: 2000 }));
        assert!(!set.admits(Peer::Cred { uid: 5, gid: 5 }));
        assert!(!set.admits(Peer::Unknown));
    }

    #[test]
    fn the_kernel_names_the_peer_on_linux_only() {
        let (a, _b) = UnixStream::pair().unwrap();
        match of(&a) {
            #[cfg(target_os = "linux")]
            Peer::Cred { uid, .. } => {
                use std::os::unix::fs::MetadataExt;
                let probe = std::env::temp_dir().join(format!("kira-peer-{}", std::process::id()));
                std::fs::write(&probe, b"x").unwrap();
                let owner = std::fs::metadata(&probe).unwrap().uid();
                let _ = std::fs::remove_file(&probe);
                assert_eq!(uid, owner);
            }
            peer => assert!(!supported() && peer == Peer::Unknown, "{peer:?}"),
        }
    }
}
