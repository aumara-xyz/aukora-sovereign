// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who is on the other end of the door socket.

use std::os::unix::net::UnixStream;

/// The caller of one connection, as the kernel reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// `SO_PEERCRED` uid (Linux).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Uid(u32),
    /// The platform cannot say. Only acceptable when the policy relies on the socket's own permissions.
    Unknown,
}

/// Read the connecting process's credentials from the kernel.
#[cfg(target_os = "linux")]
pub fn of(stream: &UnixStream) -> Peer {
    match rustix::net::sockopt::socket_peercred(stream) {
        Ok(credentials) => Peer::Uid(credentials.uid.as_raw()),
        Err(_) => Peer::Unknown,
    }
}

/// Only Linux reports peer credentials without unsafe code; elsewhere the policy must use socket permissions.
#[cfg(not(target_os = "linux"))]
pub fn of(_stream: &UnixStream) -> Peer {
    Peer::Unknown
}

/// Whether this platform can enforce a uid allowlist.
pub const fn peercred_supported() -> bool {
    cfg!(target_os = "linux")
}
