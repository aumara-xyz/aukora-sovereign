// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cage interfaces frozen in wave 0. Kernel operations remain row-labelled stubs.
//! No stub reports a launched guest, installed restriction or recorded boot.

#![warn(missing_docs)]

pub mod boot;
pub mod cage;
pub mod cgroup;
pub mod landlock;
pub mod netns;
pub mod profiles;
pub mod seccomp;
