// SPDX-License-Identifier: AGPL-3.0-or-later
//! Body HTTP contracts. Runtime entry points remain unimplemented in wave 0.
#![forbid(unsafe_code)]

pub mod api;
pub mod approvals;
pub mod assets;
pub mod claim;
pub mod documents;
pub mod fd4;
pub mod ingress;
pub mod owner_origin;
pub mod preload;
pub mod session;
pub mod shell;
pub mod sites;
pub mod tls;
