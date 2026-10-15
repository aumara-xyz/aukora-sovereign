// SPDX-License-Identifier: AGPL-3.0-or-later
//! Supervisor wiring contracts. Runtime bodies are assigned to rows 23, 128 and 130.
#![forbid(unsafe_code)]

pub mod ingress;
pub mod observations;
pub mod router;
pub mod runtime;
pub mod services;
pub mod session;
pub mod transport;

pub mod exit;
