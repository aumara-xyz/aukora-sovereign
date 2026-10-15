// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay contracts for rows 54 and 70. Operational entry points remain row stubs.
//! No stub establishes a connection, verifies a witness or reports publication.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod egress;
pub mod witness;

pub use auth::AuthContext;
pub use client::{Client, Filter, PublishAck, QueryResult, RelayTransport};
pub use egress::{EgressPolicy, RelayRule, ValidatedRelay};
pub use witness::{HeadExpectation, HeadWitness, RetainedHeadV1};

/// A relay operation reports an owning-organ refusal through canon.
pub type Result<T> = canon::Result<T>;
