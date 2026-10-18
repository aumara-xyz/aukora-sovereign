// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host-owned adapters pass typed requests to organs without guest descriptors.

pub mod approval;
pub mod approvals;
pub mod broker;
pub mod gate;
pub mod kira;
pub mod ledger;
pub mod messaging;
pub mod runtime;
pub mod snapshot;
pub(crate) mod slider;

pub use broker::BrokerAdapter;
pub use gate::GateAdapter;
pub use ledger::{HostClock, HostLedger};
