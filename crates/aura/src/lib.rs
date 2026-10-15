// SPDX-License-Identifier: AGPL-3.0-or-later
//! Aura's wave-0 contracts. Storage and verification entry points refuse until wave 1.
#![forbid(unsafe_code)]

pub mod export;
pub mod ledger;
pub mod merkle;
pub mod record;
pub mod schema;
pub mod storage;

pub use ledger::{Ledger, LedgerTxn, RecordSigner, TransactionServices, TrustedClock};

pub(crate) fn unavailable<T>() -> canon::Result<T> {
    Err(canon::codes::AURA_UNVERIFIED)
}
