// SPDX-License-Identifier: AGPL-3.0-or-later
//! Auma's bounded harness contracts. Runtime attachment remains fail-closed.
#![forbid(unsafe_code)]

pub mod action_gate;
pub mod agent_loop;
pub mod compaction;
pub mod context;
pub mod dispatch;
pub mod fd3;
pub mod fd4;
pub mod presets;
pub mod rails;
pub mod session;
pub mod sites;

fn main() -> std::process::ExitCode {
    eprintln!("guest:runtime-not-attached");
    std::process::ExitCode::FAILURE
}
