// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

pub mod adapters;
mod approvals;
mod config;
mod data;
pub mod faces;
mod health;
mod host;
mod identity;
mod release;
mod state;
mod web;

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

fn run() -> canon::Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let [command, option, path] = arguments.as_slice() else {
        return Err(canon::Refusal {
            organ: "supervisor",
            reason: "usage",
        });
    };
    if command != "serve" || option != "--config" {
        return Err(canon::Refusal {
            organ: "supervisor",
            reason: "usage",
        });
    }
    let config = config::NodeConfig::load(std::path::Path::new(path))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| canon::codes::SUPERVISOR_STATE)?;
    runtime.block_on(host::serve(config))
}
