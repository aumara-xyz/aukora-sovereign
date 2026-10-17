// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]

pub mod adapters;
mod approvals;
mod build;
mod config;
mod data;
mod door;
mod engine;
mod engine_plugins;
pub mod faces;
mod health;
mod host;
mod identity;
mod model_broker;
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
    if arguments.first().is_some_and(|command| command == "release") {
        return release::pointer::run(&arguments[1..]);
    }
    // The Rust door for the engine's crossings (engine/plugins/aukora-door): `door serve --socket PATH --policy FILE`.
    if arguments.first().is_some_and(|command| command == "door") {
        return door::run(&arguments[1..]);
    }
    // The engine's root closure step (deploy/units/aukora-engine.service): `engine closure --control D --from D --to D`.
    if arguments.first().is_some_and(|command| command == "engine") {
        return engine::cli(&arguments[1..]);
    }
    // Kira 2, the shared memory service on the Mac: serve, register, token, import, mcp.
    if arguments.first().is_some_and(|command| command == "kira") {
        return kira::shared::service::cli(&arguments[1..]);
    }
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
