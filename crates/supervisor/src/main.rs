// SPDX-License-Identifier: AGPL-3.0-or-later
//! Node supervisor and confined development runner.

mod boot_probe;
mod config;
mod dispatcher;
#[cfg(test)]
mod e2e;
mod immune;
mod invites;
mod ledger;
mod node;
mod nostr_identity;
mod nostr_messaging;
mod nostr_witness;
mod openviking;
mod organs;
mod owner;
mod reboot_floor;
#[cfg(test)]
mod refresh_http_tests;
#[cfg(test)]
mod refusal_visibility_tests;
mod release_immune;
#[cfg(test)]
mod release_immune_tests;
#[cfg(test)]
mod release_stale_tests;
mod runtime;
mod state;

#[cfg(target_os = "linux")]
mod devrun;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        #[cfg(target_os = "linux")]
        Some("devrun") => devrun::run(&args[1..]),
        Some("serve") => serve(config_path(&args[1..])?).await,
        Some("claim-link") => claim_link(config_path(&args[1..])?),
        Some("invite-check") => invites::check_files(&args[1..]),
        Some("invite-card") => invite_binding(&args[1..], false),
        Some("invite-issue") => invite_binding(&args[1..], true),
        Some("floor-evidence") => floor_evidence(config_path(&args[1..])?),
        Some("immune-check") if args.len() == 1 => immune_check().await,
        _ => {
            eprintln!("usage: sovereign serve --config FILE | claim-link --config FILE | invite-card --config FILE --request FILE | invite-issue --config FILE --request FILE | invite-check INVITE ALLOWLIST STATE ALLOCATION | floor-evidence --config FILE | immune-check | devrun [options]");
            std::process::exit(2)
        }
    }
}

fn invite_binding(args: &[String], issue: bool) -> anyhow::Result<()> {
    use std::io::Read;
    if args.len() != 4 || args[0] != "--config" || args[2] != "--request" {
        anyhow::bail!("invites:usage");
    }
    private_umask();
    let config = config::Config::load(std::path::Path::new(&args[1]))?;
    state::private_file(&config.state_dir.join("node.ed25519"))?;
    state::private_file(&config.state_dir.join("node.sqlite3"))?;
    let signer = std::sync::Arc::new(state::node_key(&config.state_dir)?);
    let mut db = state::connection(&config.state_dir.join("node.sqlite3"))?;
    let stored: String = db.query_row("SELECT id FROM supervisor_node", [], |row| row.get(0))?;
    if stored != config.node_id {
        anyhow::bail!("supervisor:node-mismatch");
    }
    let identity = nostr_identity::Identity::open(&mut db, signer.clone())?;
    let mut owner = owner::Owner::open(
        db,
        config.node_id,
        config.webauthn.rp_id,
        config.webauthn.origin,
        signer,
    )
    .map_err(|e| anyhow::anyhow!(e.code))?;
    let mut bytes = Vec::new();
    std::fs::File::open(&args[3])?
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        anyhow::bail!("invites:shape");
    }
    canon::parse(&bytes)?;
    let request = serde_json::from_slice(&bytes)?;
    let result = if issue {
        owner.invite_issue(request, identity.node_key())
    } else {
        owner.invite_card(request, identity.node_key())
    };
    println!("{}", result.map_err(|e| anyhow::anyhow!(e.code))?);
    Ok(())
}

async fn immune_check() -> anyhow::Result<()> {
    let corpus = ::immune::Corpus::embedded()?;
    let handle = tokio::runtime::Handle::current();
    let report =
        tokio::task::spawn_blocking(move || immune::replay(&corpus, immune::REPLAY_BUDGET, handle))
            .await??;
    println!("antibody_corpus_sha256 {}", report.root);
    println!("antibody_pass_count {}/{}", report.passed, report.total);
    if let Some(code) = report.refusal_code() {
        anyhow::bail!(code);
    }
    Ok(())
}

fn config_path(args: &[String]) -> anyhow::Result<&std::path::Path> {
    if args.len() != 2 || args[0] != "--config" {
        anyhow::bail!("supervisor:config-required");
    }
    Ok(std::path::Path::new(&args[1]))
}
fn claim_link(path: &std::path::Path) -> anyhow::Result<()> {
    private_umask();
    let config = config::Config::load(path)?;
    // Claim creation can run beside serve, but cannot provision a second node key.
    let key_path = config.state_dir.join("node.ed25519");
    let lock = if key_path.exists() {
        None
    } else {
        Some(state::prepare(&config.state_dir)?)
    };
    let signer = std::sync::Arc::new(state::node_key(&config.state_dir)?);
    let mut owner = owner::Owner::open(
        state::connection(&config.state_dir.join("node.sqlite3"))?,
        config.node_id,
        config.webauthn.rp_id,
        config.webauthn.origin,
        signer,
    )
    .map_err(|e| anyhow::anyhow!(e.code))?;
    let token = owner.create_claim().map_err(|e| anyhow::anyhow!(e.code))?;
    println!("{}/#claim={token}", config.owner_origin);
    drop(lock);
    Ok(())
}
fn floor_evidence(path: &std::path::Path) -> anyhow::Result<()> {
    private_umask();
    let config = config::Config::load(path)?;
    println!(
        "{}",
        serde_json::to_string(&reboot_floor::export_existing(&config)?)?
    );
    Ok(())
}
async fn serve(path: &std::path::Path) -> anyhow::Result<()> {
    private_umask();
    let config = config::Config::load(path)?;
    let node = node::Node::open(config.clone(), tokio::runtime::Handle::current())?;
    let mut settings = frontdoor::Config::behind_proxy(
        config.node_id,
        config.owner_hostname,
        config.chat_hostname,
        config.state_dir.join("sockets/ui.sock"),
        config.trusted_proxy.peers,
    );
    settings.session_lifetime = std::time::Duration::from_secs(config.limits.session_seconds);
    settings.request_timeout = std::time::Duration::from_secs(config.limits.request_seconds);
    settings.max_body_bytes = config.limits.max_body_bytes;
    settings.max_connections = config.limits.max_connections;
    let frontdoor =
        frontdoor::Frontdoor::new(settings, node.clone()).map_err(|e| anyhow::anyhow!(e.code))?;
    *node
        .frontdoor
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor:lock"))? = std::sync::Arc::downgrade(&frontdoor);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let runtime = runtime::start(node.clone(), node.runtime_config())?;
    let guest = async move {
        loop {
            if runtime.is_finished() {
                return runtime
                    .join()
                    .map_err(|_| anyhow::anyhow!("runtime:thread-panicked"))?;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    };
    tokio::select! {
        result=frontdoor.serve(listener)=>{result?;}
        result=guest=>{result?;anyhow::bail!("runtime:stopped");}
    }
    Ok(())
}
fn private_umask() {
    // SAFETY: the supervisor sets its umask before creating state or guest workers.
    unsafe {
        libc::umask(0o077);
    }
}
