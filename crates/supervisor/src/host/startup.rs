// SPDX-License-Identifier: AGPL-3.0-or-later
use canon::Result;
use std::fs::File;

pub(super) fn require_initial_sessions(
    transaction: &aura::LedgerTxn<'_>,
    sessions: &File,
) -> Result<()> {
    let missing = canon::Refusal {
        organ: "supervisor",
        reason: "sessions-missing",
    };
    // Claims are served only after genesis commits. An empty install context also
    // permits restarting a first boot interrupted after node identity creation.
    let (context, _, _) = transaction.floor_install_context().map_err(|_| missing)?;
    if context.sequence != 1 || context.previous_hash.is_some() {
        return Err(missing);
    }
    let mut entries = rustix::fs::Dir::read_from(sessions).map_err(|_| missing)?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|_| missing)?;
        match entry.file_name().to_bytes() {
            b"." | b".." | b"sessions.lock" => {}
            // Retain claim databases, their sidecars and incomplete session writes.
            _ => return Err(missing),
        }
    }
    Ok(())
}

/// Stop accepting requests before joining the bounded blocking relay worker.
pub(super) async fn serve_until_shutdown(host: std::sync::Arc<super::Host>) -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| canon::codes::SUPERVISOR_STATE)?;
    tokio::select! {
        result = crate::web::serve_handoff(host) => result,
        _ = terminate.recv() => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
