// SPDX-License-Identifier: AGPL-3.0-or-later
//! What the wire shows of a note: who may read it, its validity, lifecycle state, evidence and corrections.

use super::*;

/// `current`, `expired` (past its `valid_to`) or `not-yet-valid` (before its `valid_from`) at time `at`.
pub(super) fn validity(meta: &crate::shared::note::NoteMeta, at: u64) -> &'static str {
    crate::shared::hybrid::validity(meta, at)
}

/// May `caller` read `note`? The owner reads everything. Anyone else reads the scopes it is registered for, but not a
/// `local` note (unless it wrote it itself: an agent is not locked out of its own note) and not another agent's
/// `resume:<name>` handoff.
pub(super) fn visible(caller: &Caller, note: &StoredNote) -> bool {
    let own = hex(note.event.pubkey.as_bytes()) == caller.pubkey;
    (caller.owner || own || note.meta.privacy != Privacy::Local)
        && slot_readable_by(note.meta.slot.as_deref(), own, caller.owner)
        && caller.reads_scope(&note.meta.scope)
}

/// The note that stands where a superseded `note` once did, when this caller may read it (an id the caller cannot read
/// is not revealed). `None` for a live note. A store error is an error, never "no current note".
pub(super) fn current_visible(store: &SharedStore, caller: &Caller, note: &StoredNote) -> Result<Option<String>> {
    let Some(id) = note.current_id.as_deref() else { return Ok(None) };
    Ok(store.get(id)?.filter(|current| visible(caller, current)).map(|current| hex(current.event.id.as_bytes())))
}

/// The ids among `ids` that name a note this caller may read. The rest are dropped without a trace (no per-id marker, no
/// count): an id of a note the caller cannot open would tell it that the note exists. Non-note entries are kept.
fn readable_ids(store: &SharedStore, caller: &Caller, ids: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for id in ids {
        if !is_hex64(id) || store.get(id)?.is_some_and(|n| visible(caller, &n)) {
            out.push(id.clone());
        }
    }
    Ok(out)
}

/// The corrections proposed against a live note that nobody entitled has accepted yet, as far as this caller may read
/// them: `{event, by, replacement, reason}` (`replacement` is null for a proposal to retract). A reviewer's proposal beside
/// the note, not yet in force. A proposal whose replacement note exists but is not readable by this caller is left out.
pub(super) fn proposals_visible(store: &SharedStore, caller: &Caller, note: &StoredNote) -> Result<Vec<Value>> {
    let id = hex(note.event.id.as_bytes());
    let mut out = Vec::new();
    for p in store.pending_corrections(&id)? {
        let replacement = match p.replacement.as_deref() {
            None => None,
            Some(rep) => match store.get(rep)? {
                Some(n) if visible(caller, &n) && !n.quarantined => Some(hex(n.event.id.as_bytes())),
                _ => continue,
            },
        };
        let by = store.agent(&p.by)?.map_or_else(|| "unknown".to_owned(), |a| a.name);
        out.push(json!({"event": p.event, "by": by, "replacement": replacement, "reason": p.reason}));
    }
    Ok(out)
}

/// Where a note stands in its life, computed from the relations the store holds, as far as this caller may read them:
/// `corrected` (a correction in force retired it; `current_id` says what stands now), `disputed` (a counterevidence
/// note cites it), `resolved` (it stands where a corrected note once did),
/// `supported` (it stands on the owner's words or review, an owner-run import, or roots by two different authors) and
/// `proposed` (a claim nobody has backed). It labels; it never changes what `found` means (a dispute is one note
/// away for anyone who can write, so it must not be able to veto an owner's decision). A store error fails the read:
/// it must not turn into "no dispute". Pending correction proposals are advisory metadata until accepted.
pub(super) fn lifecycle(store: &SharedStore, caller: &Caller, note: &StoredNote, evidence: &str) -> Result<&'static str> {
    if note.superseded_by.is_some() {
        return Ok("corrected");
    }
    let id = hex(note.event.id.as_bytes());
    for other in store.counter_evidence(&id)? {
        if store.get(&other)?.is_some_and(|n| {
            visible(caller, &n) && !n.quarantined && n.superseded_by.is_none() && validity(&n.meta, now()) == "current"
        }) {
            return Ok("disputed");
        }
    }
    Ok(if store.replaces_something(&id)? {
        "resolved"
    } else if evidence == "unverified" {
        "proposed"
    } else {
        "supported"
    })
}

/// A note as the wire shows it, built from a store read (which re-verified it). `evidence` is what a recall found the
/// statement to stand on (all its repeaters together); without one it is worked out from the note's own roots. `sources`
/// and `roots` list only notes this caller may read.
pub(super) fn note_json(store: &SharedStore, caller: &Caller, note: &StoredNote, evidence: Option<&str>) -> Result<Value> {
    let (m, current) = (&note.meta, current_visible(store, caller, note)?);
    let evidence = match evidence {
        Some(evidence) => evidence,
        None => crate::shared::hybrid::evidence_of(store, note, now(), &|n| visible(caller, n))?,
    };
    let (sources, roots) = (readable_ids(store, caller, &m.sources)?, readable_ids(store, caller, &note.roots)?);
    Ok(json!({
        "id": hex(note.event.id.as_bytes()), "seq": note.seq, "author": hex(note.event.pubkey.as_bytes()),
        "author_name": note.author_name, "created_at": note.event.created_at, "text": note.event.content,
        "subject": m.subject, "lane": m.lane.wire(), "form": m.form.wire(), "review": m.review.wire(),
        "privacy": m.privacy.wire(), "capture": m.capture.wire(), "scope": m.scope, "epoch": m.epoch,
        "sources": sources, "slot": m.slot, "valid_from": m.valid_from, "valid_to": m.valid_to,
        "roots": roots, "superseded_by": note.superseded_by, "current_id": current, "quarantined": note.quarantined,
        "validity": validity(&note.meta, now()), "proposals": proposals_visible(store, caller, note)?,
        "evidence": evidence, "state": lifecycle(store, caller, note, evidence)?,
        // A note that cites nothing the reader can see is, to that reader, a root of its own: nothing in the store
        // supports it but its author's word.
        "lineage": if sources.is_empty() { "unsupported" } else { "sourced" },
    }))
}

/// A quarantined note: that it existed, who signed it and its statement hash, never its text.
pub(super) fn stub(note: &StoredNote) -> Value {
    json!({
        "id": hex(note.event.id.as_bytes()), "author": hex(note.event.pubkey.as_bytes()),
        "created_at": note.event.created_at, "statement_hash": hex(&note.meta.statement_hash), "correction": "quarantined",
    })
}

/// The note; a stub if it is quarantined; for a note this caller may not read, only a receipt that it exists.
pub(super) fn view(store: &SharedStore, caller: &Caller, note: &StoredNote) -> Result<Value> {
    Ok(if !visible(caller, note) {
        json!({"id": hex(note.event.id.as_bytes()), "privacy": note.meta.privacy.wire(), "withheld": true})
    } else if note.quarantined {
        stub(note)
    } else {
        note_json(store, caller, note, None)?
    })
}
