// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    digest, field, head, integer, json, merkle, object, verify_bundle, BundleInputs, Value,
};

#[derive(Debug, PartialEq, Eq)]
pub struct WitnessReport {
    pub witnessed_sequence: usize,
    pub proof_sequence: usize,
}

/// Checks a relay witness against authenticated entries, without granting authority.
pub fn verify_witness(proof: &[u8], event: &[u8]) -> Result<WitnessReport, String> {
    let event =
        nostr::event::Event::parse(event).map_err(|_| "verifier:witness-malformed".to_owned())?;
    if event.kind != 30078
        || event.tags != vec![vec!["d".to_owned(), "aukora-aura-head".to_owned()]]
    {
        return Err("verifier:witness-malformed".into());
    }
    let value = json::parse_canonical(event.content.as_bytes())
        .map_err(|_| "verifier:witness-malformed".to_owned())?;
    let map = object(&value).map_err(|_| "verifier:witness-malformed".to_owned())?;
    let sequence = field(map, "sequence").and_then(integer);
    let tree_size = field(map, "treeSize").and_then(integer);
    if !matches!((sequence, tree_size), (Ok(sequence), Ok(size)) if sequence == size && size > 0) {
        return Err("verifier:witness-size".into());
    }
    let witnessed =
        head(event.content.as_bytes()).map_err(|_| "verifier:witness-malformed".to_owned())?;
    let bundle = json::parse_canonical(proof).map_err(|_| "verifier:witness-proof".to_owned())?;
    let bundle = object(&bundle).map_err(|_| "verifier:witness-proof".to_owned())?;
    let rows = match bundle.get("rows") {
        Some(Value::Array(rows)) => rows,
        _ => return Err("verifier:witness-proof".into()),
    };
    let mut bindings = rows.iter().filter_map(|row| {
        let row = object(row).ok()?;
        (row.get("kind") == Some(&Value::String("nostr.bind".into()))).then_some(row)
    });
    let binding = bindings.next().ok_or("verifier:witness-binding")?;
    if bindings.next().is_some() {
        return Err("verifier:witness-binding".into());
    }
    let signer = (|| {
        let body = object(field(binding, "body")?)?;
        let node = object(field(body, "node")?)?;
        digest(field(node, "pubkey")?)
    })()
    .map_err(|_: String| "verifier:witness-binding".to_owned())?;
    if event.pubkey != signer {
        return Err("verifier:witness-signer".into());
    }
    let report = verify_bundle(BundleInputs {
        bundle: proof,
        pinned_key: None,
        checkpoint: None,
    });
    if report.verdict.exit_code() >= 2 {
        return Err("verifier:witness-proof".into());
    }
    if witnessed.size > rows.len() {
        return Err("verifier:witness-size".into());
    }
    let hashes = rows[..witnessed.size]
        .iter()
        .map(|row| digest(field(object(row)?, "hash")?))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "verifier:witness-proof".to_owned())?;
    let leaves = hashes.iter().map(merkle::leaf).collect::<Vec<_>>();
    if merkle::root(&leaves) != witnessed.root || hashes.last() != Some(&witnessed.hash) {
        return Err("verifier:witness-fork".into());
    }
    Ok(WitnessReport {
        witnessed_sequence: witnessed.size,
        proof_sequence: rows.len(),
    })
}
