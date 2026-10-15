//! A portable snapshot; its embedded key and head are observations, not independent trust.

use canon::{canonical_json, Value};
use ed25519_dalek::VerifyingKey;
use rusqlite::Connection;

use crate::{merkle, scan_verified_entries, walk, Entry, Error, MAX_BUFFER_BYTES};

fn row_value(entry: &Entry) -> Value {
    Value::Object(vec![
        ("seq".into(), Value::Integer(entry.sequence as i64)),
        ("prev".into(), Value::String(entry.prev.clone())),
        ("hash".into(), Value::String(entry.hash.clone())),
        ("sig".into(), Value::String(entry.sig.clone())),
        ("at".into(), Value::Integer(entry.at)),
        ("kind".into(), Value::String(entry.kind.clone())),
        ("actor".into(), Value::String(entry.actor.clone())),
        ("op".into(), Value::String(entry.op.clone())),
        ("phase".into(), Value::String(entry.phase.clone())),
        ("body".into(), entry.body.clone()),
    ])
}

#[derive(Default)]
struct Proof {
    rows: Vec<u8>,
    hashes: Vec<merkle::Hash>,
}

impl Proof {
    fn push(&mut self, entry: &Entry, hash: merkle::Hash, budget: usize) -> Result<(), Error> {
        let row = canonical_json(&row_value(entry)).map_err(crate::invalid_body)?;
        // Bound both encoded rows and the digest buffer before retaining them.
        if self
            .rows
            .len()
            .saturating_add(row.len() + 1)
            .saturating_add((self.hashes.len() + 1).saturating_mul(32))
            > budget
        {
            return Err(Error::new("aura:memory-limit").at(entry.sequence));
        }
        if !self.rows.is_empty() {
            self.rows.push(b',');
        }
        self.rows.extend(row);
        self.hashes.push(hash);
        Ok(())
    }

    fn finish(self, key: &VerifyingKey) -> Result<Vec<u8>, Error> {
        let head = merkle::retained_head(&self.hashes, self.hashes.len())?.to_json()?;
        let mut bytes = format!(
            "{{\"head\":{head},\"publicKey\":\"{}\",\"rows\":[",
            hex::encode(key.as_bytes())
        )
        .into_bytes();
        bytes.extend(self.rows);
        bytes.extend_from_slice(b"],\"schema\":\"aukora-aura-cold-proof-v1\"}");
        if bytes.len() > MAX_BUFFER_BYTES {
            return Err(Error::new("aura:memory-limit"));
        }
        // The complete transport must satisfy C1, including its enclosing objects.
        canon::parse(&bytes).map_err(crate::invalid_body)?;
        Ok(bytes)
    }
}

/// Keep the downloaded file outside the node; verification can pin another retained head.
pub fn export_cold_proof(entries: &[Entry], key: &VerifyingKey) -> Result<Vec<u8>, Error> {
    walk(entries, key, None)?;
    let mut proof = Proof::default();
    for entry in entries {
        proof.push(entry, crate::digest(&entry.hash)?, MAX_BUFFER_BYTES)?;
    }
    proof.finish(key)
}

/// Authenticate and export full rows, public key and covering head from one SQLite snapshot.
pub fn export_cold_proof_database(
    connection: &Connection,
    key: &VerifyingKey,
) -> Result<Vec<u8>, Error> {
    let mut proof = Proof::default();
    scan_verified_entries(connection, key, None, |entry, hash| {
        proof.push(&entry, hash, MAX_BUFFER_BYTES)
    })?;
    proof.finish(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn antibody_cold_export_bounds_encoded_rows_and_hashes() {
        let entry = Entry {
            sequence: 1,
            prev: crate::DOMAIN.into(),
            hash: "00".repeat(32),
            sig: String::new(),
            at: 0,
            kind: "boot.facts".into(),
            actor: "supervisor".into(),
            op: String::new(),
            phase: "fact".into(),
            body: Value::Object(vec![]),
        };
        let budget = canonical_json(&row_value(&entry)).unwrap().len() + 32;
        assert_eq!(
            Proof::default()
                .push(&entry, [0; 32], budget)
                .unwrap_err()
                .code,
            "aura:memory-limit"
        );
        Proof::default().push(&entry, [0; 32], budget + 1).unwrap();
    }

    #[test]
    fn antibody_cold_export_bounds_complete_document() {
        let proof = Proof {
            rows: vec![b'0'; MAX_BUFFER_BYTES],
            hashes: vec![[0; 32]],
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]).verifying_key();
        assert_eq!(proof.finish(&key).unwrap_err().code, "aura:memory-limit");
    }
}
