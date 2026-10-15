use crate::{canonical, digest, exact_keys, field, object, sha256, string, Value};
use std::collections::BTreeMap;

pub fn check(row: &BTreeMap<String, Value>, aura_key: &[u8; 32]) -> Result<(), String> {
    let body = object(field(row, "body")?)?;
    if string(field(row, "phase")?)? != "fact"
        || !exact_keys(
            body,
            &[
                "schema",
                "node",
                "agent",
                "aura_key",
                "statement_sha256",
                "node_sig",
                "agent_sig",
            ],
        )
        || string(field(body, "schema")?)? != "aukora-nostr-bind-v1"
    {
        return Err("verifier:nostr-binding-shape".into());
    }
    if digest(field(body, "aura_key")?)? != *aura_key {
        return Err("verifier:nostr-aura-key".into());
    }
    let node = identity(field(body, "node")?)?;
    let agent = identity(field(body, "agent")?)?;
    let statement = Value::Object(
        [
            (
                "domain",
                Value::String("aukora:nostr-identity-binding:v1".into()),
            ),
            ("aura_key", field(body, "aura_key")?.clone()),
            ("node", Value::String(hex::encode(node))),
            ("agent", Value::String(hex::encode(agent))),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect(),
    );
    let statement_hash = sha256(&canonical(&statement));
    if statement_hash != digest(field(body, "statement_sha256")?)? {
        return Err("verifier:nostr-statement".into());
    }
    for (role, public_key) in [("node", node), ("agent", agent)] {
        let code = format!("verifier:nostr-{role}-signature");
        let signature = string(field(body, &format!("{role}_sig"))?)?;
        let signature = nostr::hex_decode::<64>(signature).map_err(|_| code.clone())?;
        nostr::verify(&public_key, &statement_hash, &signature).map_err(|_| code)?;
    }
    Ok(())
}

fn identity(value: &Value) -> Result<[u8; 32], String> {
    let identity = object(value)?;
    if !exact_keys(identity, &["pubkey", "npub"]) {
        return Err("verifier:nostr-binding-shape".into());
    }
    let public_key = digest(field(identity, "pubkey")?)?;
    let npub = nostr::npub_encode(&public_key).map_err(|_| "verifier:nostr-npub".to_owned())?;
    if string(field(identity, "npub")?)? != npub {
        return Err("verifier:nostr-npub".into());
    }
    Ok(public_key)
}
