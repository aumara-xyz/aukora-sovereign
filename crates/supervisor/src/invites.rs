// SPDX-License-Identifier: AGPL-3.0-or-later
use anyhow::{bail, Result};
use nostr::{event::Event, SecretKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fs, io::Read, path::Path};

pub const TTL_SECONDS: u64 = 48 * 60 * 60;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub schema: String,
    pub event: Value,
    pub invite_event_id: String,
    pub inviter_npub: String,
    pub claim_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    schema: String,
    root: String,
    inviter_npub: String,
    invitee_label: String,
    issued_at: u64,
    expires_at: u64,
    code: String,
    claim_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowlist {
    schema: String,
    root: String,
    members: Vec<String>,
}

fn statement(event: &Event) -> Result<Statement> {
    event
        .verify()
        .map_err(|_| anyhow::anyhow!("spawn:invite-signature"))?;
    let parsed = canon::parse(event.content.as_bytes())
        .map_err(|_| anyhow::anyhow!("spawn:invite-shape"))?;
    if canon::canonical_json(&parsed)? != event.content.as_bytes() {
        bail!("spawn:invite-shape");
    }
    let body: Statement =
        serde_json::from_str(&event.content).map_err(|_| anyhow::anyhow!("spawn:invite-shape"))?;
    if event.kind != 39701
        || body.schema != "aukora-node-invite-v1"
        || !hex(&body.code, 32)
        || !hex(&body.claim_sha256, 64)
        || body.invitee_label.is_empty()
        || body.invitee_label.len() > 128
        || body.invitee_label.chars().any(char::is_control)
        || event.tags != vec![vec!["d".to_owned(), body.code.clone()]]
        || nostr::npub_encode(&event.pubkey)? != body.inviter_npub
        || nostr::npub_decode(&body.root).is_err()
        || body.issued_at != event.created_at
        || body.issued_at.checked_add(TTL_SECONDS) != Some(body.expires_at)
    {
        bail!("spawn:invite-shape");
    }
    Ok(body)
}

pub fn signed_invite(
    key: &SecretKey,
    root: &str,
    label: &str,
    claim_sha256: &str,
    at: u64,
    code: &str,
) -> Result<Event> {
    let draft = invite_draft(key, root, label, claim_sha256, at, code)?;
    let event = Event::sign(
        key,
        at,
        39701,
        vec![vec!["d".into(), code.into()]],
        draft["content"].as_str().unwrap().into(),
    )?;
    statement(&event)?;
    Ok(event)
}

pub fn invite_draft(
    key: &SecretKey,
    root: &str,
    label: &str,
    claim_sha256: &str,
    at: u64,
    code: &str,
) -> Result<Value> {
    if nostr::npub_decode(root).is_err()
        || label.is_empty()
        || label.len() > 128
        || label.chars().any(char::is_control)
        || !hex(claim_sha256, 64)
        || !hex(code, 32)
    {
        bail!("spawn:invite-shape");
    }
    let body = json!({"schema":"aukora-node-invite-v1","root":root,
        "inviter_npub":nostr::npub_encode(&key.public_key())?,"invitee_label":label,
        "issued_at":at,"expires_at":at.checked_add(TTL_SECONDS).ok_or_else(||anyhow::anyhow!("spawn:invite-shape"))?,
        "code":code,"claim_sha256":claim_sha256});
    Ok(
        json!({"created_at":at,"kind":39701,"pubkey":hex::encode(key.public_key()),
        "tags":[["d",code]],"content":String::from_utf8(crate::node::canon_bytes(&body)?)?}),
    )
}

pub fn admission(event: &Event) -> Result<Admission> {
    let body = statement(event)?;
    Ok(Admission {
        schema: "aukora-spawn-invite-v1".into(),
        event: serde_json::from_str(&event.to_json())?,
        invite_event_id: hex::encode(event.id),
        inviter_npub: body.inviter_npub,
        claim_sha256: body.claim_sha256,
    })
}

pub fn validate_admission(value: &Admission) -> Result<()> {
    let event = Event::parse(&serde_json::to_vec(&value.event)?)
        .map_err(|_| anyhow::anyhow!("spawn:invite-signature"))?;
    let expected = admission(&event)?;
    if value.schema != expected.schema
        || value.invite_event_id != expected.invite_event_id
        || value.inviter_npub != expected.inviter_npub
        || value.claim_sha256 != expected.claim_sha256
    {
        bail!("spawn:invite-provenance");
    }
    Ok(())
}

pub fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        bail!("spawn:invite-shape");
    }
    Ok(bytes)
}

pub fn check_files(args: &[String]) -> Result<()> {
    if args.len() != 4 {
        bail!("spawn:invite-usage");
    }
    let event = Event::parse(&bounded_read(Path::new(&args[0]))?)
        .map_err(|_| anyhow::anyhow!("spawn:invite-signature"))?;
    let allowlist = bounded_read(Path::new(&args[1]))?;
    let now = u64::try_from(crate::state::now_ms()?)? / 1000;
    let admitted = consume(&event, &allowlist, Path::new(&args[2]), &args[3], now)?;
    println!(
        "{}",
        json!({"schema":admitted.schema,"event":admitted.event,
        "invite_event_id":admitted.invite_event_id,"inviter_npub":admitted.inviter_npub,
        "claim_sha256":admitted.claim_sha256})
    );
    Ok(())
}

fn consume(
    event: &Event,
    allowlist: &[u8],
    state: &Path,
    allocation: &str,
    now: u64,
) -> Result<Admission> {
    let body = statement(event)?;
    if now < body.issued_at {
        bail!("spawn:invite-future");
    }
    if now >= body.expires_at {
        bail!("spawn:invite-expired");
    }
    canon::parse(allowlist).map_err(|_| anyhow::anyhow!("spawn:invite-allowlist"))?;
    let list: Allowlist =
        serde_json::from_slice(allowlist).map_err(|_| anyhow::anyhow!("spawn:invite-allowlist"))?;
    if list.schema != "aukora-inviter-allowlist-v1"
        || list.root != body.root
        || nostr::npub_decode(&list.root).is_err()
        || list.members.len() > 1024
        || list
            .members
            .iter()
            .any(|member| nostr::npub_decode(member).is_err())
        || !(body.inviter_npub == list.root || list.members.contains(&body.inviter_npub))
    {
        bail!("spawn:invite-not-allowlisted");
    }
    if allocation.is_empty() || allocation.len() > 256 {
        bail!("spawn:invite-allocation");
    }
    private_directory(state)?;
    let path = state.join("invites.sqlite3");
    for name in [
        "invites.sqlite3",
        "invites.sqlite3-journal",
        "invites.sqlite3-wal",
        "invites.sqlite3-shm",
    ] {
        private_file(&state.join(name), name == "invites.sqlite3")?;
    }
    let mut db = Connection::open(&path)?;
    db.execute_batch("PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS network(root TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS consumed(event TEXT PRIMARY KEY, inviter TEXT NOT NULL, code TEXT NOT NULL, allocation TEXT NOT NULL UNIQUE, UNIQUE(inviter,code));
        CREATE TRIGGER IF NOT EXISTS consumed_pin BEFORE UPDATE ON consumed BEGIN SELECT RAISE(ABORT,'spawn:invite-reused'); END;
        CREATE TRIGGER IF NOT EXISTS consumed_retain BEFORE DELETE ON consumed BEGIN SELECT RAISE(ABORT,'spawn:invite-reused'); END;")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network: Option<String> = tx
        .query_row("SELECT root FROM network", [], |r| r.get(0))
        .optional()?;
    if network.as_ref().is_some_and(|root| root != &body.root) {
        bail!("spawn:invite-network");
    }
    if network.is_none() {
        tx.execute("INSERT INTO network VALUES(?)", [&body.root])?;
    }
    let id = hex::encode(event.id);
    let used: Option<(String,String)> = tx.query_row(
        "SELECT event,allocation FROM consumed WHERE event=?1 OR (inviter=?2 AND code=?3) OR allocation=?4",
        params![id,body.inviter_npub,body.code,allocation], |r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((prior_id, prior_allocation)) = used {
        if prior_id != id || prior_allocation != allocation {
            bail!("spawn:invite-reused");
        }
    } else {
        tx.execute(
            "INSERT INTO consumed VALUES(?1,?2,?3,?4)",
            params![id, body.inviter_npub, body.code, allocation],
        )?;
    }
    tx.commit()?;
    fs::File::open(state)?.sync_all()?;
    admission(event)
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let info = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no arguments and does not change process state.
    let uid = unsafe { libc::geteuid() };
    if !path.is_absolute() || !info.is_dir() || info.mode() & 0o077 != 0 || info.uid() != uid {
        bail!("spawn:invite-state");
    }
    for ancestor in path.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            bail!("spawn:invite-state");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn private_file(path: &Path, create: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !create {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) => (),
        }
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    // SAFETY: geteuid has no arguments and does not change process state.
    let uid = unsafe { libc::geteuid() };
    if !info.is_file() || info.nlink() != 1 || info.mode() & 0o077 != 0 || info.uid() != uid {
        bail!("spawn:invite-state");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(at: u64) -> (tempfile::TempDir, Event, Vec<u8>) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = SecretKey::from_bytes([59; 32]).unwrap();
        let root = nostr::npub_encode(&key.public_key()).unwrap();
        let event = signed_invite(
            &key,
            &root,
            "Friend",
            &"ab".repeat(32),
            at,
            &"cd".repeat(16),
        )
        .unwrap();
        let list = serde_json::to_vec(
            &json!({"schema":"aukora-inviter-allowlist-v1","root":root,"members":[]}),
        )
        .unwrap();
        (dir, event, list)
    }
    #[test]
    fn antibody_invite_forgery_is_refused() {
        let (dir, mut event, list) = fixture(100);
        event.sig[0] ^= 1;
        assert_eq!(
            consume(&event, &list, dir.path(), "one", 101)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-signature"
        );
    }
    #[test]
    fn antibody_invite_expiry_and_future_are_refused() {
        let (dir, event, list) = fixture(100);
        assert_eq!(
            consume(&event, &list, dir.path(), "one", 100 + TTL_SECONDS)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-expired"
        );
        assert_eq!(
            consume(&event, &list, dir.path(), "one", 99)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-future"
        );
        consume(&event, &list, dir.path(), "one", 100).unwrap();
    }
    #[test]
    fn antibody_invite_reuse_survives_node_deletion() {
        let (dir, event, list) = fixture(100);
        consume(&event, &list, dir.path(), "one", 101).unwrap();
        consume(&event, &list, dir.path(), "one", 102).unwrap();
        assert_eq!(
            consume(&event, &list, dir.path(), "two", 102)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-reused"
        );
        let db = Connection::open(dir.path().join("invites.sqlite3")).unwrap();
        assert!(db.execute("DELETE FROM consumed", []).is_err());
        assert!(db
            .execute("UPDATE consumed SET allocation='two'", [])
            .is_err());
    }
    #[test]
    fn antibody_invite_allowlist_and_root_are_required() {
        let (dir, event, _) = fixture(100);
        let other =
            nostr::npub_encode(&SecretKey::from_bytes([60; 32]).unwrap().public_key()).unwrap();
        let list = serde_json::to_vec(
            &json!({"schema":"aukora-inviter-allowlist-v1","root":other,"members":[nostr::npub_encode(&event.pubkey).unwrap()]}),
        )
        .unwrap();
        assert_eq!(
            consume(&event, &list, dir.path(), "one", 101)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-not-allowlisted"
        );
        let root = nostr::npub_encode(&event.pubkey).unwrap();
        let key = SecretKey::from_bytes([60; 32]).unwrap();
        let event = signed_invite(
            &key,
            &root,
            "Friend",
            &"ab".repeat(32),
            100,
            &"cd".repeat(16),
        )
        .unwrap();
        let list = serde_json::to_vec(
            &json!({"schema":"aukora-inviter-allowlist-v1","root":root,"members":[]}),
        )
        .unwrap();
        assert_eq!(
            consume(&event, &list, dir.path(), "one", 101)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-not-allowlisted"
        );
    }
    #[test]
    fn antibody_invite_shape_and_provenance_are_bound() {
        let (_, event, _) = fixture(100);
        let mut admitted = admission(&event).unwrap();
        validate_admission(&admitted).unwrap();
        admitted.claim_sha256 = "00".repeat(32);
        assert_eq!(
            validate_admission(&admitted).unwrap_err().to_string(),
            "spawn:invite-provenance"
        );
        let key = SecretKey::from_bytes([59; 32]).unwrap();
        let padded = Event::sign(
            &key,
            100,
            39701,
            event.tags.clone(),
            format!(" {}", event.content),
        )
        .unwrap();
        assert_eq!(
            statement(&padded).err().unwrap().to_string(),
            "spawn:invite-shape"
        );
        let mut value: Value = serde_json::from_str(&event.content).unwrap();
        value["expires_at"] = json!(100 + TTL_SECONDS + 1);
        let altered = Event::sign(&key, 100, 39701, event.tags, value.to_string()).unwrap();
        assert_eq!(
            statement(&altered).err().unwrap().to_string(),
            "spawn:invite-shape"
        );
    }

    #[test]
    fn antibody_invite_state_is_private_and_consumed_codes_cannot_be_reassigned() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (dir, event, list) = fixture(100);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            consume(&event, &list, dir.path(), "one", 101)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-state"
        );
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        symlink(
            dir.path().join("missing"),
            dir.path().join("invites.sqlite3-journal"),
        )
        .unwrap();
        assert!(consume(&event, &list, dir.path(), "one", 101).is_err());
        fs::remove_file(dir.path().join("invites.sqlite3-journal")).unwrap();
        consume(&event, &list, dir.path(), "one", 101).unwrap();
        let mut body: Value = serde_json::from_str(&event.content).unwrap();
        body["invitee_label"] = json!("Someone else");
        let key = SecretKey::from_bytes([59; 32]).unwrap();
        let changed = Event::sign(&key, 100, 39701, event.tags.clone(), body.to_string()).unwrap();
        assert_eq!(
            consume(&changed, &list, dir.path(), "two", 101)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-reused"
        );
        let replacement = signed_invite(
            &key,
            &nostr::npub_encode(&key.public_key()).unwrap(),
            "Friend",
            &"ab".repeat(32),
            100,
            &"ee".repeat(16),
        )
        .unwrap();
        assert_eq!(
            consume(&replacement, &list, dir.path(), "one", 101)
                .err()
                .unwrap()
                .to_string(),
            "spawn:invite-reused"
        );
    }
}
