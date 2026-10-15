// SPDX-License-Identifier: AGPL-3.0-or-later
use nostr::{event::Event, SecretKey};
use serde_json::{json, Value};
use std::{
    fs,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn event(key: &SecretKey, root: &str, at: u64, code: &str) -> Event {
    let body = json!({"schema":"aukora-node-invite-v1","root":root,
        "inviter_npub":nostr::npub_encode(&key.public_key()).unwrap(),"invitee_label":"Friend",
        "issued_at":at,"expires_at":at+172800,"code":code,"claim_sha256":"ab".repeat(32)});
    let content = String::from_utf8(
        canon::canonical_json(&canon::parse(&serde_json::to_vec(&body).unwrap()).unwrap()).unwrap(),
    )
    .unwrap();
    Event::sign(key, at, 39701, vec![vec!["d".into(), code.into()]], content).unwrap()
}

struct Fixture {
    directory: tempfile::TempDir,
    key: SecretKey,
    root: String,
    at: u64,
}
impl Fixture {
    fn new() -> Self {
        let directory =
            tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let key = SecretKey::from_bytes([59; 32]).unwrap();
        let root = nostr::npub_encode(&key.public_key()).unwrap();
        fs::write(
            directory.path().join("allowlist.json"),
            json!({"schema":"aukora-inviter-allowlist-v1","root":root,"members":[]}).to_string(),
        )
        .unwrap();
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            directory,
            key,
            root,
            at,
        }
    }
    fn spawn(&self, invite: &Event, name: &str) -> Output {
        fs::write(self.directory.path().join("invite.json"), invite.to_json()).unwrap();
        Command::new("bash")
            .arg(format!(
                "{}/../../deploy/spawn/spawn.sh",
                env!("CARGO_MANIFEST_DIR")
            ))
            .args([
                "create",
                name,
                "--on",
                "nebius-vm",
                "--spend-ok",
                "--invite",
            ])
            .arg(self.directory.path().join("invite.json"))
            .arg("--allowlist")
            .arg(self.directory.path().join("allowlist.json"))
            .env("AUKORA_SPAWN_STATE", self.directory.path().join("state"))
            .env("AUKORA_INVITE_VERIFIER", env!("CARGO_BIN_EXE_sovereign"))
            .env("AUKORA_VM_HOURLY_ESTIMATE", "0.01")
            .env_remove("AUKORA_NEBIUS_PARENT_ID")
            .output()
            .unwrap()
    }
    fn expect(&self, invite: &Event, name: &str, code: &str) {
        let output = self.spawn(invite, name);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let err = String::from_utf8(output.stderr).unwrap();
        assert!(err.contains(code), "expected {code}, got {err}");
    }
}

#[test]
fn antibody_spawn_checks_real_forged_expired_and_non_allowlisted_invites() {
    let f = Fixture::new();
    let mut forged = event(&f.key, &f.root, f.at, &"1".repeat(32));
    forged.sig[0] ^= 1;
    f.expect(&forged, "forged", "spawn:invite-signature");
    f.expect(
        &event(&f.key, &f.root, f.at - 172800, &"2".repeat(32)),
        "expired",
        "spawn:invite-expired",
    );
    let other = SecretKey::from_bytes([60; 32]).unwrap();
    f.expect(
        &event(&other, &f.root, f.at, &"3".repeat(32)),
        "stranger",
        "spawn:invite-not-allowlisted",
    );
    assert!(!f.directory.path().join("state/invites.sqlite3").exists());
}

#[test]
fn antibody_spawn_consumes_before_backend_and_reuse_cannot_allocate() {
    let f = Fixture::new();
    let invite = event(&f.key, &f.root, f.at, &"4".repeat(32));
    f.expect(&invite, "friend", "spawn:nebius-parent");
    let provenance: Value = serde_json::from_slice(
        &fs::read(
            f.directory
                .path()
                .join("state/nebius-vm/friend/invite.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(provenance["invite_event_id"], hex::encode(invite.id));
    assert_eq!(provenance["inviter_npub"], f.root);
    f.expect(&invite, "friend", "spawn:nebius-parent");
    f.expect(&invite, "second", "spawn:invite-reused");
    fs::remove_dir_all(f.directory.path().join("state/nebius-vm/friend")).unwrap();
    f.expect(&invite, "friend", "spawn:invite-reused");
}
