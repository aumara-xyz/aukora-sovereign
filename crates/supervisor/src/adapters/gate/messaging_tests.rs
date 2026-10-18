// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use canon::digest::Digest32;
use canon::ids::SubjectId;
use ed25519_dalek::{Signer, SigningKey};

struct SignerKey(SigningKey);
impl aura::RecordSigner for SignerKey {
    fn public_keys(&self) -> Result<Vec<canon::alg::PublicKey>> {
        Ok(vec![canon::alg::PublicKey {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.verifying_key().to_bytes().to_vec(),
        }])
    }
    fn sign_entry_hash(&self, hash: Digest32) -> Result<canon::alg::Signatures> {
        canon::alg::Signatures::new(vec![canon::alg::Signature {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.sign(hash.as_bytes()).to_bytes().to_vec(),
        }])
    }
}

#[test]
fn guest_proposals_cannot_reach_any_messaging_target() {
    let path = std::env::temp_dir().join(format!("guest-messaging-{}", hex::encode(random::<8>())));
    std::fs::create_dir_all(&path).unwrap();
    let path = std::fs::canonicalize(path).unwrap();
    let ledger = Arc::new(
        HostLedger::open(
            &path.join("aura.sqlite3"),
            Arc::new(SignerKey(SigningKey::from_bytes(&[19; 32]))),
            Arc::new(crate::adapters::HostClock),
        )
        .unwrap(),
    );
    let adapter = GateAdapter::start(
        path.clone(),
        File::open(&path).unwrap(),
        GateConfig {
            node: canon::ids::NodeId::from_bytes([13; 16]),
            targets: vec![],
            proposal_lifetime_ms: 300_000,
            ceremony_lifetime_ms: 300_000,
        },
        ledger,
    )
    .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    // The whole messaging/ namespace, not two exact names: a third messaging target is refused the same way. (The
    // owner's contact card still proposes through propose_owner_requested: see the end of
    // adapters::messaging::tests::one_real_contact_card_admits_owner_sends_and_verified_projection_survives_restart.)
    for target in [messaging::CONTACT_TARGET, messaging::SEND_TARGET, "messaging/other.json", "messaging/contacts.json.new"] {
        let result = runtime.block_on(adapter.propose(
            PrincipalScope {
                subject: SubjectId::parse(&format!("aukora:1:{}", "01".repeat(32))).unwrap(),
                epoch: 1,
            },
            &FrameId::new("guest".into()).unwrap(),
            Propose {
                target: target.into(),
                base_sha256: Digest32::sha256(b"base"),
                new_bytes_b64: String::new(),
                note: String::new(),
                cell: None,
            },
        ));
        assert!(matches!(result, Err(code) if code == codes::GATE_UNKNOWN_TARGET));
    }
    // Nor can an engine read the owner's contact list (keys and labels) back out of the gate.
    for target in [messaging::CONTACT_TARGET, "messaging/other.json"] {
        let result = runtime.block_on(adapter.read(
            PrincipalScope {
                subject: SubjectId::parse(&format!("aukora:1:{}", "01".repeat(32))).unwrap(),
                epoch: 1,
            },
            canon::fd3_payloads::Read { target: target.into() },
        ));
        assert!(matches!(result, Err(code) if code == codes::GATE_UNKNOWN_TARGET), "{target}");
    }
    drop(adapter);
    std::fs::remove_dir_all(path).unwrap();
}
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}
