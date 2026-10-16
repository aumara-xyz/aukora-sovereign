// SPDX-License-Identifier: AGPL-3.0-or-later
//! Installed-release pointer verification holds Aura's writer reservation until release.

use super::{exact_keys, refuse, text};
use crate::{adapters::HostClock, config::NodeConfig};
use aura::{RecordSigner, TrustedClock};
use canon::{
    alg::{AlgorithmId, PublicKey, Signature, Signatures},
    authority::{AuthorityTxn, OwnerAssertion},
    digest::Digest32,
    ids::CredentialId,
    json::{self, SafeInteger, Value, ValueView},
    Result,
};
use rustix::fs::{open, openat, Mode, OFlags};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::mpsc,
    time::Duration,
};
use zeroize::Zeroizing;

const POINTER_DOMAIN: &[u8] = b"aukora:release-pointer:v2\0";

struct Pointer {
    verdict: Value,
    not_after: i64,
    challenge: Digest32,
}

struct VerificationSigner(PublicKey);

impl RecordSigner for VerificationSigner {
    fn public_keys(&self) -> Result<Vec<PublicKey>> {
        Ok(vec![self.0.clone()])
    }

    fn sign_entry_hash(&self, _: Digest32) -> Result<Signatures> {
        Err(refuse("pointer-read-only"))
    }
}

pub(crate) fn run(arguments: &[OsString]) -> Result<()> {
    let [command, config_flag, config_path, pointer_flag, pointer_path, assertion_flag, assertion_path] =
        arguments
    else {
        return Err(refuse("release-pointer-usage"));
    };
    if command != "verify-pointer"
        || config_flag != "--config"
        || pointer_flag != "--pointer"
        || assertion_flag != "--assertion"
    {
        return Err(refuse("release-pointer-usage"));
    }
    let config = NodeConfig::load(Path::new(config_path))?;
    let instance = installed_instance(&config)?;
    let raw = read_input(Path::new(pointer_path), 4096)?;
    let pointer = Pointer::parse(&raw, &config.node, &instance, HostClock.now_ms()?)?;
    let assertion = json::parse_strict(&read_input(Path::new(assertion_path), 16_384)?)?;
    exact_keys(
        &assertion,
        &[
            "schema",
            "credential_id",
            "authenticator_data",
            "client_data_json",
            "signature",
        ],
    )?;
    if text(&assertion, "schema")? != "aukora-release-assertion-v1" {
        return Err(refuse("pointer-assertion"));
    }
    let credential = CredentialId::new(decoded(&assertion, "credential_id", 1024)?)?;
    let signer = verification_signer(&config)?;
    let mut ledger =
        aura::Ledger::open_existing_authority(&config.state_root.join("aura.sqlite3"))?;
    let mut transaction = ledger.begin(aura::TransactionServices {
        signer: &signer,
        clock: &HostClock,
    })?;
    let binding = transaction.owner_binding(&credential)?;
    if binding.owner_origin != config.owner_origin
        || binding.top_origin != config.shell_origin
        || config.owner_origin.strip_prefix("https://") != Some(binding.relying_party.as_str())
    {
        return Err(refuse("pointer-owner-binding"));
    }
    OwnerAssertion {
        v: 1,
        algorithm: binding.algorithm,
        credential_id: credential,
        authenticator_data: decoded(&assertion, "authenticator_data", 37)?,
        client_data_json: decoded(&assertion, "client_data_json", 16_384)?,
        signature: Signature {
            v: 1,
            algorithm: binding.algorithm,
            bytes: decoded(&assertion, "signature", 128)?,
        },
    }
    .verify_challenge(&mut transaction, pointer.challenge.as_bytes())?;
    pointer.require_live(HostClock.now_ms()?)?;
    {
        let mut output = std::io::stdout().lock();
        output
            .write_all(&pointer.verdict.canonical_bytes())
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.flush())
            .map_err(|_| refuse("pointer-channel"))?;
    }
    wait_release(pointer.not_after)?;
    pointer.require_live(HostClock.now_ms()?)?;
    transaction.rollback()
}

impl Pointer {
    fn parse(raw: &[u8], node: &str, instance: &str, now: i64) -> Result<Self> {
        let outer = json::parse_strict(raw)?;
        exact_keys(&outer, &["schema", "body"])?;
        if outer.canonical_bytes() != raw || text(&outer, "schema")? != "aukora-release-pointer-v2"
        {
            return Err(refuse("pointer-format"));
        }
        let body = outer.get("body").ok_or(refuse("pointer-format"))?;
        exact_keys(
            body,
            &["node", "instance", "commit", "release", "seq", "not_after"],
        )?;
        if text(body, "node")? != node {
            return Err(refuse("pointer-node"));
        }
        if !hex(text(body, "instance")?, 64) || text(body, "instance")? != instance {
            return Err(refuse("pointer-instance"));
        }
        if !hex(text(body, "commit")?, 40) || !hex(text(body, "release")?, 64) {
            return Err(refuse("pointer-format"));
        }
        let not_after = positive_integer(body, "not_after")?;
        let seq = positive_integer(body, "seq")?;
        let mut fields = Vec::new();
        for name in ["node", "instance", "commit", "release"] {
            fields.push((name.into(), value_text(text(body, name)?)?));
        }
        fields.push(("seq".into(), Value::integer(SafeInteger::new(seq)?)));
        fields.push((
            "not_after".into(),
            Value::integer(SafeInteger::new(not_after)?),
        ));
        fields.push((
            "sha256".into(),
            value_text(Digest32::sha256(raw).to_string())?,
        ));
        let result = Self {
            verdict: Value::object(fields)?,
            not_after,
            challenge: Digest32::sha256(&[POINTER_DOMAIN, raw].concat()),
        };
        result.require_live(now)?;
        Ok(result)
    }

    fn require_live(&self, now: i64) -> Result<()> {
        if now < 0 || now >= self.not_after {
            Err(refuse("pointer-expired"))
        } else {
            Ok(())
        }
    }
}

fn installed_instance(config: &NodeConfig) -> Result<String> {
    let directory = super::trusted_directory(
        config
            .release_state
            .parent()
            .ok_or(refuse("pointer-instance"))?,
    )?;
    let raw = super::read(&directory, "instance.json", 4096)?;
    let record = json::parse_strict(&raw)?;
    exact_keys(&record, &["schema", "node", "instance"])?;
    let instance = text(&record, "instance")?;
    if record.canonical_bytes() != raw
        || text(&record, "schema")? != "aukora-node-instance-v1"
        || text(&record, "node")? != config.node
        || !hex(instance, 64)
    {
        return Err(refuse("pointer-instance"));
    }
    Ok(instance.into())
}

fn verification_signer(config: &NodeConfig) -> Result<VerificationSigner> {
    let parent =
        super::trusted_directory(config.state_root.parent().ok_or(refuse("pointer-state"))?)?;
    let directory: File = openat(
        &parent,
        config
            .state_root
            .file_name()
            .ok_or(refuse("pointer-state"))?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| refuse("pointer-state"))?
    .into();
    let metadata = directory.metadata().map_err(|_| refuse("pointer-state"))?;
    if metadata.mode() & 0o077 != 0 {
        return Err(refuse("pointer-state"));
    }
    let file: File = openat(
        &directory,
        "aura-signing-key",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| refuse("pointer-state"))?
    .into();
    let info = file.metadata().map_err(|_| refuse("pointer-state"))?;
    if !info.is_file()
        || info.uid() != metadata.uid()
        || info.mode() & 0o7777 != 0o600
        || info.nlink() != 1
        || info.len() != 32
    {
        return Err(refuse("pointer-state"));
    }
    let mut seed = Zeroizing::new([0; 32]);
    (&file)
        .read_exact(&mut seed[..])
        .map_err(|_| refuse("pointer-state"))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(VerificationSigner(PublicKey {
        v: 1,
        algorithm: AlgorithmId::Ed25519,
        bytes: key.verifying_key().to_bytes().to_vec(),
    }))
}

fn read_input(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file: File = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| refuse("pointer-input"))?
    .into();
    let metadata = file.metadata().map_err(|_| refuse("pointer-input"))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum as u64 {
        return Err(refuse("pointer-input"));
    }
    let mut raw = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| refuse("pointer-input"))?;
    if raw.len() > maximum || raw.len() as u64 != metadata.len() {
        return Err(refuse("pointer-input"));
    }
    Ok(raw)
}

fn decoded(value: &Value, name: &str, maximum: usize) -> Result<Vec<u8>> {
    aumlok::webauthn::decode_base64url(text(value, name)?, maximum)
}

fn positive_integer(value: &Value, name: &str) -> Result<i64> {
    match value.get(name).map(Value::view) {
        Some(ValueView::Integer(number)) if number.get() > 0 => Ok(number.get()),
        _ => Err(refuse("pointer-format")),
    }
}

fn hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn wait_release(not_after: i64) -> Result<()> {
    let remaining = not_after
        .checked_sub(HostClock.now_ms()?)
        .filter(|ms| *ms > 0)
        .ok_or(refuse("pointer-expired"))?;
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut message = Vec::new();
        let result = std::io::stdin()
            .take(9)
            .read_to_end(&mut message)
            .map(|_| message == b"release\n")
            .unwrap_or(false);
        let _ = send.send(result);
    });
    match receive.recv_timeout(Duration::from_millis((remaining as u64).min(60_000))) {
        Ok(true) => Ok(()),
        _ => Err(refuse("pointer-reservation")),
    }
}

#[cfg(test)]
mod refusal_checks {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use canon::authority::{
        AuthorityRecord, FactRecord, LifecycleRecord, OwnerAuthorization, OwnerBinding,
        OwnerOperation, PendingAuthorityRecord, StandingUseContext, VerifiedProof,
        VerifiedStandingUse,
    };
    use canon::ids::ProposalId;
    use ed25519_dalek::Signer;

    struct AnchoredOwner(OwnerBinding);

    impl AuthorityTxn for AnchoredOwner {
        fn transaction_id(&self) -> Digest32 {
            Digest32::sha256(b"pointer-unit-transaction")
        }
        fn owner_binding(&mut self, credential: &CredentialId) -> Result<OwnerBinding> {
            if credential != &self.0.credential_id {
                return Err(canon::codes::GATE_CREDENTIAL_MISMATCH);
            }
            Ok(self.0.clone())
        }
        fn rebuild_authorization(
            &mut self,
            _: &ProposalId,
            _: OwnerOperation,
        ) -> Result<OwnerAuthorization> {
            Err(refuse("pointer-read-only"))
        }
        fn verify_signature(
            &mut self,
            key: &PublicKey,
            message: &[u8],
            signature: &Signature,
        ) -> Result<()> {
            let bytes: &[u8; 32] = key
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| refuse("pointer-signature"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|_| refuse("pointer-signature"))?;
            let signature = ed25519_dalek::Signature::from_slice(&signature.bytes)
                .map_err(|_| refuse("pointer-signature"))?;
            key.verify_strict(message, &signature)
                .map_err(|_| refuse("pointer-signature"))
        }
        fn persist_counter(&mut self, _: &VerifiedProof) -> Result<()> {
            Err(refuse("pointer-read-only"))
        }
        fn consume(&mut self, _: &VerifiedProof) -> Result<()> {
            Err(refuse("pointer-read-only"))
        }
        fn append(
            &mut self,
            _: VerifiedProof,
            _: PendingAuthorityRecord,
        ) -> Result<AuthorityRecord> {
            Err(refuse("pointer-read-only"))
        }
        fn check_standing_use(
            &mut self,
            _: &ProposalId,
            _: Digest32,
            _: &ProposalId,
            _: OwnerOperation,
        ) -> Result<StandingUseContext> {
            Err(refuse("pointer-read-only"))
        }
        fn append_standing(
            &mut self,
            _: VerifiedStandingUse,
            _: PendingAuthorityRecord,
        ) -> Result<AuthorityRecord> {
            Err(refuse("pointer-read-only"))
        }
        fn append_lifecycle(&mut self, _: LifecycleRecord) -> Result<AuthorityRecord> {
            Err(refuse("pointer-read-only"))
        }
        fn append_fact(&mut self, _: FactRecord) -> Result<AuthorityRecord> {
            Err(refuse("pointer-read-only"))
        }
    }

    #[test]
    fn pointer_refuses_foreign_instance_expiry_and_wrong_credential() -> Result<()> {
        let instance = "1".repeat(64);
        let body = Value::object(vec![
            ("node".into(), value_text("t1")?),
            ("instance".into(), value_text(&instance)?),
            ("commit".into(), value_text("2".repeat(40))?),
            ("release".into(), value_text("3".repeat(64))?),
            ("seq".into(), Value::integer(SafeInteger::new(1)?)),
            ("not_after".into(), Value::integer(SafeInteger::new(2000)?)),
        ])?;
        let raw = Value::object(vec![
            ("schema".into(), value_text("aukora-release-pointer-v2")?),
            ("body".into(), body),
        ])?
        .canonical_bytes();
        let pointer = Pointer::parse(&raw, "t1", &instance, 1000)?;
        assert!(matches!(Pointer::parse(&raw, "t1", &"4".repeat(64), 1000),
            Err(error) if error == refuse("pointer-instance")));
        assert!(matches!(Pointer::parse(&raw, "t1", &instance, 2000),
            Err(error) if error == refuse("pointer-expired")));

        let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let credential_id = CredentialId::new(vec![6; 32])?;
        let mut authority = AnchoredOwner(OwnerBinding {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            credential_id: credential_id.clone(),
            public_key: PublicKey {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
            epoch: 1,
            relying_party: "owner.example.invalid".into(),
            owner_origin: "https://owner.example.invalid".into(),
            top_origin: "https://example.invalid".into(),
            sign_counter: 0,
        });
        let client = Value::object(vec![
            ("type".into(), value_text("webauthn.get")?),
            (
                "challenge".into(),
                value_text(URL_SAFE_NO_PAD.encode(pointer.challenge.as_bytes()))?,
            ),
            ("origin".into(), value_text(&authority.0.owner_origin)?),
            ("topOrigin".into(), value_text(&authority.0.top_origin)?),
            ("crossOrigin".into(), Value::boolean(true)),
        ])?
        .canonical_bytes();
        let mut auth = Digest32::sha256(authority.0.relying_party.as_bytes())
            .as_bytes()
            .to_vec();
        auth.extend_from_slice(&[5, 0, 0, 0, 0]);
        let mut message = auth.clone();
        message.extend_from_slice(Digest32::sha256(&client).as_bytes());
        let mut assertion = OwnerAssertion {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            credential_id,
            authenticator_data: auth,
            client_data_json: client,
            signature: Signature {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: key.sign(&message).to_bytes().to_vec(),
            },
        };
        assertion.verify_challenge(&mut authority, pointer.challenge.as_bytes())?;
        assertion.credential_id = CredentialId::new(vec![7; 32])?;
        assert_eq!(
            assertion.verify_challenge(&mut authority, pointer.challenge.as_bytes()),
            Err(canon::codes::GATE_CREDENTIAL_MISMATCH)
        );
        Ok(())
    }
}

fn value_text(value: impl Into<String>) -> Result<Value> {
    Value::text(value.into())
}
