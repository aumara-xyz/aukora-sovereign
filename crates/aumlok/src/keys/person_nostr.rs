// SPDX-License-Identifier: AGPL-3.0-or-later
//! Personal Nostr keys and versioned Aura binding bodies.
use super::*;

/// Domain for a binding wrapper with independent person rotation and owner epochs.
pub const BINDING_DOMAIN: &str = "aukora:aumlok-person-nostr-binding:v1";

/// Public request; the unchanged inner binding epoch remains the owner epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonNostrBindingRequest {
    /// Person key rotation epoch, starting at zero independently of passkey rotation.
    pub epoch: u32,
    /// Scope and public material requiring a separate exact-byte owner approval.
    pub binding: KeyBindingRequest,
}
impl PersonNostrBindingRequest {
    /// Exact bytes whose hash the owner approves; no fields are added to key-binding v1.
    pub fn approval_bytes(&self) -> Result<Vec<u8>> {
        domain_bytes(BINDING_DOMAIN, &binding_value(&self.binding, self.epoch)?)
    }
}

/// Bind public material through the same owner-proof and Aura transaction as other keys.
pub fn bind<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    approval: VerifiedProof,
    request: PersonNostrBindingRequest,
) -> Result<AuthorityRecord> {
    bind_key_body(txn, approval, request.binding, Some(request.epoch))
}

pub(super) fn binding_value(request: &KeyBindingRequest, epoch: u32) -> Result<Value> {
    if request.role != KeyRole::PersonNostr {
        return Err(refuse("key-role"));
    }
    object([
        ("schema", text(BINDING_DOMAIN)?),
        ("epoch", number(u64::from(epoch))?),
        ("body", request_value(request)?),
    ])
}

pub(super) fn parse_binding(value: &Value) -> Result<PersonNostrBindingRequest> {
    exact_fields(value, &["schema", "epoch", "body"])?;
    if value_text(field(value, "schema")?)? != BINDING_DOMAIN {
        return Err(refuse("key-version"));
    }
    let epoch =
        u32::try_from(value_u64(field(value, "epoch")?)?).map_err(|_| refuse("key-epoch"))?;
    let binding = parse_request(field(value, "body")?)?;
    binding_value(&binding, epoch)?;
    Ok(PersonNostrBindingRequest { epoch, binding })
}

/// Read the public binding and rotation epoch from the retained approved wrapper.
/// Storage keeps that wrapper as `request`; this read grants no authority.
pub fn load<T: AuthorityTxn + ?Sized>(txn: &mut T, key: KeyId) -> Result<(KeyBinding, u32)> {
    let binding = load_binding(txn, key)?;
    let stored = txn
        .authority_state("aumlok.key-binding", &key.0.to_string())?
        .ok_or(refuse("key-missing"))?;
    let request = parse_binding(field(&stored, "request")?)?;
    if request.binding != binding.request {
        return Err(refuse("key-context"));
    }
    Ok((binding, request.epoch))
}

/// Domain for the person's identity-root-derived Nostr scalar, including its separator.
pub const PERSON_NOSTR_DOMAIN: &[u8] = b"aukora:aumlok-person-nostr:v1\0";

/// Identity-root access is confined to the owner browser, as for the phrase envelope.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use super::*;
    use crate::envelope::owner::IdentityRoot;
    use crate::phrase::owner::OwnerBrowser;
    use canon::provenance::Npub;
    use zeroize::Zeroizing;

    /// Personal Nostr scalar with no raw-byte export, Debug or serialization.
    pub struct PersonNostrKey {
        _secret: Zeroizing<[u8; 32]>,
        public: [u8; 32],
        epoch: u32,
    }

    impl PersonNostrKey {
        /// Derive the same personal key from a restored root and the recorded epoch.
        pub fn derive(browser: &OwnerBrowser, root: &IdentityRoot, epoch: u32) -> Result<Self> {
            let (secret, public) = person_nostr_material(root.bytes(browser), epoch)?;
            Ok(Self {
                _secret: secret,
                public,
                epoch,
            })
        }

        /// Return the BIP-340 x-only public key, without granting authority.
        pub fn public_key(&self) -> PublicKey {
            PublicKey {
                v: 1,
                algorithm: AlgorithmId::Secp256k1Schnorr,
                bytes: self.public.to_vec(),
            }
        }

        /// Encode the public key with the pinned NIP-19 Bech32 primitive.
        pub fn npub(&self) -> Result<Npub> {
            Npub::encode_key_bytes(self.public)
        }

        /// Prepare exact-byte owner approval without changing the personal rotation epoch.
        pub fn binding_request(
            &self,
            scope: KeyScope,
            owner_epoch: u64,
            operation_id: OperationId,
        ) -> Result<PersonNostrBindingRequest> {
            let request = KeyBindingRequest {
                v: KEY_BINDING_VERSION,
                algorithm: AlgorithmId::Secp256k1Schnorr,
                key_id: KeyId(hash_bytes(&self.public)),
                role: KeyRole::PersonNostr,
                material: KeyMaterial::Public(self.public_key()),
                scope,
                epoch: owner_epoch,
                operation_id,
            };
            validate_request(&request)?;
            Ok(PersonNostrBindingRequest {
                epoch: self.epoch,
                binding: request,
            })
        }
    }

    fn person_nostr_material(
        root: &[u8; 32],
        epoch: u32,
    ) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
        let mut digest = Sha256::new();
        digest.update(PERSON_NOSTR_DOMAIN);
        digest.update(root);
        digest.update(epoch.to_be_bytes());
        let secret = Zeroizing::new(<[u8; 32]>::from(digest.finalize()));
        let signing = k256::schnorr::SigningKey::from_slice(secret.as_ref())
            .map_err(|_| canon::codes::AUMLOK_PERSON_NOSTR_OUT_OF_RANGE)?;
        Ok((secret, signing.verifying_key().to_bytes().into()))
    }
}
