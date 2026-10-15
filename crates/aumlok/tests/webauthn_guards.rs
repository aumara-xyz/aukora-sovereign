// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable software keys exercise the verifier's refusals.
use aumlok::webauthn::{
    owner_authorization_challenge, verify_assertion, verify_backup_assertion,
    verify_prf_registration, verify_registration, AssertionMaterial, Config, Credential, PublicKey,
    RegistrationContext, RegistrationMaterial,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::value::Value as Cbor;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

const OWNER: &str = "test-owner";
const RP: &str = "owner.test";
const ORIGIN: &str = "https://owner.test";

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge() -> String {
    b64([7_u8; 32])
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[9_u8; 32].into()).unwrap()
}

fn config() -> Config {
    Config {
        rp_id: RP.into(),
        origin: ORIGIN.into(),
        credential: Credential {
            owner_id: OWNER.into(),
            credential_id: b64(b"credential-one"),
            public_key: PublicKey::Es256(
                signer()
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
            user_handle: b64(b"owner-one"),
            sign_count: 0,
            backup_eligible: false,
        },
    }
}

fn client(kind: &str) -> Vec<u8> {
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}",
        challenge()
    )
    .into_bytes()
}

fn assertion_with(
    client: &[u8],
    rp: &str,
    flags: u8,
    count: u32,
    trailing: bool,
) -> AssertionMaterial {
    let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
    auth.push(flags);
    auth.extend_from_slice(&count.to_be_bytes());
    if trailing {
        auth.push(0);
    }
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(client));
    let signature: Signature = signer().sign(&signed);
    AssertionMaterial {
        kind: "passkey".into(),
        credential_id: b64(b"credential-one"),
        client_data_json: b64(client),
        authenticator_data: b64(auth),
        signature: b64(signature.to_der().as_bytes()),
        user_handle: Some(b64(b"owner-one")),
    }
}

fn assertion() -> AssertionMaterial {
    assertion_with(&client("webauthn.get"), RP, 5, 1, false)
}

fn backup_extension(name: &str, bytes: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(
        &Cbor::Map(vec![(
            Cbor::Text(name.into()),
            Cbor::Bytes(vec![0xa5; bytes]),
        )]),
        &mut encoded,
    )
    .unwrap();
    encoded
}

fn backup_assertion(
    client: &[u8],
    rp: &str,
    flags: u8,
    count: u32,
    extension: &[u8],
) -> AssertionMaterial {
    let mut material = assertion_with(client, rp, flags, count, false);
    let mut auth = URL_SAFE_NO_PAD
        .decode(&material.authenticator_data)
        .unwrap();
    auth.extend_from_slice(extension);
    let signed = [auth.as_slice(), Sha256::digest(client).as_slice()].concat();
    let signature: Signature = signer().sign(&signed);
    material.authenticator_data = b64(auth);
    material.signature = b64(signature.to_der().as_bytes());
    material
}

fn backup_refused(material: &AssertionMaterial, configuration: &Config, code: &str) {
    assert_eq!(
        verify_backup_assertion(material, configuration, OWNER, &challenge(), None)
            .unwrap_err()
            .0,
        code
    );
}

#[test]
fn antibody_backup_prf_extension_is_narrow_and_backup_only() {
    assert!(verify_backup_assertion(&assertion(), &config(), OWNER, &challenge(), None).is_ok());
    for output_bytes in [32, 48] {
        let extension = backup_extension("hmac-secret", output_bytes);
        let material = backup_assertion(&client("webauthn.get"), RP, 0x85, 1, &extension);
        let verified =
            verify_backup_assertion(&material, &config(), OWNER, &challenge(), None).unwrap();
        assert!(verified.user_present && verified.user_verified);
        assert_eq!(verified.sign_count, 1);
        refused(&material, &config(), "aumlok:rp-id-mismatch");
    }
}

#[test]
fn antibody_backup_prf_extension_refuses_extra_unknown_and_malformed_cbor() {
    let valid = backup_extension("hmac-secret", 32);
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut duplicate = Vec::new();
    ciborium::ser::into_writer(
        &Cbor::Map(vec![
            (Cbor::Text("hmac-secret".into()), Cbor::Bytes(vec![0; 32])),
            (Cbor::Text("hmac-secret".into()), Cbor::Bytes(vec![0; 32])),
        ]),
        &mut duplicate,
    )
    .unwrap();
    let mut indefinite = valid.clone();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    let mut nonminimal = valid.clone();
    nonminimal.splice(0..1, [0xb8, 1]);
    for extension in [
        Vec::new(),
        vec![0xa0],
        backup_extension("evil-secret", 32),
        backup_extension("hmac-secret", 0),
        backup_extension("hmac-secret", 31),
        backup_extension("hmac-secret", 33),
        backup_extension("hmac-secret", 64),
        backup_extension("hmac-secret", 80),
        trailing,
        duplicate,
        indefinite,
        nonminimal,
    ] {
        let material = backup_assertion(&client("webauthn.get"), RP, 0x85, 1, &extension);
        backup_refused(&material, &config(), "aumlok:backup-prf-extension");
    }
}

#[test]
fn antibody_backup_prf_extension_flags_and_presence_must_match() {
    let extension = backup_extension("hmac-secret", 32);
    backup_refused(
        &backup_assertion(&client("webauthn.get"), RP, 5, 1, &extension),
        &config(),
        "aumlok:rp-id-mismatch",
    );
    for flags in [0x84, 0x81, 0x87, 0xa5, 0xc5] {
        backup_refused(
            &backup_assertion(&client("webauthn.get"), RP, flags, 1, &extension),
            &config(),
            "aumlok:up-uv-or-flags-refused",
        );
    }
    backup_refused(
        &backup_assertion(&client("webauthn.get"), RP, 0x95, 1, &extension),
        &config(),
        "aumlok:backup-eligibility-changed",
    );
    backup_refused(
        &backup_assertion(&client("webauthn.get"), RP, 0x8d, 1, &extension),
        &config(),
        "aumlok:backup-eligibility-changed",
    );
}

#[test]
fn antibody_backup_prf_assertion_checks_pinning_counter_and_full_signed_bytes() {
    let extension = backup_extension("hmac-secret", 32);
    let valid = backup_assertion(&client("webauthn.get"), RP, 0x85, 1, &extension);
    let mut wrong = valid.clone();
    wrong.credential_id = b64(b"other credential");
    backup_refused(&wrong, &config(), "aumlok:credential-not-pinned");
    let mut wrong = valid.clone();
    wrong.user_handle = Some(b64(b"other owner"));
    backup_refused(&wrong, &config(), "aumlok:user-handle-mismatch");
    let mut wrong = valid.clone();
    let mut auth = URL_SAFE_NO_PAD.decode(&wrong.authenticator_data).unwrap();
    *auth.last_mut().unwrap() ^= 1;
    wrong.authenticator_data = b64(auth);
    backup_refused(&wrong, &config(), "aumlok:signature-invalid");
    let mut wrong = valid.clone();
    wrong.signature = assertion_with(&client("webauthn.get"), RP, 0x85, 1, false).signature;
    backup_refused(&wrong, &config(), "aumlok:signature-invalid");
    let mut prior = config();
    prior.credential.sign_count = 1;
    backup_refused(&valid, &prior, "aumlok:counter-replayed");
    assert_eq!(
        verify_backup_assertion(&valid, &config(), "other owner", &challenge(), None)
            .unwrap_err()
            .0,
        "aumlok:credential-not-pinned"
    );
    assert_eq!(
        verify_backup_assertion(&valid, &config(), OWNER, &b64([8; 32]), None)
            .unwrap_err()
            .0,
        "aumlok:challenge-or-origin-mismatch"
    );
    backup_refused(
        &backup_assertion(&client("webauthn.get"), "other.test", 0x85, 1, &extension),
        &config(),
        "aumlok:rp-id-mismatch",
    );
    let changed_client = String::from_utf8(client("webauthn.get"))
        .unwrap()
        .replace(ORIGIN, "https://other.test");
    backup_refused(
        &backup_assertion(changed_client.as_bytes(), RP, 0x85, 1, &extension),
        &config(),
        "aumlok:challenge-or-origin-mismatch",
    );
}

fn refused(material: &AssertionMaterial, configuration: &Config, code: &str) {
    assert_eq!(
        verify_assertion(material, configuration, OWNER, &challenge(), None)
            .unwrap_err()
            .0,
        code
    );
}

fn changed_client(needle: &str, replacement: &str) -> AssertionMaterial {
    let raw = String::from_utf8(client("webauthn.get")).unwrap();
    assert!(raw.contains(needle));
    assertion_with(raw.replace(needle, replacement).as_bytes(), RP, 5, 1, false)
}

#[test]
fn assertion_kind_is_pinned() {
    let mut material = assertion();
    material.kind = "cookie".into();
    refused(&material, &config(), "aumlok:material-kind");
}

#[test]
fn assertion_credential_is_pinned() {
    let mut material = assertion();
    material.credential_id = b64(b"credential-two");
    refused(&material, &config(), "aumlok:credential-not-pinned");
}

#[test]
fn assertion_owner_is_pinned() {
    assert_eq!(
        verify_assertion(&assertion(), &config(), "other-owner", &challenge(), None)
            .unwrap_err()
            .0,
        "aumlok:credential-not-pinned"
    );
}

#[test]
fn assertion_user_handle_is_pinned() {
    let mut material = assertion();
    material.user_handle = Some(b64(b"other-owner"));
    refused(&material, &config(), "aumlok:user-handle-mismatch");
    material.user_handle = None;
    assert!(verify_assertion(&material, &config(), OWNER, &challenge(), None).is_ok());
}

#[test]
fn assertion_type_is_get() {
    refused(
        &assertion_with(&client("webauthn.create"), RP, 5, 1, false),
        &config(),
        "aumlok:challenge-or-origin-mismatch",
    );
}

#[test]
fn assertion_challenge_is_exact() {
    let material = changed_client(&challenge(), &b64([8_u8; 32]));
    refused(&material, &config(), "aumlok:challenge-or-origin-mismatch");
}

#[test]
fn assertion_origin_is_exact() {
    refused(
        &changed_client(ORIGIN, "https://other.owner.test"),
        &config(),
        "aumlok:challenge-or-origin-mismatch",
    );
}

#[test]
fn assertion_cross_origin_is_refused() {
    refused(
        &changed_client("\"crossOrigin\":false", "\"crossOrigin\":true"),
        &config(),
        "aumlok:challenge-or-origin-mismatch",
    );
    for replacement in [
        "\"crossOrigin\":null",
        "\"crossOrigin\":\"false\"",
        "\"crossOrigin\":0",
    ] {
        refused(
            &changed_client("\"crossOrigin\":false", replacement),
            &config(),
            "aumlok:cross-origin-refused",
        );
    }
}

#[test]
fn assertion_top_origin_is_refused() {
    refused(
        &changed_client(
            "\"crossOrigin\":false",
            "\"crossOrigin\":false,\"topOrigin\":\"https://owner.test\"",
        ),
        &config(),
        "aumlok:challenge-or-origin-mismatch",
    );
}

#[test]
fn assertion_rp_is_exact() {
    refused(
        &assertion_with(&client("webauthn.get"), "other.test", 5, 1, false),
        &config(),
        "aumlok:rp-id-mismatch",
    );
}

#[test]
fn assertion_authenticator_data_is_exactly_37_bytes() {
    refused(
        &assertion_with(&client("webauthn.get"), RP, 5, 1, true),
        &config(),
        "aumlok:rp-id-mismatch",
    );
}

#[test]
fn assertion_up_is_required() {
    refused(
        &assertion_with(&client("webauthn.get"), RP, 4, 1, false),
        &config(),
        "aumlok:up-uv-or-flags-refused",
    );
}

#[test]
fn assertion_uv_is_required() {
    refused(
        &assertion_with(&client("webauthn.get"), RP, 1, 1, false),
        &config(),
        "aumlok:up-uv-or-flags-refused",
    );
}

#[test]
fn assertion_reserved_flags_are_refused() {
    for reserved in [2, 0x20, 0x40, 0x80] {
        refused(
            &assertion_with(&client("webauthn.get"), RP, 5 | reserved, 1, false),
            &config(),
            "aumlok:up-uv-or-flags-refused",
        );
    }
}

#[test]
fn assertion_backup_eligibility_is_pinned() {
    refused(
        &assertion_with(&client("webauthn.get"), RP, 0x0d, 1, false),
        &config(),
        "aumlok:backup-eligibility-changed",
    );
}

#[test]
fn assertion_backup_state_requires_eligibility() {
    refused(
        &assertion_with(&client("webauthn.get"), RP, 0x15, 1, false),
        &config(),
        "aumlok:backup-eligibility-changed",
    );
    let mut eligible = config();
    eligible.credential.backup_eligible = true;
    assert!(verify_assertion(
        &assertion_with(&client("webauthn.get"), RP, 0x1d, 1, false),
        &eligible,
        OWNER,
        &challenge(),
        None
    )
    .is_ok());
}

#[test]
fn assertion_counter_regression_is_refused() {
    let mut configuration = config();
    configuration.credential.sign_count = 5;
    for count in [0, 4, 5] {
        refused(
            &assertion_with(&client("webauthn.get"), RP, 5, count, false),
            &configuration,
            "aumlok:counter-replayed",
        );
    }
    assert!(verify_assertion(
        &assertion_with(&client("webauthn.get"), RP, 5, 6, false),
        &configuration,
        OWNER,
        &challenge(),
        None
    )
    .is_ok());
}

#[test]
fn prime_counter_stored_nonzero_then_presented_zero_is_refused() {
    let material = assertion_with(&client("webauthn.get"), RP, 5, 0, false);
    let mut configuration = config();
    configuration.credential.sign_count = 5;
    refused(&material, &configuration, "aumlok:counter-replayed");

    // The durable counter supplied by the ceremony has the same rule.
    assert_eq!(
        verify_assertion(&material, &config(), OWNER, &challenge(), Some(5))
            .unwrap_err()
            .0,
        "aumlok:counter-replayed"
    );
}

#[test]
fn assertion_counter_zero_to_zero_is_valid() {
    let result = verify_assertion(
        &assertion_with(&client("webauthn.get"), RP, 5, 0, false),
        &config(),
        OWNER,
        &challenge(),
        None,
    )
    .unwrap();
    assert_eq!(result.sign_count, 0);
}

#[test]
fn assertion_supplied_counter_is_used() {
    assert_eq!(
        verify_assertion(&assertion(), &config(), OWNER, &challenge(), Some(1))
            .unwrap_err()
            .0,
        "aumlok:counter-replayed"
    );
}

#[test]
fn assertion_signature_is_verified() {
    let mut material = assertion();
    let mut signature = URL_SAFE_NO_PAD.decode(&material.signature).unwrap();
    *signature.last_mut().unwrap() ^= 1;
    material.signature = b64(signature);
    refused(&material, &config(), "aumlok:signature-invalid");
}

#[test]
fn assertion_base64_encoding_is_canonical() {
    let mut material = assertion();
    material.client_data_json.push('=');
    refused(&material, &config(), "aumlok:encoding-invalid");
    material = assertion();
    material.signature.clear();
    refused(&material, &config(), "aumlok:encoding-invalid");
}

#[test]
fn assertion_client_data_byte_budget_is_enforced() {
    let raw = String::from_utf8(client("webauthn.get")).unwrap();
    let raw = raw.replace(
        "\"crossOrigin\":false",
        &format!("\"crossOrigin\":false,\"extra\":\"{}\"", "x".repeat(17000)),
    );
    refused(
        &assertion_with(raw.as_bytes(), RP, 5, 1, false),
        &config(),
        "aumlok:encoding-invalid",
    );
}

#[test]
fn assertion_duplicate_client_keys_are_refused() {
    refused(
        &changed_client("\"type\":", "\"type\":\"webauthn.create\",\"type\":"),
        &config(),
        "aumlok:client-data-invalid",
    );
    refused(
        &changed_client(
            "\"crossOrigin\":false",
            "\"crossOrigin\":false,\"extra\":{\"a\":1,\"a\":2}",
        ),
        &config(),
        "aumlok:client-data-invalid",
    );
}

#[test]
fn assertion_unsafe_client_integer_is_refused() {
    refused(
        &changed_client(
            "\"crossOrigin\":false",
            "\"crossOrigin\":false,\"extra\":9007199254740992",
        ),
        &config(),
        "aumlok:client-data-invalid",
    );
}

#[test]
fn assertion_lone_surrogate_is_refused() {
    refused(
        &changed_client(
            "\"crossOrigin\":false",
            "\"crossOrigin\":false,\"extra\":\"\\ud800\"",
        ),
        &config(),
        "aumlok:client-data-invalid",
    );
}

#[test]
fn assertion_invalid_utf8_is_refused() {
    let mut raw = client("webauthn.get");
    raw.pop();
    raw.extend_from_slice(b",\"extra\":\"");
    raw.push(0xff);
    raw.extend_from_slice(b"\"}");
    refused(
        &assertion_with(&raw, RP, 5, 1, false),
        &config(),
        "aumlok:client-data-invalid",
    );
}

#[test]
fn assertion_depth_budget_is_enforced() {
    let replacement = format!(
        "\"crossOrigin\":false,\"extra\":{}0{}",
        "[".repeat(513),
        "]".repeat(513)
    );
    refused(
        &changed_client("\"crossOrigin\":false", &replacement),
        &config(),
        "aumlok:client-data-invalid",
    );
}

fn cbor(value: Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    bytes
}

fn cose() -> Vec<u8> {
    let point = signer().verifying_key().to_sec1_point(false);
    cbor(Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
        (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
        (
            Cbor::Integer((-2).into()),
            Cbor::Bytes(point.as_bytes()[1..33].to_vec()),
        ),
        (
            Cbor::Integer((-3).into()),
            Cbor::Bytes(point.as_bytes()[33..65].to_vec()),
        ),
    ]))
}

fn registration_with(rp: &str, flags: u8, key: &[u8]) -> RegistrationMaterial {
    let mut auth = Sha256::digest(rp.as_bytes()).to_vec();
    auth.push(flags);
    auth.extend_from_slice(&0_u32.to_be_bytes());
    auth.extend_from_slice(&[0_u8; 16]);
    auth.extend_from_slice(&(b"credential-one".len() as u16).to_be_bytes());
    auth.extend_from_slice(b"credential-one");
    auth.extend_from_slice(key);
    RegistrationMaterial {
        kind: "passkey-registration".into(),
        r#type: "public-key".into(),
        id: b64(b"credential-one"),
        raw_id: b64(b"credential-one"),
        client_data_json: b64(client("webauthn.create")),
        attestation_object: b64(cbor(Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth)),
        ]))),
        client_extension_results: serde_json::json!({}),
    }
}

fn registration() -> RegistrationMaterial {
    registration_with(RP, 0x45, &cose())
}

fn context() -> RegistrationContext {
    RegistrationContext {
        rp_id: RP.into(),
        origin: ORIGIN.into(),
        owner_id: OWNER.into(),
        user_handle: b64(b"owner-one"),
        existing_credential_ids: vec![],
    }
}

fn registration_refused(material: &RegistrationMaterial, code: &str) {
    assert_eq!(
        verify_registration(material, &context(), &challenge())
            .unwrap_err()
            .0,
        code
    );
}

#[test]
fn antibody_prf_registration_is_optional_and_keeps_ordinary_verifier_closed() {
    assert!(verify_prf_registration(&registration(), &context(), &challenge()).is_ok());
    for enabled in [false, true] {
        let mut material = registration();
        material.client_extension_results = serde_json::json!({"prf":{"enabled":enabled}});
        assert!(verify_prf_registration(&material, &context(), &challenge()).is_ok());
        registration_refused(&material, "aumlok:data-invalid");
        let extension = cbor(Cbor::Map(vec![(
            Cbor::Text("hmac-secret".into()),
            Cbor::Bool(enabled),
        )]));
        let material = registration_with(RP, 0xc5, &[cose(), extension].concat());
        assert!(verify_prf_registration(&material, &context(), &challenge()).is_ok());
        registration_refused(&material, "aumlok:registration-up-uv-at-or-flags-refused");
    }
}

#[test]
fn antibody_prf_registration_refuses_unrequested_client_extension_results() {
    for extensions in [
        serde_json::json!(null),
        serde_json::json!({"appid":true}),
        serde_json::json!({"prf":{}}),
        serde_json::json!({"prf":{"enabled":"true"}}),
        serde_json::json!({"prf":{"enabled":true,"results":{"first":"secret"}}}),
        serde_json::json!({"prf":{"enabled":true},"appid":true}),
    ] {
        let mut material = registration();
        material.client_extension_results = extensions;
        assert_eq!(
            verify_prf_registration(&material, &context(), &challenge())
                .unwrap_err()
                .0,
            "aumlok:data-invalid"
        );
    }
}

#[test]
fn antibody_prf_registration_pins_cose_boundary_extension_and_flags() {
    let extension = cbor(Cbor::Map(vec![(
        Cbor::Text("hmac-secret".into()),
        Cbor::Bool(true),
    )]));
    for changed_extension in [
        Vec::new(),
        vec![0xa0],
        [extension.clone(), vec![0]].concat(),
        cbor(Cbor::Map(vec![(
            Cbor::Text("evil-secret".into()),
            Cbor::Bool(true),
        )])),
        cbor(Cbor::Map(vec![(
            Cbor::Text("hmac-secret".into()),
            Cbor::Bytes(vec![0; 32]),
        )])),
        cbor(Cbor::Map(vec![
            (Cbor::Text("hmac-secret".into()), Cbor::Bool(true)),
            (Cbor::Text("hmac-secret".into()), Cbor::Bool(true)),
        ])),
        [vec![0xb8, 1], extension[1..].to_vec()].concat(),
    ] {
        let material = registration_with(RP, 0xc5, &[cose(), changed_extension].concat());
        assert_eq!(
            verify_prf_registration(&material, &context(), &challenge())
                .unwrap_err()
                .0,
            "aumlok:registration-prf-extension"
        );
    }
    let material = registration_with(RP, 0x45, &[cose(), extension.clone()].concat());
    assert!(verify_prf_registration(&material, &context(), &challenge()).is_err());
    for flags in [0xc4, 0xc1, 0x85, 0xc7, 0xe5] {
        let material = registration_with(RP, flags, &[cose(), extension.clone()].concat());
        assert_eq!(
            verify_prf_registration(&material, &context(), &challenge())
                .unwrap_err()
                .0,
            "aumlok:registration-up-uv-at-or-flags-refused"
        );
    }
    let material = registration_with("other.test", 0xc5, &[cose(), extension.clone()].concat());
    assert_eq!(
        verify_prf_registration(&material, &context(), &challenge())
            .unwrap_err()
            .0,
        "aumlok:registration-rp-id-mismatch"
    );
    let mut material = registration_with(RP, 0xc5, &[cose(), extension].concat());
    material.client_data_json = b64(String::from_utf8(client("webauthn.create"))
        .unwrap()
        .replace(ORIGIN, "https://other.test"));
    assert_eq!(
        verify_prf_registration(&material, &context(), &challenge())
            .unwrap_err()
            .0,
        "aumlok:registration-challenge-or-origin-mismatch"
    );
}

#[test]
fn registration_kind_and_type_are_pinned() {
    let mut material = registration();
    material.kind = "cookie".into();
    registration_refused(&material, "aumlok:registration-type-or-id-invalid");
    material = registration();
    material.r#type = "secret-key".into();
    registration_refused(&material, "aumlok:registration-type-or-id-invalid");
}

#[test]
fn registration_id_and_raw_id_match() {
    let mut material = registration();
    material.id = b64(b"other-id");
    registration_refused(&material, "aumlok:registration-type-or-id-invalid");
}

#[test]
fn registration_extensions_are_empty() {
    let mut material = registration();
    material.client_extension_results = serde_json::json!({"appid": true});
    assert!(verify_registration(&material, &context(), &challenge()).is_err());
}

#[test]
fn registration_existing_credential_is_refused() {
    let mut configuration = context();
    configuration
        .existing_credential_ids
        .push(b64(b"credential-one"));
    assert_eq!(
        verify_registration(&registration(), &configuration, &challenge())
            .unwrap_err()
            .0,
        "aumlok:registration-credential-already-known"
    );
}

#[test]
fn registration_challenge_has_32_bytes() {
    let mut material = registration();
    let short = b64([7_u8; 31]);
    material.client_data_json = b64(String::from_utf8(client("webauthn.create"))
        .unwrap()
        .replace(&challenge(), &short));
    assert_eq!(
        verify_registration(&material, &context(), &short)
            .unwrap_err()
            .0,
        "aumlok:registration-challenge-invalid"
    );
}

#[test]
fn registration_client_type_is_create() {
    let mut material = registration();
    material.client_data_json = b64(client("webauthn.get"));
    registration_refused(
        &material,
        "aumlok:registration-challenge-or-origin-mismatch",
    );
}

#[test]
fn registration_rp_is_exact() {
    registration_refused(
        &registration_with("other.test", 0x45, &cose()),
        "aumlok:registration-rp-id-mismatch",
    );
}

#[test]
fn registration_up_uv_at_are_required() {
    for flags in [0x44, 0x41, 5] {
        registration_refused(
            &registration_with(RP, flags, &cose()),
            "aumlok:registration-up-uv-at-or-flags-refused",
        );
    }
}

#[test]
fn registration_reserved_flags_are_refused() {
    for reserved in [2, 0x20, 0x80] {
        registration_refused(
            &registration_with(RP, 0x45 | reserved, &cose()),
            "aumlok:registration-up-uv-at-or-flags-refused",
        );
    }
}

#[test]
fn registration_backup_state_requires_eligibility() {
    registration_refused(
        &registration_with(RP, 0x55, &cose()),
        "aumlok:registration-backup-flags-invalid",
    );
    let candidate = verify_registration(
        &registration_with(RP, 0x5d, &cose()),
        &context(),
        &challenge(),
    )
    .unwrap();
    assert!(candidate.credential.backup_eligible);
    assert!(candidate.backup_state);
}

#[test]
fn registration_cbor_must_be_minimally_encoded() {
    let mut material = registration();
    let bytes = URL_SAFE_NO_PAD
        .decode(&material.attestation_object)
        .unwrap();
    assert_eq!(bytes[0], 0xa3);
    let mut nonminimal = vec![0xb8, 3];
    nonminimal.extend_from_slice(&bytes[1..]);
    material.attestation_object = b64(nonminimal);
    registration_refused(&material, "aumlok:registration-cbor-invalid");
}

#[test]
fn registration_cbor_must_be_definite() {
    let mut material = registration();
    let mut bytes = URL_SAFE_NO_PAD
        .decode(&material.attestation_object)
        .unwrap();
    bytes[0] = 0xbf;
    bytes.push(0xff);
    material.attestation_object = b64(bytes);
    registration_refused(&material, "aumlok:registration-cbor-invalid");
}

#[test]
fn registration_attestation_is_none() {
    let mut material = registration();
    let bytes = URL_SAFE_NO_PAD
        .decode(&material.attestation_object)
        .unwrap();
    let mut value: Cbor = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let Cbor::Map(ref mut entries) = value else {
        panic!("attestation map")
    };
    entries[0].1 = Cbor::Text("fido".into());
    material.attestation_object = b64(cbor(value));
    registration_refused(&material, "aumlok:registration-attestation-invalid");
}

#[test]
fn registration_cose_order_is_fixed() {
    let bytes = cose();
    let mut value: Cbor = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let Cbor::Map(ref mut entries) = value else {
        panic!("COSE map")
    };
    entries.swap(0, 1);
    registration_refused(
        &registration_with(RP, 0x45, &cbor(value)),
        "aumlok:registration-key-invalid",
    );
}

#[test]
fn registration_es256_cose_parameters_are_pinned() {
    for (index, wrong) in [(0, 3), (1, -8), (2, 2)] {
        let bytes = cose();
        let mut value: Cbor = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Cbor::Map(ref mut entries) = value else {
            panic!("COSE map")
        };
        entries[index].1 = Cbor::Integer(wrong.into());
        registration_refused(
            &registration_with(RP, 0x45, &cbor(value)),
            "aumlok:registration-key-invalid",
        );
    }
}

#[test]
fn registration_es256_point_is_on_curve() {
    let bytes = cose();
    let mut value: Cbor = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let Cbor::Map(ref mut entries) = value else {
        panic!("COSE map")
    };
    entries[3].1 = Cbor::Bytes(vec![0; 32]);
    entries[4].1 = Cbor::Bytes(vec![0; 32]);
    registration_refused(
        &registration_with(RP, 0x45, &cbor(value)),
        "aumlok:registration-key-invalid",
    );
}

#[test]
fn authorization_challenge_uses_c5_domain() {
    let canonical = br#"{"v":1}"#;
    let mut signed = b"aukora:owner-authorization:v1\0".to_vec();
    signed.extend_from_slice(canonical);
    assert_eq!(
        owner_authorization_challenge(canonical).unwrap(),
        b64(Sha256::digest(signed))
    );
    assert!(owner_authorization_challenge(br#"{ "v": 1 }"#).is_err());
}

#[test]
fn assertion_material_is_closed_and_complete() {
    let baseline = serde_json::to_value(assertion()).unwrap();
    let mut unknown = baseline.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("cookie".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<AssertionMaterial>(unknown).is_err());
    for field in [
        "kind",
        "credential_id",
        "client_data_json",
        "authenticator_data",
        "signature",
        "user_handle",
    ] {
        let mut incomplete = baseline.clone();
        incomplete.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<AssertionMaterial>(incomplete).is_err(),
            "missing {field}"
        );
    }
}

#[test]
fn registration_material_is_closed_and_complete() {
    let baseline = serde_json::to_value(registration()).unwrap();
    let mut unknown = baseline.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("cookie".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<RegistrationMaterial>(unknown).is_err());
    for field in [
        "kind",
        "type",
        "id",
        "raw_id",
        "client_data_json",
        "attestation_object",
        "client_extension_results",
    ] {
        let mut incomplete = baseline.clone();
        incomplete.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<RegistrationMaterial>(incomplete).is_err(),
            "missing {field}"
        );
    }
}

#[test]
fn credential_configuration_is_closed() {
    let mut unknown = serde_json::to_value(config().credential).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("approved".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<Credential>(unknown).is_err());
}

#[test]
fn configuration_rp_is_dns_name() {
    for rp in [
        "",
        "127.0.0.1",
        "Owner.test",
        "owner..test",
        ".owner.test",
        "owner.test.",
    ] {
        let mut configuration = config();
        configuration.rp_id = rp.into();
        assert_eq!(
            configuration.validate().unwrap_err().0,
            "aumlok:config-invalid"
        );
    }
}

#[test]
fn configuration_origin_is_https() {
    let mut configuration = config();
    configuration.origin = "http://owner.test".into();
    assert_eq!(
        configuration.validate().unwrap_err().0,
        "aumlok:origin-invalid"
    );
}

#[test]
fn configuration_origin_is_canonical() {
    for origin in [
        "https://owner.test/",
        "https://owner.test:443",
        "https://owner.test/path",
        "https://user@owner.test",
    ] {
        let mut configuration = config();
        configuration.origin = origin.into();
        assert_eq!(
            configuration.validate().unwrap_err().0,
            "aumlok:origin-invalid"
        );
    }
}

#[test]
fn configuration_origin_is_under_rp() {
    let mut configuration = config();
    configuration.origin = "https://other.test".into();
    assert_eq!(
        configuration.validate().unwrap_err().0,
        "aumlok:origin-invalid"
    );
    configuration.origin = "https://owner.test.evil.test".into();
    assert_eq!(
        configuration.validate().unwrap_err().0,
        "aumlok:origin-invalid"
    );
    configuration.origin = "https://sub.owner.test".into();
    assert!(configuration.validate().is_ok());
}

#[test]
fn configuration_owner_is_present() {
    let mut configuration = config();
    configuration.credential.owner_id.clear();
    assert_eq!(
        configuration.validate().unwrap_err().0,
        "aumlok:credential-invalid"
    );
}

#[test]
fn configuration_es256_point_is_valid() {
    let mut configuration = config();
    configuration.credential.public_key = PublicKey::Es256([vec![4], vec![0; 64]].concat());
    assert_eq!(
        configuration.validate().unwrap_err().0,
        "aumlok:key-invalid"
    );
    configuration.credential.public_key = PublicKey::Es256(
        signer()
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .to_vec(),
    );
    assert_eq!(
        configuration.validate().unwrap_err().0,
        "aumlok:key-invalid"
    );
}

#[test]
fn configuration_eddsa_key_is_not_weak() {
    let mut configuration = config();
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    configuration.credential.public_key = PublicKey::Ed25519(identity);
    assert_eq!(
        configuration.validate().unwrap_err().0,
        "aumlok:key-invalid"
    );
}

#[test]
fn eddsa_signature_is_verified() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]);
    let mut configuration = config();
    configuration.credential.public_key = PublicKey::Ed25519(key.verifying_key().to_bytes());
    let mut material = assertion();
    let auth = URL_SAFE_NO_PAD
        .decode(&material.authenticator_data)
        .unwrap();
    let client = URL_SAFE_NO_PAD.decode(&material.client_data_json).unwrap();
    let signed = [auth.as_slice(), Sha256::digest(client).as_slice()].concat();
    let signature: ed25519_dalek::Signature = key.sign(&signed);
    material.signature = b64(signature.to_bytes());
    assert!(verify_assertion(&material, &configuration, OWNER, &challenge(), None).is_ok());
    let mut broken = signature.to_bytes();
    broken[63] ^= 1;
    material.signature = b64(broken);
    refused(&material, &configuration, "aumlok:signature-invalid");
}

#[test]
fn assertion_negative_unsafe_client_integer_is_refused() {
    refused(
        &changed_client(
            "\"crossOrigin\":false",
            "\"crossOrigin\":false,\"extra\":-9007199254740992",
        ),
        &config(),
        "aumlok:client-data-invalid",
    );
}

#[test]
fn assertion_float_unsafe_client_integer_is_refused() {
    refused(
        &changed_client(
            "\"crossOrigin\":false",
            "\"crossOrigin\":false,\"extra\":9.007199254740992e15",
        ),
        &config(),
        "aumlok:client-data-invalid",
    );
}

#[test]
fn cbor_byte_budget_is_enforced_directly() {
    let bytes = cbor(Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(vec![0; 17000])),
    ]));
    assert_eq!(
        aumlok::webauthn::parse_none_attestation(&bytes)
            .unwrap_err()
            .0,
        "aumlok:registration-cbor-invalid"
    );
}

#[test]
fn registration_top_origin_is_refused() {
    let mut material = registration();
    let raw = String::from_utf8(client("webauthn.create")).unwrap();
    material.client_data_json = b64(raw.replace(
        "\"crossOrigin\":false",
        "\"crossOrigin\":false,\"topOrigin\":\"https://owner.test\"",
    ));
    registration_refused(
        &material,
        "aumlok:registration-challenge-or-origin-mismatch",
    );
}

fn with_registration_auth(
    mut material: RegistrationMaterial,
    change: impl FnOnce(&mut Vec<u8>),
) -> RegistrationMaterial {
    let bytes = URL_SAFE_NO_PAD
        .decode(&material.attestation_object)
        .unwrap();
    let mut value: Cbor = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let Cbor::Map(ref mut entries) = value else {
        panic!("attestation map")
    };
    let Cbor::Bytes(ref mut auth) = entries[2].1 else {
        panic!("authData bytes")
    };
    change(auth);
    material.attestation_object = b64(cbor(value));
    material
}

#[test]
fn registration_authenticator_data_has_required_length() {
    let material = with_registration_auth(registration(), |auth| auth.truncate(32));
    registration_refused(&material, "aumlok:registration-rp-id-mismatch");
}

#[test]
fn registration_credential_id_length_is_bounded() {
    for id_len in [0_u16, 1024] {
        let material = with_registration_auth(registration(), |auth| {
            auth[53..55].copy_from_slice(&id_len.to_be_bytes())
        });
        registration_refused(&material, "aumlok:registration-credential-id-mismatch");
    }
}

#[test]
fn registration_credential_id_is_not_truncated() {
    let material = with_registration_auth(registration(), |auth| {
        auth.truncate(55 + b"credential-one".len() - 1)
    });
    registration_refused(&material, "aumlok:registration-credential-id-mismatch");
}

#[test]
fn registration_coordinate_length_is_exact() {
    let bytes = cose();
    let mut value: Cbor = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let Cbor::Map(ref mut entries) = value else {
        panic!("COSE map")
    };
    let Cbor::Bytes(ref mut x) = entries[3].1 else {
        panic!("coordinate bytes")
    };
    x.push(0);
    registration_refused(
        &registration_with(RP, 0x45, &cbor(value)),
        "aumlok:registration-key-invalid",
    );
}

#[test]
fn registration_eddsa_cose_parameters_are_pinned() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]);
    for (index, wrong) in [(0, 2), (1, -7), (2, 1)] {
        let mut entries = vec![
            (Cbor::Integer(1.into()), Cbor::Integer(1.into())),
            (Cbor::Integer(3.into()), Cbor::Integer((-8).into())),
            (Cbor::Integer((-1).into()), Cbor::Integer(6.into())),
            (
                Cbor::Integer((-2).into()),
                Cbor::Bytes(key.verifying_key().to_bytes().to_vec()),
            ),
        ];
        entries[index].1 = Cbor::Integer(wrong.into());
        registration_refused(
            &registration_with(RP, 0x45, &cbor(Cbor::Map(entries))),
            "aumlok:registration-key-invalid",
        );
    }
}

#[test]
fn registration_credential_id_1024_bytes_is_refused() {
    let identifier = vec![b'x'; 1024];
    let mut material = with_registration_auth(registration(), |auth| {
        auth.truncate(55);
        auth[53..55].copy_from_slice(&1024_u16.to_be_bytes());
        auth.extend_from_slice(&identifier);
        auth.extend_from_slice(&cose());
    });
    material.id = b64(&identifier);
    material.raw_id = b64(identifier);
    registration_refused(&material, "aumlok:encoding-invalid");
}

fn embedded_config(rp: &str) -> Config {
    Config {
        rp_id: rp.into(),
        origin: format!("https://{rp}"),
        ..config()
    }
}

fn embedded_client(origin: &str, cross: &str, top: Option<&str>) -> Vec<u8> {
    let top = top.map_or(String::new(), |top| format!(",\"topOrigin\":\"{top}\""));
    format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{origin}\",\"crossOrigin\":{cross}{top}}}",
        challenge()
    )
    .into_bytes()
}

#[test]
fn antibody_owner_panel_passkey_inside_the_node_chat_shell_only() {
    // Peter, 2026-10-15: approvals pop up inside the spatial shell. A fingerprint taken in the
    // owner panel framed by the node's own chat origin verifies; any other embedder is refused.
    let rp = "owner-n1-1-2-3-4.sslip.io";
    let config = embedded_config(rp);
    let origin = format!("https://{rp}");
    let ok = embedded_client(&origin, "true", Some("https://chat-n1-1-2-3-4.sslip.io"));
    verify_assertion(
        &assertion_with(&ok, rp, 5, 1, false),
        &config,
        OWNER,
        &challenge(),
        None,
    )
    .unwrap();
    for (cross, top) in [
        ("true", Some("https://chat-n2-1-2-3-4.sslip.io")),
        ("true", Some("https://evil.example")),
        ("true", Some("https://owner-n1-1-2-3-4.sslip.io")),
        ("true", None),
        ("false", Some("https://chat-n1-1-2-3-4.sslip.io")),
    ] {
        let client = embedded_client(&origin, cross, top);
        assert_eq!(
            verify_assertion(
                &assertion_with(&client, rp, 5, 1, false),
                &config,
                OWNER,
                &challenge(),
                None
            )
            .unwrap_err()
            .0,
            "aumlok:challenge-or-origin-mismatch",
            "{cross} {top:?}"
        );
    }
}
