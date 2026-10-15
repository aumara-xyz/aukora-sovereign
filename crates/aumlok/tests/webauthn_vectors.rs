// SPDX-License-Identifier: AGPL-3.0-or-later
use aumlok::webauthn::*;
use serde_json::Value;

#[test]
fn prime_and_eddsa_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("../vectors/prime-webauthn.json")).unwrap();
    let fixtures = vectors["fixtures"].as_array().unwrap();
    for fixture in fixtures {
        let text = |key: &str| fixture[key].as_str().unwrap();
        let key = hex::decode(text("public_key_hex")).unwrap();
        let credential = Credential {
            owner_id: text("owner_id").into(),
            credential_id: text("credential_id").into(),
            public_key: if text("algorithm") == "ES256" {
                PublicKey::Es256(key)
            } else {
                PublicKey::Ed25519(key.try_into().unwrap())
            },
            user_handle: text("user_handle").into(),
            sign_count: fixture["prior_count"].as_u64().unwrap().try_into().unwrap(),
            backup_eligible: fixture["backup_eligible"].as_bool().unwrap(),
        };
        let result = if text("phase") == "assertion" {
            serde_json::from_value::<AssertionMaterial>(fixture["assertion"].clone())
                .map_err(|_| Refusal("aumlok:data-invalid"))
                .and_then(|material| {
                    verify_assertion(
                        &material,
                        &Config {
                            rp_id: text("rp_id").into(),
                            origin: text("origin").into(),
                            credential,
                        },
                        text("owner_id"),
                        text("challenge"),
                        None,
                    )
                    .map(|verified| {
                        assert!(verified.user_present && verified.user_verified);
                        assert_eq!(verified.comprehension, "not-proven");
                    })
                })
        } else {
            serde_json::from_value::<RegistrationMaterial>(fixture["registration"].clone())
                .map_err(|_| Refusal("aumlok:data-invalid"))
                .and_then(|material| {
                    verify_registration(
                        &material,
                        &RegistrationContext {
                            rp_id: text("rp_id").into(),
                            origin: text("origin").into(),
                            owner_id: text("owner_id").into(),
                            user_handle: text("user_handle").into(),
                            existing_credential_ids: vec![],
                        },
                        text("challenge"),
                    )
                    .map(|candidate| assert_eq!(candidate.credential, credential))
                })
        };
        assert_eq!(
            result.map(|_| "ok").unwrap_or_else(|err| err.0),
            text("expected"),
            "{}",
            text("name")
        );
    }
    println!("WebAuthn vectors: {} passed", fixtures.len());
}

#[test]
fn authorization_challenge_is_c5_domain_separated_canonical_bytes() {
    assert_eq!(
        owner_authorization_challenge(br#"{"a":1,"b":"x"}"#).unwrap(),
        "WQjrXoZtZanLFBfAnFtDgh7gVraz9UV_6O3u89v24gg"
    );
    for bytes in [
        br#"{"b":"x","a":1}"#.as_slice(),
        br#"{ "a":1}"#,
        br#"{"a":1.0}"#,
        br#"{"a":1e0}"#,
        br#"{"a":-0}"#,
        br#"{"a":9007199254740992}"#,
        br#"{"a":1,"a":1}"#,
        b"[]",
        b"\xef\xbb\xbf{}",
        br#"{"a":"\ud800"}"#,
    ] {
        assert_eq!(
            owner_authorization_challenge(bytes),
            Err(Refusal("aumlok:authorization-not-canonical"))
        );
    }
    assert!(owner_authorization_challenge("{\"𐀀\":1,\"\u{e000}\":2}".as_bytes()).is_ok());
    assert!(owner_authorization_challenge("{\"\u{e000}\":2,\"𐀀\":1}".as_bytes()).is_err());
    let nested = format!("{{\"a\":{}0{}}}", "[".repeat(64), "]".repeat(64));
    assert!(owner_authorization_challenge(nested.as_bytes()).is_err());
}
