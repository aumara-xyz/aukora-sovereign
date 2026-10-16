// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebAuthn options expose only public challenge and credential metadata.

use super::*;
use crate::webauthn::AssertionMaterial;

pub fn registration_material(value: &Value) -> Result<RegistrationMaterial> {
    crate::webauthn::decode_registration(&value.canonical_bytes())
}

pub fn assertion_material(value: &Value) -> Result<AssertionMaterial> {
    crate::webauthn::decode_assertion(&value.canonical_bytes())
}

impl Snapshot {
    pub fn options(&self) -> Result<Value> {
        let challenge = URL_SAFE_NO_PAD.encode(self.challenge()?);
        let credential = self
            .candidate
            .as_ref()
            .map(|c| &c.credential_id)
            .or(self.context.credential.as_ref());
        let public_key = if self.purpose == CeremonyPurpose::Enrolment && self.state == "fresh" {
            serde_json::json!({
                "challenge": challenge,
                "rp": { "id": self.context.origins.relying_party, "name": "AUKORA" },
                "user": { "id": URL_SAFE_NO_PAD.encode(&self.context.identity.user_handle),
                    "name": self.context.identity.owner_id, "displayName": "Owner" },
                "pubKeyCredParams": [{"type":"public-key","alg":-7},{"type":"public-key","alg":-8}],
                "timeout": MAX_CEREMONY_MS, "attestation": "none",
                "authenticatorSelection": {"residentKey":"required","userVerification":"required"},
                "excludeCredentials": [], "extensions": {"prf":{}},
            })
        } else {
            let credential = credential.ok_or_else(|| refusal("credential-id"))?;
            serde_json::json!({
                "challenge": challenge, "rpId": self.context.origins.relying_party,
                "timeout": MAX_CEREMONY_MS, "userVerification": "required",
                "allowCredentials": [{"type":"public-key","id":URL_SAFE_NO_PAD.encode(credential.as_bytes())}],
            })
        };
        let mut response = serde_json::json!({
            "ceremony_id": self.id.to_string(), "public_key": public_key,
            "expires_at": self.deadline,
        });
        if self.purpose == CeremonyPurpose::Enrolment {
            response
                .as_object_mut()
                .ok_or_else(|| refusal("ceremony-data-invalid"))?
                .remove("ceremony_id");
            response["enrolment_id"] = self.id.to_string().into();
        }
        canon::json::parse_strict(canonical(&response)?.as_bytes())
    }
}
