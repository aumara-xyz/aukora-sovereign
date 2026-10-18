// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay pins are usable only while the host's live firewall read-back matches.

use super::{canonical, disk, exact, member, number, text, NodeConfig};
use canon::{digest::Digest32, json::ValueView, Refusal, Result};
use relay::egress::EgressPolicy;

impl NodeConfig {
    pub fn current_relay_policy(&self, now_ms: u64) -> Result<EgressPolicy> {
        let policy = self.load_egress()?.policy;
        let status = canonical(&disk::read_host_file(&self.egress_status, 4096)?)?;
        check_status(&policy, &status, now_ms)?;
        Ok(policy)
    }
}

fn check_status(policy: &EgressPolicy, status: &canon::json::Value, now_ms: u64) -> Result<()> {
    exact(
        status,
        &[
            "v",
            "epoch",
            "policy_sha256",
            "loaded_policy_sha256",
            "loaded_ruleset_sha256",
            "live_ruleset_sha256",
            "ok",
            "observed_at_ms",
        ],
    )?;
    let observed = number(status, "observed_at_ms")?;
    let digest = |name| Digest32::from_hex(text(status, name)?);
    if number(status, "v")? != 1
        || number(status, "epoch")? != policy.epoch
        || !matches!(member(status, "ok")?.view(), ValueView::Boolean(true))
        || observed == 0
        || observed > now_ms
        || now_ms - observed > 30_000
        || digest("policy_sha256")? != policy.host_policy_digest
        || digest("loaded_policy_sha256")? != policy.host_policy_digest
        || digest("loaded_ruleset_sha256")? != digest("live_ruleset_sha256")?
    {
        return Err(Refusal {
            organ: "relay",
            reason: "egress-unavailable",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon::json::parse_strict;

    #[test]
    fn pins_require_fresh_matching_live_policy() {
        let hash = Digest32::sha256(b"policy");
        let rules = Digest32::sha256(b"rules");
        let policy = EgressPolicy {
            v: 1,
            epoch: 2,
            host_policy_digest: hash,
            relays: vec![],
        };
        let status = serde_json::json!({
            "v":1,"epoch":2,"policy_sha256":hash.to_string(),"loaded_policy_sha256":hash.to_string(),
            "loaded_ruleset_sha256":rules.to_string(),"live_ruleset_sha256":rules.to_string(),
            "ok":true,"observed_at_ms":1000,
        });
        let check = |v: &serde_json::Value, now| {
            check_status(
                &policy,
                &parse_strict(&serde_json::to_vec(v).unwrap()).unwrap(),
                now,
            )
        };
        assert!(check(&status, 1000).is_ok());
        assert!(check(&status, 31_001).is_err());
        assert!(check(&status, 999).is_err());
        for (field, value) in [
            ("epoch", serde_json::json!(1)),
            ("ok", serde_json::json!(false)),
            ("loaded_policy_sha256", serde_json::json!(rules.to_string())),
            ("live_ruleset_sha256", serde_json::json!(hash.to_string())),
        ] {
            let mut bad = status.clone();
            bad[field] = value;
            assert!(check(&bad, 1000).is_err());
        }
    }
}
