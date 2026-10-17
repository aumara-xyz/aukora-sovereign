// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standing grants for the door's crossing classes: the owner's pre-signed answer to one kind of crossing.
//!
//! A grant names one class and what inside it (hosts, memory lanes, MCP servers, providers, path prefixes), a
//! window (`not_before`..`expires_at`, at most seven days) and how many crossings per UTC day it may clear. It is
//! **non-onward**: it has no field that creates, widens or renews another grant, it never covers `plugin`, `persist`,
//! `shell-interactive` or `unknown` (see `CrossingClass::shape`), and a crossing it clears is judged again by the door
//! on its own bytes. It is **revocable** without a passkey (revoking only narrows): `GrantSet::revoke`.
//! Creating or widening a grant is a critical gate proposal the owner approves with a passkey; this module only
//! prepares those bytes. Data here never approves anything.

use canon::{digest::Digest32, ids::ProposalId, json::Value};

use crate::codec::{array, canonical, exact, int, number, string, string_array, strings, text};
use crate::crossing::{host_token, prefix_token, token_shape, Crossing, CrossingClass, GrantShape, CLOSED_LANES};
use crate::{refuse, Result};

pub const GRANT_TARGET: &str = "door/standing-grants.json";
pub const DAY_MS: i64 = 86_400_000;
pub const MAX_GRANT_MS: i64 = 7 * DAY_MS;
pub const MAX_SCOPE: usize = 32;
pub const MAX_PER_DAY: u32 = 100_000;
pub const MAX_GRANT_BYTES: usize = 4_096;
pub const MAX_SET_BYTES: usize = 65_536;
pub const MAX_GRANTS: usize = 64;
pub const MAX_REVOKED: usize = 256;
const ID_DOMAIN: &[u8] = b"aukora:door-grant:v1\0";

/// Registration data for the grant target; Gate owns its passkey path. The target is critical, so a grant or a
/// widening always takes a fresh passkey assertion, and the guest's own `propose` refuses `door/` targets.
pub fn grant_target_spec() -> Result<gate::target::TargetSpec> {
    critical_target(GRANT_TARGET, MAX_SET_BYTES)
}

pub fn critical_target(id: &str, max_bytes: usize) -> Result<gate::target::TargetSpec> {
    Ok(gate::target::TargetSpec {
        id: gate::target::TargetId::new(id.to_owned())?,
        class: gate::target::TargetClass::Content,
        risk: canon::authority::CardRisk::Critical,
        max_bytes,
    })
}

pub fn critical_proposal(id: &str, new_bytes: Vec<u8>, base: canon::authority::BaseDigest) -> Result<gate::ProposalRequest> {
    Ok(gate::ProposalRequest {
        target: gate::target::TargetId::new(id.to_owned())?,
        base,
        new_bytes,
        model_note: String::new(),
        cell: None,
        new_evidence: None,
        suggestion: gate::proposal::SuggestionOrder::Single,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoorGrant {
    pub class: CrossingClass,
    /// Exact entries (path prefixes for `fs-outside`); at least one, at most 32, no repeats.
    pub scope: Vec<String>,
    /// Crossings this grant may clear per UTC day; at least 1.
    pub per_day: u32,
    pub not_before: i64,
    pub expires_at: i64,
    pub nonce: ProposalId,
}

impl DoorGrant {
    fn keys() -> [&'static str; 7] {
        ["v", "class", "scope", "per_day", "not_before", "expires_at", "nonce"]
    }

    /// Exact seven-key canonical object, no unknown fields.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = canonical(bytes, MAX_GRANT_BYTES).ok_or(refuse("grant-schema"))?;
        Self::from_value(&value)
    }

    fn from_value(value: &Value) -> Result<Self> {
        let schema = || refuse("grant-schema");
        exact(value, &Self::keys()).ok_or_else(schema)?;
        let per_day = int(value, "per_day").and_then(|n| u32::try_from(n).ok()).ok_or_else(schema)?;
        let grant = Self {
            class: text(value, "class").and_then(CrossingClass::from_wire).ok_or(refuse("unknown-class"))?,
            scope: array(value, "scope").and_then(strings).ok_or_else(schema)?,
            per_day,
            not_before: int(value, "not_before").ok_or_else(schema)?,
            expires_at: int(value, "expires_at").ok_or_else(schema)?,
            nonce: text(value, "nonce").and_then(|hex| ProposalId::from_hex(hex).ok()).ok_or_else(schema)?,
        };
        if int(value, "v") != Some(1) {
            return Err(schema());
        }
        grant.validate()?;
        Ok(grant)
    }

    fn to_value(&self) -> Result<Value> {
        let bad = || refuse("grant-schema");
        Value::checked_object(vec![
            ("v".to_owned(), number(1).ok_or_else(bad)?),
            ("class".to_owned(), string(self.class.wire_name()).ok_or_else(bad)?),
            ("scope".to_owned(), string_array(&self.scope).ok_or_else(bad)?),
            ("per_day".to_owned(), number(i64::from(self.per_day)).ok_or_else(bad)?),
            ("not_before".to_owned(), number(self.not_before).ok_or_else(bad)?),
            ("expires_at".to_owned(), number(self.expires_at).ok_or_else(bad)?),
            ("nonce".to_owned(), string(&self.nonce.to_string()).ok_or_else(bad)?),
        ])
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = self.to_value()?.canonical_bytes();
        if bytes.len() > MAX_GRANT_BYTES {
            return Err(refuse("grant-bounds"));
        }
        Ok(bytes)
    }

    /// The grant's identity: a domain-separated digest of its canonical bytes. Revocation and daily counts use it.
    pub fn id(&self) -> Result<Digest32> {
        let mut preimage = ID_DOMAIN.to_vec();
        preimage.extend_from_slice(&self.canonical_bytes()?);
        Ok(Digest32::sha256(&preimage))
    }

    pub fn validate(&self) -> Result<()> {
        if self.class.shape() == GrantShape::Never {
            return Err(refuse("grant-class"));
        }
        let window = self.expires_at.checked_sub(self.not_before);
        if self.not_before < 0
            || self.expires_at > canon::json::MAX_SAFE_INTEGER
            || !window.is_some_and(|ms| ms > 0 && ms <= MAX_GRANT_MS)
            || self.per_day == 0
            || self.per_day > MAX_PER_DAY
            || self.scope.is_empty()
            || self.scope.len() > MAX_SCOPE
        {
            return Err(refuse("grant-bounds"));
        }
        let well_formed = |entry: &String| match self.class.shape() {
            GrantShape::Hosts => host_token(entry),
            GrantShape::Prefixes => prefix_token(entry),
            GrantShape::Memory => {
                token_shape(CrossingClass::Memory, entry)
                    && !entry.strip_prefix("write:").is_some_and(|lane| CLOSED_LANES.contains(&lane))
            }
            _ => token_shape(self.class, entry),
        };
        if !self.scope.iter().all(well_formed) || self.scope.iter().enumerate().any(|(i, entry)| self.scope[..i].contains(entry)) {
            return Err(refuse("grant-scope"));
        }
        Ok(())
    }

    /// Inside its window.
    pub fn live(&self, now_ms: i64) -> bool {
        self.not_before <= now_ms && now_ms < self.expires_at
    }

    /// Whether the scope names this crossing. A class mismatch never covers.
    pub fn covers(&self, crossing: &Crossing) -> bool {
        crossing.class == self.class && self.scope.iter().any(|entry| crossing.covered_by(entry))
    }
}

/// Why `GrantSet::revoke` changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeError {
    /// This id was revoked before; the set already narrows it.
    AlreadyRevoked,
    /// The revoked list is at `MAX_REVOKED`; the id was **not** recorded.
    Full,
}

/// The owner's grants and the ids of those revoked. Revoked ids stay listed so a revoked grant can never come back
/// by being signed again with the same bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantSet {
    grants: Vec<DoorGrant>,
    revoked: Vec<Digest32>,
}

impl GrantSet {
    /// `{"grants":[..],"revoked":["<id hex>",..],"v":1}`: canonical, bounded, every grant valid.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let schema = || refuse("grant-schema");
        let value = canonical(bytes, MAX_SET_BYTES).ok_or_else(schema)?;
        exact(&value, &["v", "grants", "revoked"]).ok_or_else(schema)?;
        if int(&value, "v") != Some(1) {
            return Err(schema());
        }
        let grants = array(&value, "grants").ok_or_else(schema)?;
        let revoked = array(&value, "revoked").and_then(strings).ok_or_else(schema)?;
        if grants.len() > MAX_GRANTS || revoked.len() > MAX_REVOKED {
            return Err(refuse("grant-bounds"));
        }
        let grants = grants.iter().map(DoorGrant::from_value).collect::<Result<Vec<_>>>()?;
        let revoked = revoked.iter().map(|hex| Digest32::from_hex(hex).map_err(|_| schema())).collect::<Result<Vec<_>>>()?;
        let set = Self { grants, revoked };
        set.canonical_bytes().map(|_| set)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let bad = || refuse("grant-schema");
        if self.grants.len() > MAX_GRANTS || self.revoked.len() > MAX_REVOKED {
            return Err(refuse("grant-bounds"));
        }
        let mut grants = Vec::new();
        for grant in &self.grants {
            grant.validate()?;
            grants.push(grant.to_value()?);
        }
        let revoked: Vec<String> = self.revoked.iter().map(Digest32::to_string).collect();
        let ids = self.grants.iter().map(DoorGrant::id).collect::<Result<Vec<_>>>()?;
        let repeats = |items: &[Digest32]| (0..items.len()).any(|i| items[..i].contains(&items[i]));
        if repeats(&ids) || repeats(&self.revoked) {
            return Err(refuse("grant-set"));
        }
        let value = Value::checked_object(vec![
            ("v".to_owned(), number(1).ok_or_else(bad)?),
            ("grants".to_owned(), Value::checked_array(grants)?),
            ("revoked".to_owned(), string_array(&revoked).ok_or_else(bad)?),
        ])?;
        let bytes = value.canonical_bytes();
        if bytes.len() > MAX_SET_BYTES {
            return Err(refuse("grant-bounds"));
        }
        Ok(bytes)
    }

    /// Candidate bytes for the critical grant proposal. The node and gate bind the base and the passkey; nothing
    /// here is an approval.
    pub fn proposal(&self, base: canon::authority::BaseDigest) -> Result<gate::ProposalRequest> {
        critical_proposal(GRANT_TARGET, self.canonical_bytes()?, base)
    }

    pub fn grants(&self) -> &[DoorGrant] {
        &self.grants
    }

    /// Widening: only the owner's passkey-approved bytes may become a set with a new grant, so this returns a new
    /// set for a proposal and changes nothing live.
    pub fn with_grant(&self, grant: DoorGrant) -> Result<Self> {
        let mut next = self.clone();
        next.grants.push(grant);
        next.canonical_bytes().map(|_| next)
    }

    /// Narrowing: revoke one grant by id; needs no passkey because it can only remove authority. Revoking an id that is
    /// already revoked changes nothing and says so (`AlreadyRevoked`); a full revoked list cannot take another id and
    /// says that instead (`Full`), because the caller must then `prune` or the revocation did **not** happen.
    pub fn revoke(&mut self, id: Digest32) -> core::result::Result<(), RevokeError> {
        if self.revoked.contains(&id) {
            return Err(RevokeError::AlreadyRevoked);
        }
        if self.revoked.len() >= MAX_REVOKED {
            return Err(RevokeError::Full);
        }
        self.revoked.push(id);
        Ok(())
    }

    /// Drop every grant whose window has ended (`expires_at <= now_ms`) together with its revoked id, and return how
    /// many grants went. An expired grant can never clear a crossing again, and neither can the same bytes signed
    /// again (the window is in the bytes), so its revocation record no longer protects anything; keeping it would only
    /// fill the bounded revoked list until `revoke` refused a live grant. A revoked id whose grant is not in this set
    /// is kept: nothing here says when that grant ends.
    pub fn prune(&mut self, now_ms: i64) -> usize {
        let before = self.grants.len();
        let mut gone: Vec<Digest32> = Vec::new();
        self.grants.retain(|grant| {
            if grant.expires_at > now_ms {
                return true;
            }
            if let Ok(id) = grant.id() {
                gone.push(id);
            }
            false
        });
        self.revoked.retain(|id| !gone.contains(id));
        before - self.grants.len()
    }

    pub fn is_revoked(&self, id: &Digest32) -> bool {
        self.revoked.contains(id)
    }

    /// Grants that are live, not revoked and name this crossing, with their ids.
    pub fn matching<'a>(&'a self, crossing: &'a Crossing, now_ms: i64) -> impl Iterator<Item = (Digest32, &'a DoorGrant)> + 'a {
        self.grants.iter().filter_map(move |grant| {
            let id = grant.id().ok()?;
            (grant.live(now_ms) && grant.covers(crossing) && !self.is_revoked(&id)).then_some((id, grant))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn grant(class: CrossingClass, scope: &[&str], per_day: u32) -> DoorGrant {
        DoorGrant {
            class,
            scope: scope.iter().map(|s| (*s).to_owned()).collect(),
            per_day,
            not_before: 1_000,
            expires_at: 1_000 + DAY_MS,
            nonce: ProposalId::from_bytes([7; 16]),
        }
    }

    #[test]
    fn a_grant_round_trips_through_its_one_canonical_form() {
        let grant = grant(CrossingClass::Net, &["docs.rs", "crates.io"], 50);
        let bytes = grant.canonical_bytes().unwrap();
        assert_eq!(DoorGrant::parse(&bytes).unwrap(), grant);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(DoorGrant::parse(text.replacen('{', "{ ", 1).as_bytes()).is_err());
        assert_eq!(DoorGrant::parse(&[b' '].iter().chain(&bytes).copied().collect::<Vec<_>>()).unwrap_err().reason, "grant-schema");
        let extra = text.replacen('{', "{\"extra\":1,", 1);
        assert!(DoorGrant::parse(extra.as_bytes()).is_err());
    }

    #[test]
    fn every_class_has_a_shape_and_the_never_standing_ones_refuse_a_grant() {
        for class in CrossingClass::ALL {
            let tried = match class.shape() {
                GrantShape::Hosts => grant(class, &["docs.rs"], 1),
                GrantShape::Memory => grant(class, &["read", "write:notes"], 1),
                GrantShape::Servers | GrantShape::Providers => grant(class, &["github"], 1),
                GrantShape::Prefixes => grant(class, &["/srv/shared"], 1),
                GrantShape::Never => grant(class, &["x"], 1),
            };
            let expected = if class.shape() == GrantShape::Never { Err("grant-class") } else { Ok(()) };
            assert_eq!(tried.validate().map_err(|r| r.reason), expected, "{}", class.wire_name());
        }
    }

    #[test]
    fn bounds_and_scope_are_enforced() {
        let net = |scope: &[&str]| grant(CrossingClass::Net, scope, 5);
        for (bad, why) in [
            (net(&[]), "grant-bounds"),
            (net(&["docs.rs", "docs.rs"]), "grant-scope"),
            (net(&["127.0.0.1"]), "grant-scope"),
            (net(&["*.rs"]), "grant-scope"),
            (grant(CrossingClass::Net, &["docs.rs"], 0), "grant-bounds"),
            (grant(CrossingClass::Net, &["docs.rs"], MAX_PER_DAY + 1), "grant-bounds"),
            (grant(CrossingClass::Memory, &["write:decision"], 1), "grant-scope"),
            (grant(CrossingClass::Memory, &["write:self"], 1), "grant-scope"),
            (grant(CrossingClass::FsOutside, &["/srv"], 1), "grant-scope"),
        ] {
            assert_eq!(bad.validate().unwrap_err().reason, why);
        }
        let mut long = net(&["docs.rs"]);
        long.expires_at = long.not_before + MAX_GRANT_MS + 1;
        assert_eq!(long.validate().unwrap_err().reason, "grant-bounds");
        long.expires_at = long.not_before;
        assert_eq!(long.validate().unwrap_err().reason, "grant-bounds");
    }

    #[test]
    fn a_grant_covers_only_its_class_scope_and_window() {
        let g = grant(CrossingClass::Net, &["docs.rs"], 3);
        assert!(g.covers(&Crossing::new(CrossingClass::Net, "docs.rs")));
        assert!(!g.covers(&Crossing::new(CrossingClass::Net, "crates.io")));
        assert!(!g.covers(&Crossing::new(CrossingClass::Mcp, "docs.rs")));
        assert!(!g.live(999) && g.live(1_000) && g.live(1_000 + DAY_MS - 1) && !g.live(1_000 + DAY_MS));
    }

    #[test]
    fn revocation_narrows_and_is_idempotent_and_a_set_round_trips() {
        let a = grant(CrossingClass::Net, &["docs.rs"], 3);
        let b = grant(CrossingClass::Memory, &["read"], 9);
        let mut set = GrantSet::default().with_grant(a.clone()).unwrap().with_grant(b.clone()).unwrap();
        assert_eq!(set.matching(&Crossing::new(CrossingClass::Net, "docs.rs"), 2_000).count(), 1);
        assert_eq!(set.revoke(a.id().unwrap()), Ok(()));
        assert_eq!(set.revoke(a.id().unwrap()), Err(RevokeError::AlreadyRevoked));
        assert_eq!(set.matching(&Crossing::new(CrossingClass::Net, "docs.rs"), 2_000).count(), 0);
        assert_eq!(set.matching(&Crossing::new(CrossingClass::Memory, "read"), 2_000).count(), 1);
        let bytes = set.canonical_bytes().unwrap();
        assert_eq!(GrantSet::parse(&bytes).unwrap(), set);
        // A grant that is not valid cannot hide inside a set.
        let tampered = String::from_utf8(bytes).unwrap().replace("\"read\"", "\"write:self\"");
        assert!(GrantSet::parse(tampered.as_bytes()).is_err());
    }

    #[test]
    fn the_proposal_targets_the_critical_door_grant_target() {
        let spec = grant_target_spec().unwrap();
        assert_eq!(spec.risk, canon::authority::CardRisk::Critical);
        assert_eq!(spec.id.as_str(), GRANT_TARGET);
    }

    fn aged(nonce: u8, expires_at: i64) -> DoorGrant {
        DoorGrant { nonce: ProposalId::from_bytes([nonce; 16]), not_before: 1_000, expires_at, ..grant(CrossingClass::Net, &["docs.rs"], 1) }
    }

    #[test]
    fn a_full_revoked_list_is_told_apart_from_an_id_already_revoked() {
        let mut set = GrantSet::default();
        for i in 0..MAX_REVOKED {
            let id = Digest32::sha256(&i.to_be_bytes());
            assert_eq!(set.revoke(id), Ok(()));
        }
        let first = Digest32::sha256(&0usize.to_be_bytes());
        assert_eq!(set.revoke(first), Err(RevokeError::AlreadyRevoked));
        let fresh = Digest32::sha256(b"one more");
        assert_eq!(set.revoke(fresh), Err(RevokeError::Full));
        assert!(!set.is_revoked(&fresh));
    }

    #[test]
    fn prune_drops_expired_grants_and_their_revoked_ids_and_nothing_else() {
        let live = aged(1, 1_000 + DAY_MS);
        let expired_revoked = aged(2, 5_000);
        let expired_plain = aged(3, 5_000);
        let mut set = GrantSet::default()
            .with_grant(live.clone()).unwrap()
            .with_grant(expired_revoked.clone()).unwrap()
            .with_grant(expired_plain).unwrap();
        let unknown = Digest32::sha256(b"a grant this set no longer holds");
        assert_eq!(set.revoke(expired_revoked.id().unwrap()), Ok(()));
        assert_eq!(set.revoke(live.id().unwrap()), Ok(()));
        assert_eq!(set.revoke(unknown), Ok(()));
        // Nothing has ended yet, and the end instant itself is already ended (live() is `now < expires_at`).
        assert_eq!(set.clone().prune(4_999), 0);
        assert_eq!(set.prune(5_000), 2);
        assert_eq!(set.grants(), &[live.clone()]);
        assert!(!set.is_revoked(&expired_revoked.id().unwrap()));
        assert!(set.is_revoked(&live.id().unwrap()), "a live grant stays revoked");
        assert!(set.is_revoked(&unknown), "an id with no grant here is kept");
        assert_eq!(set.prune(5_000), 0, "idempotent");
        // The pruned set is still one valid canonical set, and freed room is usable again.
        assert_eq!(GrantSet::parse(&set.canonical_bytes().unwrap()).unwrap(), set);
    }

    #[test]
    fn prune_frees_a_full_revoked_list() {
        let old = aged(9, 2_000);
        let mut set = GrantSet::default().with_grant(old.clone()).unwrap();
        assert_eq!(set.revoke(old.id().unwrap()), Ok(()));
        for i in 1..MAX_REVOKED {
            assert_eq!(set.revoke(Digest32::sha256(&i.to_be_bytes())), Ok(()));
        }
        assert_eq!(set.revoke(Digest32::sha256(b"x")), Err(RevokeError::Full));
        assert_eq!(set.prune(2_000), 1);
        assert_eq!(set.revoke(Digest32::sha256(b"x")), Ok(()));
    }
}
