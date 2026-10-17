// SPDX-License-Identifier: AGPL-3.0-or-later
//! The slider for the door's crossings: Rust computes a floor from the owner's setting, grants and today's counts;
//! Laya's escalation can only raise it (`max(floor, laya)`); nothing here approves anything.
//!
//! The four settings (the composer's "Risk 1-4") are distinct:
//! - `ask` (1): every crossing asks, whatever grants exist.
//! - `risky` (2, the default): only risky classes ask. A routine class clears only inside a live standing grant (and
//!   its counts).
//! - `limits` (3): any grantable class clears inside a live grant and today's counts, risky ones included; once a
//!   count is spent, the crossing asks again.
//! - `trusted` (4): any grantable class clears inside a live grant with NO count. The grant's own scope, its window
//!   (seven days at most) and its revocation are the bounds, and a grant exists only because the owner's passkey
//!   approved it.
//!
//! A class that cannot be granted (`plugin`, `persist`, `shell-interactive`, `unknown`) asks under every setting.
//! Moving to a higher number is a loosening and takes the owner's passkey; Laya can only raise the floor.

use std::collections::BTreeMap;

use canon::{authority::BaseDigest, digest::Digest32};

use crate::codec::{array, canonical, exact, int, number, string, text};
use crate::crossing::{Crossing, CrossingClass, GrantShape, Risk};
use crate::grant::{GrantSet, DAY_MS, MAX_PER_DAY};
use crate::standing::SliderSetting;
use crate::triage::TriageOutcome;
use crate::{refuse, Result};

pub const POLICY_TARGET: &str = "door/slider-policy.json";
pub const MAX_POLICY_BYTES: usize = 4_096;
/// The sha256 of `data/starter-slider-v1.json`, the starter that ships at "only risky things".
pub const STARTER_SHA256: &str = "d6ddf3e54dd57d43850f7568c310fe035a48afac8f1661ec2c4dfcd5846a5369";
const STARTER_BYTES: &[u8] = include_bytes!("../data/starter-slider-v1.json");

/// What the slider requires of one crossing. `AutoClear < Ask`; raising is `max`, lowering does not exist here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Floor {
    AutoClear,
    Ask,
}

impl Floor {
    /// The stricter of two floors.
    pub fn raise(self, other: Floor) -> Floor {
        self.max(other)
    }

    /// Laya's escalation can only raise: `Escalate` asks, `NoAdditionalEvidence` leaves the floor alone.
    pub fn raised_by(self, outcome: &TriageOutcome) -> Floor {
        match outcome {
            TriageOutcome::Escalate(_) => self.raise(Floor::Ask),
            TriageOutcome::NoAdditionalEvidence => self,
        }
    }
}

/// One class's rule: its risk (never below the built-in) and how many crossings may clear per UTC day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassRule {
    pub class: CrossingClass,
    pub risk: Risk,
    pub per_day: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SliderPolicy {
    pub setting: SliderSetting,
    /// At most one rule per class; a class with no rule has its built-in risk and a cap of zero (it asks).
    pub classes: Vec<ClassRule>,
}

fn risk_name(risk: Risk) -> &'static str {
    match risk {
        Risk::Routine => "routine",
        Risk::Risky => "risky",
    }
}

impl SliderPolicy {
    pub fn rule(&self, class: CrossingClass) -> ClassRule {
        self.classes
            .iter()
            .find(|rule| rule.class == class)
            .copied()
            .unwrap_or(ClassRule { class, risk: class.risk(), per_day: 0 })
    }

    /// Whether moving from `previous` to this setting loosens the slider, which takes the owner's passkey.
    pub fn loosens(&self, previous: SliderSetting) -> bool {
        self.setting.loosens(previous)
    }

    pub fn validate(&self) -> Result<()> {
        let sorted = self.classes.windows(2).all(|pair| pair[0].class.wire_name() < pair[1].class.wire_name());
        let ok = self.classes.iter().all(|rule| {
            rule.risk >= rule.class.risk()
                && rule.per_day <= MAX_PER_DAY
                && (rule.class.shape() != GrantShape::Never || rule.per_day == 0)
        });
        if sorted && ok {
            Ok(())
        } else {
            Err(refuse("policy-bounds"))
        }
    }

    /// `{"classes":[{"class":..,"per_day":..,"risk":..}],"setting":"ask|risky|limits|trusted","v":1}`, classes in name
    /// order.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bad = || refuse("policy-schema");
        let mut rules = Vec::new();
        for rule in &self.classes {
            rules.push(canon::json::Value::checked_object(vec![
                ("class".to_owned(), string(rule.class.wire_name()).ok_or_else(bad)?),
                ("per_day".to_owned(), number(i64::from(rule.per_day)).ok_or_else(bad)?),
                ("risk".to_owned(), string(risk_name(rule.risk)).ok_or_else(bad)?),
            ])?);
        }
        let value = canon::json::Value::checked_object(vec![
            ("v".to_owned(), number(1).ok_or_else(bad)?),
            ("setting".to_owned(), string(self.setting.wire_name()).ok_or_else(bad)?),
            ("classes".to_owned(), canon::json::Value::checked_array(rules)?),
        ])?;
        Ok(value.canonical_bytes())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let schema = || refuse("policy-schema");
        let value = canonical(bytes, MAX_POLICY_BYTES).ok_or_else(schema)?;
        exact(&value, &["v", "setting", "classes"]).ok_or_else(schema)?;
        if int(&value, "v") != Some(1) {
            return Err(schema());
        }
        let mut classes = Vec::new();
        for item in array(&value, "classes").ok_or_else(schema)? {
            exact(item, &["class", "per_day", "risk"]).ok_or_else(schema)?;
            classes.push(ClassRule {
                class: text(item, "class").and_then(CrossingClass::from_wire).ok_or(refuse("unknown-class"))?,
                per_day: int(item, "per_day").and_then(|n| u32::try_from(n).ok()).ok_or_else(schema)?,
                risk: match text(item, "risk") {
                    Some("routine") => Risk::Routine,
                    Some("risky") => Risk::Risky,
                    _ => return Err(schema()),
                },
            });
        }
        let policy = Self { setting: SliderSetting::from_policy_wire(text(&value, "setting").ok_or_else(schema)?)?, classes };
        policy.validate()?;
        Ok(policy)
    }

    /// Candidate bytes for the critical policy proposal; a loosening setting needs the owner's passkey like any
    /// other critical change.
    pub fn proposal(&self, base: BaseDigest) -> Result<gate::ProposalRequest> {
        crate::grant::critical_proposal(POLICY_TARGET, self.canonical_bytes()?, base)
    }

    /// The registration data of the policy target.
    pub fn target_spec() -> Result<gate::target::TargetSpec> {
        crate::grant::critical_target(POLICY_TARGET, MAX_POLICY_BYTES)
    }
}

/// The slider that ships: "only risky things", the two routine classes capped per day, everything else asking. The
/// bytes are pinned by `STARTER_SHA256` here and in `checks/pins.json`, and the release that carries them is the
/// owner's passkey-approved release; installing it over a stricter setting is a loosening and takes the passkey.
pub fn starter() -> Result<SliderPolicy> {
    if Digest32::sha256(STARTER_BYTES).to_string() != STARTER_SHA256 {
        return Err(refuse("policy-pin"));
    }
    SliderPolicy::parse(STARTER_BYTES)
}

/// How many crossings were cleared on one UTC day, per class and per grant. The caller persists it; a count from a
/// different day is zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    day: i64,
    classes: BTreeMap<CrossingClass, u32>,
    grants: BTreeMap<Digest32, u32>,
}

pub fn day_of(now_ms: i64) -> i64 {
    now_ms.div_euclid(DAY_MS)
}

impl Usage {
    /// The UTC day these counts are for (0 before anything was recorded).
    pub fn day(&self) -> i64 {
        self.day
    }

    fn today(&self, now_ms: i64) -> bool {
        self.day == day_of(now_ms)
    }

    pub fn class_used(&self, class: CrossingClass, now_ms: i64) -> u32 {
        if self.today(now_ms) { self.classes.get(&class).copied().unwrap_or(0) } else { 0 }
    }

    pub fn grant_used(&self, id: &Digest32, now_ms: i64) -> u32 {
        if self.today(now_ms) { self.grants.get(id).copied().unwrap_or(0) } else { 0 }
    }

    /// Count one cleared crossing against its class and grant, starting a new day when the day has turned.
    pub fn record(&mut self, class: CrossingClass, grant: Digest32, now_ms: i64) {
        if !self.today(now_ms) {
            *self = Usage { day: day_of(now_ms), ..Usage::default() };
        }
        *self.classes.entry(class).or_insert(0) += 1;
        *self.grants.entry(grant).or_insert(0) += 1;
    }
}

/// The slider's answer for one crossing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub floor: Floor,
    /// Why, in a word the door can log: `clear`, `clear-trusted`, `ask-everything`, `never-standing`, `risky-class`,
    /// `class-cap`, `no-grant`, `grant-exhausted`, `clock`, `laya`.
    pub reason: &'static str,
    /// The grant to count the crossing against, when it auto-clears.
    pub grant: Option<Digest32>,
}

impl Decision {
    fn ask(reason: &'static str) -> Self {
        Self { floor: Floor::Ask, reason, grant: None }
    }

    /// Laya can raise a clear to an ask; it cannot lower an ask, and it never produces a grant.
    pub fn raised_by(self, outcome: &TriageOutcome) -> Self {
        match (self.floor, outcome) {
            (Floor::AutoClear, TriageOutcome::Escalate(_)) => Self::ask("laya"),
            _ => self,
        }
    }
}

/// Rust's floor for one crossing. Pure: it counts nothing; the caller records a clear after it is durable.
pub fn decide(policy: &SliderPolicy, grants: &GrantSet, usage: &Usage, crossing: &Crossing, now_ms: i64) -> Decision {
    if now_ms < 0 {
        return Decision::ask("clock");
    }
    if policy.setting == SliderSetting::AskEverything {
        return Decision::ask("ask-everything");
    }
    let class = crossing.class;
    if class.shape() == GrantShape::Never {
        return Decision::ask("never-standing");
    }
    let rule = policy.rule(class);
    if !policy.setting.clears(rule.risk.max(class.risk())) {
        return Decision::ask("risky-class");
    }
    if !policy.setting.counts() {
        // Trusted: the live grant that covers this crossing clears it, whatever has been cleared today.
        return match grants.matching(crossing, now_ms).next() {
            Some((id, _)) => Decision { floor: Floor::AutoClear, reason: "clear-trusted", grant: Some(id) },
            None => Decision::ask("no-grant"),
        };
    }
    if rule.per_day == 0 || usage.class_used(class, now_ms) >= rule.per_day {
        return Decision::ask("class-cap");
    }
    let mut covered = false;
    for (id, grant) in grants.matching(crossing, now_ms) {
        covered = true;
        if usage.grant_used(&id, now_ms) < grant.per_day {
            return Decision { floor: Floor::AutoClear, reason: "clear", grant: Some(id) };
        }
    }
    Decision::ask(if covered { "grant-exhausted" } else { "no-grant" })
}

/// Rust's floor, then Laya's deterministic escalation on top: `max(floor, laya)`.
pub fn judge(policy: &SliderPolicy, grants: &GrantSet, usage: &Usage, crossing: &Crossing, now_ms: i64) -> Decision {
    decide(policy, grants, usage, crossing, now_ms).raised_by(&crossing.triage())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::DoorGrant;
    use crate::triage::Escalation;
    use canon::ids::ProposalId;

    const NOW: i64 = 5 * DAY_MS + 1_000;

    fn grant(class: CrossingClass, scope: &[&str], per_day: u32) -> DoorGrant {
        DoorGrant {
            class,
            scope: scope.iter().map(|s| (*s).to_owned()).collect(),
            per_day,
            not_before: NOW - 1_000,
            expires_at: NOW + 3 * DAY_MS,
            nonce: ProposalId::from_bytes([3; 16]),
        }
    }

    fn policy(setting: SliderSetting) -> SliderPolicy {
        let mut policy = starter().unwrap();
        policy.setting = setting;
        // The two settings that clear risky classes need a risky class with a cap to show it.
        for rule in &mut policy.classes {
            if rule.class == CrossingClass::Mcp {
                rule.per_day = 2;
            }
        }
        policy
    }

    fn grants() -> GrantSet {
        GrantSet::default()
            .with_grant(grant(CrossingClass::Net, &["docs.rs"], 2))
            .unwrap()
            .with_grant(grant(CrossingClass::Memory, &["read", "write:notes"], 10))
            .unwrap()
            .with_grant(grant(CrossingClass::Mcp, &["github"], 5))
            .unwrap()
    }

    fn net() -> Crossing {
        Crossing::new(CrossingClass::Net, "docs.rs")
    }

    #[test]
    fn the_starter_is_pinned_valid_and_at_only_risky_things() {
        let starter = starter().unwrap();
        assert_eq!(starter.setting, SliderSetting::AskRisky);
        assert_eq!(starter.canonical_bytes().unwrap(), STARTER_BYTES);
        assert_eq!(starter.classes.len(), CrossingClass::ALL.len());
        assert!(starter.rule(CrossingClass::Net).per_day > 0 && starter.rule(CrossingClass::Memory).per_day > 0);
        for class in CrossingClass::ALL.into_iter().filter(|c| c.risk() == Risk::Risky) {
            assert_eq!(starter.rule(class).per_day, 0, "{}", class.wire_name());
        }
        // A byte changed anywhere breaks the pin; installing it over a stricter setting is a loosening.
        assert!(starter.loosens(SliderSetting::AskEverything));
        assert!(!starter.loosens(SliderSetting::AskRisky) && !starter.loosens(SliderSetting::WithinTodayLimits));
    }

    #[test]
    fn ask_everything_asks_even_with_a_perfect_grant() {
        let d = judge(&policy(SliderSetting::AskEverything), &grants(), &Usage::default(), &net(), NOW);
        assert_eq!((d.floor, d.reason), (Floor::Ask, "ask-everything"));
    }

    #[test]
    fn only_risky_things_clears_a_routine_crossing_inside_a_grant_and_asks_for_the_rest() {
        let (p, g, u) = (policy(SliderSetting::AskRisky), grants(), Usage::default());
        let routine = judge(&p, &g, &u, &net(), NOW);
        assert_eq!((routine.floor, routine.reason), (Floor::AutoClear, "clear"));
        assert!(routine.grant.is_some());
        assert_eq!(judge(&p, &g, &u, &Crossing::new(CrossingClass::Memory, "write:notes"), NOW).floor, Floor::AutoClear);
        // No grant for the host, or a risky class even with a grant and a cap: ask.
        assert_eq!(judge(&p, &g, &u, &Crossing::new(CrossingClass::Net, "crates.io"), NOW).reason, "no-grant");
        assert_eq!(judge(&p, &g, &u, &Crossing::new(CrossingClass::Mcp, "github"), NOW).reason, "risky-class");
    }

    #[test]
    fn within_todays_limits_also_clears_a_granted_risky_class_until_the_count_is_spent() {
        let (p, g) = (policy(SliderSetting::WithinTodayLimits), grants());
        let mcp = Crossing::new(CrossingClass::Mcp, "github");
        let mut usage = Usage::default();
        for _ in 0..2 {
            let d = judge(&p, &g, &usage, &mcp, NOW);
            assert_eq!(d.floor, Floor::AutoClear);
            usage.record(CrossingClass::Mcp, d.grant.unwrap(), NOW);
        }
        // The class cap (2) is spent before the grant's own five.
        assert_eq!(judge(&p, &g, &usage, &mcp, NOW).reason, "class-cap");
        // Tomorrow the counts start again.
        assert_eq!(judge(&p, &g, &usage, &mcp, NOW + DAY_MS).floor, Floor::AutoClear);
    }

    #[test]
    fn the_settings_really_differ_on_the_same_crossings() {
        let (g, u) = (grants(), Usage::default());
        let mcp = Crossing::new(CrossingClass::Mcp, "github");
        let floors: Vec<_> = [SliderSetting::AskEverything, SliderSetting::AskRisky, SliderSetting::WithinTodayLimits, SliderSetting::Trusted]
            .into_iter()
            .map(|setting| (judge(&policy(setting), &g, &u, &net(), NOW).floor, judge(&policy(setting), &g, &u, &mcp, NOW).floor))
            .collect();
        assert_eq!(
            floors,
            [(Floor::Ask, Floor::Ask), (Floor::AutoClear, Floor::Ask), (Floor::AutoClear, Floor::AutoClear), (Floor::AutoClear, Floor::AutoClear)]
        );
    }

    #[test]
    fn trusted_clears_inside_a_live_grant_with_no_count_and_limits_does_not() {
        let g = grants();
        let net_grant = g.matching(&net(), NOW).next().unwrap().0;
        let mut usage = Usage::default();
        // Far past the grant's own two and the class's own cap: thirty clears in a day.
        for _ in 0..30 {
            usage.record(CrossingClass::Net, net_grant, NOW);
        }
        let limits = judge(&policy(SliderSetting::WithinTodayLimits), &g, &usage, &net(), NOW);
        assert_eq!((limits.floor, limits.reason), (Floor::Ask, "grant-exhausted"));
        let trusted = judge(&policy(SliderSetting::Trusted), &g, &usage, &net(), NOW);
        assert_eq!((trusted.floor, trusted.reason), (Floor::AutoClear, "clear-trusted"));
        assert_eq!(trusted.grant, Some(net_grant));
        // A risky class whose policy cap is zero (the starter's) clears too: under trusted the count is not asked.
        let mut p = starter().unwrap();
        p.setting = SliderSetting::Trusted;
        assert_eq!(p.rule(CrossingClass::Mcp).per_day, 0);
        let mcp = judge(&p, &g, &Usage::default(), &Crossing::new(CrossingClass::Mcp, "github"), NOW);
        assert_eq!((mcp.floor, mcp.reason), (Floor::AutoClear, "clear-trusted"));
    }

    #[test]
    fn trusted_still_needs_a_live_grant_that_covers_the_crossing() {
        let p = policy(SliderSetting::Trusted);
        let (g, u) = (grants(), Usage::default());
        // No grant for the host, the lane or the server; a grant for another class never covers.
        assert_eq!(judge(&p, &g, &u, &Crossing::new(CrossingClass::Net, "crates.io"), NOW).reason, "no-grant");
        assert_eq!(judge(&p, &g, &u, &Crossing::new(CrossingClass::Memory, "write:other"), NOW).reason, "no-grant");
        assert_eq!(judge(&p, &g, &u, &Crossing::new(CrossingClass::Delegate, "docs.rs"), NOW).reason, "no-grant");
        // Not yet live, expired, revoked: nothing.
        assert_eq!(judge(&p, &g, &u, &net(), NOW - 2_000).reason, "no-grant");
        assert_eq!(judge(&p, &g, &u, &net(), NOW + 4 * DAY_MS).reason, "no-grant");
        let mut revoked = grants();
        let id = revoked.grants()[0].id().unwrap();
        assert!(revoked.revoke(id));
        assert_eq!(judge(&p, &revoked, &u, &net(), NOW).reason, "no-grant");
        // No grants at all: trusted is not a grant.
        assert_eq!(judge(&p, &GrantSet::default(), &u, &net(), NOW).reason, "no-grant");
        assert_eq!(judge(&p, &g, &u, &net(), -1).reason, "clock");
        // Laya still raises a trusted clear to an ask.
        let look_alike = GrantSet::default().with_grant(grant(CrossingClass::Net, &["xn--e1afmkfd.example.org"], 5)).unwrap();
        let crossing = Crossing::new(CrossingClass::Net, "xn--e1afmkfd.example.org");
        assert_eq!(decide(&p, &look_alike, &u, &crossing, NOW).floor, Floor::AutoClear);
        assert_eq!(judge(&p, &look_alike, &u, &crossing, NOW).reason, "laya");
    }

    #[test]
    fn the_four_settings_are_ordered_by_what_they_loosen() {
        let order = [SliderSetting::AskEverything, SliderSetting::AskRisky, SliderSetting::WithinTodayLimits, SliderSetting::Trusted];
        for (i, setting) in order.iter().enumerate() {
            for (j, previous) in order.iter().enumerate() {
                assert_eq!(setting.loosens(*previous), i > j, "{} after {}", setting.wire_name(), previous.wire_name());
            }
        }
        // The policy file carries "trusted" and round-trips it; a pinned-codec spelling that is not a setting still fails.
        let mut p = starter().unwrap();
        p.setting = SliderSetting::Trusted;
        let bytes = p.canonical_bytes().unwrap();
        assert!(String::from_utf8(bytes.clone()).unwrap().contains("\"setting\":\"trusted\""));
        assert_eq!(SliderPolicy::parse(&bytes).unwrap(), p);
        assert!(p.loosens(SliderSetting::WithinTodayLimits) && !p.loosens(SliderSetting::Trusted));
        let text = String::from_utf8(STARTER_BYTES.to_vec()).unwrap();
        assert!(SliderPolicy::parse(text.replace("\"setting\":\"risky\"", "\"setting\":\"Trusted\"").as_bytes()).is_err());
    }

    #[test]
    fn a_grants_own_count_runs_out_and_a_revoked_or_expired_grant_clears_nothing() {
        let (p, mut g) = (policy(SliderSetting::AskRisky), grants());
        let mut usage = Usage::default();
        for _ in 0..2 {
            let d = judge(&p, &g, &usage, &net(), NOW);
            assert_eq!(d.floor, Floor::AutoClear);
            usage.record(CrossingClass::Net, d.grant.unwrap(), NOW);
        }
        assert_eq!(judge(&p, &g, &usage, &net(), NOW).reason, "grant-exhausted");
        let id = g.grants()[0].id().unwrap();
        assert!(g.revoke(id));
        assert_eq!(judge(&p, &g, &Usage::default(), &net(), NOW).reason, "no-grant");
        assert_eq!(judge(&p, &grants(), &Usage::default(), &net(), NOW + 4 * DAY_MS).reason, "no-grant");
        assert_eq!(judge(&p, &grants(), &Usage::default(), &net(), NOW - 2_000).reason, "no-grant");
        assert_eq!(judge(&p, &grants(), &Usage::default(), &net(), -1).reason, "clock");
    }

    #[test]
    fn classes_that_cannot_be_granted_ask_under_every_setting() {
        for setting in [SliderSetting::AskEverything, SliderSetting::AskRisky, SliderSetting::WithinTodayLimits, SliderSetting::Trusted] {
            for class in [CrossingClass::Plugin, CrossingClass::Persist, CrossingClass::ShellInteractive, CrossingClass::Unknown] {
                let d = judge(&policy(setting), &grants(), &Usage::default(), &Crossing::new(class, "x"), NOW);
                assert_eq!(d.floor, Floor::Ask, "{} {}", setting.wire_name(), class.wire_name());
                assert!(d.grant.is_none());
            }
        }
    }

    #[test]
    fn laya_can_raise_the_floor_and_never_lower_it() {
        let outcomes = [
            TriageOutcome::NoAdditionalEvidence,
            TriageOutcome::Escalate(Escalation::DeterministicRule),
            TriageOutcome::Escalate(Escalation::ModelConcern),
        ];
        for floor in [Floor::AutoClear, Floor::Ask] {
            for outcome in &outcomes {
                assert!(floor.raised_by(outcome) >= floor);
            }
        }
        assert_eq!(Floor::Ask.raised_by(&TriageOutcome::NoAdditionalEvidence), Floor::Ask);
        assert_eq!(Floor::AutoClear.raised_by(&TriageOutcome::Escalate(Escalation::ModelConcern)), Floor::Ask);
        // A clear the rules distrust (a look-alike host the grant happens to name) becomes an ask.
        let g = GrantSet::default().with_grant(grant(CrossingClass::Net, &["xn--e1afmkfd.example.org"], 5)).unwrap();
        let look_alike = Crossing::new(CrossingClass::Net, "xn--e1afmkfd.example.org");
        let p = policy(SliderSetting::AskRisky);
        assert_eq!(decide(&p, &g, &Usage::default(), &look_alike, NOW).floor, Floor::AutoClear);
        assert_eq!(judge(&p, &g, &Usage::default(), &look_alike, NOW).reason, "laya");
    }

    #[test]
    fn a_policy_cannot_make_a_class_safer_than_it_is_or_cap_a_never_standing_class_above_zero() {
        let mut p = starter().unwrap();
        for rule in &mut p.classes {
            if rule.class == CrossingClass::Mcp {
                rule.risk = Risk::Routine;
            }
        }
        assert_eq!(p.validate().unwrap_err().reason, "policy-bounds");
        let mut p = starter().unwrap();
        for rule in &mut p.classes {
            if rule.class == CrossingClass::Plugin {
                rule.per_day = 1;
            }
        }
        assert_eq!(p.canonical_bytes().unwrap_err().reason, "policy-bounds");
        let text = String::from_utf8(STARTER_BYTES.to_vec()).unwrap();
        assert!(SliderPolicy::parse(text.replace("\"setting\":\"risky\"", "\"setting\":\"yolo\"").as_bytes()).is_err());
        assert!(SliderPolicy::parse(format!(" {text}").as_bytes()).is_err());
    }
}
