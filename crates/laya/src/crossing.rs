// SPDX-License-Identifier: AGPL-3.0-or-later
//! The door's crossing classes as Laya sees them: how risky each is, what a standing grant may say about it, and the
//! few deterministic rules that raise a crossing to "ask". Names are the wire names of
//! `engine/plugins/aukora-door/PROTOCOL.md`; Laya does not depend on the supervisor, so the supervisor maps its own
//! class type onto this one.

use crate::triage::{Escalation, TriageOutcome};

/// Memory lanes the engine may never write (the door's own ceilings refuse them too).
pub const CLOSED_LANES: [&str; 5] = ["charter", "ruling", "decision", "self", "resume"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CrossingClass {
    Net,
    Mcp,
    Plugin,
    Memory,
    Persist,
    Delegate,
    ShellInteractive,
    FsOutside,
    Unknown,
}

/// How much a crossing of this class can cost the owner. `Routine < Risky`; a policy may only move a class up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Risk {
    Routine,
    Risky,
}

impl From<canon::authority::CardRisk> for Risk {
    fn from(value: canon::authority::CardRisk) -> Self {
        match value {
            canon::authority::CardRisk::Routine => Self::Routine,
            canon::authority::CardRisk::Critical => Self::Risky,
        }
    }
}

/// What a standing grant for a class names. `Never` classes cannot be granted at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantShape {
    /// Exact lowercase host names.
    Hosts,
    /// `read`, or `write:<lane>` for a lane the engine may write.
    Memory,
    /// Exact MCP server names.
    Servers,
    /// Exact provider names a subagent may use.
    Providers,
    /// Absolute path prefixes outside the workspace.
    Prefixes,
    /// Never standing: the owner's passkey is needed every time.
    Never,
}

impl CrossingClass {
    pub const ALL: [CrossingClass; 9] = [
        Self::Net,
        Self::Mcp,
        Self::Plugin,
        Self::Memory,
        Self::Persist,
        Self::Delegate,
        Self::ShellInteractive,
        Self::FsOutside,
        Self::Unknown,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::Mcp => "mcp",
            Self::Plugin => "plugin",
            Self::Memory => "memory",
            Self::Persist => "persist",
            Self::Delegate => "delegate",
            Self::ShellInteractive => "shell-interactive",
            Self::FsOutside => "fs-outside",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_wire(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.wire_name() == name)
    }

    /// The built-in risk. Only the two classes the door can execute for an allowlisted, attributed engine are routine.
    pub const fn risk(self) -> Risk {
        match self {
            Self::Net | Self::Memory => Risk::Routine,
            _ => Risk::Risky,
        }
    }

    /// What a grant may name. A grant is the owner's pre-signed answer to one kind of crossing, never a way to pass
    /// authority on, so a class that plants future authority or runs bytes nobody judged is never standing:
    /// `plugin` (new code), `persist` (a schedule acts later), `shell-interactive` (later input is not in the bytes
    /// judged), `unknown` (nobody knows what it is).
    pub const fn shape(self) -> GrantShape {
        match self {
            Self::Net => GrantShape::Hosts,
            Self::Memory => GrantShape::Memory,
            Self::Mcp => GrantShape::Servers,
            Self::Delegate => GrantShape::Providers,
            Self::FsOutside => GrantShape::Prefixes,
            Self::Plugin | Self::Persist | Self::ShellInteractive | Self::Unknown => GrantShape::Never,
        }
    }
}

/// What the rules see of one crossing: its class and one target token, never a body. The token is the host (`net`),
/// `read` or `write:<lane>` (`memory`), the server (`mcp`), the provider (`delegate`), the path (`fs-outside`), or
/// the package `name@digest` (`plugin`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crossing {
    pub class: CrossingClass,
    pub token: String,
}

impl Crossing {
    pub fn new(class: CrossingClass, token: impl Into<String>) -> Self {
        Self { class, token: token.into() }
    }

    /// Whether a grant scope entry covers this crossing's token.
    pub(crate) fn covered_by(&self, entry: &str) -> bool {
        match self.class.shape() {
            GrantShape::Prefixes => {
                self.token == entry || self.token.strip_prefix(entry).is_some_and(|rest| rest.starts_with('/'))
            }
            GrantShape::Never => false,
            _ => self.token == entry,
        }
    }

    /// Escalation evidence for this crossing. Deterministic, escalate-only: no outcome here is an approval, and
    /// `NoAdditionalEvidence` leaves the floor where Rust put it.
    pub fn triage(&self) -> TriageOutcome {
        if self.class.shape() == GrantShape::Never {
            return TriageOutcome::Escalate(Escalation::CriticalRisk);
        }
        if self.token.is_empty() || !token_shape(self.class, &self.token) {
            return TriageOutcome::Escalate(Escalation::MissingEvidence);
        }
        let reviewed = match self.class {
            // A look-alike (punycode) label is how a host gets mistaken for another.
            CrossingClass::Net => self.token.split('.').any(|label| label.starts_with("xn--")),
            CrossingClass::Memory => self.token.strip_prefix("write:").is_some_and(|lane| CLOSED_LANES.contains(&lane)),
            _ => false,
        };
        if reviewed {
            TriageOutcome::Escalate(Escalation::DeterministicRule)
        } else {
            TriageOutcome::NoAdditionalEvidence
        }
    }
}

fn name_token(token: &str) -> bool {
    (1..=64).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn lane_token(lane: &str) -> bool {
    (1..=32).contains(&lane.len())
        && lane.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && lane.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// A plain lowercase DNS name with at least two labels and no numeric top label (so never an IP literal).
pub(crate) fn host_token(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels.last().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

/// An absolute, normalized path with at least two segments, so a grant can never name `/` or a top-level directory.
pub(crate) fn prefix_token(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else { return false };
    let parts: Vec<&str> = rest.split('/').collect();
    path.len() <= 256
        && parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty() && *part != "." && *part != ".." && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

/// Whether a token has the right shape for its class (closed memory lanes are well-formed; they are escalated, and a
/// grant refuses them separately).
pub(crate) fn token_shape(class: CrossingClass, token: &str) -> bool {
    match class.shape() {
        GrantShape::Hosts => host_token(token),
        GrantShape::Memory => token == "read" || token.strip_prefix("write:").is_some_and(lane_token),
        GrantShape::Servers | GrantShape::Providers => name_token(token),
        GrantShape::Prefixes => prefix_token(token),
        GrantShape::Never => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_only_net_and_memory_are_routine() {
        for class in CrossingClass::ALL {
            assert_eq!(CrossingClass::from_wire(class.wire_name()), Some(class));
        }
        let routine: Vec<_> = CrossingClass::ALL.into_iter().filter(|c| c.risk() == Risk::Routine).collect();
        assert_eq!(routine, [CrossingClass::Net, CrossingClass::Memory]);
        assert_eq!(CrossingClass::from_wire("quantum"), None);
    }

    #[test]
    fn classes_that_plant_authority_or_run_unjudged_bytes_are_never_standing() {
        for class in [CrossingClass::Plugin, CrossingClass::Persist, CrossingClass::ShellInteractive, CrossingClass::Unknown] {
            assert_eq!(class.shape(), GrantShape::Never, "{}", class.wire_name());
            assert_eq!(Crossing::new(class, "x").triage(), TriageOutcome::Escalate(Escalation::CriticalRisk));
        }
    }

    #[test]
    fn tokens_have_the_shape_of_their_class() {
        assert!(token_shape(CrossingClass::Net, "docs.rs"));
        assert!(!token_shape(CrossingClass::Net, "127.0.0.1"));
        assert!(!token_shape(CrossingClass::Net, "Docs.rs"));
        assert!(token_shape(CrossingClass::Memory, "read"));
        assert!(token_shape(CrossingClass::Memory, "write:notes"));
        assert!(!token_shape(CrossingClass::Memory, "write:"));
        assert!(!token_shape(CrossingClass::Memory, "write:Notes"));
        assert!(token_shape(CrossingClass::FsOutside, "/srv/shared"));
        for bad in ["/", "/srv", "/srv/../etc", "srv/shared", "/srv//x"] {
            assert!(!token_shape(CrossingClass::FsOutside, bad), "{bad}");
        }
        assert!(token_shape(CrossingClass::Mcp, "github"));
        assert!(!token_shape(CrossingClass::Mcp, "git hub"));
    }

    #[test]
    fn a_prefix_covers_its_own_subtree_and_not_a_neighbour() {
        let inside = Crossing::new(CrossingClass::FsOutside, "/srv/shared/a/b");
        assert!(inside.covered_by("/srv/shared"));
        assert!(!Crossing::new(CrossingClass::FsOutside, "/srv/shared-evil/a").covered_by("/srv/shared"));
        assert!(!Crossing::new(CrossingClass::Net, "docs.rs").covered_by("docs.rs.evil.com"));
        assert!(Crossing::new(CrossingClass::Net, "docs.rs").covered_by("docs.rs"));
    }

    #[test]
    fn the_rules_raise_look_alike_hosts_closed_lanes_and_malformed_targets() {
        let ask = |class, token: &str| Crossing::new(class, token).triage();
        assert_eq!(ask(CrossingClass::Net, "docs.rs"), TriageOutcome::NoAdditionalEvidence);
        assert_eq!(ask(CrossingClass::Net, "xn--e1afmkfd.example.org"), TriageOutcome::Escalate(Escalation::DeterministicRule));
        assert_eq!(ask(CrossingClass::Net, ""), TriageOutcome::Escalate(Escalation::MissingEvidence));
        assert_eq!(ask(CrossingClass::Memory, "write:notes"), TriageOutcome::NoAdditionalEvidence);
        assert_eq!(ask(CrossingClass::Memory, "write:decision"), TriageOutcome::Escalate(Escalation::DeterministicRule));
        assert_eq!(ask(CrossingClass::Memory, "write:"), TriageOutcome::Escalate(Escalation::MissingEvidence));
    }
}
