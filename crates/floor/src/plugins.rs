// SPDX-License-Identifier: AGPL-3.0-or-later
//! The plugin fingerprint gate: the owner-approved set of engine plugin packages, by digest.
//!
//! The engine (the DeepSeek Harness and its Cordis plugins) is one hostile process. What it loads is decided outside
//! it: Rust assembles the plugin closure from packages whose digest the owner approved with a passkey, and from
//! nothing else. A package that is new, changed or unlisted is not loaded; it is a `plugin`-class crossing that
//! needs the owner's passkey (a critical proposal for the set that would include it). Hot reload and creator mode
//! are off in the authority context, and a package that is one of them can never be approved.
//!
//! This module is data and decisions only: it reads no file, loads nothing and approves nothing. The digest of a
//! package on disk is computed by whoever assembles it (the supervisor), and the set's bytes are stored as an
//! owner-approved gate target.

use crate::{refuse, Result};
use canon::{digest::Digest32, json};

pub const SET_MAX_BYTES: usize = 16 * 1024;
pub const MAX_PLUGINS: usize = 64;
/// The door plugin: the engine does not start without it, matching its approved digest.
pub const DOOR_PLUGIN: &str = "@aukora/door";
const SET_DOMAIN: &[u8] = b"aukora:plugin-set:v1\0";

/// One approved package. `authority` plugins sit on the engine's tool path (they judge or execute calls), so they are
/// mandatory: if one does not match, the engine does not start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginEntry {
    pub name: String,
    pub digest: Digest32,
    pub authority: bool,
}

/// A package found on disk, with the digest the assembler computed over its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    pub digest: Digest32,
}

/// Packages that are hot reload or creator mode, by name tokens (`@cordis/plugin-hmr`, `dsh-creator`).
pub fn is_hot_reload(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let tokens: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).collect();
    tokens.iter().any(|t| matches!(*t, "hmr" | "creator" | "hotreload"))
        || tokens.windows(2).any(|pair| pair == ["hot", "reload"] || pair == ["live", "reload"])
}

/// The scope of the pinned harness. The node links `node_modules/@deepseek-ai` to the pinned install inside the wall
/// (engine-prestart.sh), so no approved package may carry that scope: it would shadow the harness by name or turn
/// the link into a link inside a folder (node sweep, node-5).
const HARNESS_SCOPE: &str = "@deepseek-ai/";

fn valid_name(name: &str) -> bool {
    if name.starts_with(HARNESS_SCOPE) {
        return false;
    }
    let body = name.strip_prefix('@').unwrap_or(name);
    let mut parts = body.split('/');
    let (Some(first), second, None) = (parts.next(), parts.next(), parts.next()) else { return false };
    name.len() <= 214
        && (name.starts_with('@') == second.is_some())
        && [Some(first), second].into_iter().flatten().all(|part| {
            !part.is_empty()
                && !part.starts_with(['.', '_'])
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
        })
}

/// The approved set, sorted by name with one entry per name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PluginSet {
    entries: Vec<PluginEntry>,
}

impl PluginSet {
    /// An empty set approves nothing (and so cannot start an engine: the door is required).
    pub fn new(mut entries: Vec<PluginEntry>) -> Result<Self> {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let set = Self { entries };
        set.validate()?;
        Ok(set)
    }

    fn validate(&self) -> Result<()> {
        if self.entries.len() > MAX_PLUGINS
            || self.entries.windows(2).any(|pair| pair[0].name >= pair[1].name)
            || self.entries.iter().any(|entry| !valid_name(&entry.name) || entry.digest.as_bytes() == &[0; 32])
        {
            return Err(refuse("plugin-set"));
        }
        if self.entries.iter().any(|entry| is_hot_reload(&entry.name)) {
            return Err(refuse("plugin-hmr"));
        }
        if self.entries.iter().any(|entry| entry.name == DOOR_PLUGIN && !entry.authority) {
            return Err(refuse("plugin-set"));
        }
        Ok(())
    }

    pub fn entries(&self) -> &[PluginEntry] {
        &self.entries
    }

    /// `{"plugins":[{"authority":..,"digest":"<hex>","name":..}],"v":1}`, names sorted. These are the exact bytes of the
    /// owner-approved gate target.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bad = || refuse("plugin-set");
        let mut items = Vec::new();
        for entry in &self.entries {
            items.push(
                json::Value::checked_object(vec![
                    ("name".to_owned(), json::Value::checked_text(entry.name.clone()).map_err(|_| bad())?),
                    ("digest".to_owned(), json::Value::checked_text(entry.digest.to_string()).map_err(|_| bad())?),
                    ("authority".to_owned(), json::Value::boolean(entry.authority)),
                ])
                .map_err(|_| bad())?,
            );
        }
        let version = json::SafeInteger::new(1).map_err(|_| bad())?;
        let value = json::Value::checked_object(vec![
            ("v".to_owned(), json::Value::integer(version)),
            ("plugins".to_owned(), json::Value::checked_array(items).map_err(|_| bad())?),
        ])
        .map_err(|_| bad())?;
        let bytes = value.canonical_bytes();
        if bytes.len() > SET_MAX_BYTES {
            return Err(refuse("plugin-set"));
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bad = || refuse("plugin-set");
        if bytes.is_empty() || bytes.len() > SET_MAX_BYTES {
            return Err(bad());
        }
        let value = json::parse_strict(bytes).map_err(|_| bad())?;
        let json::ValueView::Object(members) = value.view() else { return Err(bad()) };
        let (Some(version), Some(plugins), 2) = (value.get("v"), value.get("plugins"), members.len()) else { return Err(bad()) };
        let (json::ValueView::Integer(version), json::ValueView::Array(plugins)) = (version.view(), plugins.view()) else { return Err(bad()) };
        if version.get() != 1 {
            return Err(bad());
        }
        let mut entries = Vec::new();
        for plugin in plugins {
            let json::ValueView::Object(fields) = plugin.view() else { return Err(bad()) };
            let (Some(name), Some(digest), Some(authority), 3) = (plugin.get("name"), plugin.get("digest"), plugin.get("authority"), fields.len())
            else {
                return Err(bad());
            };
            let (json::ValueView::Text(name), json::ValueView::Text(digest), json::ValueView::Boolean(authority)) =
                (name.view(), digest.view(), authority.view())
            else {
                return Err(bad());
            };
            entries.push(PluginEntry { name: name.to_owned(), digest: Digest32::from_hex(digest).map_err(|_| bad())?, authority });
        }
        let set = Self { entries };
        // The input must be its own canonical form, in name order: one spelling per approval.
        if set.canonical_bytes()? != bytes {
            return Err(bad());
        }
        Ok(set)
    }

    /// The commitment the floor pins: a domain-separated digest of the canonical bytes.
    pub fn set_hash(&self) -> Result<Digest32> {
        let mut preimage = SET_DOMAIN.to_vec();
        preimage.extend_from_slice(&self.canonical_bytes()?);
        Ok(Digest32::sha256(&preimage))
    }

    /// The set must hash to the pinned value, or nothing assembles from it.
    pub fn check_pinned(&self, pinned: &Digest32) -> Result<()> {
        if &self.set_hash()? == pinned {
            Ok(())
        } else {
            Err(refuse("plugin-set-pin"))
        }
    }

    /// The set that would result from approving one more package (or replacing the digest of a listed one). This is
    /// the proposal's candidate content: it changes nothing until the owner's passkey applies it.
    pub fn with_entry(&self, entry: PluginEntry) -> Result<Self> {
        let mut entries: Vec<PluginEntry> = self.entries.iter().filter(|existing| existing.name != entry.name).cloned().collect();
        entries.push(entry);
        Self::new(entries)
    }
}

/// What assembling the closure found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assembly {
    set_hash: Digest32,
    admitted: Vec<Candidate>,
    pending: Vec<Candidate>,
    refused: Vec<Candidate>,
    /// An approved `authority` package is missing or its bytes changed: the engine must not start, and the changed
    /// package is still in `pending`, so it reaches the owner as a proposal instead of only stopping the engine.
    authority_blocked: bool,
}

impl Assembly {
    /// The packages the engine may load: approved name, approved digest. Nothing else is in the closure.
    pub fn admitted(&self) -> &[Candidate] {
        &self.admitted
    }

    /// New, changed or unlisted packages. They are not loaded; each is a `plugin` crossing for the owner's passkey.
    pub fn pending(&self) -> &[Candidate] {
        &self.pending
    }

    /// Hot reload and creator mode: never loaded, never approvable, not even by the owner's passkey.
    pub fn refused(&self) -> &[Candidate] {
        &self.refused
    }

    /// Hot reload is off for every context the assembler builds.
    pub const fn hot_reload(&self) -> bool {
        false
    }

    /// Whether every approved `authority` package was found with its approved digest.
    pub const fn authority_blocked(&self) -> bool {
        self.authority_blocked
    }

    /// The engine may start from this closure only when no authority package is missing or changed.
    pub fn startable(&self) -> Result<()> {
        if self.authority_blocked {
            Err(refuse("plugin-authority"))
        } else {
            Ok(())
        }
    }

    /// The closure manifest the supervisor hands the engine read-only: the set hash, hot reload off and exactly the
    /// admitted packages, `{"hmr":false,"plugins":[{"digest","name"}],"set":"<hash>","v":1}`.
    pub fn manifest_bytes(&self) -> Result<Vec<u8>> {
        let bad = || refuse("plugin-set");
        let mut items = Vec::new();
        for plugin in &self.admitted {
            items.push(
                json::Value::checked_object(vec![
                    ("name".to_owned(), json::Value::checked_text(plugin.name.clone()).map_err(|_| bad())?),
                    ("digest".to_owned(), json::Value::checked_text(plugin.digest.to_string()).map_err(|_| bad())?),
                ])
                .map_err(|_| bad())?,
            );
        }
        let version = json::SafeInteger::new(1).map_err(|_| bad())?;
        let value = json::Value::checked_object(vec![
            ("v".to_owned(), json::Value::integer(version)),
            ("hmr".to_owned(), json::Value::boolean(false)),
            ("set".to_owned(), json::Value::checked_text(self.set_hash.to_string()).map_err(|_| bad())?),
            ("plugins".to_owned(), json::Value::checked_array(items).map_err(|_| bad())?),
        ])
        .map_err(|_| bad())?;
        Ok(value.canonical_bytes())
    }
}

/// Assemble the engine's plugin closure from what was found, against the approved set pinned by `pinned`.
///
/// - A found package is admitted only when its name is approved and its digest equals the approved digest.
/// - Anything else is `pending` (a `plugin` crossing), except hot reload and creator mode, which are `refused`.
/// - Every `authority` plugin must be found and admitted. If one is missing or changed the engine does not start
///   (`Assembly::startable` answers `plugin-authority`), and a changed one is still `pending`, so it becomes the owner's
///   proposal like any other changed package: the unmatched path fails closed to the owner's classification.
/// - The door plugin must be in the approved set.
pub fn assemble(approved: &PluginSet, pinned: &Digest32, found: &[Candidate]) -> Result<Assembly> {
    approved.check_pinned(pinned)?;
    if !approved.entries.iter().any(|entry| entry.name == DOOR_PLUGIN && entry.authority) {
        return Err(refuse("plugin-door-missing"));
    }
    let mut seen: Vec<&str> = Vec::new();
    let (mut admitted, mut pending, mut refused) = (Vec::new(), Vec::new(), Vec::new());
    for package in found {
        if seen.contains(&package.name.as_str()) {
            return Err(refuse("plugin-set"));
        }
        seen.push(&package.name);
        if is_hot_reload(&package.name) {
            refused.push(package.clone());
        } else if approved.entries.iter().any(|entry| entry.name == package.name && entry.digest == package.digest) {
            admitted.push(package.clone());
        } else {
            pending.push(package.clone());
        }
    }
    let authority_blocked =
        approved.entries.iter().any(|entry| entry.authority && !admitted.iter().any(|plugin| plugin.name == entry.name));
    admitted.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Assembly { set_hash: approved.set_hash()?, admitted, pending, refused, authority_blocked })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest32 {
        Digest32::sha256(&[n])
    }

    fn entry(name: &str, n: u8, authority: bool) -> PluginEntry {
        PluginEntry { name: name.to_owned(), digest: digest(n), authority }
    }

    fn found(name: &str, n: u8) -> Candidate {
        Candidate { name: name.to_owned(), digest: digest(n) }
    }

    fn approved() -> (PluginSet, Digest32) {
        let set = PluginSet::new(vec![entry("@aukora/kira-tools", 2, false), entry(DOOR_PLUGIN, 1, true)]).unwrap();
        let pin = set.set_hash().unwrap();
        (set, pin)
    }

    #[test]
    fn a_set_has_one_canonical_form_in_name_order() {
        let (set, _) = approved();
        let bytes = set.canonical_bytes().unwrap();
        assert_eq!(PluginSet::parse(&bytes).unwrap(), set);
        assert_eq!(set.entries()[0].name, DOOR_PLUGIN);
        let text = String::from_utf8(bytes).unwrap();
        assert!(PluginSet::parse(format!(" {text}").as_bytes()).is_err());
        assert!(PluginSet::parse(text.replace("\"authority\":true", "\"authority\":1").as_bytes()).is_err());
        assert!(PluginSet::parse(text.replace("\"v\":1", "\"v\":2").as_bytes()).is_err());
    }

    #[test]
    fn only_approved_digests_are_in_the_closure_and_the_rest_wait_for_a_passkey() {
        let (set, pin) = approved();
        let assembly = assemble(&set, &pin, &[found(DOOR_PLUGIN, 1), found("@aukora/kira-tools", 2), found("@evil/new", 9)]).unwrap();
        let names: Vec<_> = assembly.admitted().iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, [DOOR_PLUGIN, "@aukora/kira-tools"]);
        assert_eq!(assembly.pending(), [found("@evil/new", 9)]);
        // A listed package whose bytes changed is pending too, not loaded.
        let changed = assemble(&set, &pin, &[found(DOOR_PLUGIN, 1), found("@aukora/kira-tools", 3)]).unwrap();
        assert_eq!((changed.admitted().len(), changed.pending().len()), (1, 1));
        assert!(!changed.hot_reload());
    }

    #[test]
    fn an_authority_plugin_that_is_missing_or_changed_stops_the_engine_and_a_changed_one_is_still_a_proposal() {
        let (set, pin) = approved();
        let missing = assemble(&set, &pin, &[found("@aukora/kira-tools", 2)]).unwrap();
        assert_eq!(missing.startable().unwrap_err().reason, "plugin-authority");
        assert!(missing.pending().is_empty());
        let changed = assemble(&set, &pin, &[found(DOOR_PLUGIN, 5)]).unwrap();
        assert!(changed.authority_blocked());
        assert_eq!(changed.startable().unwrap_err().reason, "plugin-authority");
        assert_eq!(changed.pending(), [found(DOOR_PLUGIN, 5)]);
        assert!(assemble(&set, &pin, &[found(DOOR_PLUGIN, 1)]).unwrap().startable().is_ok());
    }

    #[test]
    fn a_set_without_the_door_or_with_the_wrong_pin_assembles_nothing() {
        let no_door = PluginSet::new(vec![entry("@aukora/kira-tools", 2, false)]).unwrap();
        let pin = no_door.set_hash().unwrap();
        assert_eq!(assemble(&no_door, &pin, &[found("@aukora/kira-tools", 2)]).unwrap_err().reason, "plugin-door-missing");
        let (set, _) = approved();
        assert_eq!(assemble(&set, &digest(0), &[found(DOOR_PLUGIN, 1)]).unwrap_err().reason, "plugin-set-pin");
        assert!(PluginSet::new(vec![entry(DOOR_PLUGIN, 1, false)]).is_err());
    }

    #[test]
    fn hot_reload_and_creator_mode_are_never_loaded_and_never_approvable() {
        for name in ["@cordis/plugin-hmr", "dsh-creator", "@x/hot-reload", "live-reload", "hmr"] {
            assert!(is_hot_reload(name), "{name}");
            assert_eq!(PluginSet::new(vec![entry(name, 4, false)]).unwrap_err().reason, "plugin-hmr");
        }
        for name in ["@aukora/door", "@aukora/kira-tools", "chrome-hotel", "creative"] {
            assert!(!is_hot_reload(name), "{name}");
        }
        let (set, pin) = approved();
        let assembly = assemble(&set, &pin, &[found(DOOR_PLUGIN, 1), found("@cordis/plugin-hmr", 4)]).unwrap();
        assert_eq!(assembly.refused().len(), 1);
        assert!(assembly.pending().is_empty() && assembly.admitted().len() == 1);
        let manifest = String::from_utf8(assembly.manifest_bytes().unwrap()).unwrap();
        assert!(manifest.contains("\"hmr\":false") && !manifest.contains("plugin-hmr"));
    }

    #[test]
    fn approving_one_more_package_builds_the_candidate_set_and_changes_nothing_live() {
        let (set, pin) = approved();
        let next = set.with_entry(entry("@aukora/new", 7, false)).unwrap();
        assert_eq!(next.entries().len(), 3);
        assert!(next.check_pinned(&pin).is_err());
        assert!(set.check_pinned(&pin).is_ok());
        // Replacing a listed package's digest is the same kind of change.
        assert_eq!(set.with_entry(entry("@aukora/kira-tools", 8, false)).unwrap().entries().len(), 2);
    }

    #[test]
    fn names_are_package_names() {
        for bad in ["", "Door", "@aukora", "@/x", "a/b", "../x", "x y", "_x", "@a/b/c", "@deepseek-ai/dsh-web-app", "@deepseek-ai/x"] {
            assert!(PluginSet::new(vec![entry(bad, 1, false)]).is_err(), "{bad}");
        }
        assert!(PluginSet::new(vec![entry("@aukora/door", 1, true), entry("left-pad", 2, false)]).is_ok());
        // Only the harness's own scope is reserved: a package merely named like it is still a package.
        assert!(PluginSet::new(vec![entry("@aukora/door", 1, true), entry("deepseek-ai", 2, false), entry("@deepseek/x", 3, false)]).is_ok());
    }
}
