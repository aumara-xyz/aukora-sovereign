// SPDX-License-Identifier: AGPL-3.0-or-later
//! Note metadata as NIP-01 tags. Every field is a closed set; unknown values refuse.

use canon::{Refusal, Result};
use icu_normalizer::ComposingNormalizer;
use sha2::{Digest, Sha256};

/// A memory note.
pub const NOTE_KIND: u16 = 4500;
/// Replaces one earlier note (`supersedes` tag); the old note stays readable.
pub const SUPERSEDE_KIND: u16 = 4501;
/// Quarantines every note signed by one source key (`source` tag).
pub const QUARANTINE_KIND: u16 = 4502;

fn refuse(code: &'static str) -> Refusal {
    Refusal { organ: "kira", reason: code }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Lane {
    Evidence,
    Experience,
    Charter,
    Ruling,
    Decision,
    Finding,
    SelfFile,
    Resume,
}
impl Lane {
    pub const TAG: &'static str = "lane";
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Experience => "experience",
            Self::Charter => "charter",
            Self::Ruling => "ruling",
            Self::Decision => "decision",
            Self::Finding => "finding",
            Self::SelfFile => "self",
            Self::Resume => "resume",
        }
    }
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "evidence" => Ok(Self::Evidence),
            "experience" => Ok(Self::Experience),
            "charter" => Ok(Self::Charter),
            "ruling" => Ok(Self::Ruling),
            "decision" => Ok(Self::Decision),
            "finding" => Ok(Self::Finding),
            "self" => Ok(Self::SelfFile),
            "resume" => Ok(Self::Resume),
            _ => Err(refuse("note-lane")),
        }
    }

    /// The commitment and identity lanes: only the owner's own words (`owner-typed` or `owner-signed`) may sit here.
    pub const fn owner_only(self) -> bool {
        matches!(self, Self::Charter | Self::Ruling | Self::Decision | Self::SelfFile | Self::Resume)
    }
}

/// Lanes by whitelist: an owner-only lane accepts only an owner-class capture; every other capture is refused there.
pub fn check_capture_lane(capture: Capture, lane: Lane) -> Result<()> {
    if lane.owner_only() && !capture.owner_class() {
        return Err(refuse("note-capture-lane"));
    }
    Ok(())
}

/// A registered agent's name: 1..=64 of `[a-z0-9_-]`, starting with a letter or digit.
pub fn valid_agent_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Auma's self file and resume brief, the fixed slots the engine reads at session start.
pub const SELF_SLOT: &str = "aukora:self";
pub const RESUME_SLOT: &str = "aukora:resume";

/// The slot names `get` resolves (spec v0.3 §12): Auma's self file and resume brief, and an agent's own
/// `resume:<agent>`.
pub fn readable_slot(slot: &str) -> bool {
    slot == SELF_SLOT || slot == RESUME_SLOT || slot.strip_prefix("resume:").is_some_and(valid_agent_name)
}

/// Who may write a slot: the owner any slot; any other author only its own `resume:<name>`. A slot is read back as
/// one note that a session puts in its system prompt, so an agent that could write `aukora:self` could rewrite
/// Auma's self file.
pub fn may_write_slot(slot: &str, author_name: &str, author_owner: bool) -> bool {
    author_owner || slot.strip_prefix("resume:") == Some(author_name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Form {
    Fact,
    Snapshot,
    Counterevidence,
}
impl Form {
    pub const TAG: &'static str = "form";
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::Snapshot => "snapshot",
            Self::Counterevidence => "counterevidence",
        }
    }
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "fact" => Ok(Self::Fact),
            "snapshot" => Ok(Self::Snapshot),
            "counterevidence" => Ok(Self::Counterevidence),
            _ => Err(refuse("note-form")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Review {
    Remembered,
    OwnerSigned,
}
impl Review {
    pub const TAG: &'static str = "review";
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Remembered => "remembered",
            Self::OwnerSigned => "owner_signed",
        }
    }
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "remembered" => Ok(Self::Remembered),
            "owner_signed" => Ok(Self::OwnerSigned),
            _ => Err(refuse("note-review")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Privacy {
    Local,
    Builders,
    Public,
}
impl Privacy {
    pub const TAG: &'static str = "privacy";
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Builders => "builders",
            Self::Public => "public",
        }
    }
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "local" => Ok(Self::Local),
            "builders" => Ok(Self::Builders),
            "public" => Ok(Self::Public),
            _ => Err(refuse("note-privacy")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Capture {
    OwnerTyped,
    OwnerSigned,
    ToolObserved,
    WebDerived,
    ModelGenerated,
    Import,
}
impl Capture {
    pub const TAG: &'static str = "capture";
    pub const fn wire(self) -> &'static str {
        match self {
            Self::OwnerTyped => "owner-typed",
            Self::OwnerSigned => "owner-signed",
            Self::ToolObserved => "tool-observed",
            Self::WebDerived => "web-derived",
            Self::ModelGenerated => "model-generated",
            Self::Import => "import",
        }
    }
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "owner-typed" => Ok(Self::OwnerTyped),
            "owner-signed" => Ok(Self::OwnerSigned),
            "tool-observed" => Ok(Self::ToolObserved),
            "web-derived" => Ok(Self::WebDerived),
            "model-generated" => Ok(Self::ModelGenerated),
            "import" => Ok(Self::Import),
            _ => Err(refuse("note-capture")),
        }
    }

    /// The owner's own words: only the owner channel may claim these.
    pub const fn owner_class(self) -> bool {
        matches!(self, Self::OwnerTyped | Self::OwnerSigned)
    }
}

/// What an author asks to remember. The service turns it into tags and signs it with the caller's key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteDraft {
    pub text: String,
    pub subject: String,
    pub scope: String,
    pub lane: Lane,
    pub form: Form,
    pub privacy: Privacy,
    pub capture: Capture,
    /// Event ids (hex) of notes this one was derived from; the store resolves ancestry from them.
    pub sources: Vec<String>,
    /// Optional fixed slot (`d` tag), e.g. `aukora:self` or `aukora:resume`.
    pub slot: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub epoch: u32,
}

/// Metadata parsed back from a verified note's tags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteMeta {
    pub subject: String,
    pub scope: String,
    pub lane: Lane,
    pub form: Form,
    pub review: Review,
    pub privacy: Privacy,
    pub capture: Capture,
    pub sources: Vec<String>,
    pub slot: Option<String>,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub epoch: u32,
    pub statement_hash: [u8; 32],
}

const MAX_TEXT: usize = 32_768;
const MAX_FIELD: usize = 256;
const MAX_SOURCES: usize = 64;

/// Statement normalisation: Unicode compatibility composition (NFKC), Unicode lowercase, NFKC again (lowercasing can
/// leave a sequence uncomposed), every run of whitespace collapsed to one space, trimmed. NFC and NFD spellings of
/// one word, width variants and ligatures therefore dedupe. No accent stripping: "café" and "cafe" stay two statements.
pub fn statement_hash(text: &str) -> [u8; 32] {
    let nfkc = ComposingNormalizer::new_nfkc();
    let lowered = nfkc.normalize(text).to_lowercase();
    let folded = nfkc.normalize(&lowered);
    let normalized = folded.split_whitespace().collect::<Vec<_>>().join(" ");
    Sha256::digest(normalized.as_bytes()).into()
}

fn field(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_FIELD || value.chars().any(char::is_control) {
        return Err(refuse("note-field"));
    }
    Ok(())
}

fn hex_id(value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(refuse("note-source-id"))
    }
}

impl NoteDraft {
    /// Tags for a new note. `review` is set by the service: `owner_signed` only for the owner's own key.
    pub fn tags(&self, review: Review) -> Result<Vec<Vec<String>>> {
        if self.text.trim().is_empty() || self.text.len() > MAX_TEXT {
            return Err(refuse("note-text"));
        }
        field(&self.subject)?;
        field(&self.scope)?;
        if self.sources.len() > MAX_SOURCES {
            return Err(refuse("note-sources"));
        }
        // By whitelist: only the owner's own words are filed as a commitment, the self file or the resume. Tool, model,
        // web and imported material never are; imports are promoted only by an owner-signed manifest.
        check_capture_lane(self.capture, self.lane)?;
        if let (Some(from), Some(to)) = (self.valid_from, self.valid_to) {
            if to <= from {
                return Err(refuse("note-validity"));
            }
        }
        let mut tags = vec![
            vec!["subject".into(), self.subject.clone()],
            vec!["scope".into(), self.scope.clone()],
            vec![Lane::TAG.into(), self.lane.wire().into()],
            vec![Form::TAG.into(), self.form.wire().into()],
            vec![Review::TAG.into(), review.wire().into()],
            vec![Privacy::TAG.into(), self.privacy.wire().into()],
            vec![Capture::TAG.into(), self.capture.wire().into()],
            vec!["epoch".into(), self.epoch.to_string()],
        ];
        for source in &self.sources {
            hex_id(source)?;
            tags.push(vec!["e".into(), source.clone(), String::new(), "source".into()]);
        }
        if let Some(slot) = &self.slot {
            field(slot)?;
            tags.push(vec!["d".into(), slot.clone()]);
        }
        if let Some(from) = self.valid_from {
            tags.push(vec!["valid_from".into(), from.to_string()]);
        }
        if let Some(to) = self.valid_to {
            tags.push(vec!["valid_to".into(), to.to_string()]);
        }
        Ok(tags)
    }
}

fn single<'a>(tags: &'a [Vec<String>], name: &str) -> Result<Option<&'a str>> {
    let mut found = None;
    for tag in tags {
        if tag.first().map(String::as_str) == Some(name) {
            if found.is_some() || tag.len() != 2 {
                return Err(refuse("note-tag-shape"));
            }
            found = Some(tag[1].as_str());
        }
    }
    Ok(found)
}

fn required<'a>(tags: &'a [Vec<String>], name: &str) -> Result<&'a str> {
    single(tags, name)?.ok_or_else(|| refuse("note-tag-missing"))
}

fn number(value: Option<&str>) -> Result<Option<u64>> {
    value.map(|text| text.parse::<u64>().map_err(|_| refuse("note-tag-number"))).transpose()
}

impl NoteMeta {
    /// Parse and validate the tags of a verified note event.
    pub fn parse(tags: &[Vec<String>], content: &str) -> Result<Self> {
        let sources = tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("e"))
            .map(|tag| {
                if tag.len() != 4 || tag[3] != "source" || !tag[2].is_empty() {
                    return Err(refuse("note-tag-shape"));
                }
                hex_id(&tag[1])?;
                Ok(tag[1].clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let epoch = required(tags, "epoch")?.parse::<u32>().map_err(|_| refuse("note-tag-number"))?;
        Ok(Self {
            subject: required(tags, "subject")?.to_owned(),
            scope: required(tags, "scope")?.to_owned(),
            lane: Lane::parse(required(tags, Lane::TAG)?)?,
            form: Form::parse(required(tags, Form::TAG)?)?,
            review: Review::parse(required(tags, Review::TAG)?)?,
            privacy: Privacy::parse(required(tags, Privacy::TAG)?)?,
            capture: Capture::parse(required(tags, Capture::TAG)?)?,
            sources,
            slot: single(tags, "d")?.map(str::to_owned),
            valid_from: number(single(tags, "valid_from")?)?,
            valid_to: number(single(tags, "valid_to")?)?,
            epoch,
            statement_hash: statement_hash(content),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> NoteDraft {
        NoteDraft {
            text: "The figurine is on the left shelf.".into(),
            subject: "home".into(),
            scope: "owner".into(),
            lane: Lane::Evidence,
            form: Form::Fact,
            privacy: Privacy::Builders,
            capture: Capture::OwnerTyped,
            sources: vec![],
            slot: None,
            valid_from: None,
            valid_to: None,
            epoch: 2,
        }
    }

    #[test]
    fn tags_round_trip() {
        let d = draft();
        let tags = d.tags(Review::Remembered).unwrap();
        let meta = NoteMeta::parse(&tags, &d.text).unwrap();
        assert_eq!(meta.lane, Lane::Evidence);
        assert_eq!(meta.review, Review::Remembered);
        assert_eq!(meta.epoch, 2);
    }

    #[test]
    fn model_material_cannot_be_a_decision() {
        let mut d = draft();
        d.capture = Capture::ModelGenerated;
        d.lane = Lane::Decision;
        assert!(d.tags(Review::Remembered).is_err());
        // Whitelist: tool-observed material cannot be a commitment, the self file or the resume either.
        d.capture = Capture::ToolObserved;
        for lane in [Lane::Charter, Lane::Ruling, Lane::Decision, Lane::SelfFile, Lane::Resume] {
            d.lane = lane;
            assert_eq!(d.tags(Review::Remembered), Err(refuse("note-capture-lane")));
        }
        d.capture = Capture::OwnerTyped;
        assert!(d.tags(Review::Remembered).is_ok());
    }

    #[test]
    fn slots_are_named_and_owned() {
        for slot in [SELF_SLOT, RESUME_SLOT, "resume:claude-code", "resume:grok"] {
            assert!(readable_slot(slot), "{slot}");
        }
        for slot in ["aukora:other", "resume:", "resume:../x", "resume:Grok", "self:auma", "", &"a".repeat(64)] {
            assert!(!readable_slot(slot), "{slot}");
        }
        assert!(may_write_slot(SELF_SLOT, "peter", true));
        assert!(may_write_slot("resume:grok", "grok", false));
        for (slot, author) in [(SELF_SLOT, "grok"), (RESUME_SLOT, "grok"), ("resume:claude", "grok"), ("resume:grok:x", "grok")] {
            assert!(!may_write_slot(slot, author, false), "{slot} by {author}");
        }
    }

    #[test]
    fn statement_hash_normalises_case_space_and_unicode_form_only() {
        assert_eq!(statement_hash("The  Figurine\nis here"), statement_hash("the figurine is here"));
        assert_ne!(statement_hash("café"), statement_hash("cafe"));
        // NFC and NFD spellings of one word are one statement (a red-team finding), as are width variants and ligatures.
        assert_eq!(statement_hash("caf\u{e9}"), statement_hash("cafe\u{301}"));
        assert_eq!(statement_hash("CAF\u{c9} ok"), statement_hash("cafe\u{301}  OK"));
        assert_eq!(statement_hash("\u{ff26}igurine"), statement_hash("figurine"));
        assert_eq!(statement_hash("o\u{fb03}ce"), statement_hash("office"));
    }
}
