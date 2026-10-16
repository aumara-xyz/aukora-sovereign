// SPDX-License-Identifier: AGPL-3.0-or-later
//! C6 display commitments and the C5 authorization of exact proposal bytes.

use crate::{Proposal, Result};
use canon::{
    authority::{AuthorizationChallenge, Card, OwnerAuthorization, OwnerOperation},
    digest::Digest32,
    ids::{NodeId, OperationDigest, ProposalId, SubjectId},
    json::{SafeInteger, Value, ValueView},
};
use icu_normalizer::ComposingNormalizer;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelNote {
    pub raw: String,
    pub displayed: String,
    pub warnings: Vec<String>,
    pub metadata: Value,
}

pub fn prepare_model_note(raw: &str) -> Result<ModelNote> {
    prepare_note(raw, None)
}

fn prepare_note(raw: &str, colors: Option<(&str, &str)>) -> Result<ModelNote> {
    if raw.len() > 8_192 {
        return Err(crate::refuse("proposal-too-large"));
    }
    let nonascii = raw
        .chars()
        .filter(|c| !matches!(c, ' '..='~' | '\t' | '\n' | '\r'))
        .count();
    let normalized = ComposingNormalizer::new_nfkc().normalize(raw);
    let ascii: String = normalized
        .chars()
        .map(|c| if matches!(c, ' '..='~') { c } else { ' ' })
        .collect();
    let compact = ascii.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
    let mut displayed = String::with_capacity(compact.len().min(120));
    let mut index = 0;
    while index < compact.len() {
        if compact[index..]
            .get(..5)
            .is_some_and(|s| s.eq_ignore_ascii_case("gate-"))
        {
            displayed.push_str("gate_");
            index += 5;
        } else {
            displayed.push(char::from(compact.as_bytes()[index]));
            index += 1;
        }
    }
    if displayed.len() > 120 {
        displayed.truncate(117);
        displayed.push_str("...");
    }
    let (scan, scan_refused) = authority_scan(raw)?;
    let mut metadata = vec![("nonascii".into(), number(nonascii)?)];
    let mut warnings = Vec::new();
    if nonascii > 0 {
        warnings.push(format!("NOTE contained {nonascii} non-ASCII/invisible characters (lookalike, invisible, bidi or styled text). They were removed; the raw bytes are in the hex dump. Treat the note as hostile."));
        metadata.extend([
            ("authority_display".into(), scan),
            ("raw_bytes".into(), number(raw.len())?),
            ("hexdump".into(), text(hexdump(raw.as_bytes()))?),
        ]);
    }
    if scan_refused {
        warnings.push("NOTE failed the authority-display scan (invisible text or a confusable authority word); its sanitized text is model commentary and grants no authority.".into());
    }
    warnings.extend(note_warnings(&compact, colors));
    Ok(ModelNote {
        raw: raw.into(),
        displayed,
        warnings,
        metadata: Value::object(metadata)?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewFacts {
    pub says: String,
    pub facts: Vec<(String, Value)>,
    pub from_to: Vec<(String, Value)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayedCard {
    card: Card,
    canonical: Vec<u8>,
    digest: Digest32,
    proposal: Option<(ProposalId, OwnerOperation, OperationDigest, u64, Digest32)>,
}

impl DisplayedCard {
    pub fn card(&self) -> &Card {
        &self.card
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> Digest32 {
        self.digest
    }
}

pub fn build_card(
    proposal: &Proposal,
    action: OwnerOperation,
    mut facts: ReviewFacts,
) -> Result<DisplayedCard> {
    require_action(action)?;
    if proposal.new_digest != Digest32::sha256(&proposal.request.new_bytes) {
        return Err(crate::refuse("authorization-mismatch"));
    }
    let colors = review_colors(proposal, &facts);
    let note = prepare_note(
        &proposal.request.model_note,
        colors
            .as_ref()
            .map(|(old, new)| (old.as_str(), new.as_str())),
    )?;
    for warning in &note.warnings {
        facts.facts.push(("warning".into(), text(warning)?));
    }
    let card = Card {
        v: 1,
        risk: proposal.risk,
        says: facts.says,
        facts: facts.facts,
        from_to: facts.from_to,
        model_note: note.displayed,
    };
    let canonical = card.canonical_bytes()?;
    let digest = Digest32::sha256(&canonical);
    Ok(DisplayedCard {
        card,
        canonical,
        digest,
        proposal: Some(card_binding(proposal, action)),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyContext {
    pub node: NodeId,
    pub subject: SubjectId,
    pub epoch: u64,
    pub challenge: AuthorizationChallenge,
    pub expires_at_ms: i64,
}

pub fn operation_digest(node: NodeId, proposal: &Proposal) -> Result<OperationDigest> {
    if Digest32::sha256(&proposal.request.new_bytes) != proposal.new_digest {
        return Err(crate::refuse("authorization-mismatch"));
    }
    crate::proposal::content_digest(node, &proposal.request)
}

impl DisplayedCard {
    pub(crate) fn from_stored_review(
        proposal: &Proposal,
        action: OwnerOperation,
        card: Card,
    ) -> Result<Self> {
        require_action(action)?;
        validate_stored_content(proposal, action, &card)?;
        if card.risk != proposal.risk
            || card.model_note != prepare_model_note(&proposal.request.model_note)?.displayed
        {
            return Err(crate::refuse("authorization-mismatch"));
        }
        let canonical = card.canonical_bytes()?;
        Ok(Self {
            digest: Digest32::sha256(&canonical),
            card,
            canonical,
            proposal: Some(card_binding(proposal, action)),
        })
    }
}

fn validate_stored_content(proposal: &Proposal, action: OwnerOperation, card: &Card) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let mismatch = || crate::refuse("authorization-mismatch");
    if Digest32::sha256(&proposal.request.new_bytes) != proposal.new_digest {
        return Err(mismatch());
    }
    let mut bytes = card
        .from_to
        .iter()
        .filter(|(label, _)| label == "new_bytes_b64");
    let (_, encoded) = bytes.next().ok_or_else(mismatch)?;
    if bytes.next().is_some()
        || !matches!(encoded.view(), ValueView::Text(value) if value == STANDARD.encode(&proposal.request.new_bytes))
    {
        return Err(mismatch());
    }
    let expected_label =
        if action == OwnerOperation::Apply && proposal.request.target.as_str().starts_with("sites/") {
            "bundle_sha256"
        } else {
            "new_sha256"
        };
    let mut digests = card
        .facts
        .iter()
        .filter(|(label, _)| matches!(label.as_str(), "new_sha256" | "bundle_sha256"));
    let (label, digest) = digests.next().ok_or_else(mismatch)?;
    if label != expected_label
        || digests.next().is_some()
        || !matches!(digest.view(), ValueView::Text(value) if value == proposal.new_digest.to_string())
    {
        return Err(mismatch());
    }
    Ok(())
}

pub fn authorization(
    proposal: &Proposal,
    action: OwnerOperation,
    card: &DisplayedCard,
    context: CeremonyContext,
) -> Result<OwnerAuthorization> {
    require_action(action)?;
    if card.proposal != Some(card_binding(proposal, action))
        || card.card.risk != proposal.risk
        || card.card.model_note != prepare_model_note(&proposal.request.model_note)?.displayed
        || card.canonical != card.card.canonical_bytes()?
        || card.digest != Digest32::sha256(&card.canonical)
        || proposal.state != crate::ProposalState::Pending
        || context.epoch != proposal.authority.epoch
        || context.expires_at_ms <= proposal.created_at_ms
        || context.expires_at_ms > proposal.expires_at_ms
    {
        return Err(crate::refuse("authorization-mismatch"));
    }
    let operation = operation_digest(context.node, proposal)?;
    if operation != proposal.operation_digest {
        return Err(crate::refuse("authorization-mismatch"));
    }
    let authorization = OwnerAuthorization {
        v: 1,
        algorithm: canon::alg::AlgorithmId::Sha256,
        node: context.node,
        subject: context.subject,
        op: action,
        proposal: proposal.id,
        target: proposal.request.target.as_str().into(),
        base_sha256: proposal.request.base,
        new_sha256: proposal.new_digest,
        cell: proposal.request.cell,
        display_sha256: card.digest,
        challenge: context.challenge,
        expires_at: context.expires_at_ms,
        epoch: context.epoch,
        operation,
    };
    authorization.canonical_bytes()?;
    Ok(authorization)
}

pub fn passkey_challenge(authorization: &OwnerAuthorization) -> Result<Digest32> {
    let canonical = authorization.canonical_bytes()?;
    let mut preimage = canon::domain::OWNER_AUTHORIZATION_DOMAIN
        .as_bytes()
        .to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&canonical);
    Ok(Digest32::sha256(&preimage))
}

impl DisplayedCard {
    pub(crate) fn from_install_card(card: Card) -> Result<Self> {
        if card.risk != crate::RiskTier::Critical {
            return Err(crate::refuse("install-card-risk"));
        }
        let canonical = card.canonical_bytes()?;
        let digest = Digest32::sha256(&canonical);
        Ok(Self {
            card,
            canonical,
            digest,
            proposal: None,
        })
    }
}

fn require_action(action: OwnerOperation) -> Result<()> {
    match action {
        OwnerOperation::Apply | OwnerOperation::Retire => Ok(()),
        _ => Err(crate::refuse("unsupported-operation")),
    }
}

pub(crate) fn build_release_card(proposal: &Proposal, facts: ReviewFacts) -> Result<DisplayedCard> {
    let mut card = build_card(proposal, OwnerOperation::Apply, facts)?;
    card.proposal = Some(card_binding(proposal, OwnerOperation::Release));
    Ok(card)
}

pub(crate) fn restore_release_card(proposal: &Proposal, stored: Card) -> Result<DisplayedCard> {
    let mut card = DisplayedCard::from_stored_review(proposal, OwnerOperation::Apply, stored)?;
    card.proposal = Some(card_binding(proposal, OwnerOperation::Release));
    Ok(card)
}

pub(crate) fn release_authorization(
    proposal: &Proposal,
    card: &DisplayedCard,
    context: CeremonyContext,
) -> Result<OwnerAuthorization> {
    if card.proposal != Some(card_binding(proposal, OwnerOperation::Release)) {
        return Err(crate::refuse("authorization-mismatch"));
    }
    let mut checked = card.clone();
    checked.proposal = Some(card_binding(proposal, OwnerOperation::Apply));
    let mut auth = authorization(proposal, OwnerOperation::Apply, &checked, context)?;
    auth.op = OwnerOperation::Release;
    auth.canonical_bytes()?;
    Ok(auth)
}

fn card_binding(
    proposal: &Proposal,
    action: OwnerOperation,
) -> (ProposalId, OwnerOperation, OperationDigest, u64, Digest32) {
    (
        proposal.id,
        action,
        proposal.operation_digest,
        proposal.authority.epoch,
        Digest32::sha256(proposal.request.model_note.as_bytes()),
    )
}

fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}

fn number(value: usize) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| crate::refuse("card-too-large"))?;
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn hexdump(bytes: &[u8]) -> String {
    let mut dump = bytes
        .iter()
        .take(192)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > 192 {
        dump.push_str(&format!(" ... (+{} bytes)", bytes.len() - 192));
    }
    dump
}

fn authority_scan(raw: &str) -> Result<(Value, bool)> {
    let mut categories = std::collections::BTreeSet::new();
    let mut cleaned = String::with_capacity(raw.len());
    for c in raw.chars() {
        let category = match c as u32 {
            0x200b..=0x200d | 0x2060 | 0xfeff => Some("zero_width"),
            0x061c | 0x200e..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069 => Some("bidi_control"),
            0xe0000..=0xe007f => Some("tag_char"),
            0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x100000..=0x10fffd => Some("private_use"),
            0x00..=0x08 | 0x0b..=0x0c | 0x0e..=0x1f | 0x7f..=0x9f => Some("control_char"),
            0x00ad
            | 0x034f
            | 0x115f..=0x1160
            | 0x180e
            | 0x2061..=0x2065
            | 0x206a..=0x206f
            | 0x3164
            | 0xfe00..=0xfe0f
            | 0xffa0
            | 0xfff9..=0xfffb
            | 0xe0100..=0xe01ef => Some("format_char"),
            _ => None,
        };
        if let Some(category) = category {
            categories.insert(category);
            cleaned.push(' ');
        } else {
            cleaned.push(c);
        }
    }
    let confusables = cleaned
        .split_whitespace()
        .filter(|word| {
            let normalized = ComposingNormalizer::new_nfkc().normalize(word);
            let skeleton: String = normalized
                .chars()
                .map(|c| match c {
                    'а' | 'Α' | 'А' => 'a',
                    'е' | 'Ε' | 'Е' => 'e',
                    'о' | 'Ο' | 'О' => 'o',
                    'р' | 'Ρ' | 'Р' => 'p',
                    'с' | 'С' => 'c',
                    'х' | 'Χ' | 'Х' => 'x',
                    'у' | 'Υ' | 'У' => 'y',
                    'і' | 'Ι' | 'І' => 'i',
                    _ => c.to_ascii_lowercase(),
                })
                .collect();
            skeleton != word.to_ascii_lowercase()
                && [
                    "auth",
                    "apply",
                    "approve",
                    "approved",
                    "authorise",
                    "authorize",
                    "root",
                    "owner",
                    "admin",
                    "signed",
                ]
                .contains(&skeleton.as_str())
        })
        .count();
    if confusables > 0 {
        categories.insert("confusable_authority");
    }
    let refused = !categories.is_empty();
    let composed = ComposingNormalizer::new_nfc().normalize(cleaned.trim());
    let canonical: String = composed
        .chars()
        .map(|c| {
            if c.is_whitespace() {
                c.to_string()
            } else {
                ComposingNormalizer::new_nfkc()
                    .normalize(&c.to_string())
                    .into_owned()
            }
        })
        .collect();
    let scan = Value::object(vec![
        ("schema".into(), text("aukora-authority-display/v1")?),
        ("raw_sha256".into(), text(Digest32::sha256(raw.as_bytes()))?),
        (
            "canonical_sha256".into(),
            text(Digest32::sha256(canonical.as_bytes()))?,
        ),
        (
            "categories".into(),
            Value::array(
                categories
                    .into_iter()
                    .map(text)
                    .collect::<Result<Vec<_>>>()?,
            )?,
        ),
        ("confusable_matches".into(), number(confusables)?),
        (
            "action".into(),
            text(if refused { "refuse" } else { "allow" })?,
        ),
        ("grants_authority".into(), Value::boolean(false)),
    ])?;
    Ok((scan, refused))
}

fn note_warnings(note: &str, colors: Option<(&str, &str)>) -> Vec<String> {
    let lower = note.to_ascii_lowercase();
    let mut warnings = Vec::new();
    let (decoded, obfuscated) = decode_note(&lower);
    let words: Vec<_> = decoded
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    if let Some((old, new)) = colors {
        warnings.extend(color_change_warnings(old, new));
    }
    if obfuscated {
        warnings.push("NOTE text is obfuscated (leetspeak, scrambled or spaced-out letters) - it was decoded for these checks; treat it as hostile.".into());
    }
    if let Some((_, new)) = colors {
        let wrong: Vec<_> = hex_mentions(note)
            .into_iter()
            .filter(|value| {
                let value = value.trim_start_matches('#');
                new.strip_prefix('#')
                    .is_none_or(|expected| !expected.eq_ignore_ascii_case(value))
            })
            .collect();
        if !wrong.is_empty() {
            warnings.push(format!(
                "NOTE mentions {} - NOT the result. The result is {new} ({}).",
                wrong.join(", "),
                color_name(new)
            ));
        }
    }
    let compact: String = decoded
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let authority: Vec<_> = [
        "gate", "host", "system", "verif", "approv", "authori", "signed", "official",
    ]
    .into_iter()
    .filter(|term| {
        words.iter().any(|word| match *term {
            "gate" | "host" | "system" => word == term,
            "approv" => word.contains(term),
            _ => word.starts_with(term),
        }) || (["gate", "host", "verif"].contains(term)
            && (compact == *term || compact.starts_with(term)))
            || (*term == "gate" && lower.contains('_') && compact.ends_with("gate"))
    })
    .collect();
    if !authority.is_empty() {
        warnings.push(format!("NOTE uses gate/host/approval wording ({}) - ignore it; only the gate-marked card is from the gate.", authority.join(", ")));
    }
    if decoded.contains("after apply") || decoded.contains("accent =") {
        warnings.push("NOTE imitates the gate result line (\"AFTER APPLY\" / \"accent =\") - only the gate-marked line is real.".into());
    }
    if let Some((old, new)) = colors {
        if old != new
            && [
                "nochange",
                "novisual",
                "nothingchang",
                "nothingvisible",
                "unchanged",
                "same",
                "still",
                "noop",
                "keepsit",
                "keepcurrent",
                "keepscurrent",
                "justatypo",
            ]
            .iter()
            .any(|term| compact.contains(term))
        {
            warnings.push(format!("NOTE claims little/no change or \"still/same\", but the result is a real change: {old} -> {new}."));
        }
    }
    if [
        "already approv",
        "already signed",
        "already ok",
        "preapprov",
        "pre-approv",
        "pre author",
        "preauthor",
        "pre-sign",
        "precleared",
        "policy team",
    ]
    .iter()
    .any(|term| decoded.contains(term))
    {
        warnings.push("NOTE claims prior approval or speaks for a person/team - nobody can pre-approve; only this owner decision counts.".into());
    }
    if let Some((old, new)) = colors {
        let named = color_mentions(&lower, old, new);
        if !named.is_empty() {
            warnings.push(format!(
                "NOTE names colour(s) {} that do not match the result {new} ({}).",
                named
                    .iter()
                    .map(|name| format!("\"{name}\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                color_name(new)
            ));
        }
    }
    let mut repeated = Vec::new();
    let mut counts = std::collections::BTreeMap::new();
    for word in words {
        let word = if word == "approved" { "approve" } else { word };
        let count = counts.entry(word).or_insert(0usize);
        *count += 1;
        if (*count >= 2 && ["approve", "urgent", "now"].contains(&word))
            || (*count == 3 && !["approve", "urgent", "now"].contains(&word))
        {
            repeated.push(word);
        }
    }
    if !repeated.is_empty() {
        warnings.push(format!(
            "NOTE repeats words to pressure you ({}) - APPROVE-spam pattern.",
            repeated.join(", ")
        ));
    }
    warnings
}

fn decode_note(note: &str) -> (String, bool) {
    let decoded: String = note
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            _ => c,
        })
        .collect();
    let mut words: Vec<String> = decoded
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    let mut suspicious = false;
    for word in &mut words {
        for known in [
            "change", "visual", "approve", "approved", "gate", "verified",
        ] {
            if word.len() == known.len()
                && word != known
                && word.starts_with(&known[..1])
                && word.ends_with(&known[known.len() - 1..])
            {
                let mut observed = word.as_bytes().to_vec();
                let mut expected = known.as_bytes().to_vec();
                observed.sort_unstable();
                expected.sort_unstable();
                if observed == expected {
                    *word = known.into();
                    suspicious = true;
                    break;
                }
            }
        }
    }
    let mut joined = Vec::new();
    let mut index = 0;
    while index < words.len() {
        let start = index;
        while index < words.len()
            && words[index]
                .trim_matches(|c: char| !c.is_ascii_alphabetic())
                .len()
                == 1
        {
            index += 1;
        }
        if index - start >= 3 {
            joined.push(
                words[start..index]
                    .iter()
                    .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphabetic()))
                    .collect::<String>(),
            );
            suspicious = true;
        } else {
            joined.extend(words[start..index].iter().cloned());
        }
        if index < words.len() {
            joined.push(words[index].clone());
            index += 1;
        }
    }
    let digits = note.bytes().filter(u8::is_ascii_digit).count();
    if digits >= 2
        && ["gate", "verified", "visual"]
            .iter()
            .filter(|word| decoded.contains(**word))
            .count()
            >= 2
    {
        suspicious = true;
    }
    for word in note.split(|c: char| !c.is_ascii_alphanumeric()) {
        let trailing = word.bytes().rev().take_while(u8::is_ascii_digit).count();
        if trailing >= 4 && trailing < word.len() {
            suspicious = true;
        }
    }
    (joined.join(" "), suspicious)
}

fn hex_mentions(note: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = note.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        let prefixed = bytes[index] == b'#';
        if prefixed {
            index += 1;
        }
        let digits = index;
        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }
        let count = index - digits;
        let bounded = (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
            && (index == bytes.len() || !bytes[index].is_ascii_alphanumeric());
        if bounded && ((prefixed && (3..=8).contains(&count)) || (!prefixed && count == 6)) {
            let value = note[start..index].to_owned();
            if !found.contains(&value) {
                found.push(value);
            }
        }
        if index == start {
            index += 1;
        }
    }
    found
}

fn review_colors(proposal: &Proposal, facts: &ReviewFacts) -> Option<(String, String)> {
    let before = facts
        .from_to
        .iter()
        .find(|(key, _)| key == "before")
        .and_then(|(_, value)| value_text(value));
    let after = facts
        .from_to
        .iter()
        .find(|(key, _)| key == "after")
        .and_then(|(_, value)| value_text(value));
    let old = accent(before?.as_bytes())?;
    let new = accent(
        after
            .map(str::as_bytes)
            .unwrap_or(&proposal.request.new_bytes),
    )?;
    Some((old, new))
}

fn value_text(value: &Value) -> Option<&str> {
    match value.view() {
        ValueView::Text(value) => Some(value),
        _ => None,
    }
}

fn accent(bytes: &[u8]) -> Option<String> {
    let value = canon::json::parse_strict(bytes).ok()?;
    let raw = value.get("accent").and_then(value_text)?;
    if raw == "default" {
        return Some(raw.into());
    }
    if raw.len() == 7 && raw.starts_with('#') && raw[1..].bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(raw.to_ascii_uppercase())
    } else {
        None
    }
}

fn color_name(value: &str) -> &'static str {
    match value {
        "#FFD700" => "gold",
        "#D4AF37" => "metallic gold",
        "#1E90FF" => "dodger blue",
        "#0000FF" => "blue",
        "#FFA500" => "orange",
        "#FF0000" => "red",
        "#008000" => "green",
        "#FFFFFF" => "white",
        "#000000" => "black",
        "default" => "app default (stock accent, NOT gold)",
        _ => "custom (unnamed)",
    }
}

fn color_change_warnings(old: &str, new: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    if new == "default" {
        warnings.push("RESULT IS \"default\": the app falls back to its stock accent - NOT gold (#FFD700) and not any colour named in the note.".into());
    }
    if old != new && color_name(old) == color_name(new) {
        warnings.push(format!("HARD WARNING - NAME COLLISION: the colour name \"{}\" resembles the current \"{}\" but the hex differs ({old} -> {new}). Go by the hex and the swatch: the result is NOT {old}.", color_name(new), color_name(old)));
    }
    if new.len() == 7
        && new.starts_with('#')
        && new
            .bytes()
            .zip(b"#FFD700".iter().copied())
            .filter(|(a, b)| a != b)
            .count()
            == 1
    {
        if let Ok(rgb) = hex::decode(&new[1..]) {
            let distance: u32 = rgb
                .iter()
                .zip([255u8, 215, 0])
                .map(|(a, b)| u32::from(a.abs_diff(b)))
                .sum();
            warnings.push(format!("NEAR gold (distance {distance}): the result {new} looks like #FFD700 (1 of 6 hex digits differ) but it is NOT #FFD700."));
        }
    }
    warnings
}

fn color_mentions(note: &str, old: &str, new: &str) -> Vec<String> {
    let palette = [
        "gold", "blue", "azure", "cobalt", "green", "red", "orange", "yellow", "white", "black",
        "honey",
    ];
    let words: Vec<_> = note
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .collect();
    let result_family = match new {
        "#1E90FF" | "#0000FF" => Some("blue"),
        "#FFD700" | "#D4AF37" => Some("gold"),
        "#008000" => Some("green"),
        "#FF0000" => Some("red"),
        "#FFA500" => Some("orange"),
        "#FFFFFF" => Some("white"),
        "#000000" => Some("black"),
        _ => None,
    };
    let describes_transition = ["from", "instead of", "replacing", "->"]
        .iter()
        .any(|term| note.contains(term))
        && result_family.is_some_and(|family| words.contains(&family));
    palette
        .into_iter()
        .filter(|name| {
            if !words.contains(name) {
                return false;
            }
            let family = match *name {
                "azure" | "cobalt" => "blue",
                "honey" => "gold",
                other => other,
            };
            result_family != Some(family)
                && !(describes_transition && color_name(old).contains(name))
        })
        .map(str::to_owned)
        .collect()
}
