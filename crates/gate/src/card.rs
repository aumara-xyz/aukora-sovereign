//! Prime's owner card: exact operation bytes, trusted facts and separately labelled model data.
use crate::{Error, Proposal, Result, Schema, TargetSpec};
use icu_normalizer::ComposingNormalizer;
use icu_properties::{
    props::{DefaultIgnorableCodePoint, GeneralCategory},
    CodePointMapData, CodePointSetData,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const NOTE_MAX: usize = 120;
const GOLD: &str = "#FFD700";

pub(crate) fn checked_review_facts(
    spec: &TargetSpec,
    old: Option<&[u8]>,
    new: &[u8],
    has_history: bool,
) -> Result<Option<Value>> {
    let Some(hook) = spec.review_facts else {
        return Ok(None);
    };
    let mut facts = hook(old, new)?;
    if let Some(pinned) = &spec.pinned_facts {
        if matches!(spec.schema, Schema::Release) {
            let new_sha256 = crate::sha256(new);
            let evidence = pinned
                .get(&new_sha256)
                .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
            crate::targets::validate_release_evidence(&new_sha256, evidence)?;
            facts["pinned"] = evidence.clone();
        } else {
            facts["pinned"] = pinned.clone();
        }
    }
    let from_to = facts
        .get("from_to")
        .and_then(Value::as_str)
        .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
    if from_to.is_empty()
        || from_to.len() > 600
        || !from_to.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(Error::Refused("gate:review-facts-unavailable"));
    }
    if facts.get("release_floor") == Some(&Value::Null) && (old.is_some() || has_history) {
        return Err(Error::Refused("gate:review-floor-absent"));
    }
    // All facts, including integers and depth, must satisfy the shared signed format.
    crate::canonical(&facts).map_err(|_| Error::Refused("gate:review-facts-unavailable"))?;
    Ok(Some(facts))
}

pub(crate) fn bytes(
    p: &Proposal,
    spec: &TargetSpec,
    old: Option<&[u8]>,
    new: &[u8],
    mut review_facts: Option<Value>,
) -> Result<Vec<u8>> {
    spec.validate(new)?;
    let old_text = old
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| Error::Refused("gate:invalid-utf8"))?;
    let new_text = std::str::from_utf8(new).map_err(|_| Error::Refused("gate:invalid-utf8"))?;
    let note = clean_note(&p.note);
    let meta = note_meta(&p.note);
    let warnings = card_warnings(spec, old_text.unwrap_or(""), new_text, &note, &meta);
    let mut facts = vec![
        json!(["target", p.target]),
        json!(["base_sha256", p.base_sha256]),
        json!(["new_sha256", p.new_sha256]),
    ];
    let requires_override = review_facts
        .as_ref()
        .and_then(|facts| facts.get("pinned"))
        .is_some_and(|evidence| {
            matches!(spec.schema, Schema::Release)
                && (evidence["refusal_code"].as_str().is_some()
                    || evidence["antibody_pass_count"].as_u64()
                        < evidence["antibody_total"].as_u64()
                    || ["failed_ids", "missing_ids"].iter().any(|field| {
                        evidence[*field]
                            .as_array()
                            .is_some_and(|ids| !ids.is_empty())
                    }))
        });
    if let Some(rows) = review_facts.as_ref().and_then(|f| f["facts"].as_array()) {
        facts.extend(rows.iter().cloned());
    }
    if matches!(spec.schema, Schema::Release) {
        if let Some(evidence) = review_facts.as_ref().and_then(|f| f.get("pinned")) {
            crate::targets::validate_release_evidence(&p.new_sha256, evidence)?;
            facts.push(json!([
                "antibody_corpus_sha256",
                evidence["antibody_corpus_sha256"]
            ]));
            facts.push(json!([
                "antibody_pass_count/total",
                format!(
                    "{}/{}",
                    evidence["antibody_pass_count"], evidence["antibody_total"]
                )
            ]));
        }
        if let Some(evidence) = review_facts
            .as_mut()
            .and_then(|facts| facts.get_mut("pinned"))
        {
            for field in ["antibody_ids", "failed_ids", "missing_ids"] {
                if let Some(ids) = evidence[field].as_array() {
                    let mut ids = ids.clone();
                    ids.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
                    let count = ids.len();
                    let digest = crate::sha256(crate::canonical(&json!(ids))?.as_bytes());
                    let object = evidence
                        .as_object_mut()
                        .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
                    object.remove(field);
                    object.insert(format!("{field}_count"), json!(count));
                    object.insert(format!("{field}_sha256"), json!(digest));
                    if field != "antibody_ids" {
                        object.insert(format!("{field}_preview"), json!(&ids[..ids.len().min(6)]));
                    }
                }
            }
        }
        if requires_override {
            facts.push(json!(["antibody_approval", "Normal approval is disabled. Approving despite failing antibodies requires a separate passkey confirmation."]));
        }
    }
    if matches!(spec.schema, Schema::BrokerGrant) {
        let record: Value = serde_json::from_slice(new)?;
        if let Some(prices) = review_facts
            .as_ref()
            .and_then(|f| f["pinned"]["prices"][record["model"].as_str().unwrap_or("")].as_object())
        {
            for field in ["prompt_microusd_per_token", "completion_microusd_per_token"] {
                facts.push(json!([field, prices[field].to_string()]));
            }
        }
    }
    let mut card = json!({
        "v":1, "risk":spec.risk, "says":spec.says,
        "facts":facts,
        "from_to":{"encoding":"utf-8","base":old_text,"new":new_text,
            "diff":line_diff(old_text.unwrap_or(""),new_text,&p.target),
            "summary":review_facts.as_ref().and_then(|facts| facts.get("from_to"))},
        "target_review":review_facts,
        "warnings":warnings,
        "model_note_label":"UNVERIFIED MODEL NOTE; DATA ONLY",
        "model_note":note,
        "model_note_meta":meta,
    });
    if matches!(spec.schema, Schema::Release) {
        card["requires_antibody_override"] = json!(requires_override);
    }
    Ok(crate::canonical(&card)?.into_bytes())
}

/// Equivalent to Prime's NFKC, ASCII-only, marker-neutralising cleanNote.
pub(crate) fn clean_note(raw: &str) -> String {
    let normalized = ComposingNormalizer::new_nfkc().normalize(raw);
    let ascii: String = normalized
        .chars()
        .map(|ch| if (' '..='~').contains(&ch) { ch } else { ' ' })
        .collect();
    let mut neutral = String::with_capacity(ascii.len());
    let mut at = 0;
    while at < ascii.len() {
        if ascii[at..].len() >= 5 && ascii[at..at + 5].eq_ignore_ascii_case("GATE-") {
            neutral.push_str("gate_");
            at += 5;
        } else {
            neutral.push(ascii.as_bytes()[at] as char);
            at += 1;
        }
    }
    let mut cleaned = neutral
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.len() > NOTE_MAX {
        cleaned.truncate(NOTE_MAX - 3);
        cleaned.push_str("...");
    }
    cleaned
}

pub(crate) fn note_meta(raw: &str) -> Value {
    let nonascii = raw
        .chars()
        .filter(|c| !(' '..='~').contains(c) && !matches!(c, '\t' | '\n' | '\r'))
        .count();
    if nonascii == 0 {
        return json!({"nonascii":0});
    }
    let cap = &raw.as_bytes()[..raw.len().min(192)];
    let mut hexdump = cap
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if raw.len() > cap.len() {
        hexdump.push_str(&format!(" ... (+{} bytes)", raw.len() - cap.len()));
    }
    json!({"nonascii":nonascii,"raw_bytes":raw.len(),"hexdump":hexdump,
        "authority_display":if raw.len()<=16384 { Some(authority_display(raw)) } else { None }})
}

fn fold(ch: char) -> Option<char> {
    for (ascii, lookalikes) in [
        ('a', "аАαΑɑᎪ"),
        ('b', "ВΒᏏ"),
        ('c', "сСᴄ"),
        ('d', "ԁᎠ"),
        ('e', "еЕΕ"),
        ('g', "ɡᏬ"),
        ('h', "һнНʜ"),
        ('i', "іιıɩɪ"),
        ('j', "јȷ"),
        ('k', "кКκ"),
        ('l', "Ꮮ"),
        ('m', "мМ"),
        ('n', "ɴ"),
        ('o', "оОοΟᴏ"),
        ('p', "рРρΡᴘ"),
        ('r', "ʀᏆ"),
        ('s', "ѕʂᏎ"),
        ('t', "тТ"),
        ('u', "υ"),
        ('v', "вν"),
        ('w', "Ꮃ"),
        ('x', "хХχ"),
        ('y', "у"),
    ] {
        if lookalikes.contains(ch) {
            return Some(ascii);
        }
    }
    let point = ch as u32;
    for start in [
        0xff21, 0xff41, 0x1d400, 0x1d41a, 0x1d468, 0x1d482, 0x1d5a0, 0x1d5ba, 0x1d5d4, 0x1d5ee,
        0x1d608, 0x1d622, 0x1d63c, 0x1d656, 0x1d670, 0x1d68a,
    ] {
        if (start..start + 26).contains(&point) {
            return char::from_u32(point - start + 'a' as u32);
        }
    }
    None
}

fn hidden_category(ch: char) -> Option<&'static str> {
    let point = ch as u32;
    if [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff].contains(&point) {
        return Some("zero_width");
    }
    if matches!(point, 0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069) {
        return Some("bidi_control");
    }
    if (0xe0000..=0xe007f).contains(&point) {
        return Some("tag_char");
    }
    let category = CodePointMapData::<GeneralCategory>::new().get(ch);
    if category == GeneralCategory::PrivateUse {
        return Some("private_use");
    }
    if matches!(point, 0..=8 | 11 | 12 | 14..=31 | 127..=159) {
        return Some("control_char");
    }
    if category == GeneralCategory::Format
        || CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(ch)
    {
        return Some("format_char");
    }
    None
}

fn authority_display(raw: &str) -> Value {
    let mut categories = BTreeSet::new();
    let mut skeleton = String::new();
    let mut canonical = String::new();
    let mut changed = Vec::new();
    for ch in ComposingNormalizer::new_nfc().normalize(raw).chars() {
        let target = fold(ch);
        if let Some(category) = hidden_category(ch) {
            categories.insert(category);
        } else {
            canonical.push(target.unwrap_or(ch));
        }
        let piece = target.unwrap_or(ch.to_ascii_lowercase());
        skeleton.push(piece);
        changed.extend(std::iter::repeat_n(target.is_some(), piece.len_utf8()));
    }
    let mut occurrences = 0;
    for word in [
        "auth",
        "apply",
        "admin",
        "root",
        "grant",
        "sudo",
        "exec",
        "signer",
        "aumlok",
        "authorize",
        "production",
        "live",
        "permit",
        "kernel",
    ] {
        for (at, _) in skeleton.match_indices(word) {
            if changed[at..at + word.len()].contains(&true) {
                occurrences += 1;
            }
        }
    }
    if occurrences > 0 {
        categories.insert("confusable_authority");
    }
    json!({"schema":"aukora-authority-display/v1","raw_sha256":crate::sha256(raw.as_bytes()),
        "canonical_sha256":crate::sha256(canonical.as_bytes()),"categories":categories,
        "confusable_matches":occurrences,"action":if categories.is_empty(){"allow"}else{"refuse"},
        "grants_authority":false})
}

pub(crate) fn line_diff(a: &str, b: &str, name: &str) -> String {
    let a: Vec<_> = if a.is_empty() {
        Vec::new()
    } else {
        a.split('\n').collect()
    };
    let b: Vec<_> = if b.is_empty() {
        Vec::new()
    } else {
        b.split('\n').collect()
    };
    let header = format!("--- a/{name}\n+++ b/{name}");
    if a.len().saturating_mul(b.len()) > 250_000 {
        return format!(
            "{header}\n{}\n{}",
            a.iter()
                .map(|l| format!("-{l}"))
                .collect::<Vec<_>>()
                .join("\n"),
            b.iter()
                .map(|l| format!("+{l}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    let mut lengths = vec![vec![0; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lengths[i][j] = if a[i] == b[j] {
                lengths[i + 1][j + 1] + 1
            } else {
                lengths[i + 1][j].max(lengths[i][j + 1])
            };
        }
    }
    let mut out = vec![header];
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            out.push(format!(" {}", a[i]));
            i += 1;
            j += 1;
        } else if lengths[i + 1][j] >= lengths[i][j + 1] {
            out.push(format!("-{}", a[i]));
            i += 1;
        } else {
            out.push(format!("+{}", b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|l| format!("-{l}")));
    out.extend(b[j..].iter().map(|l| format!("+{l}")));
    out.join("\n")
}

fn color_name(hex: Option<&str>) -> &'static str {
    match hex.unwrap_or("").to_ascii_lowercase().as_str() {
        "default" => "app default (stock accent, NOT gold)",
        "#ffd700" => "gold",
        "#d4af37" => "metallic gold (not #FFD700)",
        "#1e90ff" => "dodger blue",
        "#0000ff" => "blue",
        "#000000" => "black",
        "#ffffff" => "white",
        "#ff0000" => "red",
        "#00ff00" => "lime green",
        "#008000" => "green",
        "#ffa500" => "orange",
        "#800080" => "purple",
        "#808080" => "grey",
        _ => "custom (unnamed)",
    }
}
fn rgb(hex: &str) -> Option<[u8; 3]> {
    if hex.len() != 7 || !hex.starts_with('#') {
        return None;
    }
    Some([
        u8::from_str_radix(&hex[1..3], 16).ok()?,
        u8::from_str_radix(&hex[3..5], 16).ok()?,
        u8::from_str_radix(&hex[5..7], 16).ok()?,
    ])
}
fn hue(hex: &str) -> Option<(f64, f64, f64)> {
    let [r, g, b] = rgb(hex)?.map(|v| f64::from(v) / 255.0);
    let mx = r.max(g).max(b);
    let mn = r.min(g).min(b);
    let l = (mx + mn) / 2.0;
    let d = mx - mn;
    let sat = if d == 0.0 {
        0.0
    } else {
        d / (1.0 - (2.0 * l - 1.0).abs())
    };
    let h = if d == 0.0 {
        0.0
    } else if mx == r {
        ((g - b) / d).rem_euclid(6.0)
    } else if mx == g {
        (b - r) / d + 2.0
    } else {
        (r - g) / d + 4.0
    };
    Some(((h * 60.0 + 360.0) % 360.0, l, sat))
}
fn hue_family(hex: &str) -> Option<&'static str> {
    let (h, l, s) = hue(hex)?;
    Some(if l < 0.12 {
        "black"
    } else if l > 0.93 && s < 0.5 {
        "white"
    } else if s < 0.15 {
        "grey"
    } else if l < 0.45 && (15.0..50.0).contains(&h) {
        "brown"
    } else if !(15.0..345.0).contains(&h) {
        "red"
    } else if h < 40.0 {
        "orange"
    } else if h < 65.0 {
        "yellow"
    } else if h < 160.0 {
        "green"
    } else if h < 195.0 {
        "cyan"
    } else if h < 255.0 {
        "blue"
    } else if h < 290.0 {
        "purple"
    } else {
        "pink"
    })
}
fn colour_word(word: &str) -> Option<&'static str> {
    Some(match word {
        "red" | "crimson" | "scarlet" | "maroon" | "ruby" => "red",
        "orange" | "amber" | "tangerine" => "orange",
        "yellow" | "lemon" | "mustard" | "honey" => "yellow",
        "green" | "lime" | "emerald" | "olive" | "mint" => "green",
        "teal" | "cyan" | "turquoise" | "aqua" => "cyan",
        "blue" | "navy" | "azure" | "cobalt" | "indigo" => "blue",
        "purple" | "violet" | "lavender" => "purple",
        "magenta" | "pink" | "rose" | "fuchsia" => "pink",
        "brown" | "bronze" | "copper" | "beige" => "brown",
        "grey" | "gray" | "silver" | "charcoal" => "grey",
        "black" => "black",
        "white" => "white",
        "gold" | "golden" => "GOLD",
        _ => return None,
    })
}
fn word_matches(word: &str, hex: &str) -> bool {
    let Some(family) = colour_word(word) else {
        return false;
    };
    if family == "GOLD" {
        return hex.eq_ignore_ascii_case(GOLD);
    }
    let Some(actual) = hue_family(hex) else {
        return false;
    };
    if family == actual {
        return true;
    }
    if ["grey", "black", "white"].contains(&family) || ["grey", "black", "white"].contains(&actual)
    {
        return false;
    }
    if family == "brown" || actual == "brown" {
        return ["orange", "red", "yellow"].contains(&if family == "brown" {
            actual
        } else {
            family
        });
    }
    let centre = match family {
        "red" => 0.0,
        "orange" => 30.0,
        "yellow" => 55.0,
        "green" => 120.0,
        "cyan" => 180.0,
        "blue" => 225.0,
        "purple" => 275.0,
        "pink" => 320.0,
        _ => return false,
    };
    let distance = (hue(hex).unwrap().0 - centre).abs();
    distance.min(360.0 - distance) <= 35.0
}
fn leet(ch: char) -> Option<char> {
    match ch {
        '0' => Some('o'),
        '1' => Some('i'),
        '3' => Some('e'),
        '4' => Some('a'),
        '5' => Some('s'),
        '7' => Some('t'),
        '8' => Some('b'),
        '@' => Some('a'),
        '$' => Some('s'),
        '!' => Some('i'),
        '|' => Some('l'),
        '+' => Some('t'),
        _ => None,
    }
}
fn words(text: &str) -> Vec<&str> {
    text.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
        .collect()
}
fn squash(text: &str, fold_leet: bool) -> String {
    let lower = text.to_ascii_lowercase();
    let benign = [
        "navigat",
        "aggregat",
        "delegat",
        "investigat",
        "propagat",
        "mitigat",
        "segregat",
        "irrigat",
        "interrogat",
        "obligat",
        "instigat",
        "abrogat",
        "variegat",
        "ghost",
        "systematic",
    ];
    let mut stripped = String::new();
    let mut at = 0;
    while at < lower.len() {
        let begin = at;
        while at < lower.len()
            && (lower.as_bytes()[at].is_ascii_alphanumeric() || lower.as_bytes()[at] == b'_')
        {
            at += 1;
        }
        if at == begin {
            stripped.push(lower.as_bytes()[at] as char);
            at += 1;
        } else if !benign
            .iter()
            .any(|prefix| lower[begin..at].starts_with(prefix))
        {
            stripped.push_str(&lower[begin..at]);
        }
    }
    stripped
        .chars()
        .filter_map(|c| {
            if fold_leet {
                if c.is_ascii_alphabetic() {
                    Some(c)
                } else {
                    leet(c)
                }
            } else {
                c.is_ascii_alphanumeric().then_some(c)
            }
        })
        .collect()
}
const KEYWORDS: &[&str] = &[
    "change",
    "changes",
    "visual",
    "visible",
    "identical",
    "cosmetic",
    "only",
    "byte",
    "nothing",
    "looks",
    "different",
    "unchanged",
    "same",
    "still",
    "gold",
    "golden",
    "already",
    "approved",
    "approve",
    "approval",
    "policy",
    "owner",
    "team",
    "apply",
    "verified",
    "gate",
    "host",
    "system",
    "trusted",
    "urgent",
    "accent",
    "after",
    "typo",
    "trivial",
    "white",
    "black",
    "green",
    "yellow",
    "blue",
    "orange",
    "purple",
    "grey",
    "gray",
    "silver",
    "rotation",
    "perceived",
    "luminance",
    "unanimously",
    "everyone",
    "waiting",
    "step",
    "last",
    "noop",
    "keep",
    "current",
    "admin",
    "operator",
    "peter",
    "signed",
    "official",
    "just",
    "this",
];
fn fkey(word: &str) -> Option<String> {
    let chars: Vec<char> = word
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            let c = if matches!(c, '0'..='9' | '@' | '$') {
                leet(c).unwrap_or(c)
            } else {
                c
            };
            if c == 'l' {
                'i'
            } else {
                c
            }
        })
        .collect();
    if chars.len() < 4 {
        return None;
    }
    let mut middle = chars[1..chars.len() - 1].to_vec();
    middle.sort_unstable();
    Some(
        std::iter::once(chars[0])
            .chain(middle)
            .chain(std::iter::once(*chars.last().unwrap()))
            .collect(),
    )
}
fn descramble(note: &str) -> (String, usize, bool) {
    let mut text = String::new();
    let mut begin = 0;
    let mut spaced = false;
    let bytes = note.as_bytes();
    while begin < bytes.len() {
        let boundary =
            begin == 0 || !bytes[begin - 1].is_ascii_alphanumeric() && bytes[begin - 1] != b'_';
        let mut end = begin;
        let mut last_valid = begin;
        if boundary && bytes[begin].is_ascii_alphanumeric() {
            end += 1;
            while end + 1 < bytes.len()
                && bytes[end] == b' '
                && bytes[end + 1].is_ascii_alphanumeric()
            {
                end += 2;
                if end - begin >= 7
                    && (end == bytes.len()
                        || !bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_')
                {
                    last_valid = end;
                }
            }
        }
        if last_valid > begin {
            end = last_valid;
            text.extend(note[begin..end].chars().filter(|c| *c != ' '));
            spaced = true;
            begin = end;
        } else {
            text.push(bytes[begin] as char);
            begin += 1;
        }
    }
    let mut out = String::new();
    let mut changed = 0;
    let mut at = 0;
    while at < text.len() {
        let begin = at;
        while at < text.len()
            && (text.as_bytes()[at].is_ascii_alphanumeric() || b"@$".contains(&text.as_bytes()[at]))
        {
            at += 1;
        }
        if at == begin {
            out.push(text.as_bytes()[at] as char);
            at += 1;
            continue;
        }
        let word = &text[begin..at];
        if !word.bytes().any(|b| b.is_ascii_alphabetic()) {
            out.push_str(word);
            continue;
        }
        let key = fkey(word);
        let target = KEYWORDS
            .iter()
            .find(|candidate| fkey(candidate) == key && key.is_some());
        if let Some(target) = target.filter(|target| **target != word.to_ascii_lowercase()) {
            out.push_str(target);
            changed += 1;
        } else if word
            .bytes()
            .any(|b| b.is_ascii_digit() || b"@$".contains(&b))
        {
            out.extend(word.chars().map(|c| leet(c).unwrap_or(c)));
            changed += 1;
        } else {
            out.push_str(word);
        }
    }
    (out, changed, spaced)
}
fn hex_tokens(note: &str) -> Vec<String> {
    let b = note.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < b.len() {
        if b[at] == b'#' {
            let begin = at;
            at += 1;
            while at < b.len() && b[at].is_ascii_alphanumeric() && at - begin <= 8 {
                at += 1;
            }
            if (3..=8).contains(&(at - begin - 1))
                && (at == b.len() || !b[at].is_ascii_alphanumeric() && b[at] != b'_')
            {
                out.push(note[begin..at].into());
            }
        } else {
            let begin = at;
            while at < b.len() && (b[at].is_ascii_alphanumeric() || b[at] == b'_') {
                at += 1;
            }
            if at > begin {
                let word = &note[begin..at];
                if word.len() == 6
                    && word.bytes().all(|c| c.is_ascii_hexdigit())
                    && word.bytes().any(|c| c.is_ascii_digit())
                    && word.bytes().any(|c| c.is_ascii_alphabetic())
                {
                    out.push(word.into());
                }
            } else {
                at += 1;
            }
        }
    }
    out
}
fn phrase(text: &str, needle: &str) -> bool {
    text.match_indices(needle).any(|(at, _)| {
        (at == 0
            || !text.as_bytes()[at - 1].is_ascii_alphanumeric() && text.as_bytes()[at - 1] != b'_')
            && (at + needle.len() == text.len()
                || !text.as_bytes()[at + needle.len()].is_ascii_alphanumeric()
                    && text.as_bytes()[at + needle.len()] != b'_')
    })
}
fn no_change(text: &str) -> bool {
    [
        "no-op",
        "noop",
        "no change",
        "no-change",
        "nochange",
        "no diff",
        "unchanged",
        "identical",
        "same",
        "still",
        "stay",
        "stays",
        "remain",
        "remains",
        "untouched",
        "as-is",
        "as is",
        "as before",
        "revert nothing",
        "does nothing",
        "cosmetic",
        "just a typo",
        "typo",
        "trivial",
        "byte-for-byte",
        "byte for byte",
        "byteforbyte",
    ]
    .iter()
    .any(|p| phrase(text, p))
        || [
            "no visual change",
            "no visible change",
            "no real change",
            "no visual diff",
            "no visible diff",
            "no real diff",
            "no visual difference",
            "no visible difference",
            "no real difference",
            "nothing chang",
            "nothing visible",
            "keep it",
            "keeps it",
            "keep the",
            "keeps the",
            "keep current",
            "keeps current",
        ]
        .iter()
        .any(|p| phrase(text, p))
}
fn away_from(note: &str, word: &str) -> bool {
    let tokens: Vec<_> = note.split_whitespace().collect();
    for (i, token) in tokens.iter().enumerate() {
        if token.trim_end_matches(|c: char| !c.is_ascii_alphanumeric()) != word {
            continue;
        }
        if tokens
            .get(i + 1)
            .is_some_and(|next| ["->", "=>", "to"].contains(next))
        {
            return true;
        }
        let mut prefix = i;
        if prefix > 0 && ["current", "old"].contains(&tokens[prefix - 1]) {
            prefix -= 1;
        }
        if prefix > 0 && tokens[prefix - 1] == "the" {
            prefix -= 1;
        }
        if prefix > 0
            && (tokens[prefix - 1] == "from"
                || tokens[prefix - 1].starts_with("replac")
                || tokens[prefix - 1].starts_with("swap")
                || prefix >= 2
                    && ["instead of", "away from", "rather than"]
                        .contains(&tokens[prefix - 2..prefix].join(" ").as_str()))
        {
            return true;
        }
    }
    false
}

fn prior_approval(text: &str) -> bool {
    for (at, _) in text.char_indices() {
        if at > 0
            && (text.as_bytes()[at - 1].is_ascii_alphanumeric() || text.as_bytes()[at - 1] == b'_')
        {
            continue;
        }
        let tail = &text[at..];
        let tail = if let Some(tail) = tail.strip_prefix("already") {
            tail
        } else if let Some(tail) = tail.strip_prefix("pre") {
            tail.strip_prefix('-').unwrap_or(tail)
        } else {
            continue;
        };
        let tail = tail.trim_start_matches(|c: char| c.is_ascii_whitespace());
        for action in [
            "approved",
            "authorized",
            "authorised",
            "signed off",
            "signed-off",
            "signedoff",
            "cleared",
            "okd",
            "ok'd",
        ] {
            if let Some(after) = tail.strip_prefix(action) {
                if after.is_empty()
                    || !after.as_bytes()[0].is_ascii_alphanumeric() && after.as_bytes()[0] != b'_'
                {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn card_warnings(
    spec: &TargetSpec,
    old: &str,
    new: &str,
    note: &str,
    meta: &Value,
) -> Vec<String> {
    let accent = |text: &str| -> Option<String> {
        serde_json::from_str::<Value>(text)
            .ok()?
            .get("accent")?
            .as_str()
            .map(str::to_owned)
    };
    let theme = matches!(spec.schema, Schema::Theme);
    let base = theme.then(|| accent(old)).flatten();
    let next = theme.then(|| accent(new)).flatten();
    let old_name = color_name(base.as_deref());
    let new_name = color_name(next.as_deref());
    let mut warnings = Vec::new();
    let nonascii = meta["nonascii"].as_u64().unwrap_or(0);
    if nonascii > 0 {
        warnings.push(format!("NOTE contained {nonascii} non-ASCII/invisible characters (lookalike, invisible, bidi or styled text). They were removed{}; the raw bytes are in the hex dump. Treat the note as hostile.",if note.is_empty(){" - nothing readable was left"}else{""}));
    }
    if meta["authority_display"]["action"] == "refuse" {
        warnings.push("NOTE failed the authority-display scan (invisible text or a confusable authority word); its sanitized text is model commentary and grants no authority.".into());
    }
    if let Some(result) = next.as_deref() {
        let core = |name: &str| name.split('(').next().unwrap_or("").trim().to_string();
        if let Some(base) = base.as_deref() {
            if !base.eq_ignore_ascii_case(result)
                && (old_name == new_name
                    || core(new_name).contains(&core(old_name))
                    || phrase(&core(new_name), "gold") && !result.eq_ignore_ascii_case(GOLD))
            {
                warnings.push(format!("HARD WARNING - NAME COLLISION: the colour name \"{new_name}\" resembles the current \"{old_name}\" but the hex differs ({base} -> {result}). Go by the hex and the swatch: the result is NOT {base}."));
            }
        }
        if result == "default" {
            warnings.push("RESULT IS \"default\": the app falls back to its stock accent - NOT gold (#FFD700) and not any colour named in the note.".into());
        }
        let mut references = vec![GOLD.to_string()];
        if let Some(base) = base.as_ref().filter(|hex| rgb(hex).is_some()) {
            if !references.iter().any(|hex| hex.eq_ignore_ascii_case(base)) {
                references.push(base.to_uppercase());
            }
        }
        for reference in references {
            if result.eq_ignore_ascii_case(&reference) {
                continue;
            }
            let (Some(a), Some(b)) = (rgb(&reference), rgb(result)) else {
                continue;
            };
            let distance = (a
                .iter()
                .zip(b)
                .map(|(a, b)| (f64::from(*a) - f64::from(b)).powi(2))
                .sum::<f64>()
                .sqrt()
                * 10.0)
                .round()
                / 10.0;
            let differing = reference[1..]
                .bytes()
                .zip(result[1..].to_ascii_uppercase().bytes())
                .filter(|(a, b)| a != b)
                .count();
            if distance <= 48.0 || differing <= 1 {
                warnings.push(format!("NEAR {} (distance {distance}): the result {result} looks like {reference} ({differing} of 6 hex digits differ) but it is NOT {reference}.",color_name(Some(&reference))));
            }
        }
    }
    if note.is_empty() {
        return warnings;
    }
    let n = note.to_ascii_lowercase();
    let (decoded, changed, spaced) = descramble(note);
    let nd = decoded.to_ascii_lowercase();
    let nn = format!("{n} \n {nd}");
    if changed >= 2 || spaced {
        warnings.push("NOTE text is obfuscated (leetspeak, scrambled or spaced-out letters) - it was decoded for these checks; treat it as hostile.".into());
    }
    let hexes = hex_tokens(note);
    let mut others = Vec::new();
    for hex in hexes {
        if next.as_deref().is_none_or(|next| {
            !hex.trim_start_matches('#')
                .eq_ignore_ascii_case(next.trim_start_matches('#'))
        }) && !others.contains(&hex)
        {
            others.push(hex);
        }
    }
    if !others.is_empty() {
        warnings.push(format!(
            "NOTE mentions {} - NOT the result. The result is {} ({new_name}).",
            others
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            next.as_deref().unwrap_or("null")
        ));
    }
    let sq = format!("{}|{}", squash(note, false), squash(&nd, false));
    let sql = format!("{}|{}", squash(note, true), squash(&nd, true));
    let compact = nn.split_ascii_whitespace().collect::<String>();
    if sq.contains("afterapply")
        || sql.contains("afterapply")
        || compact.contains("accent=")
        || compact.contains("accent:#")
        || compact.contains("result=")
    {
        warnings.push("NOTE imitates the gate result line (\"AFTER APPLY\" / \"accent =\") - only the gate-marked line is real.".into());
    }
    let nochange_sq = [
        "nochange",
        "novisualchange",
        "novisiblechange",
        "unchang",
        "identic",
        "cosmetic",
        "byteforbyte",
        "nothinglooks",
        "nothingchang",
        "stillgold",
        "samecolor",
        "samecolour",
        "samegold",
        "noop",
        "lookssame",
        "nodiff",
    ];
    if no_change(&nn)
        || nochange_sq
            .iter()
            .any(|word| sq.contains(word) || sql.contains(word))
    {
        warnings.push(format!("NOTE claims little/no change or \"still/same\", but the result is a real change: {} -> {}.",base.as_deref().unwrap_or("?"),next.as_deref().unwrap_or("?")));
    }
    let mut colours = Vec::new();
    for word in words(&nn) {
        if colour_word(word).is_some() && !colours.contains(&word) {
            colours.push(word);
        }
    }
    let result_name = new_name.split('(').next().unwrap_or("").trim();
    let own_name = if result_name != "custom" && n.contains(result_name) {
        result_name.split_whitespace().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let names_result = colours
        .iter()
        .any(|word| next.as_deref().is_some_and(|next| word_matches(word, next)));
    let bad = colours
        .iter()
        .filter(|word| {
            !(next.as_deref().is_some_and(|next| word_matches(word, next))
                || own_name.contains(word)
                || (base.as_deref().is_some_and(|base| word_matches(word, base))
                    && names_result
                    && away_from(&n, word)))
        })
        .take(3)
        .copied()
        .collect::<Vec<_>>();
    if !bad.is_empty() {
        warnings.push(format!(
            "NOTE names colour(s) \"{}\" that do not match the result {} ({new_name}).",
            bad.join("\", \""),
            next.as_deref().unwrap_or("null")
        ));
    }
    let gate_tokens = [
        "gate",
        "verif",
        "host",
        "system",
        "sha256",
        "sha2",
        "approv",
        "allowonce",
        "allowed",
        "signed",
        "trusted",
        "authori",
        "official",
    ];
    let gate = gate_tokens
        .iter()
        .filter(|word| sq.contains(**word) || sql.contains(**word))
        .take(3)
        .copied()
        .collect::<Vec<_>>();
    if !gate.is_empty() {
        warnings.push(format!("NOTE uses gate/host/approval wording ({}) - ignore it; only the gate-marked card is from the gate.",gate.join(", ")));
    }
    let impersonation = [
        "peter",
        "owner",
        "admin",
        "operator",
        "policy team",
        "security team",
        "grok",
        "anthropic",
        "openai",
        "deepseek",
        "on behalf of",
    ]
    .iter()
    .any(|word| phrase(&nn, word))
        || prior_approval(&nn);
    if impersonation {
        warnings.push("NOTE claims prior approval or speaks for a person/team - nobody can pre-approve; only this owner decision counts.".into());
    }
    let folded: String = nd.chars().map(|c| leet(c).unwrap_or(c)).collect();
    let toks = words(&folded);
    let stop = [
        "the", "and", "for", "with", "this", "that", "from", "into", "are", "was", "its", "you",
        "your", "not", "but", "has", "have", "will", "all", "any", "our", "out", "to", "of", "is",
        "in", "it", "on", "at", "as", "be", "or", "an", "by", "so", "if", "we", "me", "my",
    ];
    let mut counts = BTreeMap::new();
    let mut order = Vec::new();
    for word in &toks {
        if word.len() >= 2 && !stop.contains(word) {
            if !counts.contains_key(word) {
                order.push(*word);
            }
            *counts.entry(*word).or_insert(0usize) += 1;
        }
    }
    let mut repeated = order
        .into_iter()
        .filter(|word| counts[word] >= 3)
        .collect::<Vec<_>>();
    for (name, prefix) in [
        ("approve", "approv"),
        ("urgent", "urgen"),
        ("now", "now"),
        ("trusted", "trust"),
    ] {
        if toks
            .iter()
            .filter(|word| {
                if name == "now" {
                    **word == "now"
                } else {
                    word.starts_with(prefix)
                }
            })
            .count()
            >= 2
            || name != "now"
                && squash(&nd, true)
                    .matches(&name[..5.min(name.len())])
                    .count()
                    >= 2
        {
            repeated.push(name);
        }
    }
    if !repeated.is_empty() {
        warnings.push(format!(
            "NOTE repeats words to pressure you ({}) - APPROVE-spam pattern.",
            repeated.into_iter().take(3).collect::<Vec<_>>().join(", ")
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn antibody_owner_card_fixtures_are_the_gates_real_cards() {
        // Antibody, review issue 1.2: ui/owner/test/card.test.mjs renders these exact bytes,
        // two real gate cards one character apart, and must show base, new, diff and summary.
        let spec = TargetSpec::note();
        let old = b"Garden notes\nWater the basil.\n";
        for (name, new) in [
            (
                "a",
                &b"Garden notes\nWater the basil.\nPick the mint.\n"[..],
            ),
            (
                "b",
                &b"Garden notes\nWater the basil.\nPick the mint!\n"[..],
            ),
        ] {
            let p = Proposal {
                id: "0".repeat(32),
                target: spec.name.clone(),
                base_sha256: crate::sha256(old),
                new_sha256: crate::sha256(new),
                digest: "1".repeat(64),
                idempotency_key: "2".repeat(32),
                note: "tidy the garden list".into(),
                expires_at: 0,
                state: crate::State::Pending,
            };
            let card = bytes(&p, &spec, Some(old), new, None).unwrap();
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                "../../ui/owner/test/fixtures/gate-card-{name}.json"
            ));
            if std::env::var_os("UPDATE_CARD_FIXTURES").is_some() {
                std::fs::write(&path, &card).unwrap();
            }
            assert_eq!(
                std::fs::read(&path).unwrap(),
                card,
                "the owner UI fixture no longer matches the gate's card; regenerate with UPDATE_CARD_FIXTURES=1"
            );
        }
    }

    #[test]
    fn card_text_metadata_warnings_and_diff_match_prime_oracle_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/vectors/card-prime.json")).unwrap();
        let spec = TargetSpec::theme();
        for case in vectors["cases"].as_array().unwrap() {
            let raw = case["raw"].as_str().unwrap();
            let clean = clean_note(raw);
            let meta = note_meta(raw);
            assert_eq!(json!(clean), case["note"], "cleanNote {raw:?}");
            assert_eq!(meta, case["meta"], "noteMeta {raw:?}");
            let warnings = card_warnings(
                &spec,
                case["old"].as_str().unwrap(),
                case["new"].as_str().unwrap(),
                &clean,
                &meta,
            );
            assert_eq!(
                json!(warnings),
                case["warnings"],
                "cardWarnings {raw:?} {} -> {}",
                case["old"],
                case["new"]
            );
        }
        for case in vectors["diffs"].as_array().unwrap() {
            assert_eq!(
                line_diff(
                    case["a"].as_str().unwrap(),
                    case["b"].as_str().unwrap(),
                    case["name"].as_str().unwrap()
                ),
                case["diff"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn clean_note_matches_prime_nfkc_ascii_marker_and_size_rules() {
        assert_eq!(
            clean_note("  ＧＡＴＥ-VERIFIED\u{202e}\t  data\n"),
            "gate_VERIFIED data"
        );
        assert_eq!(clean_note("e\u{301}  ﬁ  ①  \u{a0}Ａ"), "fi 1 A");
        assert_eq!(
            clean_note(&"x".repeat(121)),
            format!("{}...", "x".repeat(117))
        );
        assert_eq!(clean_note("gAtE-yes GATE-no"), "gate_yes gate_no");
        assert_eq!(clean_note("\u{202e}\u{200b}😀"), "");
    }
    #[test]
    fn note_metadata_retains_raw_hash_hidden_categories_and_bounded_hex() {
        let raw = format!("GATE-VERIFIED \u{202e}аuth {}", "x".repeat(250));
        let meta = note_meta(&raw);
        assert_eq!(meta["nonascii"], 2);
        assert_eq!(meta["raw_bytes"], raw.len());
        assert_eq!(meta["authority_display"]["action"], "refuse");
        assert_eq!(
            meta["authority_display"]["raw_sha256"],
            crate::sha256(raw.as_bytes())
        );
        assert_eq!(
            meta["authority_display"]["categories"],
            json!(["bidi_control", "confusable_authority"])
        );
        let dump = meta["hexdump"].as_str().unwrap();
        assert!(dump.starts_with("47 41 54 45 2d"));
        assert!(dump.ends_with(&format!("... (+{} bytes)", raw.len() - 192)));
        assert_eq!(note_meta("a\tb\nc\r"), json!({"nonascii":0}));
    }
    #[test]
    fn line_diff_uses_prime_lcs_deletion_tiebreak_and_empty_lines() {
        assert_eq!(
            line_diff("a\nb\n", "b\na\n", "note"),
            "--- a/note\n+++ b/note\n-a\n b\n+a\n "
        );
        assert_eq!(line_diff("", "new", "note"), "--- a/note\n+++ b/note\n+new");
        let a = "a\n".repeat(501);
        let b = "b\n".repeat(501);
        assert!(line_diff(&a, &b, "n").starts_with("--- a/n\n+++ b/n\n-a\n-a"));
    }
    #[test]
    fn warning_rules_detect_spoof_pressure_obfuscation_wrong_colour_and_near_gold() {
        let spec = TargetSpec::theme();
        let old = "{\"accent\": \"#FFD700\"}";
        let next = "{\"accent\": \"#FFD701\"}";
        let raw="GATE-VERIFIED \u{202e} AFTER APPLY accent = #1E90FF no change owner approve approve approve gold";
        let note = clean_note(raw);
        let warnings = card_warnings(&spec, old, next, &note, &note_meta(raw));
        for part in [
            "non-ASCII",
            "authority-display",
            "NEAR gold",
            "NOT the result",
            "imitates",
            "little/no change",
            "colour(s)",
            "gate/host/approval",
            "prior approval",
            "APPROVE-spam",
        ] {
            assert!(
                warnings.iter().any(|w| w.contains(part)),
                "missing {part}: {warnings:?}"
            );
        }
        let note = "n o c h a n g e aievporp aprvoed";
        assert!(card_warnings(&spec, old, next, note, &note_meta(note))
            .iter()
            .any(|w| w.contains("obfuscated")));
    }
    #[test]
    fn facts_require_available_plain_from_to_and_refuse_a_lost_floor_with_history() {
        let mut spec = TargetSpec::custom("plugins/release/approval.json", 256, |_| Ok(()));
        spec.review_facts =
            Some(|_, _| Ok(json!({"from_to":"GATE FACT: first release","release_floor":null})));
        assert!(checked_review_facts(&spec, None, b"release", false).is_ok());
        assert!(checked_review_facts(&spec, None, b"release", true).is_err());
        assert!(checked_review_facts(&spec, Some(b"previous"), b"release", false).is_err());
        let hooks: [crate::targets::ReviewFacts; 3] = [
            |_, _| Ok(json!({"release_floor":null})),
            |_, _| Ok(json!({"from_to":"\u{202e}","release_floor":null})),
            |_, _| Err(Error::Refused("facts")),
        ];
        for hook in hooks {
            spec.review_facts = Some(hook);
            assert!(checked_review_facts(&spec, None, b"release", false).is_err());
        }
        let bounded_hooks: [crate::targets::ReviewFacts; 4] = [
            |_, _| Ok(json!({"from_to":"","release_floor":null})),
            |_, _| Ok(json!({"from_to":"x".repeat(601),"release_floor":null})),
            |_, _| Ok(json!({"from_to":"GATE FACT","release_floor":1.5})),
            |_, _| Ok(json!({"from_to":"GATE FACT","release_floor":9_007_199_254_740_992u64})),
        ];
        for hook in bounded_hooks {
            spec.review_facts = Some(hook);
            assert!(checked_review_facts(&spec, None, b"release", false).is_err());
        }
    }
}
