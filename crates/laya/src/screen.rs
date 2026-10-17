// SPDX-License-Identifier: AGPL-3.0-or-later
//! Text screening for triage: characters that make a note read differently than it is stored, and the folding that
//! lets the phrase rules see through lookalike letters. Ordinary text (em-dashes, accents, CJK) never trips it.

/// Characters that are invisible, reorder or hide text, or carry no agreed meaning in a note.
pub(crate) fn is_deceptive(c: char) -> bool {
    matches!(
        u32::from(c),
        // C1 controls.
        0x0080..=0x009F
        // Default_Ignorable_Code_Point (soft hyphen, combining grapheme joiner, Arabic letter mark, Hangul fillers,
        // Khmer inherent vowels, Mongolian selectors, zero-width and direction marks and overrides, invisible
        // operators and deprecated format characters, variation selectors, BOM, halfwidth Hangul filler, specials,
        // shorthand and musical format controls, tag characters and the variation selectors supplement).
        | 0x00AD | 0x034F | 0x061C | 0x115F..=0x1160 | 0x17B4..=0x17B5 | 0x180B..=0x180F
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0
        | 0xFFF0..=0xFFF8 | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0000..=0xE0FFF
        // Line and paragraph separators, interlinear annotation.
        | 0x2028 | 0x2029 | 0xFFF9..=0xFFFB
        // Private use (BMP and planes 15 and 16).
        | 0xE000..=0xF8FF | 0xF0000..=0x10FFFF
        // Noncharacters.
        | 0xFDD0..=0xFDEF
    ) || (u32::from(c) & 0xFFFE) == 0xFFFE
}

/// The text read the way a person reads it: compatibility forms made plain (NFKD: ligatures, circled, superscript and
/// fullwidth letters, no-break and other odd spaces), combining marks dropped (a mark on a letter, however many,
/// cannot hide a word: "ignore\u{301} previous"), whitespace of every kind collapsed to one space, hyphen lookalikes
/// made `-`, lookalike Latin letters from Cyrillic and Greek made ASCII, and ASCII letters lowercased.
pub(crate) fn fold(text: &str) -> String {
    let decomposed = icu_normalizer::DecomposingNormalizerBorrowed::new_nfkd().normalize(text);
    let mut out = String::with_capacity(decomposed.len());
    let mut in_space = false;
    for c in decomposed.chars() {
        if is_combining_mark(c) {
            continue;
        }
        if c.is_whitespace() {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
            continue;
        }
        in_space = false;
        out.push(lookalike(c).to_ascii_lowercase());
    }
    out
}

/// Combining marks (general category M) of the blocks that sit on Latin, Cyrillic and Greek letters.
fn is_combining_mark(c: char) -> bool {
    matches!(u32::from(c), 0x0300..=0x036F | 0x0483..=0x0489 | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// The run of whitespace, ASCII or not, that pads a note so its real words scroll out of view.
pub(crate) fn has_whitespace_padding(text: &str) -> bool {
    let mut run = 0_u8;
    for c in text.chars() {
        if c.is_whitespace() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn lookalike(c: char) -> char {
    match c {
        // Hyphen and minus lookalikes.
        '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{FE63}' | '\u{FF0D}' => '-',
        // Cyrillic.
        'а' | 'А' => 'a',
        'В' => 'b',
        'с' | 'С' => 'c',
        'ԁ' => 'd',
        'е' | 'Е' => 'e',
        'Н' => 'h',
        'һ' => 'h',
        'і' | 'І' | 'Ӏ' | 'ı' => 'i',
        'ј' | 'Ј' => 'j',
        'к' | 'К' => 'k',
        'ӏ' => 'l',
        'М' => 'm',
        'о' | 'О' => 'o',
        'р' | 'Р' => 'p',
        'ԛ' => 'q',
        'ѕ' | 'Ѕ' => 's',
        'Т' => 't',
        'у' | 'У' => 'y',
        'х' | 'Х' => 'x',
        'ԝ' => 'w',
        // Greek.
        'α' | 'Α' => 'a',
        'Β' => 'b',
        'ϲ' => 'c',
        'ε' | 'Ε' => 'e',
        'Η' => 'h',
        'ι' | 'Ι' => 'i',
        'ϳ' => 'j',
        'κ' | 'Κ' => 'k',
        'Μ' => 'm',
        'ν' => 'v',
        'Ν' => 'n',
        'ο' | 'Ο' => 'o',
        'ρ' | 'Ρ' => 'p',
        'τ' | 'Τ' => 't',
        'υ' | 'Υ' => 'y',
        'χ' | 'Χ' => 'x',
        'Ζ' => 'z',
        // Fullwidth Latin letters.
        '\u{FF21}'..='\u{FF3A}' => ascii_offset(c, 0xFF21, b'A'),
        '\u{FF41}'..='\u{FF5A}' => ascii_offset(c, 0xFF41, b'a'),
        _ => c,
    }
}

fn ascii_offset(c: char, base: u32, ascii: u8) -> char {
    u32::from(c)
        .checked_sub(base)
        .and_then(|offset| u8::try_from(offset).ok())
        .and_then(|offset| ascii.checked_add(offset))
        .map_or(c, char::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_not_deceptive() {
        assert!("Phase 2 — clean seed, café, naïve, 日本語, ひらがな, 한국어, Привет, γειά, 👍"
            .chars()
            .all(|c| !is_deceptive(c)));
    }

    #[test]
    fn fold_sees_through_lookalikes_and_spacing() {
        assert_eq!(fold("Ignоre  prеvious"), "ignore previous");
        assert_eq!(fold("ＰＲＥ‐ａｐｐｒｏｖｅｄ"), "pre-approved");
    }

    #[test]
    fn fold_sees_through_combining_marks_compatibility_forms_and_odd_spaces() {
        // Combining marks on any letter, stacked or on a letter with no precomposed form, do not break a phrase.
        assert_eq!(fold("ignore\u{301} previous"), "ignore previous");
        assert_eq!(fold("i\u{300}g\u{301}n\u{302}o\u{303}r\u{304}e\u{305}\u{306} previous"), "ignore previous");
        assert_eq!(fold("ignor\u{0435}\u{0301} previous"), "ignore previous", "Cyrillic е with a mark");
        // Compatibility forms: ligatures, circled and superscript letters, no-break and ideographic spaces.
        assert_eq!(fold("ﬁrst"), "first");
        assert_eq!(fold("ⓘⓖⓝⓞⓡⓔ previous"), "ignore previous");
        assert_eq!(fold("ignore\u{00A0}\u{3000}previous"), "ignore previous");
        assert_eq!(fold("pre\u{2011}approved"), "pre-approved", "non-breaking hyphen");
        // Ordinary text keeps its letters (accents are only dropped for the match, never from the note).
        assert_eq!(fold("Café naïve"), "cafe naive");
    }
}
