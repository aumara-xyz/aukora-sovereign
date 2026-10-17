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

/// The text with whitespace of every kind collapsed to one space, hyphen lookalikes made `-`, lookalike Latin letters
/// from Cyrillic, Greek and the fullwidth forms made ASCII, and ASCII letters lowercased.
pub(crate) fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_space = false;
    for c in text.chars() {
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
}
