// SPDX-License-Identifier: AGPL-3.0-or-later
//! Phrase data and owner-browser contracts. Secret-bearing APIs exist only on wasm32.

/// Seven words: one six-letter anchor and six themed acrostic words.
pub const WORD_COUNT: usize = 7;
/// Bound on the entered UTF-8 phrase before normalization.
pub const MAX_PHRASE_BYTES: usize = 1_024;

/// A position's vocabulary, without any entered phrase text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhraseTheme {
    /// Nature vocabulary for positions two and three.
    Root,
    /// People and connection vocabulary for positions four and five.
    Unite,
    /// Spirit, space and technology vocabulary for positions six and seven.
    Rise,
}

/// The six acrostic positions after the anchor.
pub const SLOT_THEMES: [PhraseTheme; 6] = [
    PhraseTheme::Root,
    PhraseTheme::Root,
    PhraseTheme::Unite,
    PhraseTheme::Unite,
    PhraseTheme::Rise,
    PhraseTheme::Rise,
];

/// Display statistics of the shipped lists, not an authorization criterion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PhraseEntropy {
    /// Minimum entropy, rounded to the pinned display precision.
    pub minimum_bits: f64,
    /// Average entropy, rounded to the pinned display precision.
    pub average_bits: f64,
    /// Number of uniformly selected current anchors.
    pub anchor_count: usize,
}

/// Pinned list statistics; no 64-bit or 77-bit claim applies to this vocabulary.
pub const SHIPPED_ENTROPY: PhraseEntropy = PhraseEntropy {
    minimum_bits: 41.5,
    average_bits: 43.1,
    anchor_count: 92,
};

/// Owner-browser-only entry points; the native node has no phrase-taking function.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use canon::{Refusal, Result};
    use icu_normalizer::ComposingNormalizer;
    use js_sys::{Object, Reflect};
    use std::sync::OnceLock;
    use wasm_bindgen::JsValue;
    use zeroize::Zeroizing;

    /// Current generation lists, retained as pinned data.
    pub const ROOT_WORDS: &str = include_str!("../data/ROOT.txt");
    /// Current generation lists, retained as pinned data.
    pub const UNITE_WORDS: &str = include_str!("../data/UNITE.txt");
    /// Current generation lists, retained as pinned data.
    pub const RISE_WORDS: &str = include_str!("../data/RISE.txt");
    /// Current six-letter anchors; legacy lists are not a draw source.
    pub const ANCHORS: &str = include_str!("../data/ANCHORS.txt");

    const LEGACY_ANCHORS: &str = include_str!("../data/legacy/ANCHORS.txt");
    const LEGACY_WORDS: [&str; 3] = [
        include_str!("../data/legacy/ROOT.txt"),
        include_str!("../data/legacy/UNITE.txt"),
        include_str!("../data/legacy/RISE.txt"),
    ];
    const CURRENT_WORDS: [&str; 3] = [ROOT_WORDS, UNITE_WORDS, RISE_WORDS];
    const THEMES: [usize; 6] = [0, 0, 1, 1, 2, 2];

    fn refusal(reason: &'static str) -> Refusal {
        Refusal {
            organ: "aumlok",
            reason,
        }
    }

    struct Vocabulary {
        anchors: Vec<&'static str>,
        current: [Vec<&'static str>; 3],
        legacy: [Vec<&'static str>; 3],
        legacy_anchors: Vec<&'static str>,
    }

    fn vocabulary() -> &'static Vocabulary {
        static DATA: OnceLock<Vocabulary> = OnceLock::new();
        DATA.get_or_init(|| Vocabulary {
            anchors: ANCHORS.lines().collect(),
            current: CURRENT_WORDS.map(|text| text.lines().collect()),
            legacy: LEGACY_WORDS.map(|text| text.lines().collect()),
            legacy_anchors: LEGACY_ANCHORS.lines().collect(),
        })
    }

    fn assigned_in_unicode_13(scalar: char) -> bool {
        static RANGES: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
        let ranges = RANGES.get_or_init(|| {
            include_str!("../data/unicode-13-assigned-ranges.txt")
                .lines()
                .filter_map(|line| {
                    let (start, end) = line.split_once(' ')?;
                    Some((
                        u32::from_str_radix(start, 16).ok()?,
                        u32::from_str_radix(end, 16).ok()?,
                    ))
                })
                .collect()
        });
        let value = u32::from(scalar);
        let end = ranges.partition_point(|&(start, _)| start <= value);
        end > 0 && value <= ranges[end - 1].1
    }

    fn uniform_index(count: usize) -> Result<usize> {
        let bound = u32::try_from(count).map_err(|_| refusal("empty-bucket"))?;
        if bound == 0 {
            return Err(refusal("empty-bucket"));
        }
        let cutoff = bound.wrapping_neg() % bound;
        loop {
            let mut random = [0; 4];
            getrandom::fill(&mut random).map_err(|_| refusal("random-unavailable"))?;
            let value = u32::from_le_bytes(random);
            if value >= cutoff {
                return Ok((value % bound) as usize);
            }
        }
    }

    /// Browser location and its sole ancestor must match the configured origins.
    pub struct OwnerBrowser {
        owner_origin: String,
        shell_origin: String,
    }

    impl OwnerBrowser {
        /// Accept only a direct owner frame beneath the configured HTTPS shell.
        pub fn verify(expected_owner: &str, expected_shell: &str) -> Result<Self> {
            for origin in [expected_owner, expected_shell] {
                let parsed = url::Url::parse(origin).map_err(|_| refusal("owner-origin"))?;
                if parsed.scheme() != "https" || parsed.origin().ascii_serialization() != origin {
                    return Err(refusal("owner-origin"));
                }
            }
            if expected_owner == expected_shell {
                return Err(refusal("owner-origin"));
            }
            let window = web_sys::window().ok_or_else(|| refusal("owner-origin"))?;
            let location = window.location();
            if location.origin().map_err(|_| refusal("owner-origin"))? != expected_owner {
                return Err(refusal("owner-origin"));
            }
            let parent = window
                .parent()
                .map_err(|_| refusal("owner-frame"))?
                .ok_or_else(|| refusal("owner-frame"))?;
            let top = window
                .top()
                .map_err(|_| refusal("owner-frame"))?
                .ok_or_else(|| refusal("owner-frame"))?;
            if Object::is(parent.as_ref(), window.as_ref())
                || !Object::is(parent.as_ref(), top.as_ref())
            {
                return Err(refusal("owner-frame"));
            }
            let ancestors = Reflect::get(location.as_ref(), &JsValue::from_str("ancestorOrigins"))
                .map_err(|_| refusal("owner-frame"))?;
            let length = Reflect::get(&ancestors, &JsValue::from_str("length"))
                .map_err(|_| refusal("owner-frame"))?;
            let shell = Reflect::get(&ancestors, &JsValue::from_str("0"))
                .map_err(|_| refusal("owner-frame"))?;
            if length.as_f64() != Some(1.0) || shell.as_string().as_deref() != Some(expected_shell)
            {
                return Err(refusal("owner-frame"));
            }
            Ok(Self {
                owner_origin: expected_owner.to_owned(),
                shell_origin: expected_shell.to_owned(),
            })
        }

        /// Borrow the verified owner origin; unavailable before verification.
        pub fn owner_origin(&self) -> &str {
            &self.owner_origin
        }

        /// Borrow the verified shell origin; unavailable before verification.
        pub fn shell_origin(&self) -> &str {
            &self.shell_origin
        }
    }

    /// Phrase plaintext has no Debug, Display, Serialize or native-node API.
    pub struct OwnerPhrase(Zeroizing<String>);

    impl OwnerPhrase {
        /// The parsing contract is NFKC, lowercase,
        /// whitespace normalization, seven words, membership and acrostic checks.
        /// Current and legacy vocabularies are accepted only for typed recovery.
        pub fn parse(browser: &OwnerBrowser, entered: &str) -> Result<Self> {
            OwnerBrowser::verify(browser.owner_origin(), browser.shell_origin())?;
            if entered.len() > super::MAX_PHRASE_BYTES {
                return Err(refusal("phrase-too-long"));
            }
            // Later compatibility characters cannot acquire an older word spelling.
            if !entered.chars().all(assigned_in_unicode_13) {
                return Err(refusal("phrase-membership"));
            }
            let compatible = Zeroizing::new(
                ComposingNormalizer::new_nfkc()
                    .normalize(entered)
                    .into_owned(),
            );
            let lower = Zeroizing::new(compatible.to_lowercase());
            let words: Vec<&str> = lower.split_whitespace().collect();
            if words.len() != super::WORD_COUNT {
                return Err(refusal("phrase-word-count"));
            }
            let data = vocabulary();
            let anchor = words[0];
            if data.anchors.binary_search(&anchor).is_err()
                && data.legacy_anchors.binary_search(&anchor).is_err()
            {
                return Err(refusal("phrase-anchor"));
            }
            for (position, theme) in THEMES.into_iter().enumerate() {
                let word = words[position + 1];
                if data.current[theme].binary_search(&word).is_err()
                    && data.legacy[theme].binary_search(&word).is_err()
                {
                    return Err(refusal("phrase-membership"));
                }
                if word.as_bytes().first() != anchor.as_bytes().get(position) {
                    return Err(refusal("phrase-acrostic"));
                }
            }
            Ok(Self(Zeroizing::new(words.join(" "))))
        }

        /// Generation uses unbiased independent selection
        /// from current anchors and their six current theme/letter buckets.
        pub fn draw(browser: &OwnerBrowser) -> Result<Self> {
            OwnerBrowser::verify(browser.owner_origin(), browser.shell_origin())?;
            let data = vocabulary();
            let anchor = data.anchors[uniform_index(data.anchors.len())?];
            let mut phrase = Zeroizing::new(String::from(anchor));
            for (position, theme) in THEMES.into_iter().enumerate() {
                let bucket: Vec<&str> = data.current[theme]
                    .iter()
                    .copied()
                    .filter(|word| word.as_bytes().first() == anchor.as_bytes().get(position))
                    .collect();
                let word = bucket[uniform_index(bucket.len())?];
                phrase.push(' ');
                phrase.push_str(word);
            }
            Ok(Self(phrase))
        }

        /// Explicit plaintext access for the owner screen and local KDF only.
        pub fn expose<'a>(&'a self, _browser: &OwnerBrowser) -> &'a str {
            self.0.as_str()
        }
    }
}
