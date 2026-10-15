//! Draw distribution: uniform anchor, then independent uniform theme buckets.
use std::fmt;
use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::normalization::normalize;

include!("entropy_constants.rs");

const ROOT: &str = include_str!("../data/ROOT.txt");
const UNITE: &str = include_str!("../data/UNITE.txt");
const RISE: &str = include_str!("../data/RISE.txt");
const ANCHORS: &str = include_str!("../data/ANCHORS.txt");
// Legacy (v1) lists: a phrase drawn from them still parses when typed; they are never drawn.
const LEGACY_ROOT: &str = include_str!("../data/legacy/ROOT.txt");
const LEGACY_UNITE: &str = include_str!("../data/legacy/UNITE.txt");
const LEGACY_RISE: &str = include_str!("../data/legacy/RISE.txt");
const LEGACY_ANCHORS: &str = include_str!("../data/legacy/ANCHORS.txt");
const SLOT_THEME: [usize; 6] = [0, 0, 1, 1, 2, 2];
const MAX_INPUT_BYTES: usize = 1024;

type Buckets = [Vec<&'static str>; 26];

struct Lists {
    anchors: Vec<&'static str>,
    words: [Vec<&'static str>; 3],
    buckets: [Buckets; 3],
    legacy_anchors: Vec<&'static str>,
    legacy_words: [Vec<&'static str>; 3],
}

fn lists() -> &'static Lists {
    static LISTS: OnceLock<Lists> = OnceLock::new();
    LISTS.get_or_init(|| {
        let words = [ROOT, UNITE, RISE].map(|text| text.lines().collect::<Vec<_>>());
        let buckets = std::array::from_fn(|theme| {
            std::array::from_fn(|letter| {
                words[theme]
                    .iter()
                    .copied()
                    .filter(|w| usize::from(w.as_bytes()[0] - b'a') == letter)
                    .collect()
            })
        });
        Lists {
            anchors: ANCHORS.lines().collect(),
            words,
            buckets,
            legacy_anchors: LEGACY_ANCHORS.lines().collect(),
            legacy_words: [LEGACY_ROOT, LEGACY_UNITE, LEGACY_RISE]
                .map(|text| text.lines().collect::<Vec<_>>()),
        }
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhraseError {
    InputTooLong,
    WordCount,
    Anchor,
    Membership,
    Acrostic,
    RandomUnavailable,
    EmptyBucket,
}

impl PhraseError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InputTooLong => "aumlok:phrase-too-long",
            Self::WordCount => "aumlok:phrase-word-count",
            Self::Anchor => "aumlok:phrase-anchor",
            Self::Membership => "aumlok:phrase-membership",
            Self::Acrostic => "aumlok:phrase-acrostic",
            Self::RandomUnavailable => "aumlok:random-unavailable",
            Self::EmptyBucket => "aumlok:empty-bucket",
        }
    }
}

impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PhraseError {}

#[derive(Eq, PartialEq)]
pub struct Phrase(Zeroizing<String>);

impl fmt::Debug for Phrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Phrase([REDACTED])")
    }
}

impl Phrase {
    pub fn parse(input: &str) -> Result<Self, PhraseError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(PhraseError::InputTooLong);
        }
        let normalized = Zeroizing::new(normalize(input));
        let words: Vec<_> = normalized.split_whitespace().collect();
        if words.len() != 7 {
            return Err(PhraseError::WordCount);
        }
        let data = lists();
        if data.anchors.binary_search(&words[0]).is_err()
            && data.legacy_anchors.binary_search(&words[0]).is_err()
        {
            return Err(PhraseError::Anchor);
        }
        for (slot, &theme) in SLOT_THEME.iter().enumerate() {
            let word = words[slot + 1];
            if data.words[theme].binary_search(&word).is_err()
                && data.legacy_words[theme].binary_search(&word).is_err()
            {
                return Err(PhraseError::Membership);
            }
            if word.as_bytes()[0] != words[0].as_bytes()[slot] {
                return Err(PhraseError::Acrostic);
            }
        }
        Ok(Self(Zeroizing::new(words.join(" "))))
    }

    pub fn draw() -> Result<Self, PhraseError> {
        draw_with(|bytes| getrandom::fill(bytes).map_err(|_| PhraseError::RandomUnavailable))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn draw_with(
    mut random: impl FnMut(&mut [u8]) -> Result<(), PhraseError>,
) -> Result<Phrase, PhraseError> {
    let data = lists();
    let anchor = data.anchors[uniform_index(data.anchors.len(), &mut random)?];
    let mut phrase = Zeroizing::new(String::from(anchor));
    for (slot, &theme) in SLOT_THEME.iter().enumerate() {
        let bucket = &data.buckets[theme][usize::from(anchor.as_bytes()[slot] - b'a')];
        let word = bucket[uniform_index(bucket.len(), &mut random)?];
        phrase.push(' ');
        phrase.push_str(word);
    }
    Ok(Phrase(phrase))
}

fn uniform_index(
    count: usize,
    random: &mut impl FnMut(&mut [u8]) -> Result<(), PhraseError>,
) -> Result<usize, PhraseError> {
    if count == 0 {
        return Err(PhraseError::EmptyBucket);
    }
    let count = count as u128;
    let range = 1_u128 << 64;
    let cutoff = range - range % count;
    loop {
        let mut bytes = [0; 8];
        random(&mut bytes)?;
        let value = u128::from(u64::from_le_bytes(bytes));
        if value < cutoff {
            return Ok((value % count) as usize);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Entropy {
    pub minimum_bits: f64,
    pub average_bits: f64,
    pub weakest_anchor: &'static str,
    pub maximum_probability_denominator: u128,
    pub anchor_count: usize,
}

pub fn entropy() -> Entropy {
    Entropy {
        minimum_bits: MIN_ENTROPY_BITS,
        average_bits: AVERAGE_ENTROPY_BITS,
        weakest_anchor: WEAKEST_ANCHOR,
        maximum_probability_denominator: MIN_PROBABILITY_DENOMINATOR,
        anchor_count: ANCHOR_COUNT,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn fixture() -> Vec<String> {
        let data = lists();
        let anchor = data.anchors[0];
        std::iter::once(anchor.to_owned())
            .chain([0, 0, 1, 1, 2, 2].iter().enumerate().map(|(slot, &theme)| {
                data.buckets[theme][usize::from(anchor.as_bytes()[slot] - b'a')][0].to_owned()
            }))
            .collect()
    }

    fn rejects(words: &[String], reason: PhraseError) {
        assert_eq!(Phrase::parse(&words.join(" ")).unwrap_err(), reason);
    }

    #[test]
    fn typed_phrase_requires_exact_anchor_membership_count_and_acrostic() {
        let original = fixture();
        assert!(Phrase::parse(&original.join(" ")).is_ok());
        rejects(&original[..6], PhraseError::WordCount);
        let mut words = original.clone();
        words.push("extra".into());
        rejects(&words, PhraseError::WordCount);
        words = original.clone();
        words[0] = "aaaaaa".into();
        for (slot, theme) in [0, 0, 1, 1, 2, 2].into_iter().enumerate() {
            words[slot + 1] = lists().buckets[theme][0][0].into();
        }
        rejects(&words, PhraseError::Anchor);
        words = original.clone();
        words[1] = format!("{}invented", &words[0][..1]);
        rejects(&words, PhraseError::Membership);
        for (slot, &theme) in [0, 0, 1, 1, 2, 2].iter().enumerate() {
            words = original.clone();
            let letter = words[0].as_bytes()[slot];
            words[slot + 1] = lists().words[theme]
                .iter()
                .find(|w| w.as_bytes()[0] != letter)
                .unwrap()
                .to_string();
            rejects(&words, PhraseError::Acrostic);
            words = original.clone();
            let wrong = (0..3)
                .filter(|&other| other != theme)
                .flat_map(|other| lists().buckets[other][usize::from(letter - b'a')].iter())
                .find(|w| {
                    lists().words[theme].binary_search(w).is_err()
                        && lists().legacy_words[theme].binary_search(w).is_err()
                })
                .unwrap();
            words[slot + 1] = wrong.to_string();
            rejects(&words, PhraseError::Membership);
        }
        assert_eq!(
            Phrase::parse(&" ".repeat(1025)).unwrap_err(),
            PhraseError::InputTooLong
        );
    }

    #[test]
    fn typed_normalization_is_nfkc_lowercase_trim_and_canonical_spacing() {
        let text = fixture().join(" ");
        let fullwidth: String = text
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    char::from_u32(c as u32 - u32::from(b'a') + 0xff21).unwrap()
                } else {
                    '\u{3000}'
                }
            })
            .collect();
        assert_eq!(
            Phrase::parse(&format!("\u{2002}{fullwidth}\u{2002}"))
                .unwrap()
                .as_str(),
            text
        );
        assert_eq!(
            Phrase::parse(&text.replace(' ', "\t\n")).unwrap().as_str(),
            text
        );
        assert!(Phrase::parse(&text.replacen('a', "\u{0430}", 1)).is_err());
        assert!(Phrase::parse(&format!("{text}\u{200b}")).is_err());
        assert_eq!(
            format!("{:?}", Phrase::parse(&text).unwrap()),
            "Phrase([REDACTED])"
        );
    }

    #[test]
    fn draw_is_uniform_per_anchor_and_slot_without_modulo_bias() {
        let mut calls = 0;
        let selected = uniform_index(3, &mut |bytes| {
            bytes.copy_from_slice(&(if calls == 0 { u64::MAX } else { 1 }).to_le_bytes());
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(selected, 1);
        assert_eq!(
            uniform_index(4, &mut |bytes| {
                bytes.copy_from_slice(&u64::MAX.to_le_bytes());
                Ok(())
            })
            .unwrap(),
            3
        );
        assert_eq!(
            uniform_index(0, &mut |_| Ok(())).unwrap_err(),
            PhraseError::EmptyBucket
        );
        assert_eq!(
            Phrase::draw_with_failure().unwrap_err(),
            PhraseError::RandomUnavailable
        );
        for index in 0..lists().anchors.len() {
            let mut draws = 0;
            let phrase = draw_with(|bytes| {
                let value = if draws == 0 {
                    index as u64
                } else {
                    (draws * 7) as u64
                };
                bytes.copy_from_slice(&value.to_le_bytes());
                draws += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(draws, 7);
            let words: Vec<_> = phrase.as_str().split(' ').collect();
            assert_eq!(words[0], lists().anchors[index]);
            for (slot, &theme) in [0, 0, 1, 1, 2, 2].iter().enumerate() {
                let bucket = &lists().buckets[theme][usize::from(words[0].as_bytes()[slot] - b'a')];
                assert_eq!(words[slot + 1], bucket[((slot + 1) * 7) % bucket.len()]);
            }
            assert!(Phrase::parse(phrase.as_str()).is_ok());
        }
        for _ in 0..100 {
            let phrase = Phrase::draw().unwrap();
            assert!(Phrase::parse(phrase.as_str()).is_ok());
        }
    }

    impl Phrase {
        fn draw_with_failure() -> Result<Self, PhraseError> {
            draw_with(|_| Err(PhraseError::RandomUnavailable))
        }
    }

    fn source_words<'a>(snapshot: &'a serde_json::Value, name: &str) -> BTreeSet<&'a str> {
        snapshot["words"][name]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect()
    }

    fn source_candidates(snapshot: &serde_json::Value) -> ([BTreeSet<&str>; 3], BTreeSet<&str>) {
        let names = [
            "theme-nature.json",
            "theme-people.json",
            "theme-spirit.json",
        ];
        let denied: BTreeSet<_> = [
            "safety/profanity-block.json",
            "safety/ldnoobw-en.txt",
            "safety/proper-names.json",
            "safety/category-drop.json",
            "safety/pleasant-drop.json",
        ]
        .into_iter()
        .flat_map(|name| source_words(snapshot, name))
        .collect();
        let safe = |w: &&str| {
            (3..=12).contains(&w.len())
                && w.bytes().all(|c| c.is_ascii_lowercase())
                && !denied.contains(w)
        };
        let seeds: Vec<_> = include_str!("../data/legacy/RISE-SPACE-TECH-SEEDS.txt")
            .lines()
            .map(|line| line.split('#').next().unwrap().trim())
            .filter(|line| !line.is_empty())
            .collect();
        assert!(seeds
            .iter()
            .all(|s| s.bytes().all(|c| c.is_ascii_lowercase())));
        assert_eq!(
            seeds.iter().copied().collect::<BTreeSet<_>>().len(),
            seeds.len()
        );
        let extra: BTreeSet<_> = source_words(snapshot, "safety/eff_large_words.txt")
            .into_iter()
            .filter(|w| seeds.iter().any(|root| w.starts_with(root)))
            .collect();
        let mut raw = names.map(|name| source_words(snapshot, name));
        raw[2].extend(extra);
        let anchors = raw
            .iter()
            .flat_map(|ws| ws.iter().copied())
            .chain(source_words(snapshot, "aumlok-anchors.json"))
            .filter(safe)
            .filter(|w| w.len() == 6)
            .collect();
        let candidates = raw.map(|ws| ws.into_iter().filter(safe).collect());
        (candidates, anchors)
    }

    fn prefix_leaves<'a>(words: &BTreeSet<&'a str>) -> BTreeSet<&'a str> {
        let sorted: Vec<_> = words.iter().copied().collect();
        sorted
            .iter()
            .enumerate()
            .filter(|(index, word)| {
                sorted
                    .get(index + 1)
                    .is_none_or(|next| !next.starts_with(**word))
            })
            .map(|(_, &word)| word)
            .collect()
    }

    #[test]
    fn legacy_lists_are_maximal_sorted_ascii_and_apply_every_source_filter() {
        let snapshot: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/legacy/sources.json")).unwrap();
        assert_eq!(
            snapshot
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["sha256", "words"])
        );
        let (candidates, _) = source_candidates(&snapshot);
        for (theme, actual) in lists().legacy_words.iter().enumerate() {
            assert!(actual.windows(2).all(|w| w[0] < w[1]));
            let expected = prefix_leaves(&candidates[theme]);
            assert_eq!(actual.iter().copied().collect::<BTreeSet<_>>(), expected);
        }
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/legacy/entropy.json")).unwrap();
        let anchors = &lists().legacy_anchors;
        assert!(anchors.windows(2).all(|w| w[0] < w[1]));
        assert!(anchors.iter().all(|a| a.len() == 6));
        assert_eq!(
            vector["anchor_count"].as_u64().unwrap() as usize,
            anchors.len()
        );
    }

    #[test]
    fn curated_lists_ship_unchanged_and_follow_the_review_rules() {
        let sources = [
            include_str!("../data/curated/ROOT.txt"),
            include_str!("../data/curated/UNITE.txt"),
            include_str!("../data/curated/RISE.txt"),
        ];
        for (theme, source) in sources.iter().enumerate() {
            let shipped = &lists().words[theme];
            assert_eq!(shipped, &source.lines().collect::<Vec<_>>());
            assert!(shipped.windows(2).all(|w| w[0] < w[1]));
            assert!(shipped
                .iter()
                .all(|w| (3..=12).contains(&w.len()) && w.bytes().all(|c| c.is_ascii_lowercase())));
            assert!(shipped.windows(2).all(|w| !w[1].starts_with(w[0])));
        }
        let candidates: BTreeSet<_> = include_str!("../data/curated/ANCHOR-CANDIDATES.txt")
            .lines()
            .collect();
        assert!(lists()
            .anchors
            .iter()
            .all(|a| candidates.contains(a) && a.len() == 6));
    }

    #[test]
    fn a_legacy_phrase_still_parses_and_draws_use_only_curated_words() {
        let data = lists();
        let anchor = data.legacy_anchors[0];
        let mut words = vec![anchor];
        for (slot, &theme) in SLOT_THEME.iter().enumerate() {
            let letter = anchor.as_bytes()[slot];
            words.push(
                data.legacy_words[theme]
                    .iter()
                    .find(|w| w.as_bytes()[0] == letter)
                    .unwrap(),
            );
        }
        assert!(Phrase::parse(&words.join(" ")).is_ok());
        for _ in 0..200 {
            let phrase = Phrase::draw().unwrap();
            let drawn: Vec<_> = phrase.as_str().split(' ').collect();
            assert!(data.anchors.binary_search(&drawn[0]).is_ok());
            for (slot, &theme) in SLOT_THEME.iter().enumerate() {
                assert!(data.words[theme].binary_search(&drawn[slot + 1]).is_ok());
            }
        }
    }

    #[test]
    fn anchor_threshold_maximizes_exact_minimum_entropy_over_every_integer() {
        let counts: [[usize; 26]; 3] = std::array::from_fn(|theme| {
            std::array::from_fn(|letter| lists().buckets[theme][letter].len())
        });
        // Products come from the curated candidates and buckets, without using the
        // shipped anchors to decide which candidates should survive.
        let candidates: Vec<_> = include_str!("../data/curated/ANCHOR-CANDIDATES.txt")
            .lines()
            .map(|anchor| {
                let slots: Vec<_> = SLOT_THEME
                    .iter()
                    .enumerate()
                    .map(|(slot, &theme)| {
                        counts[theme][usize::from(anchor.as_bytes()[slot] - b'a')]
                    })
                    .collect();
                let capacity = *slots.iter().min().unwrap();
                let product = slots.iter().map(|&count| count as u128).product::<u128>();
                (anchor, capacity, product)
            })
            .collect();
        let maximum = candidates
            .iter()
            .map(|(_, capacity, _)| *capacity)
            .max()
            .unwrap();
        assert!(maximum > 0);
        let mut best_denominator = 0;
        let mut best_count = 0;
        let mut best_threshold = 0;
        let mut best_anchors = BTreeSet::new();
        for threshold in 1..=maximum {
            let kept: Vec<_> = candidates
                .iter()
                .filter(|(_, capacity, _)| *capacity >= threshold)
                .collect();
            let minimum_product = kept.iter().map(|(_, _, product)| *product).min().unwrap();
            let denominator = kept.len() as u128 * minimum_product;
            if denominator > best_denominator
                || (denominator == best_denominator
                    && (kept.len() > best_count
                        || (kept.len() == best_count && threshold < best_threshold)))
            {
                best_denominator = denominator;
                best_count = kept.len();
                best_threshold = threshold;
                best_anchors = kept.iter().map(|(anchor, _, _)| *anchor).collect();
            }
        }
        assert_eq!(ANCHOR_THRESHOLD, best_threshold);
        assert_eq!(ANCHOR_COUNT, best_count);
        assert_eq!(MIN_PROBABILITY_DENOMINATOR, best_denominator);
        assert!(lists().anchors.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(
            lists().anchors.iter().copied().collect::<BTreeSet<_>>(),
            best_anchors
        );
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/entropy.json")).unwrap();
        assert_eq!(
            vector["anchor_threshold"].as_u64().unwrap() as usize,
            best_threshold
        );
        assert_eq!(
            vector["candidate_anchor_count"].as_u64().unwrap() as usize,
            candidates.len()
        );
    }

    #[test]
    fn exact_distribution_entropy_matches_shipped_constants() {
        let data = lists();
        assert_eq!(data.anchors.len(), ANCHOR_COUNT);
        let products: Vec<_> = data
            .anchors
            .iter()
            .map(|&a| {
                let product = SLOT_THEME
                    .iter()
                    .enumerate()
                    .map(|(slot, &theme)| {
                        data.buckets[theme][usize::from(a.as_bytes()[slot] - b'a')].len() as u128
                    })
                    .product::<u128>();
                (product, a)
            })
            .collect();
        let &(product, anchor) = products.iter().min().unwrap();
        assert_eq!(anchor, WEAKEST_ANCHOR);
        assert_eq!(product * ANCHOR_COUNT as u128, MIN_PROBABILITY_DENOMINATOR);
        let min = (MIN_PROBABILITY_DENOMINATOR as f64).log2();
        let avg = (ANCHOR_COUNT as f64).log2()
            + products
                .iter()
                .map(|(p, _)| (*p as f64).log2())
                .sum::<f64>()
                / ANCHOR_COUNT as f64;
        assert!((min - MIN_ENTROPY_BITS).abs() < 1e-12);
        assert!((avg - AVERAGE_ENTROPY_BITS).abs() < 1e-12);
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/entropy.json")).unwrap();
        assert_eq!(
            vector["min_entropy_bits"].as_str().unwrap(),
            MIN_ENTROPY_DISPLAY
        );
        assert_eq!(
            vector["average_entropy_bits"].as_str().unwrap(),
            AVERAGE_ENTROPY_DISPLAY
        );
        assert_eq!(entropy().weakest_anchor, WEAKEST_ANCHOR);
    }
}
