use icu_normalizer::ComposingNormalizer;

pub(crate) fn normalize(input: &str) -> String {
    ComposingNormalizer::new_nfkc()
        .normalize(input)
        .to_lowercase()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::normalize;
    use sha2::{Digest, Sha256};

    #[test]
    fn compatibility_and_canonical_normalization() {
        for (input, expected) in [
            ("ＦＯＲＥＳＴ", "forest"),
            ("ﬀ ﬁ ﬂ ﬃ ﬄ", "ff fi fl ffi ffl"),
            ("\u{1d538}", "a"),
            ("\u{212b}", "å"),
            ("e\u{0301}", "é"),
            ("a\u{0301}\u{0323}", "ạ\u{0301}"),
            ("A\u{0305}\u{0301}", "a\u{0305}\u{0301}"),
            ("\u{09a1}\u{09bc}", "\u{09a1}\u{09bc}"),
            ("\u{1100}\u{1161}\u{11a8}", "각"),
            ("\u{ff76}\u{ff9e}", "ガ"),
        ] {
            assert_eq!(normalize(input), expected, "{input:?}");
        }
    }

    #[test]
    fn lowercases_after_nfkc_with_context_and_expansion() {
        assert_eq!(normalize("FOREST"), "forest");
        assert_eq!(normalize("\u{1d538}"), "a");
        assert_eq!(normalize("ΟΣ"), "ος");
        assert_eq!(normalize("İ"), "i\u{0307}");
    }

    #[test]
    fn trims_after_nfkc_and_preserves_internal_characters() {
        assert_eq!(normalize("\t\u{3000}FOREST\u{00a0}\r\n"), "forest");
        assert_eq!(normalize("\u{00a8}A"), "\u{0308}a");
        assert_eq!(normalize("forest  river"), "forest  river");
        assert_eq!(normalize("fore\u{200b}st"), "fore\u{200b}st");
        assert_eq!(normalize("fоrest"), "fоrest");
    }

    #[test]
    fn every_unicode_13_assigned_scalar_matches_python_oracle() {
        let mut digest = Sha256::new();
        let mut count = 0;
        for range in include_str!("../data/unicode-13-assigned-ranges.txt").lines() {
            let mut bounds = range.split_whitespace();
            let start = u32::from_str_radix(bounds.next().unwrap(), 16).unwrap();
            let end = u32::from_str_radix(bounds.next().unwrap(), 16).unwrap();
            assert!(bounds.next().is_none());
            for scalar in start..=end {
                let normalized = normalize(&char::from_u32(scalar).unwrap().to_string());
                digest.update(scalar.to_be_bytes());
                digest.update(u32::try_from(normalized.len()).unwrap().to_be_bytes());
                digest.update(normalized.as_bytes());
                count += 1;
            }
        }
        assert_eq!(count, 281_392);
        assert_eq!(
            hex::encode(digest.finalize()),
            "ea88d0ef7ad48857ffebd85377fe2a3b2e57638707d3f9a593a28c25c20d3f55"
        );
    }
}
