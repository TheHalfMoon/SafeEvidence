//! Structure-aware deterministic property suite for `safeevidence_contracts::bilingual`
//! (`ADR-0002`, `WP-06`, `TA-08`).

use safeevidence_contracts::bilingual::{
    NormalizedText, SpanProjectionError, extract_raw_scalar_span, is_arabic_ignorable_mark,
};

struct Prng(u64);

impl Prng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bounded(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }
}

#[test]
fn pure_ignorable_harakat_and_tatweel_slices_fail_closed_in_all_positions() {
    // Leading tatweel (0), base 'ب' (1), internal fatha+shadda (2..4), base 'ت' (4), trailing damma (5)
    let raw = "\u{0640}\u{0628}\u{064e}\u{0651}\u{062a}\u{064f}";
    let norm = NormalizedText::build(raw).expect("valid vocalized Arabic");
    assert_eq!(norm.raw_scalar_len(), 6);
    assert_eq!(norm.norm_scalar_len(), 2);

    // Pure-ignorable raw slices must fail closed (never claim to map to a base scalar):
    for (s, e) in [(0, 1), (2, 3), (2, 4), (5, 6)] {
        assert!(
            matches!(
                norm.project_raw_span_to_norm(s, e),
                Err(SpanProjectionError::OutOfBounds { .. })
            ),
            "pure-ignorable slice [{s}, {e}) must return OutOfBounds"
        );
    }

    // Full word and individual vocalized letters round-trip cleanly:
    assert_eq!(norm.project_raw_span_to_norm(0, 6), Ok((0, 2)));
    assert_eq!(norm.project_norm_span_to_raw(0, 2), Ok((0, 6)));
    assert_eq!(norm.project_raw_span_to_norm(0, 4), Ok((0, 1)));
    assert_eq!(norm.project_norm_span_to_raw(0, 1), Ok((0, 4)));
    assert_eq!(norm.project_raw_span_to_norm(4, 6), Ok((1, 2)));
    assert_eq!(norm.project_norm_span_to_raw(1, 2), Ok((4, 6)));
}

#[test]
fn property_1500_mixed_bilingual_vocalized_strings_preserve_exact_scalar_invariants() {
    const ALPHABET: &[char] = &[
        'A',
        'z',
        '4',
        ' ',
        '.',
        '?',
        '\u{0627}',
        '\u{0623}',
        '\u{0625}',
        '\u{0622}',
        '\u{0628}',
        '\u{0629}',
        '\u{0649}',
        '\u{064a}',
        '\u{06cc}',
        '\u{0640}',
        '\u{064b}',
        '\u{064e}',
        '\u{064f}',
        '\u{0650}',
        '\u{0651}',
        '\u{0652}',
        '\u{0670}',
        '\u{0664}',
        '\u{06f9}',
        '\u{061f}',
        '\u{00e9}',
        '\u{6771}',
        '\u{1f9ea}',
    ];
    const BIDI: &[char] = &[
        '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
        '\u{FEFF}',
    ];

    let mut rng = Prng::new(0xB111_60A1_2026_1127);

    for _ in 0..1_500 {
        let len = rng.bounded(40);
        let mut raw = String::new();
        for _ in 0..len {
            raw.push(ALPHABET[rng.bounded(ALPHABET.len())]);
        }

        // Injecting any forbidden BiDi control must always fail closed:
        if rng.bounded(6) == 0 {
            let mut poisoned: Vec<char> = raw.chars().collect();
            let pos = if poisoned.is_empty() {
                0
            } else {
                rng.bounded(poisoned.len())
            };
            let bidi_ch = BIDI[rng.bounded(BIDI.len())];
            poisoned.insert(pos, bidi_ch);
            let poisoned_str: String = poisoned.into_iter().collect();
            assert!(matches!(
                NormalizedText::build(&poisoned_str),
                Err(SpanProjectionError::BidiControlForbidden { .. })
            ));
        }

        let norm = NormalizedText::build(&raw).expect("clean bilingual string builds");
        let raw_chars: Vec<char> = raw.chars().collect();
        assert_eq!(norm.raw_scalar_len(), raw_chars.len());
        assert_eq!(norm.norm_scalar_len(), norm.as_str().chars().count());

        let m = norm.norm_scalar_len();
        if m == 0 {
            assert!(raw_chars.iter().all(|&c| is_arabic_ignorable_mark(c)));
            continue;
        }

        // Every normalized span [ns, ne) maps to a valid non-empty raw span containing >= 1 base char:
        let mut prev_end = 0_u64;
        for k in 0..m {
            let (rs, re) = norm.project_norm_span_to_raw(k, k + 1).unwrap();
            assert!(rs < re && re <= raw_chars.len() as u64);
            if k > 0 {
                assert!(
                    rs >= prev_end,
                    "norm_to_raw intervals must be disjoint and monotonic"
                );
            }
            prev_end = re;
            let sub = extract_raw_scalar_span(&raw, rs, re).unwrap();
            assert!(sub.chars().any(|c| !is_arabic_ignorable_mark(c)));
            assert_eq!(
                norm.project_raw_span_to_norm(rs as usize, re as usize),
                Ok((k, k + 1))
            );
        }

        // Random raw sub-spans: pure-ignorable slices fail closed; base-bearing slices succeed:
        for _ in 0..8 {
            let a = rng.bounded(raw_chars.len());
            let b = a + 1 + rng.bounded(raw_chars.len() - a);
            let has_base = raw_chars[a..b]
                .iter()
                .any(|&c| !is_arabic_ignorable_mark(c));
            let res = norm.project_raw_span_to_norm(a, b);
            if !has_base {
                assert!(res.is_err());
            } else {
                let (ns, ne) = res.unwrap();
                assert!(ns < ne && ne <= m);
                let (bs, be) = norm.project_norm_span_to_raw(ns, ne).unwrap();
                assert!(extract_raw_scalar_span(&raw, bs, be).is_ok());
            }
        }
    }
}
