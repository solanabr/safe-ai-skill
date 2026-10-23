//! BIP-39 seed-phrase detection, shared by output redaction ([`crate::redact`]) and the
//! prompt guard ([`crate::promptguard`]).
//!
//! A *token* is a maximal run of ASCII letters; a *list word* is a token in the BIP-39 English
//! list ([`crate::bip39`]), in any case. Tokens join into a run when the bytes between them
//! are a *joiner*: whitespace, `,` `"` `'` `[` `]`, and numbering (`12.` `3)` `4:`), at most
//! [`MAX_GAP`] bytes. Three kinds of run are tracked at once:
//!
//! - **list run**: list words only, joined by joiners;
//! - **phrase-shaped run**: tokens of 3 to 8 letters (list words, or lowercase non-list words),
//!   joined by joiners;
//! - **old-shape run** (the 1.0 rule): lowercase tokens of 3 to 8 letters separated by exactly
//!   one space.
//!
//! A span is a seed phrase when:
//!
//! - **bare (checksum)**: a list run of at most [`MAX_RUN`] words, or one line of it, has
//!   exactly 12/15/18/21/24 words and its checksum validates; or the run (or line) has at most
//!   [`WINDOW_SLACK`] extra words on each side of such a window (so at most 18 words) and the
//!   window has at least [`MIN_DISTINCT`] distinct words;
//! - **keyword**: a keyword ([`KEYWORDS`], whole word, optional plural, camelCase and `_` parts
//!   count) appears in the same string outside the run, and the run is a list run of 12 to
//!   [`MAX_RUN`] words, or a phrase-shaped run of 12 to [`MAX_RUN`] tokens with at most one in
//!   six off the list (typos), or an old-shape run of 12 or more words (whole up to
//!   [`MAX_RUN`]; past that its first 24 words, unless every word is a list word).
//!
//! A list run longer than [`MAX_RUN`] is a wordlist dump and is never a phrase. Work is linear
//! in the text plus at most [`MAX_CHECKSUM_TESTS`] checksums, and each tracker keeps at most
//! `MAX_RUN + 1` tokens.

use crate::bip39;

/// Longest run treated as a phrase candidate; longer list runs are wordlist dumps.
pub const MAX_RUN: usize = 48;
/// Extra list words allowed on each side of a checksum window.
pub const WINDOW_SLACK: usize = 3;
/// Distinct words a checksum window with extra words around it must have.
pub const MIN_DISTINCT: usize = 8;
/// Longest joiner between two words of a run, in bytes.
pub const MAX_GAP: usize = 16;
/// Checksum tests per text: enough for every 48-byte slice of the largest scanned payload.
pub const MAX_CHECKSUM_TESTS: usize = crate::redact::MAX_SCAN_BYTES / 48;
/// Words that make a nearby run a phrase without a checksum.
pub const KEYWORDS: [&str; 5] = ["mnemonic", "seed", "phrase", "recovery", "secret"];

/// Every seed phrase in `text`, as sorted, non-overlapping `[start, end)` byte ranges.
pub fn find(text: &str) -> Vec<(usize, usize)> {
    find_with(text, None)
}

/// [`find`], with the keyword bounds given (`Some(None)`: no keyword anywhere) or computed.
fn find_with(text: &str, keywords: Option<Option<(usize, usize)>>) -> Vec<(usize, usize)> {
    let mut scan = Scan {
        text: text.as_bytes(),
        spans: Vec::new(),
        budget: MAX_CHECKSUM_TESTS,
        keywords,
    };
    let mut list = Run::default();
    let mut shaped = Run::default();
    let mut old = Run::default();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let word = &bytes[start..i];
        let tok = Tok {
            start,
            end: i,
            idx: text.get(start..i).and_then(bip39::index),
        };
        let lower_shape = (3..=8).contains(&word.len()) && word.iter().all(u8::is_ascii_lowercase);
        let joiner_ok = |run: &Run| {
            run.last_end
                .and_then(|end| bytes.get(end..start))
                .is_some_and(is_joiner)
        };
        let single_space = |run: &Run| {
            run.last_end
                .and_then(|end| bytes.get(end..start))
                .is_some_and(|gap| gap == b" ")
        };

        let ok = tok.idx.is_some();
        let join = joiner_ok(&list);
        scan.feed(&mut list, tok, ok, join, Kind::List);
        let ok = tok.idx.is_some() || lower_shape;
        let join = joiner_ok(&shaped);
        scan.feed(&mut shaped, tok, ok, join, Kind::Shaped);
        let join = single_space(&old);
        scan.feed(&mut old, tok, lower_shape, join, Kind::Old);
    }
    scan.flush(&mut list, Kind::List);
    scan.flush(&mut shaped, Kind::Shaped);
    scan.flush(&mut old, Kind::Old);
    merge(scan.spans)
}

/// Whether the bytes between two words may join them into one run.
fn is_joiner(gap: &[u8]) -> bool {
    if gap.is_empty() || gap.len() > MAX_GAP {
        return false;
    }
    let mut prev_digit = false;
    for &b in gap {
        let ok = b.is_ascii_whitespace()
            || matches!(b, b',' | b'"' | b'\'' | b'[' | b']')
            || b.is_ascii_digit()
            || (prev_digit && matches!(b, b'.' | b')' | b':'));
        if !ok {
            return false;
        }
        prev_digit = b.is_ascii_digit();
    }
    true
}

#[derive(Clone, Copy)]
struct Tok {
    start: usize,
    end: usize,
    idx: Option<u16>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    List,
    Shaped,
    Old,
}

/// One run being built. Only the first `MAX_RUN + 1` tokens are kept; past that the run is
/// too long for every rule except the old-shape prefix, which needs the first 24.
#[derive(Default)]
struct Run {
    toks: Vec<Tok>,
    count: usize,
    non_list: usize,
    end: usize,
    last_end: Option<usize>,
}

impl Run {
    fn push(&mut self, tok: Tok) {
        if self.toks.len() <= MAX_RUN {
            self.toks.push(tok);
        }
        self.count += 1;
        if tok.idx.is_none() {
            self.non_list += 1;
        }
        self.end = tok.end;
        self.last_end = Some(tok.end);
    }

    fn start(&self) -> usize {
        self.toks.first().map_or(0, |t| t.start)
    }
}

struct Scan<'a> {
    text: &'a [u8],
    spans: Vec<(usize, usize)>,
    budget: usize,
    /// First and last start of a keyword in the text, computed on first use.
    keywords: Option<Option<(usize, usize)>>,
}

impl Scan<'_> {
    fn feed(&mut self, run: &mut Run, tok: Tok, qualifies: bool, joins: bool, kind: Kind) {
        if !qualifies {
            self.flush(run, kind);
            return;
        }
        if run.count > 0 && !joins {
            self.flush(run, kind);
        }
        run.push(tok);
    }

    fn flush(&mut self, run: &mut Run, kind: Kind) {
        if run.count >= 12 {
            self.judge(run, kind);
        }
        *run = Run::default();
    }

    fn judge(&mut self, run: &Run, kind: Kind) {
        let (start, end) = (run.start(), run.end);
        match kind {
            Kind::List => {
                if run.count > MAX_RUN {
                    return;
                }
                if self.keyword_outside(start, end) {
                    self.spans.push((start, end));
                } else {
                    self.checksum(&run.toks);
                }
            }
            Kind::Shaped => {
                if run.count <= MAX_RUN
                    && run.non_list * 6 <= run.count
                    && self.keyword_outside(start, end)
                {
                    self.spans.push((start, end));
                }
            }
            Kind::Old => {
                if !self.keyword_outside(start, end) {
                    return;
                }
                if run.count <= MAX_RUN {
                    self.spans.push((start, end));
                } else if run.non_list > 0 {
                    if let Some(t) = run.toks.get(23) {
                        self.spans.push((start, t.end));
                    }
                }
            }
        }
    }

    /// Checksum the whole list run and each line of it (see the module docs).
    fn checksum(&mut self, toks: &[Tok]) {
        let n = toks.len();
        let mut candidates = vec![(0usize, n)];
        let mut line_start = 0usize;
        for j in 1..=n {
            let breaks = j == n
                || self
                    .text
                    .get(toks[j - 1].end..toks[j].start)
                    .is_some_and(|gap| gap.contains(&b'\n'));
            if breaks {
                if (line_start, j) != (0, n) {
                    candidates.push((line_start, j));
                }
                line_start = j;
            }
        }
        for (from, to) in candidates {
            if let Some((a, b)) = self.checksum_candidate(&toks[from..to]) {
                self.spans
                    .push((toks[from + a].start, toks[from + b - 1].end));
            }
        }
    }

    /// The `[a, b)` token window of `toks` that is a checksum-valid mnemonic, if any.
    fn checksum_candidate(&mut self, toks: &[Tok]) -> Option<(usize, usize)> {
        let len = toks.len();
        let indices: Vec<u16> = toks.iter().filter_map(|t| t.idx).collect();
        if indices.len() != len {
            return None;
        }
        if bip39::LENGTHS.contains(&len) && self.test(&indices) {
            return Some((0, len));
        }
        if len > 12 + 2 * WINDOW_SLACK {
            return None;
        }
        // Every valid window of the longest length that has one, merged: a list word next to
        // the phrase can form a window that validates by chance, and the union still covers
        // the phrase.
        for &n in bip39::LENGTHS.iter().rev().filter(|&&n| n < len) {
            let mut hit: Option<(usize, usize)> = None;
            for off in 0..=(len - n) {
                if off > WINDOW_SLACK || len - n - off > WINDOW_SLACK {
                    continue;
                }
                let window = &indices[off..off + n];
                if distinct(window) >= MIN_DISTINCT && self.test(window) {
                    hit = Some(hit.map_or((off, off + n), |(a, _)| (a, off + n)));
                }
            }
            if hit.is_some() {
                return hit;
            }
        }
        None
    }

    fn test(&mut self, indices: &[u16]) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        bip39::checksum_ok(indices)
    }

    fn keyword_outside(&mut self, start: usize, end: usize) -> bool {
        let text = self.text;
        let found = *self.keywords.get_or_insert_with(|| keyword_bounds(text));
        found.is_some_and(|(first, last)| first < start || last >= end)
    }
}

fn distinct(indices: &[u16]) -> usize {
    let mut seen = indices.to_vec();
    seen.sort_unstable();
    seen.dedup();
    seen.len()
}

/// First and last start offset of a keyword in `text`: a whole token, or a camelCase part of
/// one, equal to a keyword or its plural, in any case.
fn keyword_bounds(text: &[u8]) -> Option<(usize, usize)> {
    let mut bounds: Option<(usize, usize)> = None;
    let mut note = |at: usize| {
        bounds = Some(bounds.map_or((at, at), |(first, _)| (first, at)));
    };
    let mut i = 0usize;
    while i < text.len() {
        if !text[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < text.len() && text[i].is_ascii_alphabetic() {
            i += 1;
        }
        // camelCase parts: split before an uppercase letter that follows a lowercase one.
        let mut part = start;
        for j in start + 1..=i {
            let split =
                j == i || (text[j - 1].is_ascii_lowercase() && text[j].is_ascii_uppercase());
            if split {
                if is_keyword(&text[part..j]) {
                    note(part);
                }
                part = j;
            }
        }
    }
    bounds
}

fn is_keyword(word: &[u8]) -> bool {
    KEYWORDS.iter().any(|k| {
        let k = k.as_bytes();
        word.eq_ignore_ascii_case(k)
            || (word.len() == k.len() + 1
                && word[..k.len()].eq_ignore_ascii_case(k)
                && word[k.len()].eq_ignore_ascii_case(&b's'))
    })
}

/// Sort and merge overlapping spans.
fn merge(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match out.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid mnemonics that are not published test vectors.
    const P12: &str = "session twin stem shop glass chat dune switch upset such noble wave";
    const P15: &str =
        "toe that slab again apology sock online giraffe horror aspect employ dinosaur blind polar trip";
    const P24: &str = "soda bleak common escape album hungry rigid water baby upset popular scrub \
                       fan maze pledge when science walk income tobacco answer tent float firm";

    fn found(text: &str) -> Vec<&str> {
        find(text).into_iter().map(|(a, b)| &text[a..b]).collect()
    }

    fn bare(text: &str) -> Vec<&str> {
        find_with(text, Some(None))
            .into_iter()
            .map(|(a, b)| &text[a..b])
            .collect()
    }

    #[test]
    fn bare_phrases_in_every_layout() {
        for p in [P12, P15, P24] {
            assert_eq!(found(p), [p]);
            assert_eq!(found(&p.to_ascii_uppercase()).len(), 1);
            assert_eq!(found(&format!("words: \"{p}\".")), [p]);
        }
        let wrapped = P24.replacen(" fan", "\n   fan", 1);
        assert_eq!(found(&wrapped), [wrapped.as_str()]);
        let two = format!("a: {P12}\nb: {P24}\n");
        assert_eq!(found(&two), [P12, P24]);
        let lines = format!("zoo zoo zoo\n{P12}\nzoo zoo\n");
        assert_eq!(found(&lines), [P12]);
        let words: Vec<&str> = P12.split(' ').collect();
        let json = format!("[\"{}\"]", words.join("\", \""));
        assert_eq!(found(&json).len(), 1, "{json}");
        let pretty = format!("[\n  \"{}\"\n]", words.join("\",\n  \""));
        assert_eq!(found(&pretty).len(), 1, "{pretty}");
        let numbered: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{}. {w}", i + 1))
            .collect();
        assert_eq!(found(&numbered.join(" ")).len(), 1);
        assert_eq!(found(&numbered.join("\n")).len(), 1);
        assert_eq!(found(&words.join(", ")).len(), 1);
    }

    #[test]
    fn bare_phrase_with_adjacent_list_words() {
        for text in [
            format!("please use {P12} wallet"),
            format!("Backup {P12} please"),
            format!("use any {P12} now"),
            format!("you can use {P12} now"),
            format!("{P15} also"),
            format!("{P12} also fine"),
        ] {
            let hits = bare(&text);
            assert_eq!(hits.len(), 1, "{text}");
            let phrase = if text.contains(P15) { P15 } else { P12 };
            assert!(hits[0].contains(phrase), "{text}: {hits:?}");
        }
        // Four extra list words on one side: past the slack.
        let far = format!("please use any spare {P12}");
        assert_eq!(bare(&far), Vec::<&str>::new());
    }

    #[test]
    fn repeated_word_windows_need_eight_distinct_words() {
        let vector = bip39::TEST_VECTORS[0]; // abandon x11 about
        assert_eq!(bare(vector), [vector]);
        assert_eq!(
            bare(&format!("abandon abandon {vector}")),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn prose_of_list_words_is_not_a_bare_phrase() {
        for prose in [
            "review any major change before release because random network issue can cause",
            "please review any major change before release because random network issue can \
             cause total system crash during busy weekend",
            "review any major change before release because random network issue can secret",
        ] {
            assert!(
                prose.split_whitespace().all(|w| bip39::index(w).is_some()),
                "{prose}"
            );
            assert_eq!(found(prose), Vec::<&str>::new(), "{prose}");
            assert_eq!(
                found(&format!("Note: {prose}.")),
                Vec::<&str>::new(),
                "{prose}"
            );
            assert_eq!(found(&format!("recovery {prose}")).len(), 1, "{prose}");
        }
    }

    #[test]
    fn keyword_catches_typos_numbering_commas_json_and_non_list_words() {
        let typo = P12.replace("upset", "upsett");
        let gibberish = "gizmo wizard foobar quux frob blorp zapp wibble wobble flurb snarf grault";
        let italian = "abaco abbaglio abbinato abete abisso abolire abrasivo abrogato accadere \
                       accenno accusato acetone";
        let typo_words: Vec<&str> = typo.split(' ').collect();
        let numbered: Vec<String> = typo_words
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{}) {w}", i + 1))
            .collect();
        for (phrase, keyed) in [
            (typo.clone(), format!("seed phrase: {typo}")),
            (gibberish.to_string(), format!("mnemonic: {gibberish}")),
            (italian.to_string(), format!("secret: {italian}")),
            (
                typo_words.join(", "),
                format!("Recovery phrase: {}", typo_words.join(", ")),
            ),
            (
                format!("[\"{}\"]", typo_words.join("\", \"")),
                format!("{{\"seed\": [\"{}\"]}}", typo_words.join("\", \"")),
            ),
            (
                numbered.join(" "),
                format!("seed words:\n{}", numbered.join(" ")),
            ),
        ] {
            assert_eq!(found(&phrase), Vec::<&str>::new(), "no keyword: {phrase}");
            let hits = found(&keyed);
            assert_eq!(hits.len(), 1, "{keyed}");
            let tokens: Vec<&str> = phrase
                .split(|c: char| !c.is_ascii_alphabetic())
                .filter(|w| !w.is_empty())
                .collect();
            assert!(hits[0].starts_with(tokens[0]), "{keyed}: {hits:?}");
            assert!(hits[0].ends_with(tokens[11]), "{keyed}: {hits:?}");
        }
    }

    #[test]
    fn keyword_matching_is_by_word_and_outside_the_run() {
        let typo = P12.replace("upset", "upsett");
        for (kw, hit) in [
            ("seeds:", true),
            ("seedPhrase =", true),
            ("SEED_PHRASE=", true),
            ("my_mnemonic:", true),
            ("seeded", false),
            ("secretary", false),
            ("phrases?", true),
        ] {
            assert_eq!(
                found(&format!("{kw} {typo}")).len(),
                usize::from(hit),
                "{kw}"
            );
        }
        // A keyword that is one of the run's own words doesn't count.
        let own = "review any major change before release because random network issue secret can";
        assert_eq!(found(own), Vec::<&str>::new());
    }

    #[test]
    fn wordlists_are_not_phrases() {
        let list = bip39::ENGLISH_TXT;
        assert_eq!(found(list), Vec::<&str>::new());
        assert_eq!(
            found(&format!("BIP-39 seed words:\n{list}")),
            Vec::<&str>::new()
        );
        let spaced = list.split('\n').collect::<Vec<_>>().join(" ");
        assert_eq!(found(&format!("seed words: {spaced}")), Vec::<&str>::new());
        let csv = list.split('\n').collect::<Vec<_>>().join(", ");
        assert_eq!(found(&format!("mnemonic list: {csv}")), Vec::<&str>::new());
        // 49 list words with a keyword: a dump; the old rule still takes a long run's first
        // 24 words when it has non-list words.
        let dump = ["zoo"; 49].join(" ");
        assert_eq!(found(&format!("seed: {dump}")), Vec::<&str>::new());
        let long = format!("seed: {} quux", ["zoo"; 60].join(" "));
        assert_eq!(found(&long), [["zoo"; 24].join(" ").as_str()]);
    }

    #[test]
    fn solana_keygen_output() {
        let out = format!(
            "Generating a new keypair\n\nWrote new keypair to /tmp/k.json\n{bar}\n\
             pubkey: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\n{bar}\n\
             Save this seed phrase to recover your new keypair:\n{P12}\n{bar}\n",
            bar = "=".repeat(80)
        );
        assert_eq!(found(&out), [P12]);
        assert_eq!(bare(&out), [P12]);
    }

    #[test]
    fn natural_text_has_no_bare_phrase() {
        // The repo's own prose: about 100 KB of English with code, lists and tables.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut total = 0usize;
        for rel in [
            "README.md",
            "SECURITY.md",
            "CHANGELOG.md",
            "crates/engine/ARCHITECTURE.md",
            "docs/tiers.md",
            "docs/scanner-coverage.md",
        ] {
            let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
                continue;
            };
            total += text.len();
            assert_eq!(bare(&text), Vec::<&str>::new(), "{rel}");
        }
        assert!(total > 50_000, "corpus too small: {total}");
    }

    #[test]
    fn work_is_bounded() {
        let one_run = "zoo ".repeat(1 << 19);
        assert_eq!(find(&one_run), Vec::new());
        let lines = format!("{}\n", ["zoo"; 12].join(" ")).repeat(50_000);
        assert_eq!(find(&lines), Vec::new());
        // Lines joined by newlines are one run past MAX_RUN (a dump); ended by `.` each is its
        // own 17-word run, three window tests each, until the budget runs out.
        let joined = format!("{P15} zoo zoo\n").repeat(20_000);
        assert_eq!(find(&joined), Vec::new());
        let windows = format!("{P15} zoo zoo.\n").repeat(70_000);
        let hits = find(&windows).len();
        assert!(hits > 50_000 && hits < 70_000, "{hits}");
        let keyed = format!(
            "seed:\n{}",
            format!("{} quux\n", ["zoo"; 12].join(" ")).repeat(20_000)
        );
        assert_eq!(find(&keyed).len(), 20_000);
        assert_eq!(find(""), Vec::new());
        assert_eq!(find("\u{e9}t\u{e9} zoo \u{1F600} 12. 3) [,]"), Vec::new());
        assert!(is_joiner(b" "));
        assert!(is_joiner(b"\",\n  \""));
        assert!(is_joiner(b" 12. "));
        assert!(!is_joiner(b": "));
        assert!(!is_joiner(b"-"));
        assert!(!is_joiner(&[b' '; MAX_GAP + 1]));
    }
}
