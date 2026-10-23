//! BIP-39 English wordlist and mnemonic checksum, for seed-phrase detection.
//!
//! `bip39_english.txt` is `bip-0039/english.txt` from github.com/bitcoin/bips (git blob
//! `942040ed50f7205cafc465496229128ba4f78e75`, sha256
//! `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`), embedded unchanged.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

/// The embedded wordlist file: 2048 lowercase words, one per line, sorted.
pub const ENGLISH_TXT: &str = include_str!("bip39_english.txt");

/// Mnemonic lengths BIP-39 defines (128 to 256 bits of entropy).
pub const LENGTHS: [usize; 5] = [12, 15, 18, 21, 24];

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| ENGLISH_TXT.lines().collect())
}

/// The wordlist index of `word`, compared case-insensitively. Only 3 to 8 ASCII letters can
/// match; anything else is `None` without a lookup.
pub fn index(word: &str) -> Option<u16> {
    let bytes = word.as_bytes();
    if !(3..=8).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    let mut buf = [0u8; 8];
    for (dst, src) in buf.iter_mut().zip(bytes) {
        *dst = src.to_ascii_lowercase();
    }
    let lower = &buf[..bytes.len()];
    words()
        .binary_search_by(|w| w.as_bytes().cmp(lower))
        .ok()
        .and_then(|i| u16::try_from(i).ok())
}

/// Whether `indices` (wordlist indices, 11 bits each) form a mnemonic whose checksum
/// validates: one of [`LENGTHS`], and the last `len / 3` bits equal the leading bits of
/// sha256 over the entropy that precedes them.
pub fn checksum_ok(indices: &[u16]) -> bool {
    let n = indices.len();
    if !LENGTHS.contains(&n) {
        return false;
    }
    // 24 words are 264 bits: 33 bytes.
    let mut bits = [0u8; 33];
    for (w, &idx) in indices.iter().enumerate() {
        if idx >= 2048 {
            return false;
        }
        for b in 0..11 {
            if idx & (1 << (10 - b)) != 0 {
                let pos = w * 11 + b;
                bits[pos / 8] |= 0x80 >> (pos % 8);
            }
        }
    }
    let cs_bits = n / 3;
    let ent_bytes = (n * 11 - cs_bits) / 8;
    let hash = Sha256::digest(&bits[..ent_bytes]);
    (0..cs_bits).all(|b| {
        let pos = ent_bytes * 8 + b;
        let got = bits[pos / 8] & (0x80 >> (pos % 8)) != 0;
        let want = hash[b / 8] & (0x80 >> (b % 8)) != 0;
        got == want
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indices(phrase: &str) -> Vec<u16> {
        phrase
            .split_whitespace()
            .map(|w| index(w).unwrap())
            .collect()
    }

    #[test]
    fn embedded_list_is_the_published_one() {
        let sha: String = Sha256::digest(ENGLISH_TXT.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            sha,
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        let list = words();
        assert_eq!(list.len(), 2048);
        assert!(list.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert_eq!((list[0], list[2047]), ("abandon", "zoo"));
    }

    #[test]
    fn index_is_case_insensitive_and_shape_checked() {
        assert_eq!(index("abandon"), Some(0));
        assert_eq!(index("ZOO"), Some(2047));
        assert_eq!(index("Legal"), index("legal"));
        for w in ["", "ab", "abandonxx", "the", "zo0", "über"] {
            assert_eq!(index(w), None, "{w}");
        }
    }

    // Test vectors from the reference implementation (trezor/python-mnemonic vectors.json).
    #[test]
    fn reference_vectors_validate() {
        for phrase in [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        ] {
            assert!(checksum_ok(&indices(phrase)), "{phrase}");
        }
    }

    #[test]
    fn bad_checksums_and_lengths_fail() {
        let mut v =
            indices("legal winner thank year wave sausage worth useful legal winner thank yellow");
        v[11] = index("zoo").unwrap();
        assert!(!checksum_ok(&v));
        assert!(!checksum_ok(&v[..11]));
        assert!(!checksum_ok(&[]));
        assert!(!checksum_ok(&[4096; 12]));
    }
}
