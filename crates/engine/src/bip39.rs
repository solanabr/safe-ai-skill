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

/// The 24 English reference vectors published with the reference implementation
/// (trezor/python-mnemonic `vectors.json`, git blob `d362a5d4eb1ba800a52aec30116915cd4576e1fd`),
/// in file order. Public test data, so the prompt guard lets them through.
pub const TEST_VECTORS: [&str; 24] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
    "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
    "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    "scheme spot photo card baby mountain device kick cradle pact join borrow",
    "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
    "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
    "cat swing flag economy stadium alone churn speed unique patch report train",
    "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
    "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
    "vessel ladder alter error federal sibling chat ability sun glass valve picture",
    "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
    "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
];

/// Whether the letter tokens of `text`, lowercased and joined by single spaces, are exactly
/// one of [`TEST_VECTORS`].
pub fn is_test_vector(text: &str) -> bool {
    let mut normal = String::with_capacity(text.len());
    for word in text
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
    {
        if !normal.is_empty() {
            normal.push(' ');
        }
        normal.push_str(&word.to_ascii_lowercase());
    }
    TEST_VECTORS.contains(&normal.as_str())
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

    /// Entropy column of the same `vectors.json`, in order: each vector must be the mnemonic
    /// of its entropy (checks the embedded list, the checksum and the vector text together).
    const VECTOR_ENTROPY: [&str; 24] = [
        "00000000000000000000000000000000",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "80808080808080808080808080808080",
        "ffffffffffffffffffffffffffffffff",
        "000000000000000000000000000000000000000000000000",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "808080808080808080808080808080808080808080808080",
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "8080808080808080808080808080808080808080808080808080808080808080",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "9e885d952ad362caeb4efe34a8e91bd2",
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "23db8160a31d3e0dca3688ed941adbf3",
        "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "f30f8c1da665478f49b001d94c5fc452",
        "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
    ];

    fn mnemonic_of(entropy_hex: &str) -> String {
        let entropy: Vec<u8> = (0..entropy_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&entropy_hex[i..i + 2], 16).unwrap())
            .collect();
        let hash = Sha256::digest(&entropy);
        let mut bits: Vec<bool> = entropy
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| b & (1 << i) != 0))
            .collect();
        let cs = entropy.len() * 8 / 32;
        bits.extend((0..cs).map(|i| hash[0] & (0x80 >> i) != 0));
        bits.chunks(11)
            .map(|c| words()[c.iter().fold(0usize, |a, &b| a << 1 | usize::from(b))])
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn test_vectors_are_the_mnemonics_of_their_entropy() {
        for (entropy, phrase) in VECTOR_ENTROPY.iter().zip(TEST_VECTORS) {
            assert_eq!(mnemonic_of(entropy), phrase);
            assert!(checksum_ok(&indices(phrase)), "{phrase}");
        }
    }

    #[test]
    fn is_test_vector_normalizes_but_matches_exactly() {
        assert!(is_test_vector(
            "Legal, winner \"thank\" year wave sausage worth useful legal winner thank yellow"
        ));
        assert!(is_test_vector("1. scheme 2. spot 3. photo 4. card 5. baby 6. mountain 7. device 8. kick 9. cradle 10. pact 11. join 12. borrow"));
        assert!(!is_test_vector(
            "legal winner thank year wave sausage worth useful legal winner thank"
        ));
        assert!(!is_test_vector(
            "my legal winner thank year wave sausage worth useful legal winner thank yellow"
        ));
        assert!(!is_test_vector(
            "session twin stem shop glass chat dune switch upset such noble wave"
        ));
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
