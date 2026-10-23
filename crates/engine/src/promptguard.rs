//! UserPromptSubmit guard.
//!
//! Blocks a user prompt that pastes a raw private key or seed phrase into the model
//! context. UserPromptSubmit can only block or inject (not rewrite), so the only safe
//! action on a detected secret is to block with a reason that keeps the secret itself
//! out of the model.
//!
//! The detectors are shared with [`crate::redact`] (the keypair-array, 64-byte base58
//! secret-key, and seed-phrase scanners). The published BIP-39 test vectors
//! ([`crate::bip39::TEST_VECTORS`]) are not blocked: they are public test data.

use crate::{bip39, redact};

/// Inspect a user prompt for raw secrets.
///
/// Returns `Some(reason)` to block the prompt when it contains a Solana keypair byte
/// array, a 64-byte base58 secret key, or a BIP-39 seed phrase. Returns `None` for a
/// clean prompt. The reason names the detected class but never echoes the secret.
pub fn check(prompt: &str) -> Option<String> {
    if redact::find_keypair_array(prompt).is_some() {
        return Some(
            "Prompt blocked: it contains a raw Solana keypair byte array. The secret was \
             kept out of the model context — paste a public key or file path instead."
                .to_string(),
        );
    }

    let phrase = redact::find_seed_phrases(prompt)
        .into_iter()
        .any(|(start, end)| {
            prompt
                .get(start..end)
                .is_some_and(|p| !bip39::is_test_vector(p))
        });
    if phrase {
        return Some(
            "Prompt blocked: it contains what looks like a BIP-39 seed phrase. The secret \
             was kept out of the model context — never paste a recovery phrase."
                .to_string(),
        );
    }

    // Scan base58 token runs for a 64-byte secret key (skip ordinary 32-byte pubkeys).
    for token in prompt.split(|c: char| !is_base58_char(c)) {
        if redact::is_base58_secret_key(token) {
            return Some(
                "Prompt blocked: it contains a raw 64-byte base58 private key. The secret \
                 was kept out of the model context — paste a public key or file path instead."
                    .to_string(),
            );
        }
    }

    None
}

#[inline]
fn is_base58_char(c: char) -> bool {
    matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_phrase_blocks() {
        let prompt = "here is my seed phrase: legal winner thank year wave sausage worth \
                      useful legal winner thank yellow please import it";
        assert!(check(prompt).is_some());
    }

    #[test]
    fn bare_checksum_valid_seed_phrase_blocks() {
        let prompt = "import session twin stem shop glass chat dune switch upset such noble wave";
        assert!(check(prompt).is_some());
        let prompt = "import session twin stem shop glass chat dune switch upset such noble zoo";
        assert!(check(prompt).is_none(), "checksum fails, no keyword");
    }

    #[test]
    fn published_test_vectors_are_not_blocked() {
        for vector in crate::bip39::TEST_VECTORS {
            assert!(check(vector).is_none(), "{vector}");
            assert!(check(&format!("add a test with the mnemonic \"{vector}\"")).is_none());
            assert!(check(&format!("seed phrase: {vector}")).is_none());
        }
        // One word changed, or extra words in the span: blocked.
        let edited = crate::bip39::TEST_VECTORS[15].replace("borrow", "zoo");
        assert!(check(&format!("seed phrase: {edited}")).is_some());
        let longer = format!("seed phrase: {} sock", crate::bip39::TEST_VECTORS[1]);
        assert!(check(&longer).is_some());
    }

    #[test]
    fn keypair_array_blocks() {
        let arr: Vec<String> = (0..64).map(|i| (i % 256).to_string()).collect();
        let prompt = format!("load this wallet [{}]", arr.join(","));
        assert!(check(&prompt).is_some());
    }

    #[test]
    fn base58_secret_key_blocks() {
        let secret = bs58::encode(vec![9u8; 64]).into_string();
        let prompt = format!("use private key {secret}");
        assert!(check(&prompt).is_some());
    }

    #[test]
    fn normal_prompt_allows() {
        assert_eq!(
            check("deploy my program to devnet and check the balance"),
            None
        );
        // A plain 32-byte pubkey in a prompt must not block.
        let pubkey = bs58::encode(vec![1u8; 32]).into_string();
        assert_eq!(check(&format!("send 1 SOL to {pubkey}")), None);
    }
}
