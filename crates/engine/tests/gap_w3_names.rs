//! Secret-name heuristic and transformed env dumps (W3 follow-up to the coverage round).

use safe_ai_skill::gate::Verdict;
use safe_ai_skill::gates::envread;
use safe_ai_skill::redact::{is_secret_env_name, scrub_env_lines};

fn kind(command: &str) -> &'static str {
    match envread::decide_bash(command) {
        None | Some(Verdict::NoOpinion) => "",
        Some(Verdict::Allow(_)) => "allow",
        Some(Verdict::Ask(_)) => "ask",
        Some(Verdict::Deny(_)) => "deny",
    }
}

#[test]
fn locator_and_public_names_are_not_secret() {
    for name in [
        "SOLANA_KEYPAIR_PATH",
        "ANCHOR_WALLET",
        "TOKEN_MINT",
        "AUTH_URL",
        "CLIENT_ID",
        "PATH",
        "PWD",
        "OLDPWD",
        "SESSION_ID",
        "BYPASS_CACHE",
    ] {
        assert!(!is_secret_env_name(name), "{name}");
    }
}

#[test]
fn credential_names_are_secret() {
    for name in [
        "HELIUS_API_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "HELIUS_RPC_URL",
        "GH_PAT",
        "STRIPE_SK",
        "JWT",
        "SESSION",
        "PASS",
        "DB_PWD",
        "KEYPAIR",
        "SOLANA_PRIVATE_KEY_PATH",
    ] {
        assert!(is_secret_env_name(name), "{name}");
    }
}

#[test]
fn path_values_stay_visible_unless_the_name_is_strongly_secret() {
    let out = scrub_env_lines("API_KEY=/home/u/key.json\nAPI_TOKEN=abc123\n").unwrap();
    assert!(out.contains("API_KEY=/home/u/key.json"), "{out}");
    assert!(!out.contains("abc123"), "{out}");
    let out = scrub_env_lines("PRIVATE_KEY=/home/u/key.json\n").unwrap();
    assert!(!out.contains("/home/u/key.json"), "{out}");
}

#[test]
fn transformed_or_redirected_dumps_ask() {
    for cmd in [
        "env | base64",
        "set | rev",
        "printenv | cut -d= -f2",
        "printenv | cut -c5-",
        "env > /tmp/e; base64 /tmp/e",
        "ls || env | xxd",
        "export -p | sed 's/=/ /'",
    ] {
        assert_eq!(kind(cmd), "ask", "{cmd}");
    }
}

#[test]
fn filtered_dumps_and_unrelated_pipes_have_no_opinion() {
    for cmd in [
        "env",
        "printenv",
        "env | grep HELIUS",
        "export -p | sort",
        "printenv | cut -d= -f1",
        "printenv | grep KEY | cut -c1-200",
        "env FOO=1 node x.js | tee out",
        "echo é | base64",
        "echo $ANCHOR_WALLET",
        "echo $TOKEN_MINT",
    ] {
        assert_eq!(kind(cmd), "", "{cmd}");
    }
}
