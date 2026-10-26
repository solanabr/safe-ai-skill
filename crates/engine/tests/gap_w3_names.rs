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

fn blanked(text: &str, secret: &str) -> bool {
    scrub_env_lines(text).is_some_and(|out| !out.contains(secret))
}

#[test]
fn more_output_shapes_are_redacted() {
    for (text, secret) in [
        ("API_TOKEN = s3cr3tVal\n", "s3cr3tVal"),
        ("API_TOKEN\t=\ts3cr3tVal\n", "s3cr3tVal"),
        ("+ API_TOKEN=s3cr3tVal\n", "s3cr3tVal"),
        (".env.local:API_TOKEN=s3cr3tVal\n", "s3cr3tVal"),
        ("src/a.env:12:API_TOKEN=s3cr3tVal\n", "s3cr3tVal"),
        ("{\"api_key\": \"s3cr3tVal\"}", "s3cr3tVal"),
        ("{'api_key': 's3cr3tVal'}", "s3cr3tVal"),
        ("API_TOKEN: s3cr3tVal\n", "s3cr3tVal"),
        ("{\"API_TOKEN\": 98765432}", "98765432"),
        (
            "HTTPS_PROXY=http://user:s3cr3tVal@localhost:8080\n",
            "s3cr3tVal",
        ),
        (
            "url: https://mainnet.helius-rpc.com/?api-key=s3cr3tVal\n",
            "s3cr3tVal",
        ),
    ] {
        assert!(
            blanked(text, secret),
            "{text:?} -> {:?}",
            scrub_env_lines(text)
        );
    }
}

#[test]
fn ordinary_output_is_left_alone() {
    for text in [
        "a == b\n",
        "HOME=/Users/x\n",
        "{\"name\": \"anchor\", \"version\": 3}",
        "see https://docs.solana.com/cli\n",
        "TOKEN_MINT: So11111111111111111111111111111111111111112\n",
    ] {
        assert_eq!(scrub_env_lines(text), None, "{text:?}");
    }
}
