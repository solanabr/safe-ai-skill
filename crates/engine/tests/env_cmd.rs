//! End-to-end tests for `safe-ai-skill env keys|set|unset` (#7, spec D3.4).
//!
//! Every test drives the real binary in a sandboxed temp dir (cwd and `HOME` pinned to it) and
//! feeds values on stdin exactly as the agent would:
//! `printf %s '<value>' | safe-ai-skill env set FILE KEY`. File bytes are asserted exactly, so
//! every round-trip case (CRLF, BOM, `export`, the three quote styles, multiline PEM, duplicates,
//! commented keys, no trailing newline, `$`/`#`/spaces) also proves the untouched lines survive.
//! `never_prints_values` sweeps every subcommand and error path and asserts that no secret byte
//! sequence reaches stdout or stderr.

mod common;

use std::fs;
use std::path::Path;

use common::{Invocation, Run, TempDir};
use sha2::{Digest, Sha256};

/// Run `safe-ai-skill env <args>` with cwd and `HOME` pinned to `dir`, optionally piping `stdin`.
fn run_env_in(dir: &Path, args: &[&str], stdin: Option<&str>) -> Run {
    let mut full = vec!["env"];
    full.extend_from_slice(args);
    let mut inv = Invocation::new(&full).cwd(dir).home(dir);
    if let Some(body) = stdin {
        inv = inv.stdin(body);
    }
    inv.run()
}

fn run_env(dir: &Path, args: &[&str]) -> Run {
    run_env_in(dir, args, None)
}

/// `printf %s '<value>' | safe-ai-skill env set <file> <key> [extra…]`.
fn set(dir: &Path, file: &str, key: &str, value: &str, extra: &[&str]) -> Run {
    let mut args = vec!["set", file, key];
    args.extend_from_slice(extra);
    run_env_in(dir, &args, Some(value))
}

fn unset(dir: &Path, file: &str, key: &str) -> Run {
    run_env(dir, &["unset", file, key])
}

/// First 6 hex chars of sha256(value): the fingerprint `env` shows for values ≥16 bytes.
fn fp6(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().take(3).map(|b| format!("{b:02x}")).collect()
}

/// The display column of the first `keys` row for `key` (columns re-joined by single spaces).
fn display_of(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut cols = l.split_whitespace();
            let _label = cols.next()?;
            if cols.next()? != key {
                return None;
            }
            Some(cols.collect::<Vec<_>>().join(" "))
        })
        .unwrap_or_else(|| panic!("no row for {key} in:\n{stdout}"))
}

/// The `L<n>` label of the first `keys` row for `key`.
fn label_of(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut cols = l.split_whitespace();
            let label = cols.next()?;
            (cols.next()? == key).then(|| label.to_string())
        })
        .unwrap_or_else(|| panic!("no row for {key} in:\n{stdout}"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn ok(run: &Run) {
    assert_eq!(
        run.code,
        Some(0),
        "expected exit 0\n--- stdout ---\n{}\n--- stderr ---\n{}",
        run.stdout,
        run.stderr
    );
}

fn code(run: &Run, expected: i32) {
    assert_eq!(
        run.code,
        Some(expected),
        "expected exit {expected}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        run.stdout,
        run.stderr
    );
}

/// No leftover `env` temp files next to the edited file.
fn assert_no_temp_files(dir: &Path) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.ends_with(".tmp"),
            "leftover temp file {name} in {}",
            dir.display()
        );
    }
}

// ---------------------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------------------

#[test]
fn keys_golden_output() {
    let dir = TempDir::new("env-keys-golden");
    fs::write(dir.join(".env.local"), "CLUSTER=devnet\nSHORT=hunter2\n").unwrap();
    let r = run_env(dir.path(), &["keys", ".env.local"]);
    ok(&r);
    assert_eq!(
        r.stdout,
        "# .env.local keys=2 crlf=no\nL1   CLUSTER   devnet\nL2   SHORT     set len=7\n"
    );
    assert_eq!(r.stderr, "");
}

#[test]
fn keys_masks_every_value_class() {
    let dir = TempDir::new("env-keys-mask");
    let api = "3f9a1c0b7e2d4a6f8b1c3e5d7f9a0b2c4d6e";
    let url = "https://mainnet.helius-rpc.com/?api-key=0b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e";
    let body = format!(
        "HELIUS_API_KEY={api}\nCLUSTER=devnet\nRPC_URL=\"{url}\"\nEMPTY=\nTOKEN=your-token-here\n\
         # OLD_KEY=legacy-secret-value\nPORT=8899\nSHORT=hunter2\nDEBUG=TRUE\nANGLE=<paste key>\n\
         XS=xxxxxxxx\nCHANGE=changeme\nTODO_K=TODO\nQUOTED_EMPTY=\"\"\nDB=postgres://admin:hunter2pw@db.internal:5432/app\n"
    );
    fs::write(dir.join(".env.local"), body).unwrap();
    let r = run_env(dir.path(), &["keys", ".env.local"]);
    ok(&r);
    let out = &r.stdout;
    assert!(
        out.starts_with("# .env.local keys=14 crlf=no\n"),
        "header: {out}"
    );
    assert_eq!(
        display_of(out, "HELIUS_API_KEY"),
        format!("set len=36 fp={}", fp6(api))
    );
    assert_eq!(display_of(out, "CLUSTER"), "devnet");
    assert_eq!(
        display_of(out, "RPC_URL"),
        format!("set url=https://mainnet.helius-rpc.com/… fp={}", fp6(url))
    );
    assert_eq!(display_of(out, "EMPTY"), "empty");
    assert_eq!(display_of(out, "QUOTED_EMPTY"), "empty");
    assert_eq!(display_of(out, "TOKEN"), "placeholder");
    assert_eq!(display_of(out, "#OLD_KEY"), "commented");
    assert_eq!(display_of(out, "PORT"), "8899");
    assert_eq!(display_of(out, "SHORT"), "set len=7");
    assert_eq!(display_of(out, "DEBUG"), "TRUE");
    assert_eq!(display_of(out, "ANGLE"), "placeholder");
    assert_eq!(display_of(out, "XS"), "placeholder");
    assert_eq!(display_of(out, "CHANGE"), "placeholder");
    assert_eq!(display_of(out, "TODO_K"), "placeholder");
    let db = "postgres://admin:hunter2pw@db.internal:5432/app";
    assert_eq!(
        display_of(out, "DB"),
        format!("set url=postgres://db.internal/… fp={}", fp6(db))
    );
    assert_eq!(label_of(out, "#OLD_KEY"), "L6");
    assert_eq!(label_of(out, "DB"), "L15");
    for secret in [
        api,
        "0b1c2d3e-4f5a",
        "legacy-secret-value",
        "hunter2pw",
        "admin",
        "paste key",
    ] {
        assert!(!out.contains(secret), "leaked {secret}: {out}");
    }
}

#[test]
fn keys_defaults_to_dotenv_in_cwd() {
    let dir = TempDir::new("env-keys-default");
    fs::write(dir.join(".env"), "A=devnet\n").unwrap();
    let r = run_env(dir.path(), &["keys"]);
    ok(&r);
    assert_eq!(r.stdout, "# .env keys=1 crlf=no\nL1   A   devnet\n");
}

#[test]
fn keys_header_reports_crlf_and_bom() {
    let dir = TempDir::new("env-keys-crlf");
    fs::write(dir.join("a.env"), "\u{feff}A=1\r\nB=2\r\n").unwrap();
    fs::write(dir.join("b.env"), "A=1\r\nB=2\n").unwrap();
    let a = run_env(dir.path(), &["keys", "a.env"]);
    ok(&a);
    assert!(
        a.stdout.starts_with("# a.env keys=2 crlf=yes bom=yes\n"),
        "{}",
        a.stdout
    );
    assert_eq!(display_of(&a.stdout, "A"), "1");
    let b = run_env(dir.path(), &["keys", "b.env"]);
    ok(&b);
    assert!(
        b.stdout.starts_with("# b.env keys=2 crlf=mixed\n"),
        "{}",
        b.stdout
    );
}

#[test]
fn keys_annotates_duplicates_last_wins() {
    let dir = TempDir::new("env-keys-dup");
    fs::write(
        dir.join(".env.local"),
        "A=one-secret-value-1\nB=x\nA=two-secret-value-2\n",
    )
    .unwrap();
    let r = run_env(dir.path(), &["keys", ".env.local"]);
    ok(&r);
    assert!(r.stdout.starts_with("# .env.local keys=2 "), "{}", r.stdout);
    let rows: Vec<&str> = r.stdout.lines().filter(|l| l.contains(" A ")).collect();
    assert_eq!(rows.len(), 2, "{}", r.stdout);
    assert!(rows[0].starts_with("L1 "), "{}", rows[0]);
    assert!(
        rows[0].ends_with("(duplicate; overridden by L3)"),
        "{}",
        rows[0]
    );
    assert!(rows[1].starts_with("L3 "), "{}", rows[1]);
    assert!(
        rows[1].ends_with("(duplicate; this line wins)"),
        "{}",
        rows[1]
    );
    assert!(rows[1].contains(&format!("fp={}", fp6("two-secret-value-2"))));
}

#[test]
fn keys_counts_multiline_lines_and_export() {
    let dir = TempDir::new("env-keys-ml");
    let body = "A=1\nexport PEM=\"-----BEGIN KEY-----\nAAAA\n-----END KEY-----\"\nZ=devnet\n";
    fs::write(dir.join(".env.local"), body).unwrap();
    let r = run_env(dir.path(), &["keys", ".env.local"]);
    ok(&r);
    let pem = "-----BEGIN KEY-----\nAAAA\n-----END KEY-----";
    assert!(r.stdout.contains("L2   PEM"), "{}", r.stdout);
    assert_eq!(
        display_of(&r.stdout, "PEM"),
        format!("set len={} fp={}", pem.len(), fp6(pem))
    );
    assert!(r.stdout.contains("L5   Z"), "{}", r.stdout);
}

#[test]
fn keys_json() {
    let dir = TempDir::new("env-keys-json");
    let api = "3f9a1c0b7e2d4a6f8b1c3e5d7f9a0b2c4d6e";
    fs::write(
        dir.join(".env.local"),
        format!("export HELIUS_API_KEY='{api}'\nCLUSTER=devnet\n#OLD=x\nA=1\nA=2\n"),
    )
    .unwrap();
    let r = run_env(dir.path(), &["keys", ".env.local", "--json"]);
    ok(&r);
    let v = r.json();
    assert_eq!(v["file"], ".env.local");
    assert_eq!(v["format"], "dotenv");
    assert_eq!(v["crlf"], "no");
    assert_eq!(v["bom"], false);
    let keys = v["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 5);
    assert_eq!(keys[0]["line"], 1);
    assert_eq!(keys[0]["key"], "HELIUS_API_KEY");
    assert_eq!(keys[0]["status"], "set");
    assert_eq!(keys[0]["len"], 36);
    assert_eq!(keys[0]["fp"], fp6(api));
    assert_eq!(keys[0]["export"], true);
    assert_eq!(keys[0]["quote"], "single");
    assert_eq!(keys[0]["display"], format!("set len=36 fp={}", fp6(api)));
    assert_eq!(keys[1]["status"], "verbatim");
    assert_eq!(keys[1]["value"], "devnet");
    assert_eq!(keys[2]["key"], "OLD");
    assert_eq!(keys[2]["status"], "commented");
    assert_eq!(keys[3]["duplicate"], "overridden");
    assert_eq!(keys[3]["overridden_by"], 5);
    assert_eq!(keys[4]["duplicate"], "wins");
    assert!(v.get("require").is_none());
    assert!(!r.stdout.contains(api));
}

#[test]
fn keys_require_passes_and_fails_with_exit_3() {
    let dir = TempDir::new("env-keys-req");
    fs::write(
        dir.join(".env.local"),
        "API=3f9a1c0b7e2d4a6f\nCLUSTER=devnet\nEMPTY=\nTOKEN=<your token>\n#OLD=abc\n",
    )
    .unwrap();
    let pass = run_env(
        dir.path(),
        &["keys", ".env.local", "--require", "API,CLUSTER"],
    );
    ok(&pass);

    let fail = run_env(
        dir.path(),
        &["keys", ".env.local", "--require=API,NOPE,EMPTY,TOKEN,OLD"],
    );
    code(&fail, 3);
    assert!(
        fail.stdout.starts_with("# .env.local keys=4 "),
        "{}",
        fail.stdout
    );
    for want in [
        "NOPE (missing)",
        "EMPTY (empty)",
        "TOKEN (placeholder)",
        "OLD (missing)",
    ] {
        assert!(fail.stderr.contains(want), "want {want}: {}", fail.stderr);
    }
    assert!(!fail.stderr.contains("API ("), "{}", fail.stderr);

    let json = run_env(
        dir.path(),
        &["keys", ".env.local", "--json", "--require", "API,NOPE"],
    );
    code(&json, 3);
    let v = json.json();
    assert_eq!(v["require"]["ok"], false);
    assert_eq!(v["require"]["unmet"][0]["key"], "NOPE");
    assert_eq!(v["require"]["unmet"][0]["reason"], "missing");
}

#[test]
fn keys_require_on_missing_file_exits_3() {
    let dir = TempDir::new("env-keys-req-missing");
    let r = run_env(dir.path(), &["keys", "prod.env", "--require", "API"]);
    code(&r, 3);
    assert!(r.stderr.contains("no such file"), "{}", r.stderr);
    assert!(r.stderr.contains("API (missing)"), "{}", r.stderr);
}

#[test]
fn keys_missing_file_is_an_error() {
    let dir = TempDir::new("env-keys-missing");
    let r = run_env(dir.path(), &["keys", "prod.env"]);
    code(&r, 1);
    assert_eq!(r.stdout, "");
    assert!(r.stderr.contains("prod.env: no such file"), "{}", r.stderr);
}

// ---------------------------------------------------------------------------------------
// set: round trips (exact bytes)
// ---------------------------------------------------------------------------------------

#[test]
fn set_crlf_file_keeps_crlf() {
    let dir = TempDir::new("env-set-crlf");
    let f = dir.join(".env.local");
    fs::write(&f, "A=1\r\nB=old\r\n").unwrap();
    ok(&set(dir.path(), ".env.local", "B", "x y", &[]));
    assert_eq!(read(&f), "A=1\r\nB=\"x y\"\r\n");
    ok(&set(dir.path(), ".env.local", "C", "new", &[]));
    assert_eq!(read(&f), "A=1\r\nB=\"x y\"\r\nC=new\r\n");
}

#[test]
fn set_keeps_bom_and_missing_trailing_newline() {
    let dir = TempDir::new("env-set-bom");
    let f = dir.join(".env.local");
    fs::write(&f, "\u{feff}A=1\nB=2").unwrap();
    ok(&set(dir.path(), ".env.local", "A", "9", &[]));
    assert_eq!(read(&f), "\u{feff}A=9\nB=2");
    ok(&set(dir.path(), ".env.local", "B", "3", &[]));
    assert_eq!(read(&f), "\u{feff}A=9\nB=3");
}

#[test]
fn set_appends_with_final_newline() {
    let dir = TempDir::new("env-set-append");
    let f = dir.join(".env.local");
    fs::write(&f, "A=1").unwrap();
    let r = set(dir.path(), ".env.local", "B", "2", &[]);
    ok(&r);
    assert_eq!(read(&f), "A=1\nB=2\n");
    assert!(r.stdout.contains("added B L2"), "{}", r.stdout);

    let g = dir.join("bom.env");
    fs::write(&g, "\u{feff}").unwrap();
    ok(&set(dir.path(), "bom.env", "A", "1", &[]));
    assert_eq!(read(&g), "\u{feff}A=1\n");

    let h = dir.join("empty.env");
    fs::write(&h, "").unwrap();
    ok(&set(dir.path(), "empty.env", "A", "1", &[]));
    assert_eq!(read(&h), "A=1\n");
}

#[test]
fn set_keeps_export_prefix() {
    let dir = TempDir::new("env-set-export");
    let f = dir.join(".env.local");
    fs::write(&f, "export A=1\nexport  B='x'\n").unwrap();
    ok(&set(dir.path(), ".env.local", "A", "zz", &[]));
    ok(&set(dir.path(), ".env.local", "B", "y", &[]));
    assert_eq!(read(&f), "export A=zz\nexport  B='y'\n");
    // A new key follows the style of the last assignment.
    ok(&set(dir.path(), ".env.local", "C", "v", &[]));
    assert_eq!(read(&f), "export A=zz\nexport  B='y'\nexport C=v\n");

    let g = dir.join("plain.env");
    fs::write(&g, "A=1\n").unwrap();
    ok(&set(dir.path(), "plain.env", "C", "v", &[]));
    assert_eq!(read(&g), "A=1\nC=v\n");
}

#[test]
fn set_envrc_new_keys_are_exported() {
    let dir = TempDir::new("env-set-envrc");
    let r = set(dir.path(), ".envrc", "A", "v", &[]);
    ok(&r);
    assert_eq!(read(&dir.join(".envrc")), "export A=v\n");
}

#[test]
fn set_quote_styles() {
    let dir = TempDir::new("env-set-quotes");
    let f = dir.join(".env.local");
    fs::write(
        &f,
        "S='old'\nD=\"old\"\nB1=old\nB2=old\nS2='old'\nB3=old\nB4=old\nB5=old\nD2=\"old\"\nB6=old\n\
         B7=old\nB8=old\n",
    )
    .unwrap();
    let cases = [
        ("S", "it is $5"),
        ("D", "it is $5"),
        ("B1", "plain-value_1.x/y:z@h%2B,=?&~"),
        ("B2", "has space"),
        ("S2", "it's"),
        ("B3", "a#b c"),
        ("B4", "x'y$z"),
        ("B5", "back`tick"),
        ("D2", "q\"uo\\te"),
        ("B6", ""),
        // Tilde expansion when the file is `source`d (direnv): quote `~…` and `…:~…`.
        ("B7", "~/keys/id.json"),
        ("B8", "/opt/bin:~/bin"),
    ];
    for (k, v) in cases {
        ok(&set(dir.path(), ".env.local", k, v, &[]));
    }
    assert_eq!(
        read(&f),
        "S='it is $5'\nD=\"it is \\$5\"\nB1=plain-value_1.x/y:z@h%2B,=?&~\nB2=\"has space\"\n\
         S2=\"it's\"\nB3=\"a#b c\"\nB4=\"x'y\\$z\"\nB5='back`tick'\nD2=\"q\\\"uo\\\\te\"\nB6=\n\
         B7=\"~/keys/id.json\"\nB8=\"/opt/bin:~/bin\"\n"
    );
}

#[test]
fn set_dollar_hash_space_round_trip_through_keys() {
    let dir = TempDir::new("env-set-specials");
    let f = dir.join(".env.local");
    let value = "p@ss w0rd #1 $HOME";
    ok(&set(dir.path(), ".env.local", "PW", value, &[]));
    assert_eq!(read(&f), "PW='p@ss w0rd #1 $HOME'\n");
    let k = run_env(dir.path(), &["keys", ".env.local"]);
    ok(&k);
    assert_eq!(
        display_of(&k.stdout, "PW"),
        format!("set len={} fp={}", value.len(), fp6(value))
    );
}

#[test]
fn set_quoted_keeps_inline_comment_bare_line_replaced_whole() {
    let dir = TempDir::new("env-set-comment");
    let f = dir.join(".env.local");
    fs::write(&f, "K=\"old\"  # note\nB=old # trailing\n").unwrap();
    ok(&set(dir.path(), ".env.local", "K", "new", &[]));
    ok(&set(dir.path(), ".env.local", "B", "new", &[]));
    assert_eq!(read(&f), "K=\"new\"  # note\nB=new\n");
}

#[test]
fn set_multiline_pem() {
    let dir = TempDir::new("env-set-pem");
    let f = dir.join(".env.local");
    fs::write(&f, "BEFORE=1\nAFTER=2\n").unwrap();
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----";
    let r = set(
        dir.path(),
        ".env.local",
        "PEM",
        &format!("{pem}\n"),
        &["--multiline"],
    );
    ok(&r);
    assert_eq!(read(&f), format!("BEFORE=1\nAFTER=2\nPEM=\"{pem}\"\n"));
    let k = run_env(dir.path(), &["keys", ".env.local"]);
    assert_eq!(
        display_of(&k.stdout, "PEM"),
        format!("set len={} fp={}", pem.len(), fp6(pem))
    );

    // Replace it with another PEM and append after it: the multiline entry stays one entry.
    let pem2 = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBc9\n-----END EC PRIVATE KEY-----";
    ok(&set(
        dir.path(),
        ".env.local",
        "PEM",
        pem2,
        &["--multiline"],
    ));
    ok(&set(dir.path(), ".env.local", "Z", "devnet", &[]));
    assert_eq!(
        read(&f),
        format!("BEFORE=1\nAFTER=2\nPEM=\"{pem2}\"\nZ=devnet\n")
    );
    let k = run_env(dir.path(), &["keys", ".env.local"]);
    assert!(k.stdout.contains("L6   Z"), "{}", k.stdout);
}

#[test]
fn set_multiline_into_crlf_file_uses_crlf() {
    let dir = TempDir::new("env-set-pem-crlf");
    let f = dir.join(".env.local");
    fs::write(&f, "A=1\r\n").unwrap();
    ok(&set(
        dir.path(),
        ".env.local",
        "PEM",
        "l1\r\nl2\r\n",
        &["--multiline"],
    ));
    assert_eq!(read(&f), "A=1\r\nPEM=\"l1\r\nl2\"\r\n");
    let k = run_env(dir.path(), &["keys", ".env.local"]);
    assert_eq!(display_of(&k.stdout, "PEM"), "set len=5");
}

#[test]
fn set_rejects_newline_without_multiline() {
    let dir = TempDir::new("env-set-nl");
    let f = dir.join(".env.local");
    fs::write(&f, "A=1\n").unwrap();
    let r = set(dir.path(), ".env.local", "A", "line1\nline2", &[]);
    code(&r, 1);
    assert!(r.stderr.contains("--multiline"), "{}", r.stderr);
    assert_eq!(read(&f), "A=1\n");
    // Exactly one trailing newline is stripped, so `echo value |` works without --multiline.
    ok(&set(dir.path(), ".env.local", "A", "v2\n", &[]));
    assert_eq!(read(&f), "A=v2\n");
    ok(&set(dir.path(), ".env.local", "A", "v3\r\n", &[]));
    assert_eq!(read(&f), "A=v3\n");
}

#[test]
fn set_duplicates_updates_last_and_warns_all_updates_every() {
    let dir = TempDir::new("env-set-dup");
    let f = dir.join(".env.local");
    fs::write(&f, "A=1\nB=2\nA=3\n").unwrap();
    let r = set(dir.path(), ".env.local", "A", "4", &[]);
    ok(&r);
    assert_eq!(read(&f), "A=1\nB=2\nA=4\n");
    assert!(
        r.stderr.contains("L1") && r.stderr.contains("L3") && r.stderr.contains("--all"),
        "{}",
        r.stderr
    );
    let r = set(dir.path(), ".env.local", "A", "5", &["--all"]);
    ok(&r);
    assert_eq!(read(&f), "A=5\nB=2\nA=5\n");
}

#[test]
fn set_leaves_commented_keys_untouched() {
    let dir = TempDir::new("env-set-commented");
    let f = dir.join(".env.local");
    fs::write(&f, "#A=old\n# export B=x\n").unwrap();
    ok(&set(dir.path(), ".env.local", "A", "new", &[]));
    assert_eq!(read(&f), "#A=old\n# export B=x\nA=new\n");
}

#[test]
fn set_same_value_is_unchanged() {
    let dir = TempDir::new("env-set-same");
    let f = dir.join(".env.local");
    fs::write(&f, "A=\"same value\" # keep\n").unwrap();
    let r = set(dir.path(), ".env.local", "A", "same value", &[]);
    ok(&r);
    assert_eq!(r.stdout, "unchanged A L1\n");
    assert_eq!(read(&f), "A=\"same value\" # keep\n");
}

#[test]
fn set_reports_update_by_fingerprint() {
    let dir = TempDir::new("env-set-report");
    let old = "3f9a1c0b7e2d4a6f8b1c3e5d7f9a0b2c4d6e";
    let new = "9b0e77aa11bb22cc33dd44ee55ff66aa77bb";
    fs::write(
        dir.join(".env.local"),
        format!("X=1\nY=2\nHELIUS_API_KEY={old}\n"),
    )
    .unwrap();
    let r = set(dir.path(), ".env.local", "HELIUS_API_KEY", new, &[]);
    ok(&r);
    assert_eq!(
        r.stdout,
        format!("updated HELIUS_API_KEY L3 fp {}→{}\n", fp6(old), fp6(new))
    );
    let r = set(dir.path(), ".env.local", "X", "devnet", &[]);
    assert_eq!(r.stdout, "updated X L1 1→devnet\n");
}

#[test]
fn set_warns_on_url_host_change_without_leaking_query() {
    let dir = TempDir::new("env-set-url");
    let f = dir.join(".env.local");
    fs::write(&f, "RPC_URL=https://api.devnet.solana.com\n").unwrap();
    let r = set(
        dir.path(),
        ".env.local",
        "RPC_URL",
        "https://mainnet.helius-rpc.com/?api-key=SECRETSECRETSECRET",
        &[],
    );
    ok(&r);
    assert!(
        r.stderr.contains("api.devnet.solana.com") && r.stderr.contains("mainnet.helius-rpc.com"),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains("SECRETSECRET") && !r.stdout.contains("SECRETSECRET"));
}

#[test]
fn set_creates_missing_file_0600() {
    let dir = TempDir::new("env-set-create");
    let r = set(dir.path(), ".env.local", "K", "v", &[]);
    ok(&r);
    assert!(
        r.stdout.contains("created .env.local (mode 0600)"),
        "{}",
        r.stdout
    );
    assert_eq!(read(&dir.join(".env.local")), "K=v\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.join(".env.local"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn set_missing_parent_dir_is_an_error() {
    let dir = TempDir::new("env-set-noparent");
    let r = set(dir.path(), "nope/.env.local", "K", "v", &[]);
    code(&r, 1);
    assert!(!dir.join("nope").exists());
}

#[cfg(unix)]
#[test]
fn set_keeps_existing_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("env-set-mode");
    let f = dir.join(".env.local");
    for mode in [0o600, 0o640, 0o400] {
        fs::write(&f, "A=1\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(mode)).unwrap();
        ok(&set(dir.path(), ".env.local", "A", "2", &[]));
        assert_eq!(read(&f), "A=2\n");
        let got = fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, mode, "mode {mode:o} not kept");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_no_temp_files(dir.path());
}

#[cfg(unix)]
#[test]
fn set_writes_through_symlink() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new("env-set-symlink");
    fs::create_dir(dir.join("secrets")).unwrap();
    let real = dir.join("secrets/.env.production");
    fs::write(&real, "A=1\n").unwrap();
    symlink("secrets/.env.production", dir.join(".env.local")).unwrap();
    ok(&set(dir.path(), ".env.local", "A", "2", &[]));
    assert!(fs::symlink_metadata(dir.join(".env.local"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(read(&real), "A=2\n");
    assert_no_temp_files(dir.path());
    assert_no_temp_files(&dir.join("secrets"));
    let k = run_env(dir.path(), &["keys", ".env.local"]);
    ok(&k);
    assert_eq!(display_of(&k.stdout, "A"), "2");
}

#[cfg(unix)]
#[test]
fn symlink_to_non_env_file_is_refused() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new("env-symlink-refuse");
    fs::write(dir.join("notes.txt"), "A=1\n").unwrap();
    symlink("notes.txt", dir.join(".env.local")).unwrap();
    let r = set(dir.path(), ".env.local", "A", "2", &[]);
    code(&r, 1);
    assert!(r.stderr.contains("symlink"), "{}", r.stderr);
    assert_eq!(read(&dir.join("notes.txt")), "A=1\n");
    code(&run_env(dir.path(), &["keys", ".env.local"]), 1);
    code(&unset(dir.path(), ".env.local", "A"), 1);
    assert_eq!(read(&dir.join("notes.txt")), "A=1\n");

    symlink("missing.env", dir.join("dangling.env")).unwrap();
    code(&set(dir.path(), "dangling.env", "A", "1", &[]), 1);
    assert!(!dir.join("missing.env").exists());
}

#[test]
fn non_env_files_are_refused() {
    for name in [
        "notes.txt",
        "config.json",
        "env",
        "environment",
        ".env.example",
        ".env.sample",
        ".env.template",
        ".ENV.DIST",
    ] {
        let dir = TempDir::new("env-refuse");
        let f = dir.join(name);
        fs::write(&f, "A=1\n").unwrap();
        let k = run_env(dir.path(), &["keys", name]);
        code(&k, 1);
        assert_eq!(k.stdout, "", "{name}");
        let s = set(dir.path(), name, "A", "2", &[]);
        code(&s, 1);
        code(&unset(dir.path(), name, "A"), 1);
        assert_eq!(read(&f), "A=1\n", "{name} modified");
        if name.to_ascii_lowercase().starts_with(".env.") {
            assert!(s.stderr.contains("not secret"), "{name}: {}", s.stderr);
        } else {
            assert!(
                s.stderr.contains("not an env-class file"),
                "{name}: {}",
                s.stderr
            );
        }
    }
    let dir = TempDir::new("env-refuse-new");
    code(&set(dir.path(), "new.txt", "A", "1", &[]), 1);
    assert!(!dir.join("new.txt").exists());
}

#[test]
fn env_class_names_are_accepted_case_insensitively() {
    for name in [
        ".env.local",
        ".ENV.LOCAL",
        ".Env.Production",
        "prod.env",
        "PROD.ENV",
        ".envrc",
        ".dev.vars",
        ".env.example.local",
    ] {
        let dir = TempDir::new("env-accept");
        let r = set(dir.path(), name, "A", "v", &[]);
        ok(&r);
        assert!(read(&dir.join(name)).contains("A=v\n"), "{name}");
        ok(&run_env(dir.path(), &["keys", name]));
    }
}

#[test]
fn directory_named_like_env_is_refused() {
    let dir = TempDir::new("env-dir");
    fs::create_dir(dir.join(".env.d")).unwrap();
    let r = set(dir.path(), ".env.d", "A", "1", &[]);
    code(&r, 1);
    assert!(r.stderr.contains("not a regular file"), "{}", r.stderr);
}

#[test]
fn refusals_never_echo_the_file_argument() {
    let dir = TempDir::new("env-refuse-echo");
    let d = dir.path();
    // A secret pasted where FILE goes must not be printed back.
    let secret = "sk_\x6cive_51Hx9QbF2eZvKYlo2C8dK3mN";
    let existing = format!("{secret}.txt");
    fs::write(dir.join(&existing), "A=1\n").unwrap();
    let nested = format!("{secret}/notes.txt");
    let env_in_missing_dir = format!("{secret}/.env.local");
    let runs: Vec<(Vec<&str>, Option<&str>)> = vec![
        (vec!["keys", secret], None),
        (vec!["keys", &existing], None),
        (vec!["keys", &existing, "--require", "A"], None),
        (vec!["set", secret, "K"], Some("v")),
        (vec!["set", &existing, "K"], Some("v")),
        (vec!["unset", &existing, "K"], None),
        (vec!["unset", secret, "K"], None),
        (vec!["keys", &nested], None),
        (vec!["set", &nested, "K"], Some("v")),
        (vec!["set", &env_in_missing_dir, "K"], Some("v")),
        (vec!["keys", &env_in_missing_dir], None),
    ];
    for (args, stdin) in runs {
        let r = run_env_in(d, &args, stdin);
        code(&r, 1);
        assert_eq!(r.stdout, "", "{args:?}");
        assert!(
            !r.stderr.contains(secret),
            "{args:?} echoed FILE: {}",
            r.stderr
        );
    }
    assert_eq!(read(&dir.join(&existing)), "A=1\n");

    // Once FILE passes the env-class check, only its basename is printed.
    let r = run_env(d, &["keys", &env_in_missing_dir]);
    assert!(r.stderr.contains(".env.local"), "{}", r.stderr);
    fs::create_dir(dir.join("sub")).unwrap();
    let r = set(d, "sub/.env.local", "K", "v", &[]);
    ok(&r);
    assert_eq!(
        r.stdout,
        "created .env.local (mode 0600)\nadded K L1 set len=1\n"
    );
}

// ---------------------------------------------------------------------------------------
// unset
// ---------------------------------------------------------------------------------------

#[test]
fn unset_removes_every_occurrence() {
    let dir = TempDir::new("env-unset");
    let f = dir.join(".env.local");
    fs::write(&f, "A=1\nB=2\nA=3\n").unwrap();
    let r = unset(dir.path(), ".env.local", "A");
    ok(&r);
    assert_eq!(r.stdout, "removed A L1, L3\n");
    assert_eq!(read(&f), "B=2\n");
}

#[test]
fn unset_keeps_missing_trailing_newline() {
    let dir = TempDir::new("env-unset-nonl");
    let f = dir.join(".env.local");
    fs::write(&f, "A=1\nB=2").unwrap();
    ok(&unset(dir.path(), ".env.local", "B"));
    assert_eq!(read(&f), "A=1");
    fs::write(&f, "A=1\nB=2").unwrap();
    ok(&unset(dir.path(), ".env.local", "A"));
    assert_eq!(read(&f), "B=2");
    fs::write(&f, "\u{feff}A=1\r\nB=2\r\n").unwrap();
    ok(&unset(dir.path(), ".env.local", "A"));
    assert_eq!(read(&f), "\u{feff}B=2\r\n");
}

#[test]
fn unset_multiline_entry() {
    let dir = TempDir::new("env-unset-ml");
    let f = dir.join(".env.local");
    fs::write(
        &f,
        "A=1\nPEM=\"-----BEGIN KEY-----\nAAAA\n-----END KEY-----\" # pem\nZ=2\n",
    )
    .unwrap();
    let r = unset(dir.path(), ".env.local", "PEM");
    ok(&r);
    assert_eq!(r.stdout, "removed PEM L2\n");
    assert_eq!(read(&f), "A=1\nZ=2\n");
}

#[test]
fn unset_absent_key_is_a_no_op() {
    let dir = TempDir::new("env-unset-absent");
    let f = dir.join(".env.local");
    fs::write(&f, "#A=1\nB=2\n").unwrap();
    let r = unset(dir.path(), ".env.local", "A");
    ok(&r);
    assert_eq!(r.stdout, "A not set in .env.local (no change)\n");
    assert_eq!(read(&f), "#A=1\nB=2\n");
}

#[test]
fn unset_missing_file_is_an_error() {
    let dir = TempDir::new("env-unset-missing");
    let r = unset(dir.path(), ".env.local", "A");
    code(&r, 1);
    assert!(r.stderr.contains("no such file"), "{}", r.stderr);
    assert!(!dir.join(".env.local").exists());
}

// ---------------------------------------------------------------------------------------
// Solana CLI config (env class, YAML, read-only)
// ---------------------------------------------------------------------------------------

#[test]
fn solana_cli_config_is_listed_masked_and_never_written() {
    let dir = TempDir::new("env-solana-cfg");
    let cfg_dir = dir.join(".config/solana/cli");
    fs::create_dir_all(&cfg_dir).unwrap();
    let url = "https://mainnet.helius-rpc.com/?api-key=abcdefabcdefabcdef";
    let body = format!(
        "---\njson_rpc_url: \"{url}\"\nwebsocket_url: \"\"\nkeypair_path: /home/u/.config/solana/id.json\n\
         address_labels:\n  \"11111111111111111111111111111111\": System Program\ncommitment: confirmed\n"
    );
    let cfg = cfg_dir.join("config.yml");
    fs::write(&cfg, &body).unwrap();

    for arg in [
        "~/.config/solana/cli/config.yml".to_string(),
        cfg.display().to_string(),
    ] {
        let r = run_env(dir.path(), &["keys", &arg]);
        ok(&r);
        assert!(r.stdout.contains(" keys=4 "), "{}", r.stdout);
        assert_eq!(
            display_of(&r.stdout, "json_rpc_url"),
            format!("set url=https://mainnet.helius-rpc.com/… fp={}", fp6(url))
        );
        assert_eq!(display_of(&r.stdout, "websocket_url"), "empty");
        assert!(r.stdout.contains("L2   json_rpc_url"), "{}", r.stdout);
        assert!(r.stdout.contains("L7   commitment"), "{}", r.stdout);
        assert!(!r.stdout.contains("abcdefabcdef"), "{}", r.stdout);
        let j = run_env(dir.path(), &["keys", &arg, "--json"]);
        assert_eq!(j.json()["format"], "yaml");
    }

    let r = set(
        dir.path(),
        "~/.config/solana/cli/config.yml",
        "json_rpc_url",
        "https://api.devnet.solana.com",
        &[],
    );
    code(&r, 1);
    assert!(r.stderr.contains("solana config set"), "{}", r.stderr);
    code(
        &unset(dir.path(), "~/.config/solana/cli/config.yml", "commitment"),
        1,
    );
    assert_eq!(read(&cfg), body);
}

// ---------------------------------------------------------------------------------------
// Invocation errors (exit 3, nothing on stdout)
// ---------------------------------------------------------------------------------------

#[test]
fn usage_errors_exit_3() {
    let dir = TempDir::new("env-usage");
    fs::write(dir.join(".env.local"), "A=1\n").unwrap();
    let cases: &[&[&str]] = &[
        &[],
        &["bogus"],
        &["set"],
        &["set", ".env.local"],
        &["set", ".env.local", "A", "extra"],
        &["unset", ".env.local"],
        &["unset", ".env.local", "A", "B"],
        &["keys", ".env.local", "other.env"],
        &["keys", "--bogus"],
        &["keys", "--require"],
        &["set", ".env.local", "BAD-KEY"],
        &["set", ".env.local", "1BAD"],
        &["unset", ".env.local", "A=1"],
        &["keys", ".env.local", "--require", "OK,BAD-KEY"],
        &["set", ".env.local", "A", "--json"],
        &["keys", ".env.local", "--multiline"],
    ];
    for args in cases {
        let r = run_env_in(dir.path(), args, Some(""));
        code(&r, 3);
        assert_eq!(r.stdout, "", "args {args:?}");
        assert!(!r.stderr.is_empty(), "args {args:?}");
    }
    assert_eq!(read(&dir.join(".env.local")), "A=1\n");
}

#[test]
fn help_prints_usage() {
    let dir = TempDir::new("env-help");
    let r = run_env(dir.path(), &["--help"]);
    ok(&r);
    assert!(r.stdout.contains("safe-ai-skill env keys"), "{}", r.stdout);
    assert!(r.stdout.contains("safe-ai-skill env set"), "{}", r.stdout);
    assert!(r.stdout.contains("safe-ai-skill env unset"), "{}", r.stdout);
}

// ---------------------------------------------------------------------------------------
// Values never printed — every subcommand and error path
// ---------------------------------------------------------------------------------------

/// Every 8-byte window of each secret: none may appear in any output.
fn probes(secrets: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for s in secrets {
        let b = s.as_bytes();
        if b.len() <= 8 {
            out.push((*s).to_string());
            continue;
        }
        for w in b.windows(8) {
            if let Ok(p) = std::str::from_utf8(w) {
                if !p.contains('\n') && !p.chars().all(|c| c == '-') {
                    out.push(p.to_string());
                }
            }
        }
    }
    out
}

fn assert_silent(run: &Run, probes: &[String], what: &str) {
    for p in probes {
        assert!(
            !run.stdout.contains(p.as_str()),
            "{what}: stdout leaked {p:?}\n{}",
            run.stdout
        );
        assert!(
            !run.stderr.contains(p.as_str()),
            "{what}: stderr leaked {p:?}\n{}",
            run.stderr
        );
    }
}

#[test]
fn never_prints_values() {
    let dir = TempDir::new("env-never-print");
    let d = dir.path();

    // Secrets already in the file.
    let s1 = "sk_\x6cive_51Hx9QbF2eZvKYlo2C8dK3mN";
    let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----";
    let url_key = "q7Rw9TzXc2Vb8NmKp4Ls";
    let url = format!("https://mainnet.helius-rpc.com/?api-key={url_key}");
    let s4 = "p@ss w0rd #1 $HOME";
    let short = "hunter2x";
    let dup_old = "Dup0ldValue_9f8e7d6c";
    // Secrets supplied on stdin.
    let new1 = "ghp_Zq8Kd93LmPw0XyT6vRb2NcF4";
    let new_url_key = "Zx81Kq0Lm2Np3Rt4";
    let new_url = format!("https://other-rpc.example.org/v2/{new_url_key}");
    let pem2 = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBc9Yq3hX7vT1mR4nP8kL2wS6jD0fG5aZ\n-----END EC PRIVATE KEY-----";
    // URLs with credentials in the userinfo, one with a `?` inside the password.
    let db_user = "svc_admin_q9";
    let db_pass = "Pa55w0rdS3cretZ";
    let db_url = format!("https://{db_user}:{db_pass}@db.example.com/x");
    let alt_user = "alice.smith";
    let alt_pass = "s3cr?etP4ssW0rd";
    let alt_url = format!("https://{alt_user}:{alt_pass}@db2.example.com");
    let new_db_pass = "N3wPassw0rdQ7";
    let new_db_url = format!("https://{db_user}:{new_db_pass}@db3.example.com/x");
    let new_alt_pass = "N3w?Pass99Word";
    let new_alt_url = format!("https://{alt_user}:{new_alt_pass}@db2.example.com");

    let probes = probes(&[
        s1,
        pem,
        url_key,
        s4,
        short,
        dup_old,
        new1,
        new_url_key,
        pem2,
        db_user,
        db_pass,
        alt_user,
        alt_pass,
        new_db_pass,
        new_alt_pass,
    ]);

    let file = ".env.local";
    let body = format!(
        "S1={s1}\nPEM=\"{pem}\"\nRPC_URL={url}\nS4='{s4}'\nSHORT={short}\nDUP={dup_old}\nDUP={dup_old}\n#OLD={s1}\n\
         DB_URL={db_url}\nALT_URL={alt_url}\n"
    );
    fs::write(dir.join(file), &body).unwrap();
    fs::write(dir.join("notes.txt"), format!("S1={s1}\n")).unwrap();
    fs::write(dir.join("broken.env"), "A=\"unterminated\n").unwrap();
    fs::create_dir(dir.join(".env.d")).unwrap();
    let cfg_dir = dir.join(".config/solana/cli");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(cfg_dir.join("config.yml"), format!("json_rpc_url: {url}\n")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("notes.txt", dir.join("link.env")).unwrap();

    let big = new1.repeat((1 << 20) / new1.len() + 2);
    let with_nul = format!("{new1}\0{new1}");
    let with_nl = format!("{new1}\n{new1}");
    let with_cr = format!("{new1}\r{new1}");
    let key_with_value = format!("K={new1}");
    let opt_with_value = format!("--value={new1}");
    let swallow = format!("{new1}$\" #x");

    // (args, stdin, expected exit code)
    let runs: Vec<(Vec<&str>, Option<&str>, i32)> = vec![
        // keys
        (vec!["keys", file], None, 0),
        (vec!["keys", file, "--json"], None, 0),
        (vec!["keys", file, "--require", "S1,NOPE"], None, 3),
        (vec!["keys", file, "--json", "--require=S1,NOPE"], None, 3),
        (vec!["keys", "~/.config/solana/cli/config.yml"], None, 0),
        // set: update, append, duplicates, --all, multiline, URL host change
        (vec!["set", file, "S1"], Some(new1), 0),
        (vec!["set", file, "NEW"], Some(new1), 0),
        (vec!["set", file, "DUP"], Some(new1), 0),
        (vec!["set", file, "DUP", "--all"], Some(new1), 0),
        (vec!["set", file, "PEM", "--multiline"], Some(pem2), 0),
        (vec!["set", file, "RPC_URL"], Some(new_url.as_str()), 0),
        (vec!["set", file, "S4"], Some(s4), 0),
        // credentials in a URL's userinfo (host change warning on DB_URL)
        (vec!["set", file, "DB_URL"], Some(new_db_url.as_str()), 0),
        (vec!["set", file, "ALT_URL"], Some(new_alt_url.as_str()), 0),
        // unset
        (vec!["unset", file, "SHORT"], None, 0),
        (vec!["unset", file, "NEVER_SET"], None, 0),
        // error paths: missing file
        (vec!["keys", "missing.env"], None, 1),
        (vec!["unset", "missing.env", "S1"], None, 1),
        // bad key (value on stdin, or the value smuggled into the key argument)
        (vec!["set", file, "BAD-KEY"], Some(new1), 3),
        (vec!["set", file, key_with_value.as_str()], Some(""), 3),
        // value passed as an argument / unknown option carrying it
        (vec!["set", file, "K", new1], Some(""), 3),
        (
            vec!["set", file, "K", opt_with_value.as_str()],
            Some(new1),
            3,
        ),
        // refused files, including a secret pasted where FILE goes
        (vec!["set", "notes.txt", "S1"], Some(new1), 1),
        (vec!["keys", "notes.txt"], None, 1),
        (vec!["keys", s1], None, 1),
        (vec!["set", new1, "K"], Some(new1), 1),
        (vec!["unset", s1, "K"], None, 1),
        (vec!["set", ".env.d", "S1"], Some(new1), 1),
        (
            vec!["set", "~/.config/solana/cli/config.yml", "json_rpc_url"],
            Some(new_url.as_str()),
            1,
        ),
        // stdin errors
        (vec!["set", file, "K"], Some(with_nul.as_str()), 1),
        (vec!["set", file, "K"], Some(with_nl.as_str()), 1),
        (vec!["set", file, "K"], Some(with_cr.as_str()), 1),
        (vec!["set", file, "K"], Some(big.as_str()), 1),
        // an edit that would change how another line parses is refused
        (vec!["set", "broken.env", "K"], Some(swallow.as_str()), 1),
    ];

    for (args, stdin, expected) in &runs {
        let r = run_env_in(d, args, *stdin);
        code(&r, *expected);
        assert_silent(&r, &probes, &format!("env {args:?}"));
    }

    #[cfg(unix)]
    {
        let r = set(d, "link.env", "S1", new1, &[]);
        code(&r, 1);
        assert_silent(&r, &probes, "set via symlink to non-env file");
        let r = run_env(d, &["keys", "link.env"]);
        code(&r, 1);
        assert_silent(&r, &probes, "keys via symlink to non-env file");
    }

    // The refused edits left their files alone, and no temp file survived any path.
    assert_eq!(read(&dir.join("notes.txt")), format!("S1={s1}\n"));
    assert_eq!(read(&dir.join("broken.env")), "A=\"unterminated\n");
    assert_no_temp_files(d);

    // The final file still parses to the values we set (proves the sweep really wrote them).
    let k = run_env(d, &["keys", file]);
    ok(&k);
    assert_eq!(
        display_of(&k.stdout, "S1"),
        format!("set len={} fp={}", new1.len(), fp6(new1))
    );
    assert_eq!(
        display_of(&k.stdout, "PEM"),
        format!("set len={} fp={}", pem2.len(), fp6(pem2))
    );
    assert_silent(&k, &probes, "final keys");
}

// ---------------------------------------------------------------------------------------
// D8 v2 tier check: an agent's `env set|unset` (spec §2)
// ---------------------------------------------------------------------------------------

/// `safe-ai-skill env <args>` as a Claude Code session runs it (marker `marker=1`) at `tier`
/// (raised through the env hint, which needs no trusted data dir).
fn run_env_as_agent(
    dir: &Path,
    args: &[&str],
    stdin: Option<&str>,
    tier: &str,
    marker: &str,
) -> Run {
    let mut full = vec!["env"];
    full.extend_from_slice(args);
    let mut inv = Invocation::new(&full)
        .cwd(dir)
        .home(dir)
        .env("SAFE_AI_SKILL_TIER", tier)
        .env(marker, "1");
    if let Some(body) = stdin {
        inv = inv.stdin(body);
    }
    inv.run()
}

/// `safe-ai-skill env <args>` from the user's own terminal: a cleared environment (no Claude
/// Code marker of any kind), `HOME` and the Claude config dir pinned to `dir`.
fn run_env_in_terminal(dir: &Path, args: &[&str], stdin: &str, tier: &str) -> Run {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new(common::bin())
        .arg("env")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("CLAUDE_CONFIG_DIR", dir.join(".claude"))
        .env("SAFE_AI_SKILL_DATA", common::standalone_data(dir))
        .env("PATH", "/usr/bin:/bin")
        .env("SAFE_AI_SKILL_TIER", tier)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code(),
    }
}

#[test]
fn agent_set_and_unset_are_refused_at_medium() {
    let t = TempDir::new("env-tier");
    let d = t.path();
    let env = d.join(".env");
    fs::write(&env, "A=1\nB=2\n").unwrap();
    // At High a project `.env` stays writable (its reads are denied); another env file does not.
    let envrc = d.join(".envrc");
    fs::write(&envrc, "A=1\n").unwrap();
    let r = run_env_as_agent(d, &["set", ".envrc", "A"], Some("v"), "high", "CLAUDECODE");
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("tier high"), "{}", r.stderr);
    assert_eq!(read(&envrc), "A=1\n");
    for tier in ["medium"] {
        for marker in [
            "CLAUDECODE",
            "CLAUDE_PROJECT_DIR",
            "CLAUDE_PLUGIN_ROOT",
            "CLAUDE_CODE_ENTRYPOINT",
        ] {
            let r = run_env_as_agent(
                d,
                &["set", ".env", "A"],
                Some("secret_value_123"),
                tier,
                marker,
            );
            assert_eq!(r.code, Some(1), "{tier} {marker}: {}", r.stderr);
            assert!(r.stderr.contains(&format!("tier {tier}")), "{}", r.stderr);
            assert!(r.stderr.contains("own terminal"), "{}", r.stderr);
            assert!(!r.stderr.contains("secret_value_123"), "{}", r.stderr);
        }
        let r = run_env_as_agent(d, &["unset", ".env", "B"], None, tier, "CLAUDECODE");
        assert_eq!(r.code, Some(1), "{tier}: {}", r.stderr);
        assert_eq!(read(&env), "A=1\nB=2\n", "{tier}: file untouched");
        // `keys` works at every tier.
        ok(&run_env_as_agent(
            d,
            &["keys", ".env"],
            None,
            tier,
            "CLAUDECODE",
        ));
    }
}

#[test]
fn the_backstop_uses_the_target_files_project_tier() {
    // The repo raises its own tier to medium; the command runs from elsewhere.
    let proj = TempDir::new("env-tier-proj");
    let elsewhere = TempDir::new("env-tier-cwd");
    fs::create_dir_all(proj.join(".safe-ai-skill")).unwrap();
    fs::write(proj.join(".safe-ai-skill/policy.yaml"), "tier: medium\n").unwrap();
    let env = proj.join(".env");
    fs::write(&env, "A=1\n").unwrap();
    let target = env.to_str().unwrap();
    let r = run_env_as_agent(
        elsewhere.path(),
        &["set", target, "NEWK"],
        Some("v"),
        "relaxed",
        "CLAUDECODE",
    );
    assert_eq!(r.code, Some(1), "{}", r.stderr);
    assert!(r.stderr.contains("tier medium"), "{}", r.stderr);
    assert_eq!(read(&env), "A=1\n");
}

#[test]
fn set_works_from_the_users_terminal_and_below_medium() {
    let t = TempDir::new("env-tier-ok");
    let d = t.path();
    let env = d.join(".env");
    fs::write(&env, "A=1\n").unwrap();
    // The user's own terminal, at high.
    ok(&run_env_in_terminal(d, &["set", ".env", "A"], "v2", "high"));
    assert_eq!(read(&env), "A=v2\n");
    // A Claude Code session at relaxed.
    ok(&run_env_as_agent(
        d,
        &["set", ".env", "A"],
        Some("v3"),
        "relaxed",
        "CLAUDECODE",
    ));
    assert_eq!(read(&env), "A=v3\n");
}
