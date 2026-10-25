//! The naive-exfil tripwire, best-effort (D8 v2 spec §5; #19): a network call whose destination
//! is on the tier's exfil list ([`crate::lists::exfil_hosts`] plus `secrets.exfil_hosts_extra`),
//! or that carries secret-shaped data or an encoded blob to a host that is not a known
//! developer service.
//!
//! - **Destinations.** `curl`/`wget`/httpie (`http`, `https`, `xh`)/`nc`/`ncat`/`socat`/`telnet`/
//!   `ssh`/`scp`/`rsync`, `/dev/tcp/host/port` redirects, URLs inside interpreter one-liners
//!   (`python -c`, `node -e`, heredoc code), MCP `url`/`uri`/`href` arguments, executor shell
//!   code, browser scripts (`browser_evaluate`, `browser_run_code`, `javascript_tool`) and
//!   WebFetch ([`decide_webfetch`]).
//! - **Hosts** are normalised: lowercase, userinfo, port and trailing dots stripped, percent
//!   escapes decoded, fullwidth forms folded to ASCII. Real IDN-to-punycode needs the `idna`
//!   crate, which is not a dependency: a host still non-ASCII after folding is compared as is
//!   (every listed host is ASCII, so a homoglyph names a different domain anyway).
//! - **Verdicts.** A listed host denies; a GET from a paste or file-drop host ([`PASTE_HOSTS`])
//!   asks, since the request carries no body. Secret-shaped data ([`crate::redact`] detectors,
//!   also after base64, hex or percent decoding, at most [`MAX_DECODE_DEPTH`] levels and
//!   [`MAX_DECODE_BYTES`]) in the URL or body to a host off [`DEV_HOSTS`] denies. A base64 or
//!   hex blob of [`BLOB_MIN`] characters or more, or one decoding to a byte array, asks.
//!
//! The `curl`/`wget` upload and POST checks stay in [`crate::gates::secrets`]: this gate does
//! not repeat its POST-to-unknown-host ask. Call lines: `main::cmd_gate_bash_secrets`
//! ([`decide_bash`]), `main::cmd_gate_mcp` ([`decide_mcp`]), a WebFetch gate
//! ([`decide_webfetch`]).

use std::path::Path;

use serde_json::{Map, Value};

use crate::context::shell;
use crate::gate::Verdict;
use crate::gates::secrets::{SOLANA_RPC_ALCHEMY, SOLANA_RPC_HOSTS};
use crate::policy::tier::Tier;
use crate::policy::Policy;
use crate::redact;

/// Shortest base64 or hex run treated as an encoded blob.
pub const BLOB_MIN: usize = 64;
/// Most bytes decoded (base64, hex, percent) for one call.
pub const MAX_DECODE_BYTES: usize = 64 * 1024;
/// Deepest nested decoding (base64 of base64 …).
pub const MAX_DECODE_DEPTH: usize = 3;
/// Deepest MCP payload nesting searched.
const MAX_PAYLOAD_DEPTH: usize = 8;

/// Paste and file-drop hosts on the shared list: a plain GET from one asks instead of denying.
const PASTE_HOSTS: &[&str] = &[
    "*.catbox.moe",
    "*.gofile.io",
    "*.pastebin.com",
    "*.tmpfiles.org",
    "0x0.st",
    "anonfiles.com",
    "bashupload.com",
    "catbox.moe",
    "dpaste.com",
    "dpaste.org",
    "envs.sh",
    "file.io",
    "glot.io",
    "gofile.io",
    "hastebin.com",
    "ix.io",
    "keep.sh",
    "oshi.at",
    "paste.ee",
    "pastebin.com",
    "sprunge.us",
    "temp.sh",
    "termbin.com",
    "tmpfiles.org",
    "transfer.sh",
    "uguu.se",
    "x0.at",
];

/// Developer services where encoded payloads are routine (registries, code hosts, Solana docs
/// and explorers); each entry matches the host and its subdomains. Solana RPC hosts come from
/// [`SOLANA_RPC_HOSTS`]. A listed exfil host is denied even if it were here.
const DEV_HOSTS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "crates.io",
    "docs.rs",
    "rust-lang.org",
    "rustup.rs",
    "npmjs.org",
    "npmjs.com",
    "yarnpkg.com",
    "pypi.org",
    "pythonhosted.org",
    "solana.com",
    "anza.xyz",
    "anchor-lang.com",
    "helius.dev",
    "helius.xyz",
    "solscan.io",
    "solana.fm",
];

/// Programs whose positional words are URLs or bare hosts, by argument style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Curl,
    Wget,
    Httpie,
    Stream,
    Socat,
    Ssh,
    Copy,
    Fetcher,
    Interpreter,
}

fn style_of(program: &str) -> Option<Style> {
    Some(match program {
        "curl" | "curlie" => Style::Curl,
        "wget" | "wget2" => Style::Wget,
        "http" | "https" | "xh" | "xhs" => Style::Httpie,
        "nc" | "ncat" | "netcat" | "telnet" => Style::Stream,
        "socat" => Style::Socat,
        "ssh" => Style::Ssh,
        "scp" | "sftp" | "rsync" => Style::Copy,
        "aria2c" | "axel" | "lynx" | "w3m" | "links" | "iwr" | "irm" | "invoke-webrequest"
        | "invoke-restmethod" => Style::Fetcher,
        p if p.starts_with("python")
            || matches!(
                p,
                "node" | "nodejs" | "deno" | "bun" | "ruby" | "perl" | "php"
            ) =>
        {
            Style::Interpreter
        }
        _ => return None,
    })
}

/// curl flags whose next word is a value (not a URL); `--url` and `-x` are handled apart.
const CURL_VALUE_FLAGS: &[&str] = &[
    "-d",
    "--data",
    "--data-raw",
    "--data-ascii",
    "--data-binary",
    "--data-urlencode",
    "--json",
    "--url-query",
    "-F",
    "--form",
    "--form-string",
    "-T",
    "--upload-file",
    "-H",
    "--header",
    "-X",
    "--request",
    "-o",
    "--output",
    "-A",
    "--user-agent",
    "-e",
    "--referer",
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-u",
    "--user",
    "-m",
    "--max-time",
    "--connect-timeout",
    "--retry",
    "--retry-delay",
    "--retry-max-time",
    "-w",
    "--write-out",
    "-K",
    "--config",
    "-r",
    "--range",
    "-C",
    "--continue-at",
    "-E",
    "--cert",
    "--key",
    "--cacert",
    "--limit-rate",
    "-Y",
    "-y",
    "-z",
    "--resolve",
    "--connect-to",
    "--output-dir",
];

/// curl flags that send a body.
const CURL_BODY_FLAGS: &[&str] = &[
    "-d",
    "--data",
    "--data-raw",
    "--data-ascii",
    "--data-binary",
    "--data-urlencode",
    "--json",
    "--url-query",
    "-F",
    "--form",
    "--form-string",
    "-T",
    "--upload-file",
];

const WGET_VALUE_FLAGS: &[&str] = &[
    "-O",
    "--output-document",
    "-o",
    "--output-file",
    "-a",
    "--append-output",
    "-P",
    "--directory-prefix",
    "-t",
    "--tries",
    "-T",
    "--timeout",
    "-w",
    "--wait",
    "-U",
    "--user-agent",
    "--header",
    "--post-data",
    "--post-file",
    "--body-data",
    "--body-file",
    "--method",
    "-e",
    "--execute",
    "-i",
    "--input-file",
    "-B",
    "--base",
    "--user",
    "--password",
    "--http-user",
    "--http-password",
    "--referer",
];

const WGET_BODY_FLAGS: &[&str] = &["--post-data", "--post-file", "--body-data", "--body-file"];

const STREAM_VALUE_FLAGS: &[&str] = &[
    "-p",
    "-s",
    "-w",
    "-i",
    "-q",
    "-x",
    "-X",
    "-e",
    "-c",
    "-o",
    "-O",
    "-P",
    "-T",
    "-I",
    "-V",
    "--sh-exec",
    "--exec",
    "--source-port",
    "--wait",
    "--proxy",
    "--proxy-type",
];

const SSH_VALUE_FLAGS: &[&str] = &[
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q",
    "-R", "-S", "-W", "-w", "-P",
];

/// One network destination of a command.
#[derive(Debug, Clone, Default)]
struct Dest {
    host: String,
    /// Path, query and fragment as written.
    rest: String,
}

/// What one network command sends where.
#[derive(Debug, Clone, Default)]
struct Request {
    dests: Vec<Dest>,
    /// Text the request carries besides the URL (body, form items, script code).
    body: String,
    /// It sends data beyond a plain GET (a body, a stream, an upload, code that may post).
    sends: bool,
    /// A curl/wget POST: [`crate::gates::secrets`] already asks on an unknown host.
    secrets_gate_asks: bool,
    /// A browser script reading cookies or storage and calling a network sink.
    reads_page_secrets: bool,
}

/// The verdict for a Bash `command` run in `cwd`; `None` is no opinion.
pub fn decide_bash(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = cwd;
    if !may_reach_network(command) {
        return None;
    }
    let requests = bash_requests(command);
    if requests.is_empty() {
        return None;
    }
    let mut budget = MAX_DECODE_BYTES;
    strictest(requests.iter().map(|r| judge(r, policy, tier, &mut budget)))
}

/// The verdict for an MCP call `tool_name` with `payload`; `None` is no opinion.
pub fn decide_mcp(
    tool_name: &str,
    payload: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    tier: Tier,
) -> Option<Verdict> {
    let payload = payload?;
    let browser_js = is_browser_script_tool(tool_name);
    let mut verdicts = Vec::new();
    let mut budget = MAX_DECODE_BYTES;
    walk(payload, 0, &mut |key, value, siblings| {
        let lower = key.to_ascii_lowercase();
        match lower.as_str() {
            "url" | "uri" | "href" => {
                let request = url_request(value, siblings);
                verdicts.push(judge(&request, policy, tier, &mut budget));
            }
            "command" | "cmd" => verdicts.push(decide_bash(value, cwd, policy, tier)),
            "code" | "script" | "function" | "text" | "expression" | "js" if browser_js => {
                let request = code_request(value, true);
                verdicts.push(judge(&request, policy, tier, &mut budget));
            }
            "code" | "script" => {
                let language = siblings
                    .and_then(|m| m.get("language"))
                    .and_then(Value::as_str)
                    .unwrap_or("shell")
                    .to_ascii_lowercase();
                if matches!(language.as_str(), "shell" | "bash" | "sh" | "zsh") {
                    verdicts.push(decide_bash(value, cwd, policy, tier));
                } else {
                    let request = code_request(value, false);
                    verdicts.push(judge(&request, policy, tier, &mut budget));
                }
            }
            _ => {}
        }
    });
    strictest(verdicts)
}

/// The verdict for a WebFetch of `url` (a GET; `prompt` goes to a model, not the network);
/// `None` is no opinion.
pub fn decide_webfetch(url: &str, prompt: &str, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = prompt;
    let request = Request {
        dests: parse_url(url).into_iter().collect(),
        ..Request::default()
    };
    let mut budget = MAX_DECODE_BYTES;
    judge(&request, policy, tier, &mut budget)
}

// ---------------------------------------------------------------------------
// Judging
// ---------------------------------------------------------------------------

fn judge(request: &Request, policy: &Policy, tier: Tier, budget: &mut usize) -> Option<Verdict> {
    if request.dests.is_empty() {
        return None;
    }
    let listed = match crate::lists::exfil_hosts(tier) {
        Ok(hosts) => hosts,
        Err(e) => {
            return Some(Verdict::Ask(format!(
                "{e}, so the destination `{}` is unchecked; approve only if you trust it.",
                request.dests[0].host
            )))
        }
    };
    let extra: Vec<String> = if tier == Tier::Off {
        Vec::new()
    } else {
        policy
            .secrets
            .exfil_hosts_extra
            .iter()
            .map(|h| normalize_pattern(h))
            .collect()
    };
    let mut held: Option<Verdict> = None;
    for dest in &request.dests {
        let hit = listed
            .iter()
            .copied()
            .chain(extra.iter().map(String::as_str))
            .find(|pattern| host_matches(&dest.host, pattern));
        let Some(pattern) = hit else { continue };
        if !request.sends && PASTE_HOSTS.contains(&pattern) {
            held = Some(Verdict::Ask(format!(
                "`{}` is a paste or file-drop host and what it serves is untrusted; approve only \
                 if the user asked for this URL.",
                dest.host
            )));
            continue;
        }
        return Some(Verdict::Deny(format!(
            "safe-ai-skill blocks network calls to `{}`, a known exfiltration, tunnel or paste \
             host; use a different endpoint.",
            dest.host
        )));
    }
    let outside: Vec<&Dest> = request
        .dests
        .iter()
        .filter(|d| !is_dev_host(&d.host))
        .collect();
    let Some(first) = outside.first() else {
        return held;
    };
    let host = first.host.clone();
    let mut level = Level::None;
    for dest in &outside {
        level = level.max(scan(&dest.rest, 0, budget));
    }
    if !request.body.is_empty() {
        level = level.max(scan(&request.body, 0, budget));
    }
    match level {
        Level::Secret => {
            return Some(Verdict::Deny(format!(
                "This request sends secret-shaped data (a key, token or keypair) to `{host}`; \
                 remove the secret from the URL or body."
            )))
        }
        Level::Blob if !request.secrets_gate_asks => {
            return Some(Verdict::Ask(format!(
                "This request carries an encoded blob to `{host}` that may hold local data; \
                 approve only if you know what it contains."
            )))
        }
        _ => {}
    }
    if request.reads_page_secrets {
        return Some(Verdict::Ask(format!(
            "This browser script sends page cookies or storage to `{host}`; approve only if the \
             user asked for it."
        )));
    }
    held
}

fn strictest(verdicts: impl IntoIterator<Item = Option<Verdict>>) -> Option<Verdict> {
    let mut best: Option<Verdict> = None;
    for verdict in verdicts.into_iter().flatten() {
        match verdict {
            Verdict::Deny(_) => return Some(verdict),
            Verdict::Ask(_) if best.is_none() => best = Some(verdict),
            _ => {}
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Bash extraction
// ---------------------------------------------------------------------------

/// Cheap byte prefilter: a URL, a `/dev/tcp` path, `socket`, or a network program name as a
/// word.
fn may_reach_network(command: &str) -> bool {
    if command.contains("://")
        || command.contains("/dev/tcp/")
        || command.contains("/dev/udp/")
        || command.contains("socket")
    {
        return true;
    }
    const WORDS: &[&str] = &[
        "curl", "curlie", "wget", "wget2", "http", "https", "xh", "xhs", "nc", "ncat", "netcat",
        "telnet", "socat", "ssh", "scp", "sftp", "rsync", "aria2c",
    ];
    let bytes = command.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    WORDS.iter().any(|w| {
        let mut from = 0;
        while let Some(rel) = command[from..].find(w) {
            let start = from + rel;
            let end = start + w.len();
            let before = start == 0 || !is_word(bytes[start - 1]);
            let after = end >= bytes.len() || !is_word(bytes[end]);
            if before && after {
                return true;
            }
            from = end;
        }
        false
    })
}

fn bash_requests(command: &str) -> Vec<Request> {
    let parsed = shell::parse(command);
    let mut out = Vec::new();
    for cmd in &parsed.commands {
        let program = cmd.program();
        let Some(style) = style_of(&program) else {
            continue;
        };
        let words: Vec<&str> = cmd.words.iter().skip(1).map(|w| w.text.as_str()).collect();
        let request = match style {
            Style::Curl => curl_request(&words),
            Style::Wget => wget_request(&words),
            Style::Httpie => httpie_request(&words),
            Style::Stream => stream_request(&words, command),
            Style::Socat => socat_request(&words, command),
            Style::Ssh => ssh_request(&words),
            Style::Copy => copy_request(&words),
            Style::Fetcher => fetcher_request(&words),
            Style::Interpreter => code_request(&words.join(" "), false),
        };
        if !request.dests.is_empty() {
            out.push(request);
        }
    }
    for code in &parsed.stdin_code {
        let request = code_request(code, false);
        if !request.dests.is_empty() {
            out.push(request);
        }
    }
    for path in ["/dev/tcp/", "/dev/udp/"] {
        for (at, _) in command.match_indices(path) {
            let tail = &command[at + path.len()..];
            let host: String = tail
                .chars()
                .take_while(|c| !matches!(c, '/' | ' ' | '\t' | '\n' | '"' | '\'' | ';' | ')'))
                .collect();
            if let Some(host) = normalize_host(&host) {
                out.push(Request {
                    dests: vec![Dest {
                        host,
                        rest: String::new(),
                    }],
                    body: command.to_string(),
                    sends: true,
                    ..Request::default()
                });
            }
        }
    }
    out
}

/// Positional words, skipping flags and the values of `value_flags` (`--flag=value` is one word).
/// `on_flag` sees every flag with its value.
fn positionals<'a>(
    words: &[&'a str],
    value_flags: &[&str],
    mut on_flag: impl FnMut(&'a str, Option<&'a str>),
) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut flags_done = false;
    while i < words.len() {
        let w = words[i];
        if !flags_done && w == "--" {
            flags_done = true;
        } else if !flags_done && w.starts_with('-') && w.len() > 1 {
            if let Some((flag, value)) = w.split_once('=').filter(|_| w.starts_with("--")) {
                on_flag(flag, Some(value));
            } else if value_flags.contains(&w) {
                on_flag(w, words.get(i + 1).copied());
                i += 1;
            } else if !w.starts_with("--")
                && w.len() > 2
                && value_flags
                    .iter()
                    .any(|f| f.len() == 2 && w.starts_with(*f))
            {
                on_flag(&w[..2], Some(&w[2..]));
            } else {
                on_flag(w, None);
            }
        } else {
            out.push(w);
        }
        i += 1;
    }
    out
}

fn push_dest(dests: &mut Vec<Dest>, word: &str, bare_ok: bool) {
    if let Some(dest) = parse_url(word) {
        dests.push(dest);
    } else if bare_ok {
        if let Some(dest) = parse_bare(word) {
            dests.push(dest);
        }
    }
}

fn curl_request(words: &[&str]) -> Request {
    let mut r = Request::default();
    let mut proxies = Vec::new();
    let mut urls = Vec::new();
    let mut posts = false;
    let value_flags: Vec<&str> = CURL_VALUE_FLAGS
        .iter()
        .copied()
        .chain(["--url", "-x", "--proxy", "--preproxy"])
        .collect();
    let positional = positionals(words, &value_flags, |flag, value| {
        if CURL_BODY_FLAGS.contains(&flag) {
            posts = true;
            if let Some(v) = value {
                r.body.push_str(v);
                r.body.push('\n');
            }
        }
        if matches!(flag, "-X" | "--request")
            && value
                .is_some_and(|m| !m.eq_ignore_ascii_case("GET") && !m.eq_ignore_ascii_case("HEAD"))
        {
            posts = true;
        }
        if flag == "--url" {
            urls.extend(value);
        }
        if matches!(flag, "-x" | "--proxy" | "--preproxy") {
            proxies.extend(value);
        }
    });
    for w in urls.into_iter().chain(positional) {
        push_dest(&mut r.dests, w, true);
    }
    for p in proxies {
        push_dest(&mut r.dests, p, true);
    }
    r.sends = posts;
    r.secrets_gate_asks = posts;
    r
}

fn wget_request(words: &[&str]) -> Request {
    let mut r = Request::default();
    let mut posts = false;
    let positional = positionals(words, WGET_VALUE_FLAGS, |flag, value| {
        if WGET_BODY_FLAGS.contains(&flag) {
            posts = true;
            if let Some(v) = value {
                r.body.push_str(v);
                r.body.push('\n');
            }
        }
        if flag == "--method"
            && value
                .is_some_and(|m| !m.eq_ignore_ascii_case("GET") && !m.eq_ignore_ascii_case("HEAD"))
        {
            posts = true;
        }
    });
    for w in positional {
        push_dest(&mut r.dests, w, true);
    }
    r.sends = posts;
    r.secrets_gate_asks = posts;
    r
}

fn httpie_request(words: &[&str]) -> Request {
    let mut r = Request::default();
    let positional = positionals(
        words,
        &["-a", "--auth", "-o", "--output", "--session"],
        |_, _| {},
    );
    let mut url_seen = false;
    for w in positional {
        let upper = w.to_ascii_uppercase();
        if !url_seen && w == upper && w.chars().all(|c| c.is_ascii_alphabetic()) {
            if !matches!(w, "GET" | "HEAD" | "OPTIONS") {
                r.sends = true;
            }
            continue;
        }
        if !url_seen {
            url_seen = true;
            push_dest(&mut r.dests, w, true);
            continue;
        }
        // Request items: `k=v`, `k:=json`, `k==query`, `Header:v`, `f@file`.
        if w.contains("==") {
            r.body.push_str(w);
        } else if w.contains('=') || w.contains('@') {
            r.sends = true;
            r.body.push_str(w);
        }
        r.body.push('\n');
    }
    r
}

fn stream_request(words: &[&str], command: &str) -> Request {
    let positional = positionals(words, STREAM_VALUE_FLAGS, |_, _| {});
    let mut r = Request {
        body: command.to_string(),
        sends: true,
        ..Request::default()
    };
    if let Some(host) = positional.first() {
        push_dest(&mut r.dests, host, true);
        if r.dests.is_empty() {
            if let Some(host) = normalize_host(host) {
                r.dests.push(Dest {
                    host,
                    rest: String::new(),
                });
            }
        }
    }
    r
}

fn socat_request(words: &[&str], command: &str) -> Request {
    let mut r = Request {
        body: command.to_string(),
        sends: true,
        ..Request::default()
    };
    for w in words.iter().filter(|w| !w.starts_with('-')) {
        let fields: Vec<&str> = w.split([':', ',']).collect();
        let kind = fields[0].to_ascii_uppercase();
        let at = match kind.as_str() {
            "TCP" | "TCP4" | "TCP6" | "UDP" | "UDP4" | "UDP6" | "OPENSSL" | "SSL"
            | "TCP-CONNECT" | "UDP-CONNECT" | "UDP-SENDTO" => &[1usize][..],
            "SOCKS" | "SOCKS4" | "SOCKS4A" | "SOCKS5" | "PROXY" => &[1, 2][..],
            _ => continue,
        };
        for &i in at {
            if let Some(host) = fields.get(i).and_then(|h| normalize_host(h)) {
                r.dests.push(Dest {
                    host,
                    rest: String::new(),
                });
            }
        }
    }
    r
}

fn ssh_request(words: &[&str]) -> Request {
    let positional = positionals(words, SSH_VALUE_FLAGS, |_, _| {});
    let mut r = Request {
        sends: true,
        ..Request::default()
    };
    if let Some(target) = positional.first() {
        let host = target.rsplit('@').next().unwrap_or(target);
        if let Some(host) = normalize_host(host) {
            r.dests.push(Dest {
                host,
                rest: String::new(),
            });
        }
    }
    r
}

fn copy_request(words: &[&str]) -> Request {
    let positional = positionals(words, SSH_VALUE_FLAGS, |_, _| {});
    let mut r = Request {
        sends: true,
        ..Request::default()
    };
    for w in positional {
        if let Some(dest) = parse_url(w) {
            r.dests.push(dest);
            continue;
        }
        let Some((authority, _)) = w.split_once(':') else {
            continue;
        };
        if authority.contains('/') || authority.is_empty() {
            continue;
        }
        let host = authority.rsplit('@').next().unwrap_or(authority);
        if let Some(host) = normalize_host(host) {
            r.dests.push(Dest {
                host,
                rest: String::new(),
            });
        }
    }
    r
}

fn fetcher_request(words: &[&str]) -> Request {
    let mut r = Request::default();
    for w in words {
        let lower = w.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "-body" | "-infile" | "-method" | "post" | "--post-file" | "--post-data"
        ) {
            r.sends = true;
        }
        push_dest(&mut r.dests, w, false);
    }
    r
}

/// Interpreter or browser code: every URL literal is a destination; code naming a sending API
/// counts as a body.
fn code_request(code: &str, browser: bool) -> Request {
    let mut r = Request::default();
    for at in find_all(code, "://") {
        let start = code[..at]
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-' && c != '.')
            .map_or(0, |i| i + 1);
        if let Some(dest) = parse_url(&code[start..]) {
            r.dests.push(dest);
        }
    }
    for marker in [
        "connect((",
        "create_connection((",
        "socket.connect(",
        "net.connect(",
        "TCPSocket.new(",
    ] {
        for (at, _) in code.match_indices(marker) {
            let tail = code[at + marker.len()..].trim_start_matches([' ', '"', '\'', '(']);
            let host: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
                .collect();
            if let Some(host) = normalize_host(&host) {
                r.dests.push(Dest {
                    host,
                    rest: String::new(),
                });
                r.sends = true;
            }
        }
    }
    let lower = code.to_ascii_lowercase();
    r.sends |= [
        "post", "put(", "send", "upload", "data=", "json=", "files=", "body", "write(", "beacon",
    ]
    .iter()
    .any(|w| lower.contains(w));
    r.body = code.to_string();
    if browser {
        let reads = [
            "document.cookie",
            "localstorage",
            "sessionstorage",
            "indexeddb",
            "navigator.credentials",
        ]
        .iter()
        .any(|w| lower.contains(w));
        let sinks = [
            "fetch(",
            "xmlhttprequest",
            "sendbeacon(",
            "websocket(",
            "new image",
            ".src",
            "location",
            "window.open(",
            "import(",
        ]
        .iter()
        .any(|w| lower.contains(w));
        r.reads_page_secrets = reads && sinks;
        r.sends |= r.reads_page_secrets || lower.contains("fetch(");
    }
    r
}

/// An MCP `url` argument: a GET unless a sibling names another method or a body.
fn url_request(url: &str, siblings: Option<&Map<String, Value>>) -> Request {
    let mut r = Request {
        dests: parse_url(url).into_iter().collect(),
        ..Request::default()
    };
    if let Some(map) = siblings {
        if let Some(method) = map.get("method").and_then(Value::as_str) {
            r.sends |= !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD");
        }
        for key in ["body", "data", "json", "payload", "content"] {
            if let Some(v) = map.get(key) {
                r.sends = true;
                match v {
                    Value::String(s) => r.body.push_str(s),
                    other => r.body.push_str(&other.to_string()),
                }
                r.body.push('\n');
            }
        }
    }
    r
}

fn is_browser_script_tool(tool: &str) -> bool {
    let t = tool.to_ascii_lowercase();
    [
        "evaluate",
        "javascript",
        "run_code",
        "execute_script",
        "eval_js",
    ]
    .iter()
    .any(|w| t.contains(w))
}

/// A payload string visitor: key, value, sibling map.
type Visit<'v> = dyn FnMut(&str, &str, Option<&Map<String, Value>>) + 'v;

/// Visit every string value under `value` with its key and sibling map.
fn walk(value: &Value, depth: usize, visit: &mut Visit<'_>) {
    if depth > MAX_PAYLOAD_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                match v {
                    Value::String(s) => visit(key, s, Some(map)),
                    Value::Array(items) if key == "commands" => {
                        for item in items {
                            match item {
                                Value::String(s) => visit("command", s, Some(map)),
                                other => walk(other, depth + 1, visit),
                            }
                        }
                    }
                    other => walk(other, depth + 1, visit),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, depth + 1, visit);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// URLs and hosts
// ---------------------------------------------------------------------------

fn find_all(text: &str, needle: &str) -> Vec<usize> {
    text.match_indices(needle).map(|(i, _)| i).collect()
}

/// End of a URL inside code or a word.
fn url_end(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '<' | '>' | ')' | '(' | ',' | ';' | '{' | '}'
        )
}

/// `scheme://[userinfo@]host[:port][rest]` → its normalised host and rest.
fn parse_url(word: &str) -> Option<Dest> {
    let word = word.trim_matches(|c| c == '"' || c == '\'');
    let at = word.find("://")?;
    let scheme = &word[..at];
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return None;
    }
    let after = &word[at + 3..];
    let end = after.find(url_end).unwrap_or(after.len());
    let after = &after[..end];
    let auth_end = after.find(['/', '?', '#', '\\']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(auth_end);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = normalize_host(host)?;
    Some(Dest {
        host,
        rest: rest.to_string(),
    })
}

/// A schemeless `host[:port][/rest]` word as curl, wget and httpie accept it.
fn parse_bare(word: &str) -> Option<Dest> {
    let word = word.trim_matches(|c| c == '"' || c == '\'');
    if word.is_empty() || word.starts_with(['.', '/', '~', '@', '$', '-', ':']) {
        return None;
    }
    let auth_end = word.find(['/', '?', '#']).unwrap_or(word.len());
    let (authority, rest) = word.split_at(auth_end);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = normalize_host(host)?;
    let tld = host.rsplit('.').next().unwrap_or("");
    let looks_like_host = host.contains('.')
        && (tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
            || host.parse::<std::net::Ipv4Addr>().is_ok());
    looks_like_host.then(|| Dest {
        host,
        rest: rest.to_string(),
    })
}

/// Lowercase; strip a port, brackets, trailing dots; decode percent escapes; fold fullwidth
/// forms. `None` for an empty or non-host string.
fn normalize_host(raw: &str) -> Option<String> {
    let decoded = percent_decode(raw);
    let folded: String = decoded
        .chars()
        .map(|c| match c {
            '\u{3002}' | '\u{FF0E}' | '\u{FF61}' => '.',
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            other => other,
        })
        .collect();
    let mut host = folded.trim().to_lowercase();
    if let Some(inner) = host.strip_prefix('[') {
        host = inner.split(']').next().unwrap_or("").to_string();
    } else if let Some((h, port)) = host.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') {
            host = h.to_string();
        }
    }
    let host = host.trim_end_matches('.').to_string();
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    valid.then_some(host)
}

/// A list or policy host pattern, normalised like a host (`*.` kept).
fn normalize_pattern(raw: &str) -> String {
    let raw = raw.trim();
    match raw.strip_prefix("*.") {
        Some(base) => format!("*.{}", normalize_host(base).unwrap_or_default()),
        None => normalize_host(raw).unwrap_or_default(),
    }
}

/// `*.x` matches any subdomain of `x` (not `x`); anything else matches exactly.
fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    match pattern.strip_prefix("*.") {
        Some(base) => {
            host.len() > base.len() + 1 && host.ends_with(base) && {
                host.as_bytes()[host.len() - base.len() - 1] == b'.'
            }
        }
        None => host == pattern,
    }
}

fn is_dev_host(host: &str) -> bool {
    let under = |base: &str| {
        host == base
            || (host.len() > base.len()
                && host.ends_with(base)
                && host.as_bytes()[host.len() - base.len() - 1] == b'.')
    };
    if DEV_HOSTS.iter().any(|h| under(h)) {
        return true;
    }
    if SOLANA_RPC_HOSTS.iter().any(|h| match h.strip_prefix('.') {
        Some(base) => under(base) && host != base,
        None => host == *h,
    }) {
        return true;
    }
    host.strip_suffix(SOLANA_RPC_ALCHEMY)
        .is_some_and(|sub| sub.starts_with("solana-") && !sub.ends_with('.'))
}

// ---------------------------------------------------------------------------
// Secret and blob scanning
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    None,
    Blob,
    Secret,
}

/// What `text` carries, decoding base64 and hex runs up to [`MAX_DECODE_DEPTH`] levels while
/// `budget` lasts. A base58 64-byte run after a `tx`/`signature` path segment is a transaction
/// signature, not a key, and is left out.
fn scan(text: &str, depth: usize, budget: &mut usize) -> Level {
    if text.is_empty() || *budget == 0 {
        return Level::None;
    }
    let take = text.len().min(*budget);
    *budget -= take;
    let text = text.get(..take).unwrap_or(text);
    let decoded = percent_decode(text);
    let cleaned = drop_signatures(&decoded);
    if redact::contains_key_material(&cleaned) {
        return Level::Secret;
    }
    let mut level = Level::None;
    for token in
        cleaned.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_')))
    {
        let token = token.trim_matches('/');
        if token.len() < 8 {
            continue;
        }
        if is_blob(token) {
            level = level.max(Level::Blob);
        }
        if depth + 1 >= MAX_DECODE_DEPTH || *budget == 0 {
            continue;
        }
        let bytes = if token.len() % 2 == 0 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex_decode(token)
        } else {
            b64_decode(token)
        };
        let Some(bytes) = bytes else { continue };
        let Ok(inner) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if is_byte_array(inner) {
            level = level.max(Level::Blob);
        }
        level = level.max(scan(inner, depth + 1, budget));
        if level == Level::Secret {
            return level;
        }
    }
    level
}

/// A base64 run of [`BLOB_MIN`]+ chars mixing upper, lower and digits (a slug or a path is not
/// one), or a hex run of [`BLOB_MIN`]+ digits.
fn is_blob(token: &str) -> bool {
    if token.len() < BLOB_MIN {
        return false;
    }
    if token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    let slashes = token.bytes().filter(|b| *b == b'/').count();
    token.bytes().any(|b| b.is_ascii_uppercase())
        && token.bytes().any(|b| b.is_ascii_lowercase())
        && token.bytes().any(|b| b.is_ascii_digit())
        && slashes * 20 <= token.len()
}

/// `[n, n, …]` of four or more integers in `0..=255` (keypair-shaped bytes).
fn is_byte_array(text: &str) -> bool {
    let Some(inner) = text
        .trim()
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
    else {
        return false;
    };
    let items: Vec<&str> = inner.split(',').map(str::trim).collect();
    items.len() >= 4 && items.iter().all(|i| i.parse::<u8>().is_ok())
}

/// `text` without base58 runs that follow a `tx`/`signature` path segment or query key.
fn drop_signatures(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(['/', '=']) {
        let (head, tail) = rest.split_at(i + 1);
        out.push_str(head);
        let before = head[..head.len() - 1]
            .rsplit(['/', '?', '&'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let run = tail
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(tail.len());
        if matches!(
            before.as_str(),
            "tx" | "txs" | "transaction" | "transactions" | "signature" | "sig"
        ) && bs58::decode(&tail[..run])
            .into_vec()
            .is_ok_and(|v| v.len() == 64)
        {
            rest = &tail[run..];
        } else {
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

fn percent_decode(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(token: &str) -> Option<Vec<u8>> {
    token
        .as_bytes()
        .chunks(2)
        .map(|p| Some((hex_val(p[0])? << 4) | hex_val(*p.get(1)?)?))
        .collect()
}

/// Standard or URL-safe base64, padding optional.
fn b64_decode(token: &str) -> Option<Vec<u8>> {
    let body = token.trim_end_matches('=');
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in body.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_normalise() {
        assert_eq!(
            normalize_host("WEBHOOK.SITE.").as_deref(),
            Some("webhook.site")
        );
        assert_eq!(
            normalize_host("webhook.site:443").as_deref(),
            Some("webhook.site")
        );
        assert_eq!(
            normalize_host("ｗｅｂｈｏｏｋ．ｓｉｔｅ").as_deref(),
            Some("webhook.site")
        );
        assert_eq!(
            normalize_host("webhook%2Esite").as_deref(),
            Some("webhook.site")
        );
        let d = parse_url("https://github.com:x@WebHook.Site:8443/a?b=c").unwrap();
        assert_eq!(d.host, "webhook.site");
        assert_eq!(d.rest, "/a?b=c");
    }

    #[test]
    fn host_patterns() {
        assert!(host_matches("abc.webhook.site", "*.webhook.site"));
        assert!(!host_matches("webhook.site", "*.webhook.site"));
        assert!(!host_matches("evilwebhook.site", "*.webhook.site"));
        assert!(is_dev_host("api.github.com"));
        assert!(is_dev_host("mainnet.helius-rpc.com"));
        assert!(is_dev_host("solana-mainnet.g.alchemy.com"));
        assert!(!is_dev_host("eth-mainnet.g.alchemy.com"));
        assert!(!is_dev_host("github.com.evil.io"));
    }

    #[test]
    fn scanning() {
        let mut b = MAX_DECODE_BYTES;
        assert_eq!(scan("?d=WzEsMiwzLDRd", 0, &mut b), Level::Blob);
        assert_eq!(
            scan(
                "/blog/this-is-a-very-long-slug-for-an-article-about-solana-programs",
                0,
                &mut b
            ),
            Level::None
        );
        let secret = format!("?k={}", "ghp_".to_string() + &"a1B2".repeat(10));
        assert_eq!(scan(&secret, 0, &mut b), Level::Secret);
        assert_eq!(b64_decode("WzEsMiwzLDRd").unwrap(), b"[1,2,3,4]");
    }
}
