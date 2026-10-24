//! MCP server launch commands: does what the server runs float?
//!
//! An MCP server started through a package runner fetches its code when it launches. Without
//! an exact version (or a commit, or an image digest) the code that runs can change after any
//! review, on every launch. [`floating`] reads a server's `command` + `args` and says why it
//! floats, offline:
//!
//! * `npx` / `bunx` / `pnpm dlx` / `yarn dlx` / `npm exec`: no version, `@latest` or another
//!   dist-tag, a version range, a git ref without a commit, a tarball URL;
//! * `uvx` / `uv tool run` / `pipx run` (and their `--from` / `--spec` / `--with`): no `==`
//!   (or `@`) version, a VCS ref without a commit, a URL;
//! * `docker run` / `podman run`: an image with no tag or `:latest` and no `@sha256:` digest;
//! * `go run pkg@latest`;
//! * any `git+…` argument without a commit.
//!
//! Remote (`url`) servers run nothing locally and are not judged here.

use serde_json::Value;

use super::super::context::{shell_tokens, unquote};
use super::super::{Ctx, FileOut, Severity};
use super::{is_commit, json_key_line, MAX_LOCATED};

/// Tokens of a launch: `command` and each arg, each split like a shell would (a full command
/// line written into `command`, or a script passed to `sh -c`, is read too), quotes removed.
fn tokens(command: &str, args: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for part in std::iter::once(command).chain(args.iter().copied()) {
        for (_, tok) in shell_tokens(part) {
            out.push(unquote(tok).to_string());
            if out.len() >= 512 {
                return out;
            }
        }
    }
    out
}

/// The program name of a token (`/usr/bin/npx`, `npx.cmd` → `npx`).
fn program(tok: &str) -> String {
    let base = tok
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(tok)
        .to_ascii_lowercase();
    for ext in [".cmd", ".exe", ".ps1"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    base
}

/// Why the launch `command` + `args` floats, or `None` when what it fetches is pinned (or it
/// fetches nothing this module knows).
pub fn floating(command: &str, args: &[&str]) -> Option<&'static str> {
    let toks = tokens(command, args);
    for (i, tok) in toks.iter().enumerate() {
        let rest = &toks[i + 1..];
        let next = rest.first().map(String::as_str).unwrap_or("");
        let found = match program(tok).as_str() {
            "npx" | "bunx" | "pnpx" => npm_runner(rest),
            "pnpm" | "yarn" if next == "dlx" => npm_runner(&rest[1..]),
            "npm" if next == "exec" || next == "x" => npm_runner(&rest[1..]),
            "uvx" => py_runner(rest),
            "uv" if next == "tool" && rest.get(1).map(String::as_str) == Some("run") => {
                py_runner(&rest[2..])
            }
            "uv" if next == "run" => py_with(&rest[1..]),
            "pipx" if next == "run" => py_runner(&rest[1..]),
            "docker" | "podman" if next == "run" => docker(&rest[1..]),
            "docker" | "podman"
                if next == "container" && rest.get(1).map(String::as_str) == Some("run") =>
            {
                docker(&rest[2..])
            }
            "go" if next == "run" => rest.get(1).and_then(|s| go_spec(s)),
            _ => None,
        };
        if found.is_some() {
            return found;
        }
        if tok.to_ascii_lowercase().starts_with("git+") && !git_url_pinned(tok) {
            return Some("a git ref without a commit");
        }
    }
    None
}

/// [`floating`] over an MCP server config object (`command` + `args`).
pub fn floating_cfg(cfg: &Value) -> Option<&'static str> {
    let command = cfg.get("command").and_then(Value::as_str)?;
    let args: Vec<&str> = cfg
        .get("args")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    floating(command, &args)
}

/// The launch of a server config as one line (`command arg …`, or `url <url>` for a remote
/// server), for the dependency pin; `None` for a config that launches nothing.
pub fn launch_line(cfg: &Value) -> Option<String> {
    if let Some(command) = cfg.get("command").and_then(Value::as_str) {
        let mut line = command.to_string();
        for arg in cfg
            .get("args")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            line.push(' ');
            line.push_str(arg);
        }
        return Some(line);
    }
    ["url", "serverUrl"]
        .iter()
        .find_map(|k| cfg.get(*k).and_then(Value::as_str))
        .map(|u| format!("url {u}"))
}

/// The servers object of a project MCP config: `mcpServers` or VS Code's `servers` (the
/// containers the project `.mcp.json` listing reads too).
pub fn project_servers(json: &Value) -> Option<&serde_json::Map<String, Value>> {
    json.get("mcpServers")
        .and_then(Value::as_object)
        .or_else(|| json.get("servers").and_then(Value::as_object))
}

/// [`project_servers`], or (a plugin's `.mcp.json`) the top level itself when its values are
/// server objects.
pub fn servers(json: &Value) -> Option<&serde_json::Map<String, Value>> {
    if let Some(m) = project_servers(json) {
        return Some(m);
    }
    let top = json.as_object()?;
    let looks = top.values().any(|v| {
        v.get("command").and_then(Value::as_str).is_some()
            || v.get("url").and_then(Value::as_str).is_some()
    });
    looks.then_some(top)
}

/// A shipped MCP config (`.mcp.json`, `mcp.json`, `plugin.json`, Claude Desktop's config):
/// each server whose launch floats is `mcp_unpinned_launch` at its key's line.
pub(super) fn scan_config(text: &str, out: &mut FileOut) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let Some(map) = servers(&json) else { return };
    let mut hits = 0;
    for (name, cfg) in map {
        if floating_cfg(cfg).is_some() {
            out.emit(
                "mcp_unpinned_launch",
                Severity::Warn,
                json_key_line(text, name),
                Ctx::Meta,
            );
            hits += 1;
            if hits >= MAX_LOCATED {
                return;
            }
        }
    }
}

/// Flags of npm runners that take a value (the value is not the package).
const NPM_VALUE_FLAGS: &[&str] = &[
    "--registry",
    "--cache",
    "--userconfig",
    "--globalconfig",
    "--node-options",
    "--prefix",
    "-C",
    "--workspace",
    "-w",
    "--shell",
    "--loglevel",
];

/// `npx [flags] <spec>` / `npx -p <spec> <bin>`.
fn npm_runner(rest: &[String]) -> Option<&'static str> {
    let mut packages = false;
    let mut iter = rest.iter();
    while let Some(tok) = iter.next() {
        let t = tok.as_str();
        if t == "--" {
            return iter.next().and_then(|s| npm_spec(s));
        }
        if t == "-p" || t == "--package" {
            packages = true;
            if let Some(why) = iter.next().and_then(|s| npm_spec(s)) {
                return Some(why);
            }
            continue;
        }
        if let Some(spec) = t.strip_prefix("--package=") {
            packages = true;
            if let Some(why) = npm_spec(spec) {
                return Some(why);
            }
            continue;
        }
        if t == "-c" || t == "--call" {
            return None;
        }
        if NPM_VALUE_FLAGS.contains(&t) {
            iter.next();
            continue;
        }
        if t.starts_with('-') {
            continue;
        }
        // With `-p`, the first positional is a bin the named packages provide.
        return if packages { None } else { npm_spec(t) };
    }
    None
}

/// True for an exact semver version (`1.2.3`, `v1.2.3`, `=1.2.3`, `1.2.3-rc.1+b`).
fn exact_semver(v: &str) -> bool {
    let v = v.trim_start_matches(['=', 'v']);
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Why an npm package spec floats.
fn npm_spec(spec: &str) -> Option<&'static str> {
    let s = spec.trim();
    let lower = s.to_ascii_lowercase();
    if s.is_empty() || s.starts_with(['.', '/', '~', '$']) || lower.starts_with("file:") {
        return None;
    }
    match super::npm::classify(s) {
        super::npm::Spec::GitFloating => return Some("a git ref without a commit"),
        super::npm::Spec::Remote if lower.starts_with("http") => {
            return Some("a tarball URL (its content can change)")
        }
        super::npm::Spec::Remote | super::npm::Spec::Local => return None,
        super::npm::Spec::Registry => {}
    }
    let spec = s.strip_prefix("npm:").unwrap_or(s);
    let version = if let Some(scoped) = spec.strip_prefix('@') {
        scoped.split_once('@').map(|(_, v)| v)
    } else {
        spec.split_once('@').map(|(_, v)| v)
    };
    match version {
        None | Some("") => Some("no version: the registry's latest on every launch"),
        Some(v) if v.eq_ignore_ascii_case("latest") => Some("@latest"),
        Some(v) if exact_semver(v) => None,
        Some(_) => Some("a dist-tag or version range"),
    }
}

/// Flags of Python runners that take a value that is not a package.
const PY_VALUE_FLAGS: &[&str] = &[
    "--python",
    "-p",
    "--index-url",
    "--index",
    "--default-index",
    "--extra-index-url",
    "-i",
    "--pip-args",
    "--directory",
    "--env-file",
];

/// `uvx [--from <spec>] [--with <spec>] <spec|cmd>` / `pipx run [--spec <spec>] <spec|cmd>`.
fn py_runner(rest: &[String]) -> Option<&'static str> {
    let mut from: Option<&str> = None;
    let mut iter = rest.iter();
    while let Some(tok) = iter.next() {
        let t = tok.as_str();
        let (flag, inline) = match t.split_once('=') {
            Some((f, v)) if t.starts_with("--") => (f, Some(v)),
            _ => (t, None),
        };
        match flag {
            "--from" | "--spec" => {
                let v = inline.or_else(|| iter.next().map(String::as_str));
                if let Some(why) = v.and_then(py_spec) {
                    return Some(why);
                }
                from = v.or(from);
            }
            "--with" | "-w" => {
                let v = inline.or_else(|| iter.next().map(String::as_str));
                if let Some(why) = v.and_then(py_spec) {
                    return Some(why);
                }
            }
            f if PY_VALUE_FLAGS.contains(&f) => {
                if inline.is_none() {
                    iter.next();
                }
            }
            f if f.starts_with('-') => {}
            _ => return if from.is_some() { None } else { py_spec(t) },
        }
    }
    None
}

/// `uv run --with <spec> …`: only the `--with` packages are fetched.
fn py_with(rest: &[String]) -> Option<&'static str> {
    let mut iter = rest.iter();
    while let Some(tok) = iter.next() {
        let t = tok.as_str();
        if t == "--with" || t == "-w" {
            if let Some(why) = iter.next().and_then(|s| py_spec(s)) {
                return Some(why);
            }
        } else if let Some(v) = t.strip_prefix("--with=") {
            if let Some(why) = py_spec(v) {
                return Some(why);
            }
        }
    }
    None
}

/// Why a Python package spec floats.
fn py_spec(spec: &str) -> Option<&'static str> {
    let s = spec.trim();
    let lower = s.to_ascii_lowercase();
    if s.is_empty() || s.starts_with(['.', '/', '~', '$']) || lower.starts_with("file:") {
        return None;
    }
    if lower.contains("git+") {
        return if git_url_pinned(s) {
            None
        } else {
            Some("a git ref without a commit")
        };
    }
    if lower.contains("://") {
        return Some("a URL (its content can change)");
    }
    let spec = s.split(';').next().unwrap_or(s);
    if spec.contains("===") {
        return None;
    }
    if let Some((_, v)) = spec.split_once("==") {
        let v = v.trim();
        return if v.is_empty() || v.ends_with('*') || v.contains(',') {
            Some("a version range")
        } else {
            None
        };
    }
    // `uvx pkg@1.2.3` / `uvx pkg@latest`.
    match spec.split_once('@') {
        Some((_, v)) if v.eq_ignore_ascii_case("latest") => Some("@latest"),
        Some((_, v)) if !v.trim().is_empty() && v.bytes().any(|b| b.is_ascii_digit()) => None,
        _ if spec.contains(['>', '<', '~', '!', '^']) => Some("a version range"),
        _ => Some("no version: the index's latest on every launch"),
    }
}

/// `git+<url>@<commit>` or `…#<commit>` (pip and npm forms).
fn git_url_pinned(url: &str) -> bool {
    let no_frag = url.split("#egg=").next().unwrap_or(url);
    if let Some((_, frag)) = no_frag.rsplit_once('#') {
        if is_commit(frag) {
            return true;
        }
    }
    let path = no_frag.split('#').next().unwrap_or("");
    let after = path.split("://").nth(1).unwrap_or(path);
    after
        .rsplit_once('@')
        .is_some_and(|(head, rev)| head.contains('/') && is_commit(rev))
}

/// `docker run` flags that take a value.
const DOCKER_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--env",
    "-v",
    "--volume",
    "--name",
    "-p",
    "--publish",
    "--network",
    "--net",
    "--mount",
    "-w",
    "--workdir",
    "--entrypoint",
    "-u",
    "--user",
    "--env-file",
    "-l",
    "--label",
    "--platform",
    "--pull",
    "-h",
    "--hostname",
    "--add-host",
    "--cpus",
    "-m",
    "--memory",
    "--device",
    "--cap-add",
    "--cap-drop",
    "--security-opt",
    "--tmpfs",
    "--ulimit",
    "--restart",
    "--runtime",
    "--gpus",
    "--ipc",
    "--pid",
    "--dns",
    "--log-driver",
    "--log-opt",
    "--shm-size",
    "--cidfile",
    "--group-add",
    "--expose",
    "--link",
    "--volumes-from",
    "-a",
    "--attach",
    "--health-cmd",
    "--health-interval",
    "--health-retries",
    "--health-timeout",
    "--health-start-period",
    "--stop-signal",
    "--stop-timeout",
    "--cgroupns",
    "--cgroup-parent",
    "--uts",
    "--userns",
    "--isolation",
    "--memory-swap",
    "--memory-reservation",
    "--cpu-shares",
    "-c",
    "--cpuset-cpus",
    "--cpuset-mems",
    "--cpu-period",
    "--cpu-quota",
    "--blkio-weight",
    "--sysctl",
    "--domainname",
    "--mac-address",
    "--ip",
    "--ip6",
    "--network-alias",
    "--label-file",
    "--annotation",
    "--oom-score-adj",
    "--pids-limit",
    "--storage-opt",
    "--dns-search",
    "--dns-option",
    "--device-cgroup-rule",
];

/// `docker run [flags] <image> …`.
fn docker(rest: &[String]) -> Option<&'static str> {
    let mut iter = rest.iter();
    while let Some(tok) = iter.next() {
        let t = tok.as_str();
        if DOCKER_VALUE_FLAGS.contains(&t) {
            iter.next();
            continue;
        }
        if t.starts_with('-') {
            continue;
        }
        if t.contains("@sha256:") || t.starts_with('$') {
            return None;
        }
        let last = t.rsplit('/').next().unwrap_or(t);
        return match last.split_once(':') {
            Some((_, tag)) if !tag.is_empty() && !tag.eq_ignore_ascii_case("latest") => None,
            _ => Some("a docker image without a digest or version tag (:latest)"),
        };
    }
    None
}

/// `go run <pkg>@<version>`: `@latest` (or another query) floats; a local path or a module
/// resolved by the surrounding `go.mod` fetches nothing new.
fn go_spec(spec: &str) -> Option<&'static str> {
    let (_, version) = spec.split_once('@')?;
    if version.eq_ignore_ascii_case("latest") {
        return Some("@latest");
    }
    let exact = version.starts_with('v') && exact_semver(version);
    (!exact && !is_commit(version)).then_some("a version query, not an exact version")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{pack, rules_at};
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn f(line: &str) -> Option<&'static str> {
        let mut parts = line.split(' ');
        let cmd = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();
        floating(cmd, &args)
    }

    #[test]
    fn npm_runners() {
        assert!(f("npx -y helius-mcp").is_some());
        assert!(f("npx -y helius-mcp@latest").is_some());
        assert!(f("npx --yes @scope/pkg").is_some());
        assert!(f("npx @scope/pkg@^1.2.0").is_some());
        assert!(f("npx pkg@next").is_some());
        assert_eq!(f("npx -y helius-mcp@2.2.0"), None);
        assert_eq!(f("npx -y @scope/pkg@1.0.0-rc.1 --stdio"), None);
        assert_eq!(f("npx -y mcp-remote@0.1.0 https://x.invalid/mcp"), None);
        assert!(f("npx -p pkg bin").is_some());
        assert!(f("npx --prefix /tmp/x pkg").is_some());
        assert_eq!(f("npx --prefix /tmp/x pkg@1.0.0"), None);
        assert_eq!(f("npx -p pkg@1.0.0 bin"), None);
        assert!(f("pnpm dlx pkg").is_some());
        assert!(f("yarn dlx pkg@latest").is_some());
        assert!(f("npm exec -- pkg").is_some());
        assert!(f("bunx pkg").is_some());
        assert!(f("npx github:o/r").is_some());
        assert_eq!(f(&format!("npx github:o/r#{SHA}")), None);
        assert!(f("npx https://x.invalid/p.tgz").is_some());
        assert_eq!(f("npx ./local-bin"), None);
        assert_eq!(f("/usr/local/bin/npx.cmd pkg@1.2.3"), None);
        assert!(floating("cmd", &["/c", "npx", "-y", "pkg"]).is_some());
        assert!(floating("sh", &["-c", "npx -y pkg@latest --stdio"]).is_some());
        assert!(floating("npx -y pkg", &[]).is_some());
    }

    #[test]
    fn python_runners() {
        assert!(f("uvx mcp-server-git").is_some());
        assert!(f("uvx mcp-server-git@latest").is_some());
        assert_eq!(f("uvx mcp-server-git@2025.1.14"), None);
        assert_eq!(f("uvx mcp-server-git==2025.1.14"), None);
        assert!(f("uvx --from mcp-server-git>=1 mcp-server-git").is_some());
        assert_eq!(f("uvx --from mcp-server-git==1.0 mcp-server-git"), None);
        assert!(f("uvx --from git+https://g.invalid/o/r tool").is_some());
        assert_eq!(
            f(&format!("uvx --from git+https://g.invalid/o/r@{SHA} tool")),
            None
        );
        assert!(f("uvx --python 3.12 pkg").is_some());
        assert!(f("uv tool run pkg").is_some());
        assert!(f("uv run --with pkg server.py").is_some());
        assert_eq!(f("uv run --with pkg==1.0 server.py"), None);
        assert_eq!(f("uv run server.py"), None);
        assert!(f("pipx run pkg").is_some());
        assert_eq!(f("pipx run --spec pkg==1.2 tool"), None);
    }

    #[test]
    fn docker_go_and_git() {
        assert!(f("docker run -i --rm ghcr.io/o/mcp").is_some());
        assert!(f("docker run -i --rm -e TOKEN ghcr.io/o/mcp:latest").is_some());
        assert_eq!(f("docker run -i --rm -e TOKEN ghcr.io/o/mcp:1.4.0"), None);
        assert_eq!(f("docker run -i localhost:5000/mcp:2"), None);
        assert!(f("docker run -i localhost:5000/mcp").is_some());
        assert_eq!(f("docker run --rm img@sha256:abcd"), None);
        assert!(f("podman run -v /a:/b img").is_some());
        assert!(f("docker container run -i img").is_some());
        assert_eq!(f("docker container run -i img:1.2"), None);
        assert!(f("docker run --health-cmd true --stop-signal TERM --cgroupns host img").is_some());
        assert_eq!(f("docker run --health-cmd true img:3"), None);
        assert!(f("go run github.com/o/mcp@latest").is_some());
        assert_eq!(f("go run github.com/o/mcp@v1.2.3"), None);
        assert_eq!(f("go run ./cmd/server"), None);
        assert!(f("node x.js git+https://g.invalid/o/r").is_some());
        assert_eq!(f("node server.js --port 3"), None);
        assert_eq!(f("python -m server"), None);
    }

    #[test]
    fn hostile_launches_are_bounded() {
        let long = "x ".repeat(100_000);
        assert_eq!(floating("node", &[long.as_str()]), None);
        assert!(floating("npx", &["-y"; 10_000]).is_none());
        let _ = floating("\"", &["'", "`", "\\"]);
    }

    #[test]
    fn shipped_mcp_configs_flag_each_floating_server() {
        let cfg = "{\n  \"mcpServers\": {\n    \"remote\": { \"url\": \"https://x.invalid/mcp\" },\n    \"pinned\": { \"command\": \"npx\", \"args\": [\"helius-mcp@2.2.0\"] },\n    \"floaty\": { \"command\": \"npx\", \"args\": [\"-y\", \"mcp-remote@latest\", \"https://x.invalid\"] }\n  }\n}\n";
        let r = pack(&[(".mcp.json", cfg)]);
        assert_eq!(
            rules_at(&r, "mcp_unpinned_launch"),
            vec![(".mcp.json".into(), Some(5))]
        );
        let plugin = "{\"name\": \"p\", \"mcpServers\": {\"d\": {\"command\": \"docker\", \"args\": [\"run\", \"-i\", \"img\"]}}}";
        let r = pack(&[(".claude-plugin/plugin.json", plugin)]);
        assert_eq!(rules_at(&r, "mcp_unpinned_launch").len(), 1);
        let top = "{\"srv\": {\"command\": \"uvx\", \"args\": [\"tool\"]}}";
        let r = pack(&[(".mcp.json", top)]);
        assert_eq!(rules_at(&r, "mcp_unpinned_launch").len(), 1);
        let r = pack(&[(
            "plugin.json",
            "{\"name\": \"p\", \"mcpServers\": \"./.mcp.json\"}",
        )]);
        assert!(rules_at(&r, "mcp_unpinned_launch").is_empty());
    }

    #[test]
    fn launch_lines() {
        let v: Value = serde_json::json!({"command": "npx", "args": ["-y", "a@1.0.0"]});
        assert_eq!(launch_line(&v).as_deref(), Some("npx -y a@1.0.0"));
        let v: Value = serde_json::json!({"type": "http", "url": "https://x.invalid"});
        assert_eq!(launch_line(&v).as_deref(), Some("url https://x.invalid"));
        assert_eq!(launch_line(&serde_json::json!({})), None);
    }
}
