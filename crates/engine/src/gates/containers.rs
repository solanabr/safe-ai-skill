//! Container privilege guard (G9): a container run that hands the container host-level access.
//!
//! Covers `docker`, `podman`, `nerdctl` and `finch` `run` / `create` / `exec` (and the
//! `container run|create|exec` spellings), and `compose up|run|create` (`docker compose`,
//! `podman compose`, `nerdctl compose`, `docker-compose`, `podman-compose`), whose compose files
//! are read (bounded) and their services judged the same way.
//!
//! | What the run requests | Off / Relaxed | Medium | High |
//! |---|---|---|---|
//! | `--privileged`, `--cap-add` beyond Docker's default set, `--security-opt` that turns confinement off | ask | ask | deny |
//! | the host's PID, network, IPC, user, UTS or cgroup namespace (`--pid=host`, `network_mode: host`, …) | ask | ask | deny |
//! | `--device`, `--device-cgroup-rule`, `devices:` | ask | ask | deny |
//! | a bind mount of `/`, a system tree (`/etc`, `/proc`, `/sys`, `/dev`, `/boot`, …), the home directory, a credential store (the crate's credential list), a `*.sock` socket or the runtime's state dir (`/var/run`, `/var/lib/docker`, …) | ask | ask | deny |
//! | `podman run --rootfs PATH` where PATH is one of those trees | ask | ask | deny |
//!
//! `Off` keeps the Relaxed asks; headless turns every ask into a deny upstream. Ordinary runs
//! (published ports, named volumes, the project directory, `$(pwd)`) and every other subcommand
//! (`build`, `ps`, `logs`, `pull`, …) stay silent.
//!
//! Positions come from [`shell::parse`], so a commit message naming `--privileged` is data, and
//! flags after the image belong to the container's own command. Wrappers the parser does not
//! strip (`arch`, `taskset`, `caffeinate`, …) are peeled as in [`crate::gates::gitguard`].
//!
//! Known misses: a compose file on standard input (`-f -`), `COMPOSE_FILE`, compose `include:` /
//! `extends:` files, Kubernetes manifests (`podman kube play`), a flag held in a variable, and a
//! host path spelled through a variable other than the home ones (`$PWD/..`).

use std::path::{Component, Path, PathBuf};

use serde_yaml::Value;

use crate::context::shell::{self, base_name, SimpleCommand, Word};
use crate::gate::Verdict;
use crate::gates::bash::MAX_PARSE_BYTES;
use crate::gates::{credpaths, secretpath};
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// The largest compose file read.
const MAX_COMPOSE_BYTES: u64 = 512 * 1024;

/// Most findings named in one reason.
const MAX_NAMED: usize = 3;

/// Programs that run containers.
const RUNTIMES: &[&str] = &["docker", "podman", "nerdctl", "finch"];

/// Stand-alone compose programs.
const COMPOSE_PROGRAMS: &[&str] = &["docker-compose", "podman-compose"];

/// Default compose file names, in the order compose looks for them, then the override files.
const COMPOSE_DEFAULTS: &[&str] = &[
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
];
const COMPOSE_OVERRIDES: &[&str] = &[
    "compose.override.yaml",
    "compose.override.yml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
];

/// Capabilities Docker grants by default: adding one is a no-op.
const DEFAULT_CAPS: &[&str] = &[
    "chown",
    "dac_override",
    "fsetid",
    "fowner",
    "mknod",
    "net_raw",
    "setgid",
    "setuid",
    "setfcap",
    "setpcap",
    "net_bind_service",
    "sys_chroot",
    "kill",
    "audit_write",
];

/// Host trees whose bind mount exposes or alters the host system.
const SYSTEM_TREES: &[&str] = &[
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/root",
    "/lib/modules",
];

/// `/etc` entries whose mount is routine (time zone, name resolution, CA bundles).
const ETC_BENIGN: &[&str] = &[
    "/etc/localtime",
    "/etc/timezone",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssl/certs",
    "/etc/ca-certificates",
    "/etc/pki/ca-trust",
];

/// Host trees that hold a container runtime's control socket or state.
const RUNTIME_TREES: &[&str] = &[
    "/var/run",
    "/run",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/lib/containerd",
    "/var/lib/nerdctl",
    "/run/containerd",
    "/run/docker",
    "/run/podman",
    "/run/user",
];

/// Prefix programs that run the rest of their argv (the parser strips the common ones).
const RUNNERS: &[&str] = &[
    "env",
    "sudo",
    "doas",
    "nice",
    "nohup",
    "time",
    "timeout",
    "stdbuf",
    "ionice",
    "chrt",
    "taskset",
    "numactl",
    "arch",
    "xargs",
    "setsid",
    "unbuffer",
    "chronic",
    "caffeinate",
    "command",
    "builtin",
    "exec",
    "watch",
    "flock",
    "prlimit",
    "faketime",
    "systemd-run",
    "proxychains",
    "proxychains4",
    "torsocks",
    "strace",
    "ltrace",
    "rlwrap",
    "runuser",
    "sg",
];

/// Runners whose first positional is not the command.
const POSITIONAL_RUNNERS: &[&str] = &["flock", "sg", "runuser", "timeout", "taskset"];

/// Decide a Bash `command` against the container privilege guard (see the module docs). `None`
/// when nothing in it gives a container host-level access. `cwd` anchors relative mount sources
/// and compose files; `policy` is unused and kept for the gate signature.
pub fn decide(command: &str, cwd: &Path, _policy: &Policy, tier: Tier) -> Option<Verdict> {
    if command.len() > MAX_PARSE_BYTES || !may_concern(command) {
        return None;
    }
    let parsed = shell::parse(command);
    let mut dir = cwd.to_path_buf();
    let mut found: Vec<String> = Vec::new();
    let mut what = "container run";
    for cmd in &parsed.commands {
        // `cd infra && docker compose up`: compose reads the files where it runs.
        if cmd.program() == "cd" {
            match cmd.words.get(1) {
                Some(w) if !w.dynamic && cmd.words.len() == 2 => {
                    dir = lexical(&dir.join(expand_home(&w.text)))
                }
                _ => {}
            }
            continue;
        }
        let peeled;
        let cmd = if is_container_program(&cmd.program()) {
            cmd
        } else {
            match peel(&cmd.words) {
                Some(p) => {
                    peeled = p;
                    &peeled
                }
                None => continue,
            }
        };
        let before = found.len();
        let label = judge(cmd, &dir, &mut found);
        if found.len() > before {
            what = label;
        }
    }
    if found.is_empty() {
        return None;
    }
    let named = found
        .iter()
        .take(MAX_NAMED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let more = found.len().saturating_sub(MAX_NAMED);
    let named = if more > 0 {
        format!("{named} and {more} more")
    } else {
        named
    };
    Some(if tier >= Tier::High {
        Verdict::Deny(format!(
            "safe-ai-skill container guard: this {what} gives the container host-level access \
             ({named}); the high tier denies it, so drop that option or ask the user to run it \
             themselves."
        ))
    } else {
        Verdict::Ask(format!(
            "safe-ai-skill container guard: this {what} gives the container host-level access \
             ({named}); confirm the container needs it before approving."
        ))
    })
}

/// The byte prefilter: `docker`, `podman`, `nerdctl` or `finch` in any case, with quotes and
/// backslashes inside the word skipped (`d\ocker`, `"pod"man`), or ANSI-C quoting.
/// Allocation-free.
pub fn may_concern(command: &str) -> bool {
    let b = command.as_bytes();
    if b.windows(2).any(|w| w == b"$'") {
        return true;
    }
    const NEEDLES: [&[u8]; 4] = [b"docker", b"podman", b"nerdctl", b"finch"];
    let skip = |c: u8| matches!(c, b'\\' | b'\'' | b'"');
    for i in 0..b.len() {
        let first = b[i].to_ascii_lowercase();
        'needle: for needle in NEEDLES {
            if first != needle[0] {
                continue;
            }
            let mut j = i + 1;
            for &want in &needle[1..] {
                while j < b.len() && skip(b[j]) {
                    j += 1;
                }
                if b.get(j).map(u8::to_ascii_lowercase) != Some(want) {
                    continue 'needle;
                }
                j += 1;
            }
            return true;
        }
    }
    false
}

fn is_container_program(program: &str) -> bool {
    RUNTIMES.contains(&program) || COMPOSE_PROGRAMS.contains(&program)
}

/// The container command behind a chain of [`RUNNERS`], if `words` is one.
fn peel(words: &[Word]) -> Option<SimpleCommand> {
    let first = base_name(&words.first()?.text);
    if !RUNNERS.contains(&first.as_str()) {
        return None;
    }
    let mut prev_runner = Some(first);
    let mut prev_option = false;
    for (i, w) in words.iter().enumerate().skip(1) {
        let t = w.text.as_str();
        let base = base_name(t);
        if is_container_program(&base) {
            return Some(SimpleCommand {
                words: words[i..].to_vec(),
                indirect: true,
                writes_file: false,
                canonical: false,
            });
        }
        let positional = prev_runner
            .as_deref()
            .is_some_and(|r| POSITIONAL_RUNNERS.contains(&r));
        let number = t.starts_with(|c: char| c.is_ascii_digit());
        let assignment = t.split_once('=').is_some_and(|(n, _)| {
            !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        let runner = RUNNERS.contains(&base.as_str());
        if !(t.starts_with('-') || number || assignment || runner || prev_option || positional) {
            return None;
        }
        prev_option = t.starts_with('-') && !t.contains('=');
        prev_runner = runner.then_some(base);
    }
    None
}

// ---- runtime CLI ---------------------------------------------------------------------------

/// Runtime-level options that take the next word.
fn global_optarg(o: &str) -> bool {
    matches!(
        o,
        "-H" | "--host"
            | "-c"
            | "--context"
            | "--config"
            | "-l"
            | "--log-level"
            | "--tlscacert"
            | "--tlscert"
            | "--tlskey"
            | "--url"
            | "--connection"
            | "--root"
            | "--runroot"
            | "--storage-driver"
            | "--storage-opt"
            | "--cgroup-manager"
            | "--identity"
            | "--namespace"
            | "-n"
            | "--address"
            | "-a"
            | "--snapshotter"
            | "--cni-path"
            | "--data-root"
            | "--network-cmd-path"
            | "--events-backend"
            | "--runtime"
            | "--tmpdir"
            | "--volumepath"
            | "--imagestore"
            | "--module"
    )
}

/// The index of the first non-option word from `start`, skipping options and their values.
fn next_positional(words: &[Word], start: usize, optarg: fn(&str) -> bool) -> Option<usize> {
    let mut i = start;
    while let Some(w) = words.get(i) {
        let t = w.text.as_str();
        if !t.starts_with('-') || t == "-" {
            return Some(i);
        }
        if optarg(t) {
            i += 1;
        }
        i += 1;
    }
    None
}

/// Judge one container command, pushing findings; returns what it is for the reason.
fn judge(cmd: &SimpleCommand, dir: &Path, found: &mut Vec<String>) -> &'static str {
    let words = &cmd.words;
    let program = cmd.program();
    if COMPOSE_PROGRAMS.contains(&program.as_str()) {
        compose(words, 1, dir, found);
        return "compose run";
    }
    let Some(mut i) = next_positional(words, 1, global_optarg) else {
        return "container run";
    };
    let mut sub = words[i].text.as_str();
    if sub == "container" {
        let Some(j) = next_positional(words, i + 1, |_| false) else {
            return "container run";
        };
        i = j;
        sub = words[i].text.as_str();
    }
    match sub {
        "run" | "create" | "exec" => {
            run_options(&words[i + 1..], dir, found, sub == "exec");
            "container run"
        }
        "compose" => {
            compose(words, i + 1, dir, found);
            "compose run"
        }
        _ => "container run",
    }
}

/// Short options of `run`/`create`/`exec`/`compose run` that take a value.
const SHORT_VALUE: &[u8] = b"acehlmpuvwn";

/// Long options of `run`/`create`/`exec`/`compose run` that take no value; every other long
/// option takes one (unless spelled `--opt=value`).
const LONG_BOOL: &[&str] = &[
    "--privileged",
    "--rm",
    "--detach",
    "--interactive",
    "--tty",
    "--init",
    "--read-only",
    "--publish-all",
    "--no-healthcheck",
    "--oom-kill-disable",
    "--sig-proxy",
    "--disable-content-trust",
    "--quiet",
    "--help",
    "--rootfs",
    "--replace",
    "--rmi",
    "--no-hosts",
    "--read-only-tmpfs",
    "--env-host",
    "--tls-verify",
    "--http-proxy",
    "--use-aliases",
    "--service-ports",
    "--no-deps",
    "--build",
    "--remove-orphans",
    "--no-TTY",
    "--quiet-pull",
    "--no-start",
    "--force-recreate",
    "--no-recreate",
    "--no-build",
    "--always-recreate-deps",
    "--abort-on-container-exit",
    "--abort-on-container-failure",
    "--no-color",
    "--no-log-prefix",
    "--timestamps",
    "--wait",
    "--watch",
    "--menu",
    "--renew-anon-volumes",
    "--compatibility",
    "--dry-run",
    "--all-resources",
];

/// Read `run`-style options from `words` (after the subcommand) up to the image (or service).
fn run_options(words: &[Word], dir: &Path, found: &mut Vec<String>, exec: bool) {
    let mut rootfs = false;
    let mut i = 0;
    while let Some(w) = words.get(i) {
        let t = w.text.as_str();
        if t == "--" || !t.starts_with('-') || t == "-" {
            if rootfs && !exec {
                if let Some(why) = host_path_risk(t, dir) {
                    found.push(format!("the root filesystem {why}"));
                }
            }
            return;
        }
        let next = words.get(i + 1).map(|w| w.text.as_str());
        let (name, value, used_next): (String, Option<&str>, bool) =
            if let Some(long) = t.strip_prefix("--") {
                match long.split_once('=') {
                    Some((n, v)) => (format!("--{n}"), Some(v), false),
                    None if LONG_BOOL.contains(&t) => (t.to_string(), None, false),
                    None => (t.to_string(), next, true),
                }
            } else {
                // A short cluster: booleans until a value-taking letter, which takes the rest of the
                // word (or the next one).
                let body = &t.as_bytes()[1..];
                match body.iter().position(|c| SHORT_VALUE.contains(c)) {
                    Some(p) => {
                        let name = format!("-{}", body[p] as char);
                        let rest = &t[2 + p..];
                        let rest = rest.strip_prefix('=').unwrap_or(rest);
                        if rest.is_empty() {
                            (name, next, true)
                        } else {
                            (name, Some(rest), false)
                        }
                    }
                    None => (t.to_string(), None, false),
                }
            };
        if name == "--rootfs" {
            rootfs = true;
        }
        check_option(&name, value, dir, found);
        i += if used_next { 2 } else { 1 };
    }
}

/// One `run` option and its value.
fn check_option(name: &str, value: Option<&str>, dir: &Path, found: &mut Vec<String>) {
    let v = value.unwrap_or("");
    match name {
        "--privileged" => {
            if !v.eq_ignore_ascii_case("false") {
                found.push("privileged mode".into());
            }
        }
        "--cap-add" => {
            for cap in v.split(',') {
                if let Some(c) = risky_cap(cap) {
                    found.push(format!("the {c} capability"));
                }
            }
        }
        "--pid" | "--network" | "--net" | "--ipc" | "--userns" | "--uts" | "--cgroupns" => {
            if v.eq_ignore_ascii_case("host") {
                found.push(namespace(name.trim_start_matches('-')));
            }
        }
        "--security-opt" => {
            if let Some(f) = unconfined(v) {
                found.push(f);
            }
        }
        "--device" | "--device-cgroup-rule" => found.push(format!("host device {}", short(v))),
        "-v" | "--volume" => {
            if let Some(why) = volume_spec(v, dir) {
                found.push(why);
            }
        }
        "--mount" => {
            if let Some(why) = mount_spec(v, dir) {
                found.push(why);
            }
        }
        _ => {}
    }
}

fn namespace(kind: &str) -> String {
    let what = match kind {
        "pid" => "PID",
        "network" | "net" | "network_mode" => "network",
        "ipc" => "IPC",
        "userns" | "userns_mode" => "user",
        "uts" => "UTS",
        _ => "cgroup",
    };
    format!("the host's {what} namespace")
}

/// A capability outside Docker's default set, normalised (`CAP_SYS_ADMIN` → `SYS_ADMIN`).
fn risky_cap(cap: &str) -> Option<String> {
    let c = cap.trim().to_ascii_lowercase();
    let c = c.strip_prefix("cap_").unwrap_or(&c);
    if c.is_empty() || DEFAULT_CAPS.contains(&c) {
        return None;
    }
    Some(short(&c.to_ascii_uppercase()))
}

/// A `--security-opt` / `security_opt` entry that turns confinement off.
fn unconfined(opt: &str) -> Option<String> {
    let o = opt.trim().to_ascii_lowercase();
    let off = o.contains("unconfined")
        || matches!(
            o.as_str(),
            "label=disable" | "label:disable" | "label=disabled"
        );
    off.then(|| format!("security option {}", short(&o)))
}

/// A value shown in a reason: bounded, with no sentence break.
fn short(v: &str) -> String {
    let mut s: String = v.chars().take(60).collect();
    if v.chars().count() > 60 {
        s.push('…');
    }
    s.replace(". ", ".").replace(['(', ')'], "")
}

/// A `-v host:container[:opts]` spec: the finding for its host side, if any.
fn volume_spec(spec: &str, dir: &Path) -> Option<String> {
    let host = host_side(spec)?;
    host_path_risk(host, dir).map(|why| format!("a bind mount of {why}"))
}

/// The host side of `host:container[:opts]`; `None` for an anonymous volume (`-v /data`).
fn host_side(spec: &str) -> Option<&str> {
    let b = spec.as_bytes();
    // A Windows drive (`C:\…`, `C:/…`) keeps its colon.
    let start = if b.len() > 2
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && matches!(b[2], b'\\' | b'/')
    {
        2
    } else {
        0
    };
    let mut depth = 0usize;
    for i in start..b.len() {
        match b[i] {
            b'{' | b'(' if i > 0 && b[i - 1] == b'$' => depth += 1,
            b'}' | b')' if depth > 0 => depth -= 1,
            b':' if depth == 0 => return Some(&spec[..i]),
            _ => {}
        }
    }
    None
}

/// A `--mount type=bind,source=…,target=…` spec.
fn mount_spec(spec: &str, dir: &Path) -> Option<String> {
    let mut kind = "volume";
    let mut source = None;
    for field in spec.split(',') {
        let (k, v) = field.split_once('=').unwrap_or((field, ""));
        match k.trim().to_ascii_lowercase().as_str() {
            "type" => kind = v.trim(),
            "source" | "src" => source = Some(v.trim()),
            _ => {}
        }
    }
    if !kind.eq_ignore_ascii_case("bind") {
        return None;
    }
    host_path_risk(source?, dir).map(|why| format!("a bind mount of {why}"))
}

/// Whether a mount source names a path rather than a named volume.
fn is_path_like(raw: &str) -> bool {
    raw.starts_with(['/', '.', '~', '$', '%', '\\'])
        || raw.contains(['/', '\\'])
        || (raw.len() >= 2 && raw.as_bytes()[1] == b':')
}

fn expand_home(raw: &str) -> String {
    match (raw.strip_prefix('~'), credpaths::home_dirs().first()) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            format!("{}{rest}", home.to_string_lossy().trim_end_matches('/'))
        }
        _ => raw.to_string(),
    }
}

/// Resolve `.` and `..` without touching the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// What a host path given to a container is, when it is host-level: `None` for a named volume,
/// the project tree or any ordinary directory.
fn host_path_risk(raw: &str, dir: &Path) -> Option<String> {
    let raw = raw.trim().trim_matches(['"', '\'']);
    if raw.is_empty() || !is_path_like(raw) {
        return None;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("ssh_auth_sock") {
        return Some("the SSH agent socket".into());
    }
    let rooted =
        raw.starts_with(['/', '~', '$', '%', '\\']) || raw.as_bytes().get(1) == Some(&b':');
    let full = if rooted {
        raw.to_string()
    } else {
        lexical(&dir.join(raw)).to_string_lossy().into_owned()
    };
    let norm = secretpath::normalize(&full, None);
    let norm = if norm.len() > 1 {
        norm.trim_end_matches('/').to_string()
    } else {
        norm
    };
    let segs: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    let drive_root = segs.len() == 1 && segs[0].len() == 2 && segs[0].ends_with(':');
    if norm == "/" || segs.is_empty() && norm.starts_with('/') || drive_root {
        return Some("the host's root filesystem".into());
    }
    if segs.last().is_some_and(|s| s.ends_with(".sock")) {
        return Some(format!("the control socket {}", short(raw)));
    }
    let under = |tree: &str| norm == tree || norm.starts_with(&format!("{tree}/"));
    if RUNTIME_TREES.iter().any(|t| under(t)) {
        return Some(format!("the runtime directory {}", short(raw)));
    }
    let etc_ok = ETC_BENIGN.iter().any(|t| under(t));
    if !etc_ok && SYSTEM_TREES.iter().any(|t| under(t)) {
        return Some(format!("the system path {}", short(raw)));
    }
    if is_home(&norm, &segs) {
        return Some("your home directory".into());
    }
    if matches!(norm.as_str(), "/users" | "/home") {
        return Some("every user's home directory".into());
    }
    let path = Path::new(&norm);
    if credpaths::is_credential(path) {
        return Some(format!("the credential store {}", short(raw)));
    }
    if credpaths::reaches_store(Path::new(&full)) {
        return Some(format!("{}, which holds credential stores", short(raw)));
    }
    None
}

/// Whether a normalised path names a home directory itself.
fn is_home(norm: &str, segs: &[&str]) -> bool {
    if segs.len() == 1
        && (segs[0].starts_with('~')
            || matches!(
                segs[0],
                "$home" | "${home}" | "$userprofile" | "${userprofile}" | "%userprofile%"
            ))
    {
        return true;
    }
    if segs.len() == 2 && matches!(segs[0], "users" | "home") {
        return true;
    }
    if segs.len() == 3 && segs[0].ends_with(':') && segs[1] == "users" {
        return true;
    }
    credpaths::home_dirs().iter().any(|h| {
        let h = secretpath::normalize(&h.to_string_lossy(), None);
        h.trim_end_matches('/') == norm
    })
}

// ---- compose -------------------------------------------------------------------------------

/// Compose-level options that take the next word.
fn compose_optarg(o: &str) -> bool {
    matches!(
        o,
        "-f" | "--file"
            | "-p"
            | "--project-name"
            | "--project-directory"
            | "--profile"
            | "--env-file"
            | "--ansi"
            | "--progress"
            | "--parallel"
            | "-H"
            | "--host"
            | "--context"
            | "-c"
    )
}

/// `compose [opts] up|run|create …` with words from `start` (after `compose`).
fn compose(words: &[Word], start: usize, dir: &Path, found: &mut Vec<String>) {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut project_dir = dir.to_path_buf();
    let mut i = start;
    let mut sub = None;
    while let Some(w) = words.get(i) {
        let t = w.text.as_str();
        if !t.starts_with('-') || t == "-" {
            sub = Some(i);
            break;
        }
        let (o, inline) = match t.split_once('=') {
            Some((o, v)) if o.starts_with("--") => (o, Some(v)),
            _ if t.len() > 2
                && (t.starts_with("-f") || t.starts_with("-p"))
                && !t.starts_with("--") =>
            {
                (&t[..2], Some(&t[2..]))
            }
            _ => (t, None),
        };
        let value = inline.or_else(|| words.get(i + 1).map(|w| w.text.as_str()));
        match o {
            "-f" | "--file" => {
                if let Some(v) = value {
                    files.push(lexical(&dir.join(expand_home(v))));
                }
            }
            "--project-directory" => {
                if let Some(v) = value {
                    project_dir = lexical(&dir.join(expand_home(v)));
                }
            }
            _ => {}
        }
        if inline.is_none() && compose_optarg(o) {
            i += 1;
        }
        i += 1;
    }
    let Some(s) = sub else { return };
    let verb = words[s].text.as_str();
    if !matches!(verb, "up" | "run" | "create") {
        return;
    }
    if verb == "run" {
        run_options(&words[s + 1..], dir, found, false);
    }
    if files.is_empty() {
        if let Some(f) = COMPOSE_DEFAULTS
            .iter()
            .map(|n| project_dir.join(n))
            .find(|p| p.is_file())
        {
            files.push(f);
            files.extend(
                COMPOSE_OVERRIDES
                    .iter()
                    .map(|n| project_dir.join(n))
                    .find(|p| p.is_file()),
            );
        }
    }
    for file in &files {
        compose_file(file, found);
    }
}

/// Judge every service (and top-level bind volume) of one compose file.
fn compose_file(path: &Path, found: &mut Vec<String>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if meta.len() > MAX_COMPOSE_BYTES {
        found.push(format!(
            "compose file {} too large to inspect",
            short(&name)
        ));
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(mut doc) = serde_yaml::from_str::<Value>(&text) else {
        return;
    };
    let _ = doc.apply_merge();
    let base = path.parent().unwrap_or(Path::new("."));
    if let Some(services) = doc.get("services").and_then(Value::as_mapping) {
        for (svc_name, svc) in services {
            let svc_name = svc_name.as_str().unwrap_or("?");
            let before = found.len();
            service(svc, base, found);
            for f in &mut found[before..] {
                *f = format!("service {} {f}", short(svc_name));
            }
        }
    }
    // A named volume the local driver binds to a host path.
    if let Some(volumes) = doc.get("volumes").and_then(Value::as_mapping) {
        for (vol_name, vol) in volumes {
            let Some(device) = vol
                .get("driver_opts")
                .and_then(|o| o.get("device"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if let Some(why) = host_path_risk(device, base) {
                let vol_name = vol_name.as_str().unwrap_or("?");
                found.push(format!("volume {} bound to {why}", short(vol_name)));
            }
        }
    }
}

fn yaml_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// A sequence of scalars (or a single scalar).
fn yaml_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Sequence(items)) => items.iter().filter_map(yaml_str).collect(),
        Some(other) => yaml_str(other).into_iter().collect(),
        None => Vec::new(),
    }
}

/// One compose service.
fn service(svc: &Value, base: &Path, found: &mut Vec<String>) {
    let truthy = |v: &Value| match v {
        Value::Bool(b) => *b,
        Value::String(s) => matches!(s.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1"),
        _ => false,
    };
    if svc.get("privileged").is_some_and(truthy) {
        found.push("privileged mode".into());
    }
    for cap in yaml_list(svc.get("cap_add")) {
        if let Some(c) = risky_cap(&cap) {
            found.push(format!("the {c} capability"));
        }
    }
    for key in ["pid", "network_mode", "ipc", "userns_mode", "uts", "cgroup"] {
        if svc
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|v| v.eq_ignore_ascii_case("host"))
        {
            found.push(namespace(key));
        }
    }
    for opt in yaml_list(svc.get("security_opt")) {
        if let Some(f) = unconfined(&opt) {
            found.push(f);
        }
    }
    for key in ["devices", "device_cgroup_rules"] {
        match svc.get(key) {
            Some(Value::Sequence(items)) => {
                for d in items {
                    let shown = yaml_str(d)
                        .or_else(|| d.get("source").and_then(yaml_str))
                        .unwrap_or_else(|| "access".into());
                    found.push(format!("host device {}", short(&shown)));
                }
            }
            Some(Value::Null) | None => {}
            Some(_) => found.push("host device access".into()),
        }
    }
    if let Some(Value::Sequence(volumes)) = svc.get("volumes") {
        for v in volumes {
            let why = match v {
                Value::String(spec) => volume_spec(spec, base),
                Value::Mapping(_) => {
                    let kind = v.get("type").and_then(Value::as_str).unwrap_or("volume");
                    match v.get("source").and_then(Value::as_str) {
                        Some(src) if kind.eq_ignore_ascii_case("bind") => {
                            host_path_risk(src, base).map(|w| format!("a bind mount of {w}"))
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            found.extend(why);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(cmd: &str, tier: Tier) -> Option<Verdict> {
        decide(cmd, Path::new("/tmp/proj"), &Policy::default(), tier)
    }

    #[test]
    fn prefilter() {
        assert!(may_concern("DOCKER run"));
        assert!(may_concern("d\\ocker run"));
        assert!(may_concern("\"pod\"man run"));
        assert!(!may_concern("cargo build && ls"));
    }

    #[test]
    fn host_side_parsing() {
        assert_eq!(host_side("/a:/b:ro"), Some("/a"));
        assert_eq!(host_side("C:\\Users\\me:/b"), Some("C:\\Users\\me"));
        assert_eq!(
            host_side("${HOME:-/x}/.aws:/root/.aws"),
            Some("${HOME:-/x}/.aws")
        );
        assert_eq!(host_side("/data"), None);
    }

    #[test]
    fn verdicts() {
        assert!(matches!(
            d("docker run --privileged x", Tier::Medium),
            Some(Verdict::Ask(_))
        ));
        assert!(matches!(
            d("docker run --privileged x", Tier::High),
            Some(Verdict::Deny(_))
        ));
        assert!(d("docker run --rm -p 8899:8899 image", Tier::High).is_none());
        assert!(d("docker run img ls --privileged", Tier::High).is_none());
        assert!(d("docker run --cap-add NET_BIND_SERVICE x", Tier::High).is_none());
    }
}
