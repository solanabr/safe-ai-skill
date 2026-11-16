//! Package publish gate: a command that uploads a package version to a registry.
//!
//! Ported from the ai-kit `egress-guard` publish check. A registry keeps a published version (npm
//! never reuses one, and a yanked crates.io version stays downloadable), and the registry is a
//! host every other check lets through, so no host list stops the upload.
//!
//! | What | Off / Relaxed | Medium | High |
//! |---|---|---|---|
//! | A publish (`PUBLISHERS`): `npm`, `pnpm`, `yarn` and `bun publish`, `yarn npm publish`, `cargo publish`, `twine upload`, `gem push`, … | ask | deny | deny |
//!
//! `Off` acts as `Relaxed`; headless turns the ask into a deny upstream. A dry run (`--dry-run`,
//! and `cargo publish -n`) is not a publish, for the tools that have one.
//!
//! Positions come from [`shell::parse`], so a commit message or a changelog line naming
//! `npm publish` is data. A publisher is also found behind a wrapper the parser does not strip
//! (`flock`, `taskset`, …), a package runner (`npx`, `pnpm dlx`, `uvx`, …), `python -m twine`,
//! and a `yarn`, `pnpm` or `bun` that runs a publisher's own binary (`yarn lerna publish`).
//!
//! Known misses: a publish inside a package script (`npm run release`), a Makefile target or a
//! script file, a program or subcommand held in a variable, and an upload by `curl`.

use std::path::Path;

use crate::context::shell::{self, base_name, Word};
use crate::gate::Verdict;
use crate::gates::bash::MAX_PARSE_BYTES;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// Deepest chain of runners followed (`flock f npx lerna publish`).
const MAX_DEPTH: usize = 4;

/// Publishers: the program, the subcommand words that make it upload, and its dry-run flags.
const PUBLISHERS: &[(&str, &[&str], &[&str])] = &[
    ("npm", &["publish"], &["--dry-run"]),
    ("pnpm", &["publish"], &["--dry-run"]),
    ("yarn", &["publish"], &[]),
    ("yarn", &["npm", "publish"], &["--dry-run"]),
    ("bun", &["publish"], &["--dry-run"]),
    ("deno", &["publish"], &["--dry-run"]),
    ("jsr", &["publish"], &["--dry-run"]),
    ("lerna", &["publish"], &[]),
    ("changeset", &["publish"], &[]),
    ("cargo", &["publish"], &["--dry-run", "-n"]),
    ("cargo", &["workspaces", "publish"], &["--dry-run"]),
    ("cargo", &["ws", "publish"], &["--dry-run"]),
    ("twine", &["upload"], &[]),
    ("poetry", &["publish"], &["--dry-run"]),
    ("uv", &["publish"], &["--dry-run"]),
    ("flit", &["publish"], &[]),
    ("hatch", &["publish"], &[]),
    ("pdm", &["publish"], &["--dry-run"]),
    ("gem", &["push"], &[]),
    ("dotnet", &["nuget", "push"], &[]),
    ("nuget", &["push"], &[]),
    ("dart", &["pub", "publish"], &["--dry-run", "-n"]),
    ("flutter", &["pub", "publish"], &["--dry-run", "-n"]),
    ("mix", &["hex.publish"], &["--dry-run"]),
    ("pod", &["trunk", "push"], &[]),
    ("vsce", &["publish"], &[]),
    ("ovsx", &["publish"], &[]),
];

/// Prefix programs that run the rest of their argv as a command (the parser strips the common
/// ones: `env`, `sudo`, `nice`, `timeout`, `xargs`, …).
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
    "chroot",
    "prlimit",
    "nsenter",
    "unshare",
    "runuser",
    "sg",
    "faketime",
    "firejail",
    "systemd-run",
    "proxychains",
    "proxychains4",
    "torsocks",
    "strace",
    "ltrace",
    "rlwrap",
    "xvfb-run",
    "dbus-run-session",
    "parallel",
];

/// Runners whose first positional is not the command (`flock FILE cmd`, `chroot DIR cmd`).
const POSITIONAL_RUNNERS: &[&str] = &["chroot", "flock", "sg", "runuser", "timeout", "taskset"];

/// Package runners that run a package's binary: `(runner, subcommand)`, an empty subcommand
/// meaning the runner alone (`npx lerna publish`).
const PACKAGE_RUNNERS: &[(&str, &str)] = &[
    ("npx", ""),
    ("pnpx", ""),
    ("bunx", ""),
    ("uvx", ""),
    ("npm", "exec"),
    ("npm", "x"),
    ("pnpm", "exec"),
    ("pnpm", "dlx"),
    ("yarn", "exec"),
    ("yarn", "dlx"),
    ("yarn", "run"),
    ("bun", "x"),
    ("bun", "run"),
    ("uv", "run"),
    ("pipx", "run"),
    ("poetry", "run"),
    ("pdm", "run"),
    ("hatch", "run"),
];

/// Value-taking options of [`PACKAGE_RUNNERS`].
const RUNNER_VALUE_OPTIONS: &[&str] = &[
    "-p",
    "--package",
    "--with",
    "--from",
    "--spec",
    "--python",
    "--project",
    "--directory",
    "-e",
    "--env",
];

/// Decide a Bash `command` against the publish gate (see the module docs). `None` when it
/// publishes nothing. `cwd` and `policy` are unused and kept for the gate signature.
pub fn decide(command: &str, _cwd: &Path, _policy: &Policy, tier: Tier) -> Option<Verdict> {
    if command.len() > MAX_PARSE_BYTES || !may_concern(command) {
        return None;
    }
    let parsed = shell::parse(command);
    let found = parsed
        .commands
        .iter()
        .find_map(|cmd| publish(&cmd.words, 0))?;
    // `Off` keeps the Relaxed ask.
    let tier = tier.max(Tier::Relaxed);
    Some(if tier >= Tier::Medium {
        Verdict::Deny(format!(
            "safe-ai-skill publish gate: this runs `{found}`, which uploads a package to a \
             registry that keeps every published version; the {} tier denies it, so ask the user \
             to publish it themselves.",
            tier.label()
        ))
    } else {
        Verdict::Ask(format!(
            "safe-ai-skill publish gate: this runs `{found}`, which uploads a package to a \
             registry that keeps every published version; confirm the package, the version and \
             the registry before approving."
        ))
    })
}

/// The byte prefilter: `publish`, `upload` or `push` in any case, with quotes and backslashes
/// inside the word skipped (`pub"l"ish`, `p\ush`), or ANSI-C quoting. Allocation-free.
pub fn may_concern(command: &str) -> bool {
    let b = command.as_bytes();
    if b.windows(2).any(|w| w == b"$'") {
        return true;
    }
    const NEEDLES: [&[u8]; 3] = [b"publish", b"upload", b"push"];
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

/// The publish `words` run, as `program subcommand` (`npm publish`), looking through runners;
/// `None` when they publish nothing.
fn publish(words: &[Word], depth: usize) -> Option<String> {
    if depth > MAX_DEPTH {
        return None;
    }
    let program = base_name(&words.first()?.text);
    for (name, sub, dry_run) in PUBLISHERS {
        if *name != program {
            continue;
        }
        if runs_subcommand(words, sub) {
            // A dry-run flag counts anywhere after the program (`npm --dry-run publish`).
            if dry_run_of(&words[1..], dry_run) {
                return None;
            }
            return Some(format!("{name} {}", sub.join(" ")));
        }
    }
    // `yarn workspace <name> <command>` and `yarn workspaces foreach [options] <command>` run
    // `yarn <command>` in the workspaces.
    if program == "yarn" {
        if let Some(at) = yarn_workspace_command(words) {
            let mut inner = vec![words[0].clone()];
            inner.extend_from_slice(&words[at..]);
            return publish(&inner, depth + 1);
        }
    }
    let inner = runner_target(words, &program)?;
    publish(&words[inner..], depth + 1)
}

/// Value-taking options of `yarn workspaces foreach`.
const FOREACH_VALUE_OPTIONS: &[&str] = &["--from", "--include", "--exclude", "-j", "--jobs"];

/// Where the command `yarn workspace NAME …` or `yarn workspaces foreach [options] …` runs in
/// each workspace starts, if `words` is one.
fn yarn_workspace_command(words: &[Word]) -> Option<usize> {
    let mut i = match words.get(1)?.text.as_str() {
        "workspace" => 3,
        "workspaces" if words.get(2)?.text == "foreach" => 3,
        _ => return None,
    };
    if words[1].text == "workspaces" {
        while let Some(w) = words.get(i) {
            let t = w.text.as_str();
            if !t.starts_with('-') {
                break;
            }
            let o = t.split_once('=').map_or(t, |(o, _)| o);
            i += if FOREACH_VALUE_OPTIONS.contains(&o) && !t.contains('=') {
                2
            } else {
                1
            };
        }
    }
    (i < words.len()).then_some(i)
}

/// Whether `words` (program first) run subcommand `sub`: options and their values may come
/// before it (`npm --registry R publish`, `cargo +nightly publish`), and an expansion there may
/// be one.
fn runs_subcommand(words: &[Word], sub: &[&str]) -> bool {
    let mut matched = 0;
    let mut after_option = false;
    for (i, w) in words.iter().enumerate().skip(1) {
        let t = w.text.as_str();
        if t.starts_with('-') && t.len() > 1 && t != "--" {
            let long = t.starts_with("--") && !t.contains('=');
            after_option = matched == 0 && (long || t.len() == 2);
            continue;
        }
        if t == sub[matched] {
            matched += 1;
            after_option = false;
            if matched == sub.len() {
                return true;
            }
            continue;
        }
        let toolchain = i == 1 && t.starts_with('+');
        if matched == 0 && (after_option || toolchain || w.dynamic) {
            after_option = false;
            continue;
        }
        return false;
    }
    false
}

/// Whether `words` hold one of `flags`, a dry run.
fn dry_run_of(words: &[Word], flags: &[&str]) -> bool {
    words.iter().any(|w| {
        flags
            .iter()
            .any(|f| w.text == *f || w.text.strip_prefix(f) == Some("=true"))
    })
}

/// The index of the command a runner at `words[0]` (base name `program`) runs, if it is one:
/// a prefix program, a package runner, `python -m twine`, or a `yarn`, `pnpm` or `bun` that runs
/// a publisher's binary.
fn runner_target(words: &[Word], program: &str) -> Option<usize> {
    if RUNNERS.contains(&program) {
        return prefix_target(words, program);
    }
    if shell::is_interpreter(program) && program.starts_with("python") {
        let at = words.iter().position(|w| w.text == "-m")?;
        return (words.get(at + 1)?.text == "twine").then_some(at + 1);
    }
    let second = words.get(1).map(|w| w.text.as_str()).unwrap_or_default();
    if let Some((_, sub)) = PACKAGE_RUNNERS
        .iter()
        .find(|(name, sub)| *name == program && (sub.is_empty() || *sub == second))
    {
        let mut i = if sub.is_empty() { 1 } else { 2 };
        while let Some(w) = words.get(i) {
            let t = w.text.as_str();
            if t == "--" {
                i += 1;
                break;
            }
            if !t.starts_with('-') {
                break;
            }
            let o = t.split_once('=').map_or(t, |(o, _)| o);
            i += if RUNNER_VALUE_OPTIONS.contains(&o) && !t.contains('=') {
                2
            } else {
                1
            };
        }
        return (i < words.len()).then_some(i);
    }
    // `yarn lerna publish`: a package manager running a binary by name.
    let bin = matches!(program, "yarn" | "pnpm" | "bun")
        && PUBLISHERS
            .iter()
            .any(|(name, _, _)| *name == base_name(second) && *name != program);
    bin.then_some(1)
}

/// The command behind a chain of [`RUNNERS`]: every word before it is a runner, an option, an
/// option's value, a number or mask, an assignment or a runner's positional operand.
fn prefix_target(words: &[Word], first: &str) -> Option<usize> {
    let mut prev_runner = Some(first.to_string());
    let mut prev_option = false;
    for (i, w) in words.iter().enumerate().skip(1) {
        let t = w.text.as_str();
        let base = base_name(t);
        if PUBLISHERS.iter().any(|(name, _, _)| *name == base)
            || PACKAGE_RUNNERS.iter().any(|(name, _)| *name == base)
            || shell::is_interpreter(&base)
        {
            return Some(i);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(command: &str, tier: Tier) -> &'static str {
        match decide(command, Path::new("."), &Policy::default(), tier) {
            Some(Verdict::Ask(_)) => "A",
            Some(Verdict::Deny(_)) => "D",
            _ => "-",
        }
    }

    fn row(command: &str, want: [&str; 4]) {
        let got = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High].map(|t| v(command, t));
        assert_eq!(got, want, "{command}");
    }

    #[test]
    fn publishes_ask_below_medium_and_deny_from_medium() {
        for cmd in [
            "npm publish",
            "npm publish --access public --tag next",
            "pnpm -r publish",
            "pnpm --filter ./pkg publish --no-git-checks",
            "yarn publish --new-version 1.2.3",
            "yarn npm publish",
            "bun publish",
            "cargo publish",
            "cargo +nightly publish -p my-crate",
            "cargo publish --manifest-path crates/x/Cargo.toml",
            "cargo ws publish --from-git",
            "npm --registry https://registry.npmjs.org publish",
            "npm -w packages/a publish",
            "deno publish",
            "twine upload dist/*",
            "python3 -m twine upload dist/*",
            "uvx twine upload dist/*",
            "poetry publish --build",
            "uv publish",
            "gem push x-1.0.gem",
            "dotnet nuget push x.nupkg --source https://api.nuget.org/v3/index.json",
            "dart pub publish --force",
            "mix hex.publish",
            "pod trunk push X.podspec",
            "vsce publish",
            "npx lerna publish from-package --yes",
            "npx changeset publish",
            "pnpm changeset publish",
            "yarn lerna publish",
            "npm exec -- lerna publish",
            "npx jsr publish",
            "yarn workspaces foreach -A --topological npm publish --tolerate-republish",
            "yarn workspaces foreach --include '@a/*' npm publish",
            "yarn workspace @a/b npm publish",
            "yarn workspace a publish",
        ] {
            row(cmd, ["A", "A", "D", "D"]);
        }
    }

    #[test]
    fn every_spelling_is_the_same_publish() {
        for cmd in [
            "env NODE_AUTH_TOKEN=x npm publish",
            "sudo -u ci cargo publish",
            "nice -n 5 npm publish",
            "timeout 600 cargo publish",
            "flock /tmp/l npm publish",
            "taskset 0x1 cargo publish",
            "arch -arm64 npm publish",
            "\"npm\" pub\"l\"ish",
            "n\\pm publish",
            "/usr/local/bin/npm publish",
            "bash -c 'npm publish'",
            "sh -c \"cd pkg && npm publish\"",
            "if true; then npm publish; fi",
            "echo $(npm publish)",
            "cd pkg && npm publish",
            "npm run build && npm publish",
            "watch 'npm publish'",
            "parallel npm publish ::: a b",
            "npm $FLAGS publish",
            "$'\\x6epm' publish",
        ] {
            assert_eq!(v(cmd, Tier::Relaxed), "A", "{cmd}");
            assert_eq!(v(cmd, Tier::High), "D", "{cmd}");
        }
    }

    #[test]
    fn dry_runs_reads_and_mentions_are_silent() {
        for cmd in [
            "npm publish --dry-run",
            "npm publish --dry-run=true",
            "npm --dry-run publish",
            "pnpm publish --dry-run",
            "cargo publish --dry-run",
            "cargo publish -n",
            "cargo publish --locked --dry-run",
            "deno publish --dry-run",
            "dart pub publish -n",
            "npm pack",
            "npm view my-pkg",
            "npm install publish",
            "npm run publish",
            "npm run release",
            "cargo build --release",
            "cargo package",
            "git push origin main",
            "git commit -m 'npm publish 1.2.3'",
            "echo npm publish",
            "grep -rn 'cargo publish' docs",
            "cat > notes.md <<'EOF'\nnpm publish\nEOF",
            "twine check dist/*",
            "gem build x.gemspec",
            "docker push img",
            "yarn add publish",
            "python3 -m build",
        ] {
            row(cmd, ["-", "-", "-", "-"]);
        }
        // A dry run of one publish does not cover another on the line.
        row(
            "cargo publish --dry-run && cargo publish",
            ["A", "A", "D", "D"],
        );
        // A tool with no dry run publishes whatever the flag says.
        row("yarn publish --dry-run", ["A", "A", "D", "D"]);
    }

    #[test]
    fn reasons_name_the_publisher_and_end_in_a_remedy() {
        let ask = decide(
            "npx lerna publish",
            Path::new("."),
            &Policy::default(),
            Tier::Relaxed,
        );
        let Some(Verdict::Ask(reason)) = ask else {
            panic!("{ask:?}")
        };
        assert!(reason.contains("`lerna publish`"), "{reason}");
        let deny = decide(
            "cargo publish",
            Path::new("."),
            &Policy::default(),
            Tier::Medium,
        );
        let Some(Verdict::Deny(reason)) = deny else {
            panic!("{deny:?}")
        };
        assert!(reason.contains("the medium tier denies it"), "{reason}");
        assert!(reason.ends_with("themselves."), "{reason}");
    }

    #[test]
    fn prefilter() {
        assert!(may_concern("npm publish"));
        assert!(may_concern("npm pub\"l\"ish"));
        assert!(may_concern("git push"));
        assert!(!may_concern("cargo build --release"));
        assert!(!may_concern("npm install"));
    }
}
