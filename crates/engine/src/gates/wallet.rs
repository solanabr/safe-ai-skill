//! Default-wallet destruction (D8 v2 spec §3.1; owned by F3): `solana-keygen new|recover` with
//! `--force/-f` and no `-o` or an outfile naming `~/.config/solana/id.json` or the CLI config's
//! `keypair_path`; Bash `rm|mv|cp|tee|dd of=|>` onto that file; Write/Edit/NotebookEdit to it.
//! Denied on every cluster at every tier, headless or not; no grant, repo or env relaxes it.
//!
//! The keygen verbs come from the shared list's `irreversible any` rows
//! ([`crate::lists::irreversible`]). The protected files are `~/.config/solana/id.json` under
//! `$HOME` and under the account's passwd home (a repo-set `HOME` cannot move the real one out
//! of reach), and the `keypair_path` of `$HOME/.config/solana/cli/config.yml`. Paths compare
//! lexically (case-insensitively: macOS volumes usually are) and, when the file exists, by
//! its canonical path, so a symlink onto the wallet counts.
//!
//! Call lines: `main::cmd_gate_bash_secrets` ([`decide_bash`]; `solana-keygen` is not matched
//! by the bash gate's `if`) and `main::cmd_gate_tamper` ([`decide_file`]).

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::context::shell::{self, SimpleCommand, Word};
use crate::gate::Verdict;
use crate::lists::{self, VerbCluster};
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// The default wallet, relative to a home dir.
const DEFAULT_WALLET: &str = ".config/solana/id.json";

/// The solana CLI config, relative to a home dir.
const CLI_CONFIG: &str = ".config/solana/cli/config.yml";

/// Largest CLI config read for its `keypair_path`.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Programs that delete, move or overwrite every path argument they name.
const CLOBBER_ALL: &[&str] = &["rm", "unlink", "shred", "truncate", "tee", "mv", "srm"];

/// Programs whose last path argument (or `-t DIR`) is a destination they overwrite.
const CLOBBER_DEST: &[&str] = &["cp", "install", "ln", "rsync", "ditto", "scp"];

/// The verdict for a Bash `command` run in `cwd`; `None` is no opinion.
pub fn decide_bash(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = (policy, tier);
    let parsed = shell::parse(command);
    let redirects = command.contains('>');
    let relevant = |c: &SimpleCommand| {
        let p = c.program();
        p == "solana-keygen"
            || p == "dd"
            || CLOBBER_ALL.contains(&p.as_str())
            || CLOBBER_DEST.contains(&p.as_str())
    };
    if !redirects && !parsed.commands.iter().any(relevant) {
        return None;
    }
    let homes = Homes::from_env();
    let wallets = Wallets::load(&homes);
    let keygen_rows = keygen_rows();
    for cmd in parsed.commands.iter().filter(|c| relevant(c)) {
        if let Some(reason) = keygen(cmd, cwd, &homes, &wallets, &keygen_rows) {
            return Some(deny(reason, command));
        }
        if let Some(reason) = clobber(cmd, cwd, parsed.cwd_changed, &homes, &wallets) {
            return Some(deny(reason, command));
        }
    }
    if !redirects {
        return None;
    }
    redirect_target(command, cwd, &homes, &wallets)
        .map(|target| deny(format!("a redirection overwrites {target}"), command))
}

/// The verdict for a Write|Edit|MultiEdit|NotebookEdit `tool_input`; `None` is no opinion.
pub fn decide_file(
    tool_input: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    tier: Tier,
) -> Option<Verdict> {
    let _ = (policy, tier);
    let input = tool_input?;
    let raw = ["file_path", "notebook_path", "path"]
        .iter()
        .find_map(|k| input.get(k).and_then(Value::as_str))?;
    let homes = Homes::from_env();
    let wallets = Wallets::load(&homes);
    let path = resolve(raw, cwd, &homes)?;
    wallets.hit(&path).map(|target| {
        Verdict::Deny(format!(
            "Writing {target} would destroy the default Solana wallet (spec §3.1: denied on \
             every cluster at every tier). Edit it yourself outside the agent if you intend to."
        ))
    })
}

fn deny(what: String, command: &str) -> Verdict {
    Verdict::Deny(format!(
        "Default-wallet destruction: {what} (spec §3.1: denied on every cluster at every \
         tier). Run it yourself outside the agent if you intend it: `{}`",
        command.trim()
    ))
}

/// The home dirs whose `~/.config/solana/id.json` is protected.
struct Homes {
    /// `$HOME`, which `~` and `$HOME` expand to in the command.
    env: Option<PathBuf>,
    /// The passwd home (the account's real one).
    passwd: Option<PathBuf>,
}

impl Homes {
    fn from_env() -> Homes {
        Homes {
            env: std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from),
            passwd: crate::datadir::passwd_home(),
        }
    }

    /// The home `~` and `$HOME` expand to.
    fn expand_base(&self) -> Option<&Path> {
        self.env.as_deref().or(self.passwd.as_deref())
    }
}

/// The protected wallet files.
struct Wallets {
    /// (lexical, lowercased path; display form)
    paths: Vec<(String, String)>,
    /// Canonical forms of those that exist.
    canonical: Vec<PathBuf>,
}

impl Wallets {
    fn load(homes: &Homes) -> Wallets {
        let mut files: Vec<PathBuf> = [&homes.env, &homes.passwd]
            .iter()
            .filter_map(|h| h.as_ref().map(|h| h.join(DEFAULT_WALLET)))
            .collect();
        if let Some(home) = homes.expand_base() {
            if let Some(custom) = config_keypair_path(home) {
                if let Some(path) = resolve(&custom, home, homes) {
                    files.push(path);
                }
            }
        }
        let paths = files
            .iter()
            .map(|p| (key(p), p.display().to_string()))
            .collect();
        let canonical = files
            .iter()
            .filter_map(|p| std::fs::canonicalize(p).ok())
            .collect();
        Wallets { paths, canonical }
    }

    /// The display form of the wallet `path` names, if it names one.
    fn hit(&self, path: &Path) -> Option<String> {
        let k = key(path);
        if let Some((_, shown)) = self.paths.iter().find(|(p, _)| *p == k) {
            return Some(shown.clone());
        }
        let real = std::fs::canonicalize(path).ok()?;
        self.canonical
            .contains(&real)
            .then(|| real.display().to_string())
    }

    /// Whether some wallet's file name is `name` (for paths after a directory change).
    fn has_file_name(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.paths
            .iter()
            .any(|(p, _)| p.rsplit('/').next() == Some(name.as_str()))
    }

    /// The wallet a copy of `source` into directory `dir` would overwrite.
    fn hit_in_dir(&self, dir: &Path, source: &str) -> Option<String> {
        let name = Path::new(source).file_name()?;
        self.hit(&dir.join(name))
    }
}

/// A lexical comparison key: normalised, lowercased, `/`-separated.
fn key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

/// `keypair_path` from `<home>/.config/solana/cli/config.yml`, when set.
fn config_keypair_path(home: &Path) -> Option<String> {
    let path = home.join(CLI_CONFIG);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(&path)
        .ok()?
        .take(MAX_CONFIG_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    text.lines()
        .find_map(|l| l.trim().strip_prefix("keypair_path:"))
        .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|v| !v.is_empty())
}

/// Resolve a path word: `~`, `$HOME`, `${HOME}` expanded, relative to `cwd`, lexically
/// normalised. `None` when it holds any other expansion.
fn resolve(raw: &str, cwd: &Path, homes: &Homes) -> Option<PathBuf> {
    let raw = raw.trim();
    let home_rel = ["~/", "$HOME/", "${HOME}/"]
        .iter()
        .find_map(|p| raw.strip_prefix(p));
    let joined = if let Some(rest) = home_rel {
        homes.expand_base()?.join(rest)
    } else if matches!(raw, "~" | "$HOME" | "${HOME}") {
        homes.expand_base()?.to_path_buf()
    } else if raw.contains(['$', '`']) || raw.starts_with('~') || raw.is_empty() {
        return None;
    } else if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        cwd.join(raw)
    };
    Some(normalise(&joined))
}

/// Remove `.` and fold `..` without touching the file system.
fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `(verb, force flags)` from the list's `irreversible any` keygen rows.
fn keygen_rows() -> Vec<(String, String)> {
    let Ok(rows) = lists::irreversible() else {
        // Fail closed: the 1.1.0-era shapes.
        return [
            ("new", "--force"),
            ("new", "-f"),
            ("recover", "--force"),
            ("recover", "-f"),
        ]
        .iter()
        .map(|(v, f)| (v.to_string(), f.to_string()))
        .collect();
    };
    rows.iter()
        .filter(|v| v.cluster == VerbCluster::Any)
        .filter(|v| v.argv.first().is_some_and(|p| p == "solana-keygen"))
        .filter_map(|v| {
            let verb = v.argv.get(1)?.clone();
            let flag = v
                .argv
                .iter()
                .find_map(|t| t.strip_prefix('[').and_then(|t| t.strip_suffix(']')))?;
            Some((verb, flag.to_string()))
        })
        .collect()
}

/// The parsed flags of a `solana-keygen` command.
struct KeygenArgs<'a> {
    verb: Option<&'a str>,
    flags: Vec<String>,
    /// The `-o/--outfile` value, when given (`Some("")` when it is missing).
    outfile: Option<&'a Word>,
    outfile_flag: bool,
}

fn keygen_args(words: &[Word]) -> KeygenArgs<'_> {
    let mut args = KeygenArgs {
        verb: None,
        flags: Vec::new(),
        outfile: None,
        outfile_flag: false,
    };
    let mut i = 1;
    while let Some(word) = words.get(i) {
        i += 1;
        let text = word.text.as_str();
        if let Some(value) = text.strip_prefix("--outfile=") {
            args.outfile_flag = true;
            if !value.is_empty() {
                args.outfile = Some(word);
                args.flags.push("--outfile".into());
            }
            continue;
        }
        if text == "--outfile" {
            args.outfile_flag = true;
            args.outfile = words.get(i);
            i += 1;
            continue;
        }
        if text.starts_with("--") {
            args.flags
                .push(text.split('=').next().unwrap_or(text).to_string());
            continue;
        }
        if let Some(cluster) = text.strip_prefix('-').filter(|c| !c.is_empty()) {
            // A short cluster: `-f`, `-fo x`, `-sf`; `o` takes the rest or the next word.
            for (at, c) in cluster.char_indices() {
                if c == 'o' {
                    args.outfile_flag = true;
                    let rest = &cluster[at + 1..];
                    if rest.is_empty() {
                        args.outfile = words.get(i);
                        i += 1;
                    } else {
                        args.outfile = Some(word);
                    }
                    break;
                }
                args.flags.push(format!("-{c}"));
            }
            continue;
        }
        if args.verb.is_none() {
            args.verb = Some(text);
        }
    }
    args
}

/// The outfile path a `-o` word names (`-ofile`, `--outfile=file`, or the word itself).
fn outfile_text(word: &Word) -> &str {
    let t = word.text.as_str();
    if let Some(v) = t.strip_prefix("--outfile=") {
        return v;
    }
    if t.starts_with('-') && !t.starts_with("--") {
        if let Some(at) = t.find('o') {
            return &t[at + 1..];
        }
    }
    t
}

/// Why a `solana-keygen` command destroys the default wallet, if it does.
fn keygen(
    cmd: &SimpleCommand,
    cwd: &Path,
    homes: &Homes,
    wallets: &Wallets,
    rows: &[(String, String)],
) -> Option<String> {
    if cmd.program() != "solana-keygen" {
        return None;
    }
    let args = keygen_args(&cmd.words);
    let verb = args.verb?.to_ascii_lowercase();
    let forced = rows
        .iter()
        .any(|(v, flag)| *v == verb && args.flags.iter().any(|f| f == flag));
    if !forced {
        return None;
    }
    let Some(word) = args.outfile else {
        return (!args.outfile_flag).then(|| {
            format!(
                "`solana-keygen {verb}` with --force and no outfile overwrites the default wallet"
            )
        });
    };
    let text = outfile_text(word);
    match resolve(text, cwd, homes) {
        Some(path) => wallets
            .hit(&path)
            .map(|target| format!("`solana-keygen {verb} --force` overwrites {target}")),
        // An outfile the gate cannot resolve may be the wallet.
        None => Some(format!(
            "`solana-keygen {verb} --force` writes `{text}`, which may be the default wallet"
        )),
    }
}

/// Why a file command deletes, moves or overwrites a wallet, if it does.
fn clobber(
    cmd: &SimpleCommand,
    cwd: &Path,
    cwd_changed: bool,
    homes: &Homes,
    wallets: &Wallets,
) -> Option<String> {
    let program = cmd.program();
    let args: Vec<&str> = cmd.words.iter().skip(1).map(|w| w.text.as_str()).collect();
    let hit = |raw: &str| -> Option<String> {
        if let Some(path) = resolve(raw, cwd, homes) {
            if let Some(target) = wallets.hit(&path) {
                return Some(target);
            }
            // After `cd`, a relative path may be anywhere: a wallet file name counts.
            let relative = !raw.starts_with(['/', '~', '$']);
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if cwd_changed && relative && wallets.has_file_name(name) {
                return Some(format!("`{raw}` (after a directory change)"));
            }
        }
        None
    };
    if program == "dd" {
        return args
            .iter()
            .filter_map(|a| a.strip_prefix("of="))
            .find_map(hit)
            .map(|t| format!("`dd` writes {t}"));
    }
    let paths: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-') || *a == "-")
        .collect();
    if CLOBBER_ALL.contains(&program.as_str()) {
        return paths
            .iter()
            .find_map(|a| hit(a))
            .map(|t| format!("`{program}` removes or overwrites {t}"));
    }
    if CLOBBER_DEST.contains(&program.as_str()) {
        let target_dir = args
            .iter()
            .position(|a| *a == "-t" || *a == "--target-directory")
            .and_then(|i| args.get(i + 1))
            .copied()
            .or_else(|| {
                args.iter()
                    .find_map(|a| a.strip_prefix("--target-directory="))
            });
        let (dest, sources): (&str, Vec<&str>) = match target_dir {
            Some(dir) => (dir, paths.iter().copied().filter(|p| *p != dir).collect()),
            None => {
                let (last, rest) = paths.split_last()?;
                (*last, rest.to_vec())
            }
        };
        if let Some(t) = hit(dest) {
            return Some(format!("`{program}` overwrites {t}"));
        }
        let dir = resolve(dest, cwd, homes)?;
        return sources
            .iter()
            .find_map(|s| wallets.hit_in_dir(&dir, s))
            .map(|t| format!("`{program}` overwrites {t}"));
    }
    None
}

/// The wallet a `>`/`>>`/`>|`/`&>` redirection in `command` writes, if any. The parser drops
/// redirections, so the raw text is scanned (nested `-c` scripts included).
fn redirect_target(command: &str, cwd: &Path, homes: &Homes, wallets: &Wallets) -> Option<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '>' {
            i += 1;
            continue;
        }
        i += 1;
        while i < chars.len() && matches!(chars[i], '>' | '|' | '&') {
            if chars[i] == '&' {
                // `>&2` duplicates a descriptor.
                break;
            }
            i += 1;
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        let mut word = String::new();
        while i < chars.len() {
            let c = chars[i];
            if c.is_whitespace() || matches!(c, ';' | '|' | '&' | ')' | '<' | '>') {
                break;
            }
            if !matches!(c, '"' | '\'' | '\\') {
                word.push(c);
            }
            i += 1;
        }
        if word.is_empty() {
            continue;
        }
        if let Some(target) = resolve(&word, cwd, homes).and_then(|p| wallets.hit(&p)) {
            return Some(target);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn homes(home: &str) -> Homes {
        Homes {
            env: Some(PathBuf::from(home)),
            passwd: None,
        }
    }

    #[test]
    fn resolve_expands_home_and_normalises() {
        let h = homes("/h");
        let cwd = Path::new("/p");
        assert_eq!(
            resolve("~/.config/solana/id.json", cwd, &h),
            Some(PathBuf::from("/h/.config/solana/id.json"))
        );
        assert_eq!(
            resolve("${HOME}/a/../.config/./solana/id.json", cwd, &h),
            Some(PathBuf::from("/h/.config/solana/id.json"))
        );
        assert_eq!(resolve("k.json", cwd, &h), Some(PathBuf::from("/p/k.json")));
        assert_eq!(resolve("$X/id.json", cwd, &h), None);
    }

    #[test]
    fn keygen_args_read_short_clusters_and_outfiles() {
        let parsed = shell::parse("solana-keygen new -fo out.json");
        let args = keygen_args(&parsed.commands[0].words);
        assert_eq!(args.verb, Some("new"));
        assert!(args.flags.iter().any(|f| f == "-f"));
        assert_eq!(args.outfile.map(outfile_text), Some("out.json"));
        let parsed = shell::parse("solana-keygen new --outfile=x.json --force");
        let args = keygen_args(&parsed.commands[0].words);
        assert_eq!(args.outfile.map(outfile_text), Some("x.json"));
        assert!(args.flags.iter().any(|f| f == "--force"));
    }

    #[test]
    fn keygen_rows_come_from_the_shared_list() {
        let rows = keygen_rows();
        for want in [
            ("new", "--force"),
            ("new", "-f"),
            ("recover", "--force"),
            ("recover", "-f"),
        ] {
            assert!(
                rows.iter().any(|(v, f)| v == want.0 && f == want.1),
                "{want:?} in {rows:?}"
            );
        }
    }

    #[test]
    fn redirections_onto_the_wallet_are_found() {
        let h = homes("/h");
        let w = Wallets {
            paths: vec![(
                "/h/.config/solana/id.json".into(),
                "/h/.config/solana/id.json".into(),
            )],
            canonical: Vec::new(),
        };
        let cwd = Path::new("/p");
        assert!(redirect_target("echo [] > ~/.config/solana/id.json", cwd, &h, &w).is_some());
        assert!(
            redirect_target("echo x >>\"$HOME/.config/solana/id.json\"", cwd, &h, &w).is_some()
        );
        assert!(
            redirect_target("bash -c 'cat k >| ~/.config/solana/id.json'", cwd, &h, &w).is_some()
        );
        assert!(redirect_target("echo x > out.json 2>&1", cwd, &h, &w).is_none());
    }
}
