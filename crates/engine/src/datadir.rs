//! Plugin data dir resolution, shared by every hook and CLI subcommand.
//!
//! The CLI must find the same state the hooks read, so both resolve it here (spec D2.8):
//!
//! 1. `CLAUDE_PLUGIN_DATA` (always set for a plugin hook);
//! 2. else an existing `safe-ai-skill-*` dir under the plugin-data root(s):
//!    `$CLAUDE_CONFIG_DIR/plugins/data` first when that var is set, then
//!    `~/.claude/plugins/data` (`~` is `HOME`, else `USERPROFILE`). When several match,
//!    `safe-ai-skill-safe-ai-skill` wins, then `safe-ai-skill-stbr`, then the
//!    lexicographically smallest name;
//! 3. else `<first root>/safe-ai-skill-safe-ai-skill` (created on first write).
//!
//! There is no `./.safe-ai-skill` fallback: a relative state dir would let a repo plant it.
//! With none of the variables set the dir is unresolvable and [`data_dir`] errors.
//!
//! [`DataDir::trusted`] says whether state there may relax anything (grants, trust, mode).
//! It is `false` when the canonical path is inside `CLAUDE_PROJECT_DIR` or the hook `cwd`,
//! or outside every plugin-data root: a repo's `.claude/settings.json` can point
//! `CLAUDE_PLUGIN_DATA` into its own tree. Callers still read untrusted state for
//! tightening; they never relax on it.

use std::path::{Component, Path, PathBuf};

use crate::error::{EngineError, Error};

/// Prefix of the per-install plugin data dir Claude Code creates (`<plugin>-<marketplace>`).
const DIR_PREFIX: &str = "safe-ai-skill-";

/// Install dir names preferred, in order, when several `safe-ai-skill-*` dirs exist.
const PREFERRED: [&str; 2] = ["safe-ai-skill-safe-ai-skill", "safe-ai-skill-stbr"];

/// The resolved plugin data dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDir {
    /// Where state lives (as resolved, not canonicalized).
    pub path: PathBuf,
    /// `false` when the dir is under the project (or hook cwd) or outside the plugin-data roots.
    pub trusted: bool,
}

/// Resolve the data dir from the process environment, judging trust against
/// `CLAUDE_PROJECT_DIR` only. See the module docs for the order.
pub fn data_dir() -> Result<DataDir, EngineError> {
    data_dir_with_cwd(None)
}

/// [`data_dir`], also distrusting a dir under the hook payload's `cwd`.
pub fn data_dir_with_cwd(cwd: Option<&Path>) -> Result<DataDir, EngineError> {
    resolve(&Env::from_lookup(|k| std::env::var_os(k)), cwd)
}

/// The environment inputs of the resolution (empty values count as unset).
#[derive(Debug, Default, Clone)]
struct Env {
    plugin_data: Option<PathBuf>,
    config_dir: Option<PathBuf>,
    home: Option<PathBuf>,
    project_dir: Option<PathBuf>,
}

impl Env {
    fn from_lookup(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> Env {
        let var = |k: &str| get(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        Env {
            plugin_data: var("CLAUDE_PLUGIN_DATA"),
            config_dir: var("CLAUDE_CONFIG_DIR"),
            home: var("HOME").or_else(|| var("USERPROFILE")),
            project_dir: var("CLAUDE_PROJECT_DIR"),
        }
    }

    /// The plugin-data roots, `$CLAUDE_CONFIG_DIR` first.
    fn roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(cfg) = &self.config_dir {
            roots.push(cfg.join("plugins").join("data"));
        }
        if let Some(home) = &self.home {
            roots.push(home.join(".claude").join("plugins").join("data"));
        }
        roots
    }
}

fn resolve(env: &Env, cwd: Option<&Path>) -> Result<DataDir, EngineError> {
    let roots = env.roots();
    let path = match &env.plugin_data {
        Some(dir) => dir.clone(),
        None => match roots.iter().find_map(|r| pick_install_dir(r)) {
            Some(dir) => dir,
            None => roots.first().map(|r| r.join(PREFERRED[0])).ok_or_else(|| {
                Error::Other(
                    "cannot resolve the plugin data dir: CLAUDE_PLUGIN_DATA, CLAUDE_CONFIG_DIR, \
                     HOME and USERPROFILE are all unset"
                        .to_string(),
                )
            })?,
        },
    };
    let trusted = is_trusted(&path, &roots, env.project_dir.as_deref(), cwd);
    Ok(DataDir { path, trusted })
}

/// The preferred existing `safe-ai-skill-*` dir directly under `root`, if any.
fn pick_install_dir(root: &Path) -> Option<PathBuf> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(DIR_PREFIX))
        .collect();
    names.sort();
    let pick = PREFERRED
        .iter()
        .find(|p| names.iter().any(|n| n == *p))
        .map(|p| p.to_string())
        .or_else(|| names.into_iter().next())?;
    Some(root.join(pick))
}

fn is_trusted(path: &Path, roots: &[PathBuf], project: Option<&Path>, cwd: Option<&Path>) -> bool {
    let Some(canon) = canonical_lenient(path) else {
        return false;
    };
    let inside = |base: &Path| canonical_lenient(base).is_some_and(|b| canon.starts_with(&b));
    if project.into_iter().chain(cwd).any(inside) {
        return false;
    }
    roots
        .iter()
        .any(|root| canonical_lenient(root).is_some_and(|r| canon != r && canon.starts_with(&r)))
}

/// Canonicalize `path` even when its tail does not exist yet: canonicalize the deepest
/// existing ancestor, then apply the remaining components lexically (a missing component
/// cannot be a symlink, so `..` there just pops). A relative path is taken from the process
/// cwd. `None` when nothing resolves.
fn canonical_lenient(path: &Path) -> Option<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut existing = abs.as_path();
    let mut base = loop {
        if let Ok(c) = std::fs::canonicalize(existing) {
            break c;
        }
        existing = existing.parent()?;
    };
    // `existing` is a component prefix of `abs`; apply the rest of `abs` lexically.
    let skip = existing.components().count();
    for comp in abs.components().skip(skip) {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                base.pop();
            }
            Component::Normal(name) => base.push(name),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn tmp(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "safe_ai_skill_datadir_{tag}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn env_home(home: &Path) -> Env {
        Env {
            home: Some(home.to_path_buf()),
            ..Env::default()
        }
    }

    fn data_root(home: &Path) -> PathBuf {
        home.join(".claude").join("plugins").join("data")
    }

    #[test]
    fn plugin_data_env_wins_and_is_trusted_under_the_root() {
        let home = tmp("envwins");
        let pd = data_root(&home).join("safe-ai-skill-x");
        let env = Env {
            plugin_data: Some(pd.clone()),
            ..env_home(&home)
        };
        let d = resolve(&env, None).unwrap();
        assert_eq!(d.path, pd);
        assert!(d.trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn data_dir_under_project_is_untrusted() {
        let home = tmp("underproj");
        let project = home.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let env = Env {
            plugin_data: Some(project.join(".safe-ai-skill")),
            project_dir: Some(project.clone()),
            ..env_home(&home)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        // Inside a root too: the project check alone must distrust it.
        let nested = data_root(&home).join("safe-ai-skill-x").join("proj");
        std::fs::create_dir_all(&nested).unwrap();
        let env = Env {
            plugin_data: Some(nested.join("state")),
            project_dir: Some(nested),
            ..env_home(&home)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn project_containing_the_root_makes_it_untrusted() {
        // A project dir that contains the plugin-data root (claude launched in `~`) distrusts it.
        let home = tmp("projhome");
        let pd = data_root(&home).join("safe-ai-skill-safe-ai-skill");
        let env = Env {
            plugin_data: Some(pd),
            project_dir: Some(home.clone()),
            ..env_home(&home)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn data_dir_under_hook_cwd_is_untrusted() {
        let home = tmp("undercwd");
        // The cwd holds a root, so only the cwd check can distrust the dir.
        let cwd = home.join(".claude");
        std::fs::create_dir_all(&cwd).unwrap();
        let env = Env {
            plugin_data: Some(data_root(&home).join("safe-ai-skill-x")),
            ..env_home(&home)
        };
        assert!(!resolve(&env, Some(&cwd)).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn data_dir_outside_the_roots_is_untrusted() {
        let home = tmp("outside");
        let env = Env {
            plugin_data: Some(home.join("elsewhere")),
            ..env_home(&home)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn the_root_itself_is_untrusted() {
        let home = tmp("rootitself");
        let env = Env {
            plugin_data: Some(data_root(&home)),
            ..env_home(&home)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn dotdot_escape_through_a_missing_dir_is_untrusted() {
        let home = tmp("dotdot");
        let escape = data_root(&home)
            .join("missing")
            .join("..")
            .join("..")
            .join("..")
            .join("..")
            .join("loot");
        let env = Env {
            plugin_data: Some(escape),
            ..env_home(&home)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_from_the_root_into_the_project_is_untrusted() {
        let home = tmp("symlink");
        let project = home.join("proj");
        let root = data_root(&home);
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&project, root.join("safe-ai-skill-evil")).unwrap();
        let env = Env {
            plugin_data: Some(root.join("safe-ai-skill-evil")),
            project_dir: Some(project),
            ..env_home(&home)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn install_dir_preference_order() {
        let home = tmp("prefer");
        let root = data_root(&home);
        for name in [
            "safe-ai-skill-aaa",
            "safe-ai-skill-stbr",
            "safe-ai-skill-safe-ai-skill",
            "other-plugin-x",
        ] {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        let env = env_home(&home);
        let pick = |env: &Env| resolve(env, None).unwrap();
        let d = pick(&env);
        assert_eq!(d.path, root.join("safe-ai-skill-safe-ai-skill"));
        assert!(d.trusted);
        std::fs::remove_dir_all(root.join("safe-ai-skill-safe-ai-skill")).unwrap();
        assert_eq!(pick(&env).path, root.join("safe-ai-skill-stbr"));
        std::fs::remove_dir_all(root.join("safe-ai-skill-stbr")).unwrap();
        std::fs::create_dir_all(root.join("safe-ai-skill-zzz")).unwrap();
        assert_eq!(pick(&env).path, root.join("safe-ai-skill-aaa"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn no_install_dir_defaults_under_the_root_never_relative() {
        let home = tmp("default");
        let d = resolve(&env_home(&home), None).unwrap();
        assert_eq!(d.path, data_root(&home).join("safe-ai-skill-safe-ai-skill"));
        assert!(d.path.is_absolute());
        assert!(d.trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn config_dir_root_comes_first() {
        let home = tmp("cfgdir");
        let cfg = home.join("cfg");
        std::fs::create_dir_all(data_root(&home).join("safe-ai-skill-stbr")).unwrap();
        let env = Env {
            config_dir: Some(cfg.clone()),
            ..env_home(&home)
        };
        // Nothing under the config root: the ~/.claude install is found.
        assert_eq!(
            resolve(&env, None).unwrap().path,
            data_root(&home).join("safe-ai-skill-stbr")
        );
        let under_cfg = cfg.join("plugins").join("data").join("safe-ai-skill-stbr");
        std::fs::create_dir_all(&under_cfg).unwrap();
        let d = resolve(&env, None).unwrap();
        assert_eq!(d.path, under_cfg);
        assert!(d.trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn unresolvable_without_any_variable() {
        assert!(resolve(&Env::default(), None).is_err());
    }

    #[test]
    fn userprofile_stands_in_for_home_and_empty_counts_as_unset() {
        let env = Env::from_lookup(|k| match k {
            "HOME" => Some(OsString::new()),
            "USERPROFILE" => Some(OsString::from("/users/me")),
            "CLAUDE_PLUGIN_DATA" => Some(OsString::new()),
            _ => None,
        });
        assert_eq!(env.home, Some(PathBuf::from("/users/me")));
        assert_eq!(env.plugin_data, None);
    }
}
