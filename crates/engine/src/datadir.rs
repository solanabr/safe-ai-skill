//! Plugin data dir resolution, shared by every hook and CLI subcommand.
//!
//! The CLI must find the same state the hooks read, so both resolve it here (spec D2.8):
//!
//! 1. `CLAUDE_PLUGIN_DATA` (always set for a plugin hook);
//! 2. else an existing `safe-ai-skill-*` dir under the plugin-data root:
//!    `$CLAUDE_CONFIG_DIR/plugins/data` when that var is set (it replaces `~/.claude`, as in
//!    Claude Code), else `<home>/.claude/plugins/data`. `<home>` is the OS user-database home
//!    (see below), falling back to `HOME`/`USERPROFILE` only when the lookup fails. In the
//!    root, `safe-ai-skill-safe-ai-skill` wins, then `safe-ai-skill-stbr`; failing both, a
//!    lone `safe-ai-skill-*` dir is used, and several are ambiguous (unresolved);
//! 3. else unresolved: an error telling the user to set `CLAUDE_PLUGIN_DATA`. No dir is
//!    invented (the plugin's dir exists once Claude Code installed it).
//!
//! There is no `./.safe-ai-skill` fallback: a relative state dir would let a repo plant it.
//! When nothing resolves, [`data_dir`] errors; code that needs a path anyway uses
//! [`unresolved`], a sentinel that loads nothing and refuses stores.
//!
//! ## Trust
//!
//! [`DataDir::trusted`] says whether state there may relax anything (grants, trust, mode).
//! A repo's `.claude/settings.json` `env` can set `HOME`, `CLAUDE_CONFIG_DIR` and
//! `CLAUDE_PLUGIN_DATA`, so the trust roots never come from the environment alone. The dir is
//! trusted iff its canonical path is strictly inside one of:
//!
//! - `<passwd home>/.claude/plugins/data`, where `<passwd home>` is
//!   `getpwuid_r(geteuid())->pw_dir` on unix. This root is trusted even when the project or
//!   the hook cwd contains it (claude started in `$HOME`). On Windows there is no user
//!   database lookup yet: `USERPROFILE` stands in, which a repo's settings env could override;
//! - `$CLAUDE_CONFIG_DIR/plugins/data`, only when the canonical `CLAUDE_CONFIG_DIR` is under
//!   the passwd home and not inside `CLAUDE_PROJECT_DIR` or the hook cwd, and the data dir
//!   itself is not inside either. (An allow-list: a deny-list of temp dirs would trust
//!   whatever a repo-set `TMPDIR` leaves out.)
//!
//! Everything else is untrusted. Callers still read untrusted state for tightening; they never
//! relax on it.
//!
//! **Hooks must call [`data_dir_with_cwd`]`(Some(cwd))`** with the payload's `cwd`, so a
//! `CLAUDE_CONFIG_DIR` inside the session's tree is distrusted even when
//! `CLAUDE_PROJECT_DIR` is unset. The CLI uses [`data_dir`].

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
    /// Whether state here may relax anything; see the module docs.
    pub trusted: bool,
}

impl DataDir {
    /// `true` for the [`unresolved`] sentinel.
    pub fn is_unresolved(&self) -> bool {
        self.path == unresolved_path()
    }
}

/// The sentinel for an unresolvable data dir: untrusted, [`crate::statefile`] loads nothing
/// from it and refuses to store into it, and its path lies under a device file, so plain
/// filesystem reads and writes under it fail too.
pub fn unresolved() -> DataDir {
    DataDir {
        path: unresolved_path(),
        trusted: false,
    }
}

fn unresolved_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\NUL\safe-ai-skill-unresolved")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/dev/null/safe-ai-skill-unresolved")
    }
}

/// Resolve the data dir from the process environment, judging trust against
/// `CLAUDE_PROJECT_DIR` only. Hooks use [`data_dir_with_cwd`].
pub fn data_dir() -> Result<DataDir, EngineError> {
    data_dir_with_cwd(None)
}

/// [`data_dir`], also distrusting a `CLAUDE_CONFIG_DIR` inside the hook payload's `cwd`.
pub fn data_dir_with_cwd(cwd: Option<&Path>) -> Result<DataDir, EngineError> {
    let mut env = Env::from_lookup(|k| std::env::var_os(k));
    env.passwd_home = passwd_home();
    resolve(&env, cwd)
}

/// The inputs of the resolution (empty variables count as unset).
#[derive(Debug, Default, Clone)]
struct Env {
    plugin_data: Option<PathBuf>,
    config_dir: Option<PathBuf>,
    /// `HOME`, else `USERPROFILE`: a discovery fallback only, never a trust root.
    env_home: Option<PathBuf>,
    project_dir: Option<PathBuf>,
    /// The OS user-database home: the trusted home root.
    passwd_home: Option<PathBuf>,
}

impl Env {
    fn from_lookup(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> Env {
        let var = |k: &str| get(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        Env {
            plugin_data: var("CLAUDE_PLUGIN_DATA"),
            config_dir: var("CLAUDE_CONFIG_DIR"),
            env_home: var("HOME").or_else(|| var("USERPROFILE")),
            project_dir: var("CLAUDE_PROJECT_DIR"),
            passwd_home: None,
        }
    }

    fn config_root(&self) -> Option<PathBuf> {
        self.config_dir
            .as_ref()
            .map(|c| c.join("plugins").join("data"))
    }

    fn home_root(&self) -> Option<PathBuf> {
        self.passwd_home
            .as_ref()
            .map(|h| h.join(".claude").join("plugins").join("data"))
    }

    /// The root searched for an install dir: `$CLAUDE_CONFIG_DIR` replaces `~/.claude`.
    fn discovery_roots(&self) -> Vec<PathBuf> {
        if let Some(root) = self.config_root() {
            return vec![root];
        }
        let home = self.passwd_home.as_ref().or(self.env_home.as_ref());
        home.map(|h| h.join(".claude").join("plugins").join("data"))
            .into_iter()
            .collect()
    }
}

/// What a plugin-data root holds.
enum Install {
    None,
    One(PathBuf),
    Ambiguous,
}

fn resolve(env: &Env, cwd: Option<&Path>) -> Result<DataDir, EngineError> {
    let path = match &env.plugin_data {
        Some(dir) => dir.clone(),
        None => discover(&env.discovery_roots())?,
    };
    let trusted = is_trusted(&path, env, cwd) || test_trusted();
    Ok(DataDir { path, trusted })
}

/// Test-only: integration tests cannot place a data dir under the real passwd home, so a
/// `test-hooks` build trusts the resolved dir when [`TEST_TRUST_ENV`] is `1`. Never in a
/// release build (the feature is never enabled there).
#[cfg(feature = "test-hooks")]
fn test_trusted() -> bool {
    std::env::var(TEST_TRUST_ENV).is_ok_and(|v| v == "1")
}

#[cfg(not(feature = "test-hooks"))]
fn test_trusted() -> bool {
    false
}

/// The `test-hooks` override read by [`test_trusted`].
pub const TEST_TRUST_ENV: &str = "SAFE_AI_SKILL_TEST_TRUST_DATA_DIR";

fn discover(roots: &[PathBuf]) -> Result<PathBuf, EngineError> {
    for root in roots {
        match pick_install_dir(root) {
            Install::One(dir) => return Ok(dir),
            Install::Ambiguous => {
                return Err(Error::Other(format!(
                    "cannot pick the plugin data dir: several safe-ai-skill-* dirs under {}; \
                     set CLAUDE_PLUGIN_DATA",
                    root.display()
                )))
            }
            Install::None => {}
        }
    }
    Err(Error::Other(match roots.first() {
        Some(root) => format!(
            "no plugin data dir under {} (is the plugin installed?); set CLAUDE_PLUGIN_DATA to \
             the plugin's data dir, usually ~/.claude/plugins/data/safe-ai-skill-<marketplace>",
            root.display()
        ),
        None => "cannot resolve the plugin data dir: no CLAUDE_PLUGIN_DATA, CLAUDE_CONFIG_DIR or \
                 home; set CLAUDE_PLUGIN_DATA"
            .to_string(),
    }))
}

/// The install dir under `root`: a preferred name, else the only `safe-ai-skill-*` dir.
fn pick_install_dir(root: &Path) -> Install {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Install::None;
    };
    let names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(DIR_PREFIX))
        .collect();
    if let Some(p) = PREFERRED.iter().find(|p| names.iter().any(|n| n == *p)) {
        return Install::One(root.join(p));
    }
    match names.as_slice() {
        [] => Install::None,
        [only] => Install::One(root.join(only)),
        _ => Install::Ambiguous,
    }
}

fn is_trusted(path: &Path, env: &Env, cwd: Option<&Path>) -> bool {
    let Some(canon) = canonical_lenient(path) else {
        return false;
    };
    let strictly_inside =
        |root: &Path| canonical_lenient(root).is_some_and(|r| canon != r && canon.starts_with(&r));

    if env.home_root().is_some_and(|r| strictly_inside(&r)) {
        return true;
    }

    // `$CLAUDE_CONFIG_DIR` is env-settable, so its root is allow-listed: the config dir must
    // be under the passwd home, and neither it nor the data dir inside the project or cwd.
    let (Some(cfg), Some(cfg_root), Some(home)) =
        (&env.config_dir, env.config_root(), &env.passwd_home)
    else {
        return false;
    };
    let (Some(cfg), Some(home)) = (canonical_lenient(cfg), canonical_lenient(home)) else {
        return false;
    };
    // A home of `/` (no parent) would put every config dir "under the home".
    if home.parent().is_none() {
        return false;
    }
    let session_dirs: Vec<PathBuf> = env
        .project_dir
        .iter()
        .map(PathBuf::as_path)
        .chain(cwd)
        .filter_map(canonical_lenient)
        .collect();
    let in_session = |p: &Path| session_dirs.iter().any(|d| p.starts_with(d));
    cfg.starts_with(&home) && !in_session(&cfg) && !in_session(&canon) && strictly_inside(&cfg_root)
}

/// The effective user's home from the OS user database (`getpwuid_r`).
#[cfg(unix)]
pub fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;

    let mut size = 1024usize;
    while size <= 1 << 20 {
        let mut buf: Vec<libc::c_char> = vec![0; size];
        // SAFETY: `passwd` is plain old data; zeroed is a valid initial value for the out-param.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call and `buf.len()` is the buffer's size.
        let rc = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            size *= 2;
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success `pw_dir` points to a NUL-terminated string inside `buf`, which is
        // alive until the end of this iteration; it is copied out before `buf` drops.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        let dir = std::ffi::OsStr::from_bytes(dir.to_bytes());
        return (!dir.is_empty()).then(|| PathBuf::from(dir));
    }
    None
}

/// Windows has no user-database lookup here yet: `USERPROFILE` (repo-settable) stands in.
#[cfg(not(unix))]
pub fn passwd_home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Canonicalize `path` even when its tail does not exist yet: canonicalize the deepest
/// existing ancestor, then apply the remaining components lexically (a missing component
/// cannot be a symlink, so `..` there just pops). A relative path is taken from the process
/// cwd. `None` when nothing resolves. The result is only ever compared, so on Windows it is
/// case-folded ([`fold_case`]): the lexical tail keeps the caller's spelling.
fn canonical_lenient(path: &Path) -> Option<PathBuf> {
    canonical_lenient_cased(path).map(fold_case)
}

/// Windows paths compare case-insensitively; elsewhere `path` is returned unchanged.
fn fold_case(path: PathBuf) -> PathBuf {
    if cfg!(windows) {
        lowercase_path(&path)
    } else {
        path
    }
}

fn lowercase_path(path: &Path) -> PathBuf {
    PathBuf::from(path.to_string_lossy().to_lowercase())
}

fn canonical_lenient_cased(path: &Path) -> Option<PathBuf> {
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

    /// An environment whose user-database home is `home`.
    fn env_home(home: &Path) -> Env {
        Env {
            env_home: Some(home.to_path_buf()),
            passwd_home: Some(home.to_path_buf()),
            ..Env::default()
        }
    }

    fn data_root(home: &Path) -> PathBuf {
        home.join(".claude").join("plugins").join("data")
    }

    fn with_plugin_data(env: Env, pd: PathBuf) -> Env {
        Env {
            plugin_data: Some(pd),
            ..env
        }
    }

    #[test]
    fn lowercase_path_folds_every_component() {
        assert_eq!(
            lowercase_path(Path::new("C:/Users/Me/.Claude/Plugins")),
            PathBuf::from("c:/users/me/.claude/plugins")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_trust_ignores_case_in_the_missing_tail() {
        let home = tmp("wincase");
        let pd = data_root(&home)
            .join("safe-ai-skill-x")
            .to_string_lossy()
            .replace(".claude", ".CLAUDE")
            .replace("plugins", "Plugins");
        let d = resolve(&with_plugin_data(env_home(&home), PathBuf::from(pd)), None).unwrap();
        assert!(d.trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn plugin_data_under_the_home_root_is_trusted() {
        let home = tmp("envwins");
        let pd = data_root(&home).join("safe-ai-skill-x");
        let d = resolve(&with_plugin_data(env_home(&home), pd.clone()), None).unwrap();
        assert_eq!(d.path, pd);
        assert!(d.trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn data_dir_in_the_project_tree_is_untrusted() {
        let home = tmp("underproj");
        let project = home.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let env = Env {
            project_dir: Some(project.clone()),
            ..with_plugin_data(env_home(&home), project.join(".safe-ai-skill"))
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn home_root_is_trusted_when_the_project_or_cwd_contains_it() {
        // claude started in `$HOME`: the project and cwd are ancestors of the root.
        let home = tmp("projhome");
        let pd = data_root(&home).join("safe-ai-skill-safe-ai-skill");
        let env = Env {
            project_dir: Some(home.clone()),
            ..with_plugin_data(env_home(&home), pd)
        };
        assert!(resolve(&env, Some(&home)).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn project_nested_inside_the_home_root_is_trusted() {
        let home = tmp("nested");
        let nested = data_root(&home).join("safe-ai-skill-x").join("proj");
        std::fs::create_dir_all(&nested).unwrap();
        let env = Env {
            project_dir: Some(nested.clone()),
            ..with_plugin_data(env_home(&home), nested.join("state"))
        };
        assert!(resolve(&env, Some(&nested)).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn repo_set_home_is_not_a_trust_root() {
        // The repo's settings env sets HOME=/tmp/x and points the data dir under it.
        let real = tmp("realhome");
        let fake = tmp("fakehome");
        let env = Env {
            env_home: Some(fake.clone()),
            passwd_home: Some(real.clone()),
            ..Env::default()
        };
        let pd = data_root(&fake).join("safe-ai-skill-safe-ai-skill");
        assert!(
            !resolve(&with_plugin_data(env.clone(), pd), None)
                .unwrap()
                .trusted
        );
        // Without CLAUDE_PLUGIN_DATA, discovery uses the passwd home, not HOME.
        std::fs::create_dir_all(data_root(&fake).join("safe-ai-skill-stbr")).unwrap();
        std::fs::create_dir_all(data_root(&real).join("safe-ai-skill-safe-ai-skill")).unwrap();
        assert_eq!(
            resolve(&env, None).unwrap().path,
            data_root(&real).join("safe-ai-skill-safe-ai-skill")
        );
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_dir_all(&fake);
    }

    #[test]
    fn data_dir_outside_the_roots_is_untrusted() {
        let home = tmp("outside");
        let env = with_plugin_data(env_home(&home), home.join("elsewhere"));
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn the_root_itself_is_untrusted() {
        let home = tmp("rootitself");
        let env = with_plugin_data(env_home(&home), data_root(&home));
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
        assert!(
            !resolve(&with_plugin_data(env_home(&home), escape), None)
                .unwrap()
                .trusted
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_from_the_root_into_the_project_is_untrusted() {
        let home = tmp("symlink");
        let elsewhere = tmp("symlink_target");
        let root = data_root(&home);
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("safe-ai-skill-evil")).unwrap();
        let env = with_plugin_data(env_home(&home), root.join("safe-ai-skill-evil"));
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn config_dir_under_the_passwd_home_is_trusted_outside_project_and_cwd() {
        let home = tmp("cfgok");
        let cfg = home.join(".claude-alt");
        let project = home.join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let pd = cfg.join("plugins").join("data").join("safe-ai-skill-stbr");
        let env = Env {
            config_dir: Some(cfg),
            project_dir: Some(project.clone()),
            ..with_plugin_data(env_home(&home), pd)
        };
        assert!(resolve(&env, Some(&project)).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn config_dir_outside_the_passwd_home_is_untrusted() {
        // A repo sets CLAUDE_CONFIG_DIR (and TMPDIR, so no deny-list can help) elsewhere.
        let home = tmp("cfghome");
        let elsewhere = tmp("cfgelsewhere");
        let pd = elsewhere
            .join("plugins")
            .join("data")
            .join("safe-ai-skill-stbr");
        let env = Env {
            config_dir: Some(elsewhere.clone()),
            ..with_plugin_data(env_home(&home), pd)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn config_root_is_never_trusted_when_the_passwd_home_is_the_filesystem_root() {
        let base = tmp("cfgslash");
        let cfg = base.join("cfg");
        let pd = cfg.join("plugins").join("data").join("safe-ai-skill-stbr");
        let env = Env {
            config_dir: Some(cfg),
            passwd_home: Some(PathBuf::from("/")),
            ..with_plugin_data(Env::default(), pd)
        };
        assert!(!resolve(&env, None).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn config_dir_inside_the_project_or_cwd_is_untrusted() {
        let home = tmp("cfgproj");
        let project = home.join("proj");
        let cfg = project.join(".cfg");
        std::fs::create_dir_all(&cfg).unwrap();
        let pd = cfg.join("plugins").join("data").join("safe-ai-skill-stbr");
        let env = Env {
            config_dir: Some(cfg.clone()),
            ..with_plugin_data(env_home(&home), pd)
        };
        assert!(resolve(&env, None).unwrap().trusted, "control");
        let in_project = Env {
            project_dir: Some(project.clone()),
            ..env.clone()
        };
        assert!(!resolve(&in_project, None).unwrap().trusted);
        assert!(!resolve(&env, Some(&project)).unwrap().trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn data_dir_in_the_project_under_a_config_root_is_untrusted() {
        // The config dir itself is fine; the project sits inside its data root.
        let home = tmp("cfgdataproj");
        let cfg = home.join(".claude-alt");
        let project = cfg.join("plugins").join("data").join("safe-ai-skill-x");
        std::fs::create_dir_all(&project).unwrap();
        let env = Env {
            config_dir: Some(cfg),
            ..with_plugin_data(env_home(&home), project.join("state"))
        };
        assert!(resolve(&env, None).unwrap().trusted, "control");
        let in_project = Env {
            project_dir: Some(project.clone()),
            ..env.clone()
        };
        assert!(!resolve(&in_project, None).unwrap().trusted);
        assert!(!resolve(&env, Some(&project)).unwrap().trusted);
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
        let d = resolve(&env, None).unwrap();
        assert_eq!(d.path, root.join("safe-ai-skill-safe-ai-skill"));
        assert!(d.trusted);
        std::fs::remove_dir_all(root.join("safe-ai-skill-safe-ai-skill")).unwrap();
        assert_eq!(
            resolve(&env, None).unwrap().path,
            root.join("safe-ai-skill-stbr")
        );
        std::fs::remove_dir_all(root.join("safe-ai-skill-stbr")).unwrap();
        // A lone non-preferred install is used.
        assert_eq!(
            resolve(&env, None).unwrap().path,
            root.join("safe-ai-skill-aaa")
        );
        // Two non-preferred installs are ambiguous: unresolved, not a guess.
        std::fs::create_dir_all(root.join("safe-ai-skill-zzz")).unwrap();
        assert!(resolve(&env, None).is_err());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn no_install_dir_is_an_error_naming_claude_plugin_data() {
        let home = tmp("default");
        let err = resolve(&env_home(&home), None).unwrap_err().to_string();
        assert!(err.contains("CLAUDE_PLUGIN_DATA"), "{err}");
        assert!(!data_root(&home)
            .join("safe-ai-skill-safe-ai-skill")
            .exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn config_dir_root_replaces_the_home_root() {
        let home = tmp("cfgdir");
        let cfg = home.join("cfg");
        std::fs::create_dir_all(data_root(&home).join("safe-ai-skill-stbr")).unwrap();
        let env = Env {
            config_dir: Some(cfg.clone()),
            ..env_home(&home)
        };
        // `$CLAUDE_CONFIG_DIR` replaces `~/.claude`: the home install is not consulted.
        assert!(resolve(&env, None).is_err());
        let under_cfg = cfg.join("plugins").join("data").join("safe-ai-skill-stbr");
        std::fs::create_dir_all(&under_cfg).unwrap();
        let d = resolve(&env, None).unwrap();
        assert_eq!(d.path, under_cfg);
        assert!(d.trusted);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn unresolvable_without_any_input() {
        assert!(resolve(&Env::default(), None).is_err());
    }

    #[test]
    fn unresolved_sentinel_is_untrusted_and_unusable() {
        let d = unresolved();
        assert!(d.is_unresolved());
        assert!(!d.trusted);
        assert!(std::fs::create_dir_all(d.path.join("x")).is_err());
        assert!(std::fs::read(d.path.join("grants.json")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn passwd_home_is_found() {
        let home = passwd_home().unwrap();
        assert!(home.is_absolute());
    }

    #[test]
    fn userprofile_stands_in_for_home_and_empty_counts_as_unset() {
        let env = Env::from_lookup(|k| match k {
            "HOME" => Some(OsString::new()),
            "USERPROFILE" => Some(OsString::from("/users/me")),
            "CLAUDE_PLUGIN_DATA" => Some(OsString::new()),
            _ => None,
        });
        assert_eq!(env.env_home, Some(PathBuf::from("/users/me")));
        assert_eq!(env.plugin_data, None);
    }
}
