//! Whether a skill pack is tracked by git, read straight from the repository files.
//!
//! `supply_chain.on_block: move` must never move a pack a repository tracks (a submodule, or
//! files in the index): the move would show up as a deletion the next `git status` reports. The
//! pack tree is untrusted, so git is never run here (a repository's config can name programs
//! git then executes): the answer comes from `.gitmodules` and the binary `.git/index`, parsed
//! by hand. Every doubt (an unreadable, oversized or split index, an unknown version) counts as
//! tracked, so the pack is denied in place instead of moved.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Largest index or `.gitmodules` read (an oversized one counts as tracked).
const MAX_READ: u64 = 64 * 1024 * 1024;
/// Index entry fields before the path (`ondisk_size` without the extended flags).
const ENTRY_FIXED: usize = 62;
/// Mode of a submodule entry (gitlink), after masking the file-type bits.
const MODE_GITLINK: u32 = 0o160000;
/// Mode of a sparse-index directory entry.
const MODE_DIR: u32 = 0o040000;
/// Mask of the file-type bits of an index mode.
const MODE_TYPE: u32 = 0o170000;

/// Whether a pack may be moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tracking {
    /// No repository tracks it: it may be moved.
    Untracked,
    /// A repository tracks it, or that cannot be ruled out. The text finishes
    /// "not moved: tracked by git" in the report.
    Tracked(&'static str),
}

impl Tracking {
    /// The pack must stay where it is.
    pub fn is_tracked(self) -> bool {
        matches!(self, Tracking::Tracked(_))
    }
}

/// Whether the pack directory `pack` is tracked by any enclosing git repository, or is a
/// repository (a clone) itself.
pub fn tracking(pack: &Path) -> Tracking {
    let Some(pack) = absolute(pack) else {
        return Tracking::Tracked("its path cannot be resolved");
    };
    if pack.join(".git").exists() {
        return Tracking::Tracked("it is a git repository or submodule checkout");
    }
    for root in pack.ancestors().skip(1) {
        let rel = match pack.strip_prefix(root) {
            Ok(rel) => slash(rel),
            Err(_) => continue,
        };
        if rel.is_empty() {
            continue;
        }
        let git = root.join(".git");
        let gitmodules = root.join(".gitmodules");
        if !git.exists() && !gitmodules.exists() {
            continue;
        }
        match read_bounded(&gitmodules) {
            Slurp::Missing => {}
            Slurp::Unreadable => return Tracking::Tracked("its .gitmodules cannot be read"),
            Slurp::Data(bytes) => {
                if submodule_covers(&String::from_utf8_lossy(&bytes), &rel) {
                    return Tracking::Tracked("it is a submodule path in .gitmodules");
                }
            }
        }
        if git.exists() {
            let Some(index) = index_path(&git, root) else {
                return Tracking::Tracked("its git directory cannot be resolved");
            };
            match read_bounded(&index) {
                // A repository with nothing staged has no index file.
                Slurp::Missing => {}
                Slurp::Unreadable => return Tracking::Tracked("the git index cannot be read"),
                Slurp::Data(bytes) => match index_covers(&bytes, &rel) {
                    Ok(true) => return Tracking::Tracked("the git index lists it"),
                    Ok(false) => {}
                    Err(()) => return Tracking::Tracked("the git index cannot be parsed"),
                },
            }
        }
    }
    Tracking::Untracked
}

/// `path` made absolute, with symlinks in its directory resolved (the last component, which a
/// move would rename, is kept as it is).
fn absolute(path: &Path) -> Option<PathBuf> {
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let name = full.file_name()?;
    let parent = full.parent()?.canonicalize().ok()?;
    Some(parent.join(name))
}

/// `/`-separated normal components of `rel`.
fn slash(rel: &Path) -> String {
    rel.components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

enum Slurp {
    Missing,
    Unreadable,
    Data(Vec<u8>),
}

/// Open flags that keep `open` from blocking on a FIFO or taking a terminal as the controlling
/// one (the file type is checked on the open handle afterwards).
#[cfg(unix)]
fn safe_open_flags() -> i32 {
    libc::O_NONBLOCK | libc::O_NOCTTY
}

/// `path` read in full when it is a regular file of at most [`MAX_READ`] bytes. A FIFO, a
/// device (a tty, `/dev/zero`), a directory, or a symlink to one is [`Slurp::Unreadable`]: it is
/// opened without blocking and its type is taken from the open handle, so nothing swapped in
/// after a check can stall the sweep, and the caller treats it as tracked.
fn read_bounded(path: &Path) -> Slurp {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(safe_open_flags());
    }
    let file = match options.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Slurp::Missing,
        Err(_) => return Slurp::Unreadable,
    };
    match file.metadata() {
        Ok(m) if m.is_file() && m.len() <= MAX_READ => {}
        _ => return Slurp::Unreadable,
    }
    let mut bytes = Vec::new();
    match file.take(MAX_READ + 1).read_to_end(&mut bytes) {
        Ok(n) if (n as u64) <= MAX_READ => Slurp::Data(bytes),
        _ => Slurp::Unreadable,
    }
}

/// The index file of the repository whose `.git` is `git` (a directory, or a `gitdir:` file
/// as in a worktree or a submodule checkout).
fn index_path(git: &Path, root: &Path) -> Option<PathBuf> {
    if git.is_dir() {
        return Some(git.join("index"));
    }
    let Slurp::Data(bytes) = read_bounded(git) else {
        return None;
    };
    let text = String::from_utf8_lossy(&bytes);
    let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let target = Path::new(target);
    let dir = if target.is_absolute() {
        target.to_path_buf()
    } else {
        root.join(target)
    };
    dir.is_dir().then(|| dir.join("index"))
}

/// Lowercased, so a case-insensitive filesystem cannot slip a differently-cased spelling past
/// the comparison (a false match only keeps a pack in place).
fn fold(path: &str) -> String {
    path.trim_matches('/').to_lowercase()
}

/// `target` is, contains or lies inside a path `.gitmodules` declares.
fn submodule_covers(body: &str, target: &str) -> bool {
    let target = fold(target);
    body.lines().any(|line| {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        if key.trim() != "path" {
            return false;
        }
        let declared = fold(value.trim().trim_matches('"').trim_start_matches("./"));
        !declared.is_empty() && related(&declared, &target)
    })
}

/// `a` equals `b`, or one is a directory prefix of the other.
fn related(a: &str, b: &str) -> bool {
    a == b
        || b.strip_prefix(a).is_some_and(|rest| rest.starts_with('/'))
        || a.strip_prefix(b).is_some_and(|rest| rest.starts_with('/'))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_be_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// The offset-encoded varint of index version 4 (the bytes of the previous path to drop).
fn varint(bytes: &[u8], at: &mut usize) -> Option<usize> {
    let mut byte = *bytes.get(*at)?;
    *at = at.checked_add(1)?;
    let mut value = usize::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = *bytes.get(*at)?;
        *at = at.checked_add(1)?;
        value = value.checked_add(1)?.checked_mul(128)?;
        value = value.checked_add(usize::from(byte & 0x7f))?;
    }
    Some(value)
}

/// Longest path an index entry may have (`PATH_MAX`; git's own name-length field is 12 bits).
/// A longer one is not parsed further: the index is treated as unreadable.
const MAX_NAME: usize = 4096;

/// How an index path relates to the (folded) target.
#[derive(PartialEq, Eq)]
enum Rel {
    Equal,
    /// The target is a directory prefix of the path (the path lies inside the target).
    Inside,
    /// The path is a directory prefix of the target (the target lies inside the path).
    Contains,
    Apart,
}

/// `path` against `target` (already [`fold`]ed), ASCII-case-insensitively and without
/// allocating; a path with non-ASCII bytes is lower-cased as text first.
fn relation(path: &[u8], target: &[u8]) -> Rel {
    if !path.is_ascii() {
        let lowered = String::from_utf8_lossy(path).to_lowercase();
        return relation_ascii(lowered.as_bytes(), target);
    }
    relation_ascii(path, target)
}

fn relation_ascii(path: &[u8], target: &[u8]) -> Rel {
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    let path = &path[..end];
    let n = path.len().min(target.len());
    if !path[..n].eq_ignore_ascii_case(&target[..n]) {
        return Rel::Apart;
    }
    match path.len().cmp(&target.len()) {
        std::cmp::Ordering::Equal => Rel::Equal,
        std::cmp::Ordering::Greater if path[target.len()] == b'/' => Rel::Inside,
        std::cmp::Ordering::Less if target[path.len()] == b'/' => Rel::Contains,
        _ => Rel::Apart,
    }
}

fn at(base: usize, add: usize) -> Result<usize, ()> {
    base.checked_add(add).ok_or(())
}

/// `Ok(true)` when an index entry is, lies inside or (for a submodule or a sparse directory)
/// contains `target`; `Err` for anything this parser does not fully understand (an unknown
/// version, a truncated or split index, a path over [`MAX_NAME`]).
///
/// Work is linear in the index size: a version-4 path is rebuilt in one reused buffer (the
/// previous path truncated, the new suffix appended), and the comparison allocates nothing for
/// ASCII paths.
fn index_covers(bytes: &[u8], target: &str) -> Result<bool, ()> {
    if bytes.get(..4) != Some(b"DIRC") {
        return Err(());
    }
    let version = be32(bytes, 4).ok_or(())?;
    if !(2..=4).contains(&version) {
        return Err(());
    }
    let count = be32(bytes, 8).ok_or(())? as usize;
    // Every entry takes more than one byte.
    if count > bytes.len() {
        return Err(());
    }
    let target = fold(target);
    let target = target.as_bytes();
    let mut cursor = 12usize;
    let mut name: Vec<u8> = Vec::new();
    for _ in 0..count {
        let start = cursor;
        let mode = be32(bytes, at(start, 24)?).ok_or(())?;
        let flag_bytes = bytes.get(at(start, 60)?..at(start, 62)?).ok_or(())?;
        let flags = u16::from_be_bytes([flag_bytes[0], flag_bytes[1]]);
        let mut name_at = at(start, ENTRY_FIXED)?;
        if version >= 3 && flags & 0x4000 != 0 {
            name_at = at(name_at, 2)?;
        }
        if version == 4 {
            let mut c = name_at;
            let strip = varint(bytes, &mut c).ok_or(())?;
            let rest = bytes.get(c..).ok_or(())?;
            let nul = rest
                .iter()
                .take(MAX_NAME.saturating_add(1))
                .position(|b| *b == 0)
                .ok_or(())?;
            let keep = name.len().checked_sub(strip).ok_or(())?;
            name.truncate(keep);
            name.extend_from_slice(&rest[..nul]);
            if name.len() > MAX_NAME {
                return Err(());
            }
            cursor = at(at(c, nul)?, 1)?;
        } else {
            let rest = bytes.get(name_at..).ok_or(())?;
            let nul = rest
                .iter()
                .take(MAX_NAME.saturating_add(1))
                .position(|b| *b == 0)
                .ok_or(())?;
            name.clear();
            name.extend_from_slice(&rest[..nul]);
            // Entries are padded with 1 to 8 NULs to a multiple of 8 bytes.
            let size = at(at(name_at.checked_sub(start).ok_or(())?, nul)?, 8)? & !7;
            cursor = at(start, size)?;
        }
        if cursor > bytes.len() {
            return Err(());
        }
        let kind = mode & MODE_TYPE;
        let container = kind == MODE_GITLINK || kind == MODE_DIR || name.ends_with(b"/");
        let hit = match relation(&name, target) {
            Rel::Equal | Rel::Inside => true,
            Rel::Contains => container,
            Rel::Apart => false,
        };
        if hit {
            return Ok(true);
        }
    }
    // Extensions follow the entries. A split index keeps its entries in another file.
    let mut ext = cursor;
    while bytes.len().saturating_sub(ext) > 20 + 8 {
        let sig = bytes.get(ext..at(ext, 4)?).ok_or(())?;
        if sig == b"link" {
            return Err(());
        }
        let size = be32(bytes, at(ext, 4)?).ok_or(())? as usize;
        ext = at(at(ext, 8)?, size)?;
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn temp(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "safe-ai-skill-gittracked-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base.canonicalize().unwrap()
    }

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "protocol.file.allow=always",
            ])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn pack(root: &Path, rel: &str) -> PathBuf {
        let dir = root.join(rel);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SKILL.md"), "# p\n").unwrap();
        dir
    }

    #[test]
    fn a_folder_outside_any_repository_is_untracked() {
        let root = temp("none");
        let p = pack(&root, ".claude/skills/evil");
        assert_eq!(tracking(&p), Tracking::Untracked);
    }

    #[test]
    fn staged_files_make_a_pack_tracked_in_every_index_version() {
        for version in ["2", "3", "4"] {
            let root = temp(&format!("idx{version}"));
            git(&root, &["init", "-q"]);
            let tracked = pack(&root, ".claude/skills/tracked");
            let loose = pack(&root, ".claude/skills/loose");
            fs::write(root.join(".claude/skills/other"), "x").unwrap();
            git(
                &root,
                &["add", ".claude/skills/tracked", ".claude/skills/other"],
            );
            git(&root, &["update-index", "--index-version", version]);
            assert!(tracking(&tracked).is_tracked(), "v{version}");
            assert_eq!(tracking(&loose), Tracking::Untracked, "v{version}");
        }
    }

    #[test]
    fn many_entries_with_shared_prefixes_parse_in_version_4() {
        let root = temp("many");
        git(&root, &["init", "-q"]);
        for i in 0..40 {
            let dir = root.join(format!("d/sub{i}/deep"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("f.txt"), "x").unwrap();
        }
        let target = pack(&root, "d/sub17/pack");
        git(&root, &["add", "d"]);
        git(&root, &["update-index", "--index-version", "4"]);
        assert!(tracking(&target).is_tracked());
        assert_eq!(tracking(&pack(&root, "d/sub17/other")), Tracking::Untracked);
    }

    #[test]
    fn a_submodule_path_and_a_pack_inside_one_are_tracked() {
        let root = temp("sub");
        let upstream = temp("sub-up");
        git(&upstream, &["init", "-q"]);
        fs::write(upstream.join("SKILL.md"), "# sub\n").unwrap();
        git(&upstream, &["add", "."]);
        git(&upstream, &["commit", "-q", "-m", "x"]);
        git(&root, &["init", "-q"]);
        fs::create_dir_all(root.join(".claude/skills")).unwrap();
        git(
            &root,
            &[
                "submodule",
                "add",
                "-q",
                upstream.to_str().unwrap(),
                ".claude/skills/ext/jup",
            ],
        );
        let sub = root.join(".claude/skills/ext/jup");
        assert!(tracking(&sub).is_tracked());
        // Not even its `.git` file: a path in `.gitmodules` alone is enough.
        let bare = temp("sub-gm");
        fs::write(
            bare.join(".gitmodules"),
            "[submodule \"x\"]\n\tpath = .claude/skills/ext/x\n\turl = https://example.invalid/x\n",
        )
        .unwrap();
        let x = pack(&bare, ".claude/skills/ext/x");
        assert!(tracking(&x).is_tracked());
        assert_eq!(
            tracking(&pack(&bare, ".claude/skills/ext/y")),
            Tracking::Untracked
        );
    }

    #[test]
    fn a_clone_inside_the_project_is_tracked_by_its_own_repository() {
        let root = temp("nested");
        git(&root, &["init", "-q"]);
        let clone = pack(&root, ".claude/skills/cloned");
        git(&clone, &["init", "-q"]);
        assert!(tracking(&clone).is_tracked());
    }

    #[test]
    fn a_worktree_gitfile_is_followed_to_its_own_index() {
        let main = temp("wt-main");
        git(&main, &["init", "-q"]);
        fs::write(main.join("a"), "a").unwrap();
        git(&main, &["add", "a"]);
        git(&main, &["commit", "-q", "-m", "x"]);
        let wt = temp("wt-tree").join("w");
        git(&main, &["worktree", "add", "-q", wt.to_str().unwrap()]);
        let tracked = pack(&wt, "skills/tracked");
        git(&wt, &["add", "skills/tracked"]);
        let loose = pack(&wt, "skills/loose");
        assert!(wt.join(".git").is_file());
        assert!(tracking(&tracked).is_tracked());
        assert_eq!(tracking(&loose), Tracking::Untracked);
    }

    #[test]
    fn a_case_variant_spelling_still_counts() {
        let root = temp("case");
        git(&root, &["init", "-q"]);
        let p = pack(&root, "Skills/Tracked");
        git(&root, &["add", "Skills"]);
        assert!(tracking(&p).is_tracked());
        assert!(super::index_covers(
            &fs::read(root.join(".git/index")).unwrap(),
            "skills/tracked"
        )
        .unwrap());
    }

    #[test]
    fn an_unreadable_or_unknown_index_counts_as_tracked() {
        let root = temp("bad");
        git(&root, &["init", "-q"]);
        let p = pack(&root, "s/p");
        fs::write(root.join(".git/index"), b"not an index").unwrap();
        assert_eq!(
            tracking(&p),
            Tracking::Tracked("the git index cannot be parsed")
        );
        let mut future = b"DIRC".to_vec();
        future.extend_from_slice(&9u32.to_be_bytes());
        future.extend_from_slice(&0u32.to_be_bytes());
        fs::write(root.join(".git/index"), &future).unwrap();
        assert!(tracking(&p).is_tracked());
        // A truncated entry list.
        let mut cut = b"DIRC".to_vec();
        cut.extend_from_slice(&2u32.to_be_bytes());
        cut.extend_from_slice(&5u32.to_be_bytes());
        fs::write(root.join(".git/index"), &cut).unwrap();
        assert!(tracking(&p).is_tracked());
    }

    #[test]
    fn a_split_index_counts_as_tracked() {
        let root = temp("split");
        git(&root, &["init", "-q"]);
        fs::write(root.join("f"), "x").unwrap();
        git(&root, &["add", "f"]);
        git(&root, &["update-index", "--split-index"]);
        let p = pack(&root, "s/p");
        assert!(tracking(&p).is_tracked());
    }

    #[test]
    fn a_repository_with_nothing_staged_tracks_nothing() {
        let root = temp("empty");
        git(&root, &["init", "-q"]);
        let p = pack(&root, "s/p");
        assert_eq!(tracking(&p), Tracking::Untracked);
    }

    #[test]
    fn the_decision_never_runs_git() {
        // A `core.fsmonitor` or `core.hooksPath` in the repository would run if git did.
        let root = temp("noexec");
        git(&root, &["init", "-q"]);
        let marker = root.join("RAN");
        let config = root.join(".git/config");
        let mut body = fs::read_to_string(&config).unwrap();
        body.push_str(&format!(
            "[core]\n\tfsmonitor = touch {}\n",
            marker.display()
        ));
        fs::write(&config, body).unwrap();
        let p = pack(&root, "s/p");
        let _ = tracking(&p);
        assert!(!marker.exists());
    }

    /// A hand-built index (version 4): `(strip, suffix, mode)` per entry.
    fn v4_index(entries: &[(usize, Vec<u8>, u32)]) -> Vec<u8> {
        let mut out = b"DIRC".to_vec();
        out.extend_from_slice(&4u32.to_be_bytes());
        out.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
        for (strip, suffix, mode) in entries {
            let mut fixed = vec![0u8; ENTRY_FIXED];
            fixed[24..28].copy_from_slice(&mode.to_be_bytes());
            out.extend_from_slice(&fixed);
            // Git's offset encoding of the strip count.
            let mut v = *strip;
            let mut enc = vec![(v & 0x7f) as u8];
            while v >> 7 > 0 {
                v = (v >> 7) - 1;
                enc.push(0x80 | (v & 0x7f) as u8);
            }
            enc.reverse();
            out.extend_from_slice(&enc);
            out.extend_from_slice(suffix);
            out.push(0);
        }
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    #[test]
    fn version_4_prefixes_are_stripped_on_raw_bytes() {
        // A non-UTF-8 byte would grow to three bytes in a lossy copy and shift the strip.
        let idx = v4_index(&[
            (0, b"s/\xff1/aa".to_vec(), 0o100644),
            (5, b"k".to_vec(), 0o100644),
        ]);
        assert_eq!(index_covers(&idx, "s/k"), Ok(true));
        assert_eq!(index_covers(&idx, "s/other"), Ok(false));
    }

    #[test]
    fn an_index_path_over_4096_bytes_is_refused() {
        let long = vec![b'a'; MAX_NAME + 1];
        let idx = v4_index(&[(0, long, 0o100644)]);
        assert_eq!(index_covers(&idx, "x/y"), Err(()));
        let ok = v4_index(&[(0, vec![b'a'; MAX_NAME], 0o100644)]);
        assert_eq!(index_covers(&ok, "x/y"), Ok(false));
    }

    #[test]
    fn a_hostile_index_costs_linear_time() {
        use std::time::Instant;
        // Each entry keeps the whole previous path and adds one byte: refused at 4096 bytes,
        // long before the entry count could make a quadratic rebuild matter.
        let growing: Vec<(usize, Vec<u8>, u32)> = std::iter::once((0, b"a".to_vec(), 0o100644))
            .chain((0..100_000).map(|_| (0, b"a".to_vec(), 0o100644)))
            .collect();
        let started = Instant::now();
        assert_eq!(index_covers(&v4_index(&growing), "x/y"), Err(()));
        assert!(started.elapsed().as_secs() < 2, "{:?}", started.elapsed());
        // Names that stay at 4000 bytes for 150k entries (strip one byte, add one): linear.
        let mut steady = vec![(0, vec![b'a'; 4000], 0o100644)];
        steady.extend((0..150_000).map(|_| (1, b"b".to_vec(), 0o100644)));
        let idx = v4_index(&steady);
        let started = Instant::now();
        assert_eq!(index_covers(&idx, "x/y"), Ok(false));
        assert!(started.elapsed().as_secs() < 5, "{:?}", started.elapsed());
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    /// `tracking(pack)` with a deadline: a read that blocks fails the test instead of hanging it.
    #[cfg(unix)]
    fn tracking_within(pack: &Path) -> Tracking {
        let (tx, rx) = std::sync::mpsc::channel();
        let pack = pack.to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(tracking(&pack));
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("tracking() blocked on a special file")
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_index_or_gitmodules_counts_as_tracked_without_blocking() {
        let root = temp("fifo-index");
        git(&root, &["init", "-q"]);
        let p = pack(&root, "s/p");
        fs::remove_file(root.join(".git/index")).ok();
        mkfifo(&root.join(".git/index"));
        assert_eq!(
            tracking_within(&p),
            Tracking::Tracked("the git index cannot be read")
        );

        let root = temp("fifo-gm");
        let p = pack(&root, ".claude/skills/evil");
        mkfifo(&root.join(".claude/skills/.gitmodules"));
        assert_eq!(
            tracking_within(&p),
            Tracking::Tracked("its .gitmodules cannot be read")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_device_counts_as_tracked_without_blocking() {
        let root = temp("dev-link");
        git(&root, &["init", "-q"]);
        let p = pack(&root, "s/p");
        fs::remove_file(root.join(".git/index")).ok();
        for device in ["/dev/null", "/dev/zero"] {
            let _ = fs::remove_file(root.join(".git/index"));
            std::os::unix::fs::symlink(device, root.join(".git/index")).unwrap();
            assert!(tracking_within(&p).is_tracked(), "{device}");
        }
        let root = temp("dev-link-gm");
        let p = pack(&root, ".claude/skills/evil");
        std::os::unix::fs::symlink("/dev/zero", root.join(".claude/skills/.gitmodules")).unwrap();
        assert!(tracking_within(&p).is_tracked());
    }
}
