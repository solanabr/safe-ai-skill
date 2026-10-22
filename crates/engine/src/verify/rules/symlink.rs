//! Symlinks (spec D2.4): never followed, always reported; a target that leaves the pack feeds
//! the `symlink_escape` combo. The target is resolved from the link's own directory, expanding
//! in-pack symlinks met on the way (`a -> sub/l/..` with `sub/l -> ..` leaves the pack); nothing
//! outside the pack is ever touched.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Component, Path};

use super::{Ctx, FileOut, Severity, Signal};

/// Symlink expansions before a chain counts as a loop (the kernel's own limit is 40).
const MAX_HOPS: usize = 40;

/// `base` is the pack directory, `abs` the link and `rel` its pack-relative path.
pub(super) fn scan(base: &Path, abs: &Path, rel: &Path) -> FileOut {
    let mut out = FileOut::new(rel);
    out.emit("symlink", Severity::Info, None, Ctx::Meta);
    if let Ok(target) = std::fs::read_link(abs) {
        if escapes(base, rel, &target) {
            out.emit("symlink_escape", Severity::High, None, Ctx::Meta);
            out.signal(Signal::SymlinkEscape, Ctx::Meta);
        }
    }
    out
}

/// One step of a link target.
enum Step {
    Root,
    Up,
    Name(OsString),
}

fn steps(target: &Path) -> Vec<Step> {
    target
        .components()
        .filter_map(|c| match c {
            Component::Prefix(_) | Component::RootDir => Some(Step::Root),
            Component::CurDir => None,
            Component::ParentDir => Some(Step::Up),
            Component::Normal(name) => Some(Step::Name(name.to_os_string())),
        })
        .collect()
}

/// True when `target`, read from the directory holding `rel`, leaves the pack. Absolute targets
/// always leave it: the pack can be moved or copied, the link cannot follow. In-pack symlinks on
/// the way are expanded in place; a chain longer than [`MAX_HOPS`] is a loop, not an escape.
fn escapes(base: &Path, rel: &Path, target: &Path) -> bool {
    let mut dir: Vec<OsString> = rel
        .parent()
        .map(|p| p.iter().map(|c| c.to_os_string()).collect())
        .unwrap_or_default();
    let mut queue: VecDeque<Step> = steps(target).into();
    let mut hops = 0;
    while let Some(step) = queue.pop_front() {
        match step {
            Step::Root => return true,
            Step::Up => {
                if dir.pop().is_none() {
                    return true;
                }
            }
            Step::Name(name) => {
                dir.push(name);
                let here = dir.iter().fold(base.to_path_buf(), |p, c| p.join(c));
                // Not a link (or not there): a plain path component.
                let Ok(next) = std::fs::read_link(&here) else {
                    continue;
                };
                hops += 1;
                if hops > MAX_HOPS {
                    return false;
                }
                dir.pop();
                for step in steps(&next).into_iter().rev() {
                    queue.push_front(step);
                }
            }
        }
    }
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Ctx, Grade, Severity};

    #[test]
    fn internal_links_are_info() {
        let pack = TempPack::new("links-in");
        pack.file("AGENTS.md", "# a\n");
        pack.file("plugin/skills/x/SKILL.md", "# x\n");
        pack.symlink("CLAUDE.md", "AGENTS.md");
        pack.symlink("dev-plugin/plugin/skills", "../../plugin/skills");
        pack.symlink("loop", "loop");
        let r = pack.scan();
        let f = hits(&r, "symlink");
        assert_eq!(f.len(), 3, "{r:?}");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::Info, Ctx::Meta, None)
        );
        assert!(r.combos.is_empty(), "{r:?}");
        assert_eq!(grade(&r), Grade::Clean);
    }

    #[test]
    fn a_chain_through_an_in_pack_link_that_leaves_blocks() {
        let pack = TempPack::new("links-chain");
        pack.file("SKILL.md", "# s\n");
        pack.symlink("sub/l2", "..");
        pack.symlink("esc", "sub/l2/..");
        pack.symlink("deep/a", "../hop");
        pack.symlink("hop", "deep/../..");
        pack.symlink("ok", "sub/l2/SKILL.md");
        let r = pack.scan();
        let escaped: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f.rule == "symlink_escape")
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(escaped, ["deep/a", "esc", "hop"], "{r:?}");
        assert_eq!(grade(&r), Grade::Block);
    }

    #[test]
    fn escaping_links_block() {
        for target in ["/etc/passwd", "../../outside", "a/../../.."] {
            let pack = TempPack::new("links-out");
            pack.file("SKILL.md", "# s\n");
            pack.symlink("examples/passwd.txt", target);
            let r = pack.scan();
            let c = combo(&r, "symlink_escape");
            assert!(c.is_some(), "{target}: {r:?}");
            assert_eq!(
                c.unwrap().path,
                std::path::PathBuf::from("examples/passwd.txt")
            );
            assert!(has(&r, "symlink_escape"));
        }
    }
}
