//! Symlinks (spec D2.4): never followed, always reported; a target that leaves the pack —
//! judged lexically from the link's own directory — feeds the `symlink_escape` combo.

use std::path::{Component, Path};

use super::{Ctx, FileOut, Severity, Signal};

pub(super) fn scan(abs: &Path, rel: &Path) -> FileOut {
    let mut out = FileOut::new(rel);
    out.emit("symlink", Severity::Info, None, Ctx::Meta);
    if let Ok(target) = std::fs::read_link(abs) {
        if escapes(rel, &target) {
            out.emit("symlink_escape", Severity::High, None, Ctx::Meta);
            out.signal(Signal::SymlinkEscape, Ctx::Meta);
        }
    }
    out
}

/// True when `target`, read from the directory holding `rel`, leaves the pack. Absolute targets
/// always leave it: the pack can be moved or copied, the link cannot follow.
fn escapes(rel: &Path, target: &Path) -> bool {
    let mut depth = rel.parent().map_or(0, |p| p.components().count());
    for component in target.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => return true,
            Component::ParentDir => match depth.checked_sub(1) {
                Some(d) => depth = d,
                None => return true,
            },
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
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
