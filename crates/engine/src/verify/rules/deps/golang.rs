//! Go: `go.mod` requirements without a `go.sum`, and `replace` directives that redirect a
//! module somewhere other than a local path.

use std::path::Path;

use super::super::{line_no, Ctx, FileOut, Severity};
use super::{PackFiles, MAX_LOCATED};

/// `go.mod`.
pub(super) fn go_mod(rel: &Path, text: &str, pack: &PackFiles<'_>, out: &mut FileOut) {
    let mut block: Option<&str> = None;
    let mut first_require: Option<u32> = None;
    let mut redirects = 0;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == ")" {
            block = None;
            continue;
        }
        let (directive, rest) = match block {
            Some(d) => (d, line),
            None => {
                let (d, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
                let rest = rest.trim();
                if rest == "(" {
                    block = match d {
                        "require" => Some("require"),
                        "replace" => Some("replace"),
                        _ => Some("other"),
                    };
                    continue;
                }
                (d, rest)
            }
        };
        match directive {
            "require" if !rest.is_empty() => {
                first_require.get_or_insert(line_no(i));
            }
            "replace" => {
                let target = rest.split("=>").nth(1).unwrap_or("").trim();
                let local = target.starts_with("./")
                    || target.starts_with("../")
                    || target.starts_with('/');
                if !target.is_empty() && !local && redirects < MAX_LOCATED {
                    redirects += 1;
                    out.emit(
                        "dep_nonregistry_source",
                        Severity::Warn,
                        Some(line_no(i)),
                        Ctx::Meta,
                    );
                }
            }
            _ => {}
        }
    }
    if let Some(line) = first_require {
        if !pack.sibling(rel, "go.sum") {
            out.emit(
                "dep_lockfile_missing",
                Severity::Warn,
                Some(line),
                Ctx::Meta,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{pack, rules_at};

    #[test]
    fn go_mod_requires_need_a_go_sum_and_remote_replaces_redirect() {
        let m = "module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.0.0 // indirect\n)\n\nreplace github.com/a/b => github.com/evil/b v1.0.1\nreplace github.com/c/d => ../d\n";
        let r = pack(&[("go.mod", m)]);
        assert_eq!(
            rules_at(&r, "dep_lockfile_missing"),
            vec![("go.mod".into(), Some(6))]
        );
        assert_eq!(
            rules_at(&r, "dep_nonregistry_source"),
            vec![("go.mod".into(), Some(9))]
        );
        let r = pack(&[("go.mod", m), ("go.sum", "")]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty());
        let r = pack(&[("go.mod", "module x\ngo 1.22\n")]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty());
    }
}
