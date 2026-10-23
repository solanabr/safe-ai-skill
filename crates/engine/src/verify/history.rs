//! Git history scan of a pack (#10), at `verify add|check` only (spec D2 §9: the SessionStart
//! sweep keeps its budget).
//!
//! A pack checked out from git carries every earlier version of its files in `.git`: content
//! that was added and then removed, a quietly amended commit, a branch the user can check out.
//! This module reads the pack's own object store through [`gitobj`] (git is never run) and:
//!
//! * scans every blob in the store with the content rules ([`rules::scan_blob`]), named by the
//!   first commit (oldest committer time) whose tree holds it. Blobs byte-identical to the
//!   working-tree file at the same `HEAD` path are skipped: the checkout scan already covers them.
//!   Unreachable objects are scanned too (an amend leaves the old commit behind);
//! * flags a commit whose subject says documentation (`docs:`, "Update README.md", "fix typo")
//!   but whose diff against its parent adds or changes executable files: `docs_commit_code`
//!   (WARN), and `docs_commit_sink` (BLOCK) when a blob that commit introduced grades HIGH or
//!   worse on its own (the #10 stealer: "Update README.md" slipping a padded `eval` into a test).
//!
//! Only findings at WARN or above and combos are kept, deduplicated per rule and path across
//! versions; their path reads `git:<commit>:<path>`. Every cap that stops the scan (time, bytes,
//! objects, the per-object size cap) or object that cannot be read is reported as
//! `history_unscanned` (WARN) with its reason, never as a clean history.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use super::gitobj::{
    self, parse_commit, parse_tree, Budget, Commit, Error, Kind, Limits, ObjectId, Repo, Store,
    TreeEntry,
};
use super::rules::{self, ComboHit, Ctx, Finding, Grade, PackReport, Severity};
use super::{heuristics, Report};

/// Time one history scan may take.
pub const HISTORY_TIME: Duration = Duration::from_secs(10);
/// Inflated bytes one history scan may produce.
pub const HISTORY_BYTES: u64 = 512 * 1024 * 1024;
/// Objects one history scan may enumerate and read.
pub const HISTORY_OBJECTS: u64 = 500_000;
/// Deepest tree nesting walked.
const MAX_TREE_DEPTH: usize = 64;
/// Changed files collected per commit diff.
const MAX_DIFF_FILES: usize = 10_000;

/// The caps `verify add|check` scans history under.
pub fn check_limits() -> Limits {
    Limits {
        max_bytes: HISTORY_BYTES,
        max_objects: HISTORY_OBJECTS,
        max_object: usize::try_from(rules::MAX_SCAN_BYTES).unwrap_or(usize::MAX),
        deadline: Instant::now().checked_add(HISTORY_TIME),
    }
}

/// Counts for the report and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub commits: usize,
    pub blobs: usize,
    pub blobs_scanned: usize,
    /// Blobs skipped as identical to the checked-out file.
    pub in_checkout: usize,
}

/// What a history scan found.
#[derive(Debug, Clone, Default)]
pub struct HistoryReport {
    /// WARN-or-above findings and combos; paths are `git:<commit>:<path>`.
    pub report: PackReport,
    /// Why part of the history went unscanned (empty: all of it was scanned).
    pub unscanned: Vec<String>,
    pub stats: Stats,
}

impl HistoryReport {
    /// The v1 [`Report`] view `verify add|check` prints: the rule mapping of the checkout scan,
    /// and `history_unscanned` carrying its reasons.
    pub fn legacy(&self) -> Report {
        let mut report = heuristics::legacy_report(&self.report);
        let why = self.unscanned.join("; ");
        for f in &mut report.findings {
            if f.kind == "history_unscanned" {
                f.detail = format!("{}: {why}", rules::describe("history_unscanned"));
            }
        }
        report
    }
}

/// Scan the history of the repository whose `.git` sits in `root`, under [`check_limits`].
pub fn scan(root: &Path) -> HistoryReport {
    scan_with(root, check_limits())
}

/// [`scan`] under explicit caps.
pub fn scan_with(root: &Path, limits: Limits) -> HistoryReport {
    let mut out = HistoryReport::default();
    match Repo::open(root) {
        Ok(None) => {}
        Ok(Some(repo)) => {
            out.unscanned.extend(repo.notes.iter().cloned());
            let mut budget = Budget::new(limits);
            let store = Store::open(&repo, &mut budget);
            for idx in &store.skipped {
                out.unscanned
                    .push(format!("pack {idx} is unreadable or corrupt"));
            }
            let mut walk = Walk {
                root,
                store,
                budget,
                trees: HashMap::new(),
                corrupt: 0,
                oversize: 0,
                missing_trees: 0,
                deep: false,
                out: &mut out,
                seen: HashSet::new(),
            };
            walk.run(&repo);
        }
        Err(reason) => out.unscanned.push(reason),
    }
    if !out.unscanned.is_empty() {
        out.report.findings.push(Finding {
            rule: "history_unscanned",
            sev: Severity::Warn,
            path: PathBuf::from("git"),
            line: None,
            ctx: Ctx::Meta,
        });
    }
    out
}

/// Where a blob was first seen.
#[derive(Clone)]
struct Origin {
    commit: ObjectId,
    path: String,
    executable: bool,
    /// Position of the commit in time order.
    order: usize,
}

struct Walk<'a> {
    root: &'a Path,
    store: Store,
    budget: Budget,
    trees: HashMap<ObjectId, Rc<Vec<TreeEntry>>>,
    corrupt: usize,
    oversize: usize,
    missing_trees: usize,
    deep: bool,
    out: &'a mut HistoryReport,
    /// `(rule, path, severity)` already reported from another version.
    seen: HashSet<(&'static str, String, Severity)>,
}

impl Walk<'_> {
    fn run(&mut self, repo: &Repo) {
        let (commit_ids, blobs) = self.classify();
        let commits = self.commits(&commit_ids);
        self.out.stats.commits = commits.len();
        self.out.stats.blobs = blobs.len();
        let origins = self.name_blobs(&commits);
        let in_checkout = self.in_checkout(repo);
        let docs = self.docs_commits(&commits);
        self.scan_blobs(&blobs, &origins, &in_checkout, &docs);
        self.report_gaps(blobs.len());
    }

    fn note(&mut self, err: Error) {
        match err {
            Error::TooLarge => self.oversize += 1,
            Error::Corrupt(_) => self.corrupt += 1,
            Error::Missing | Error::Budget => {}
        }
    }

    /// Commit ids and blob ids of every object in the store.
    fn classify(&mut self) -> (Vec<ObjectId>, Vec<ObjectId>) {
        let (mut commits, mut blobs) = (Vec::new(), Vec::new());
        for id in self.store.ids() {
            match self.store.info(&id, &mut self.budget) {
                Ok((Kind::Commit, _)) => commits.push(id),
                Ok((Kind::Blob, _)) => blobs.push(id),
                Ok(_) => {}
                Err(Error::Budget) => break,
                Err(e) => self.note(e),
            }
        }
        (commits, blobs)
    }

    /// Parsed commits, oldest committer time first.
    fn commits(&mut self, ids: &[ObjectId]) -> Vec<(ObjectId, Commit)> {
        let mut commits = Vec::new();
        for id in ids {
            match self.store.read(id, &mut self.budget) {
                Ok(obj) => match parse_commit(&obj.data) {
                    Ok(c) => commits.push((*id, c)),
                    Err(e) => self.note(e),
                },
                Err(Error::Budget) => break,
                Err(e) => self.note(e),
            }
        }
        commits.sort_by_key(|(id, c)| (c.time, *id));
        commits
    }

    fn tree(&mut self, id: &ObjectId) -> Result<Rc<Vec<TreeEntry>>, Error> {
        if let Some(t) = self.trees.get(id) {
            return Ok(t.clone());
        }
        let obj = self.store.read(id, &mut self.budget)?;
        if obj.kind != Kind::Tree {
            return Err(Error::Corrupt("not a tree"));
        }
        let entries = Rc::new(parse_tree(&obj.data)?);
        self.trees.insert(*id, entries.clone());
        Ok(entries)
    }

    /// A tree, with failures counted (`None` when it cannot be used).
    fn tree_or_note(&mut self, id: &ObjectId) -> Option<Rc<Vec<TreeEntry>>> {
        match self.tree(id) {
            Ok(t) => Some(t),
            Err(Error::Missing) => {
                self.missing_trees += 1;
                None
            }
            Err(e) => {
                self.note(e);
                None
            }
        }
    }

    /// Each blob's first path, walking every commit's tree (each tree once).
    fn name_blobs(&mut self, commits: &[(ObjectId, Commit)]) -> HashMap<ObjectId, Origin> {
        let mut origins: HashMap<ObjectId, Origin> = HashMap::new();
        let mut visited: HashSet<ObjectId> = HashSet::new();
        for (order, (cid, commit)) in commits.iter().enumerate() {
            let mut stack = vec![(commit.tree, String::new(), 0usize)];
            while let Some((tree, prefix, depth)) = stack.pop() {
                if self.budget.check().is_err() {
                    return origins;
                }
                if !visited.insert(tree) {
                    continue;
                }
                let Some(entries) = self.tree_or_note(&tree) else {
                    continue;
                };
                for e in entries.iter() {
                    let path = join(&prefix, &e.name);
                    if e.is_tree() {
                        if depth < MAX_TREE_DEPTH {
                            stack.push((e.id, path, depth + 1));
                        } else {
                            self.deep = true;
                        }
                    } else if e.is_file() {
                        origins.entry(e.id).or_insert(Origin {
                            commit: *cid,
                            path,
                            executable: e.is_executable(),
                            order,
                        });
                    }
                }
            }
        }
        origins
    }

    /// Blobs of `HEAD`'s tree whose bytes equal the working-tree file at the same path.
    fn in_checkout(&mut self, repo: &Repo) -> HashSet<ObjectId> {
        let mut same = HashSet::new();
        let Some(head) = repo.head() else {
            return same;
        };
        let Ok(obj) = self.store.read(&head, &mut self.budget) else {
            return same;
        };
        let Ok(commit) = parse_commit(&obj.data) else {
            return same;
        };
        let mut stack = vec![(commit.tree, String::new(), 0usize)];
        while let Some((tree, prefix, depth)) = stack.pop() {
            let Ok(entries) = self.tree(&tree) else {
                continue;
            };
            for e in entries.iter() {
                let path = join(&prefix, &e.name);
                if e.is_tree() && depth < MAX_TREE_DEPTH {
                    stack.push((e.id, path, depth + 1));
                    continue;
                }
                if !e.is_file() || same.contains(&e.id) {
                    continue;
                }
                let cap = self.budget.limits.max_object as u64;
                let Some(disk) = gitobj::read_regular(&self.root.join(&path), cap) else {
                    continue;
                };
                match self.store.read(&e.id, &mut self.budget) {
                    Ok(blob) if *blob.data == *disk => {
                        same.insert(e.id);
                    }
                    Err(Error::Budget) => return same,
                    _ => {}
                }
            }
        }
        same
    }

    /// Docs-described commits that touch executable files: blob → the commit that introduced it.
    fn docs_commits(&mut self, commits: &[(ObjectId, Commit)]) -> HashMap<ObjectId, ObjectId> {
        let trees: HashMap<ObjectId, ObjectId> =
            commits.iter().map(|(id, c)| (*id, c.tree)).collect();
        let mut introduced = HashMap::new();
        for (cid, commit) in commits {
            if commit.parents.len() > 1 || !is_docs_subject(&commit.subject) {
                continue;
            }
            let parent_tree = match commit.parents.first() {
                None => None,
                Some(p) => match trees.get(p) {
                    Some(t) => Some(*t),
                    // A shallow clone's boundary: the parent is not here to diff against.
                    None => continue,
                },
            };
            let mut changed = Vec::new();
            self.diff(parent_tree, commit.tree, "", 0, &mut changed);
            let code: Vec<(String, TreeEntry)> = changed
                .into_iter()
                .filter(|(path, e)| executable_path(path, e))
                .collect();
            let Some((first, _)) = code.first() else {
                continue;
            };
            self.out.report.findings.push(Finding {
                rule: "docs_commit_code",
                sev: Severity::Warn,
                path: shown(cid, first),
                line: None,
                ctx: Ctx::Meta,
            });
            for (_, e) in code {
                introduced.entry(e.id).or_insert(*cid);
            }
        }
        introduced
    }

    /// Files added or changed (content or mode) from `old` to `new`.
    fn diff(
        &mut self,
        old: Option<ObjectId>,
        new: ObjectId,
        prefix: &str,
        depth: usize,
        out: &mut Vec<(String, TreeEntry)>,
    ) {
        if old == Some(new) || out.len() >= MAX_DIFF_FILES {
            return;
        }
        if depth > MAX_TREE_DEPTH {
            self.deep = true;
            return;
        }
        let Some(new_entries) = self.tree_or_note(&new) else {
            return;
        };
        let old_entries = match old {
            Some(o) => match self.tree_or_note(&o) {
                Some(t) => t,
                None => return,
            },
            None => Rc::new(Vec::new()),
        };
        let before: HashMap<&str, &TreeEntry> =
            old_entries.iter().map(|e| (e.name.as_str(), e)).collect();
        for e in new_entries.iter() {
            let path = join(prefix, &e.name);
            let prev = before.get(e.name.as_str());
            if e.is_tree() {
                let prev_tree = prev.filter(|p| p.is_tree()).map(|p| p.id);
                self.diff(prev_tree, e.id, &path, depth + 1, out);
            } else if e.is_file() && !prev.is_some_and(|p| p.id == e.id && p.mode == e.mode) {
                out.push((path, e.clone()));
            }
        }
    }

    fn scan_blobs(
        &mut self,
        blobs: &[ObjectId],
        origins: &HashMap<ObjectId, Origin>,
        in_checkout: &HashSet<ObjectId>,
        docs: &HashMap<ObjectId, ObjectId>,
    ) {
        // A checked-out blob is scanned only when a docs commit introduced it (for the combo);
        // its own findings come from the checkout scan.
        let mut order: Vec<ObjectId> = blobs
            .iter()
            .filter(|id| !in_checkout.contains(*id) || docs.contains_key(*id))
            .copied()
            .collect();
        self.out.stats.in_checkout = blobs.iter().filter(|id| in_checkout.contains(*id)).count();
        // Blobs a docs commit slipped in first, then by the commit that first holds them.
        order.sort_by_key(|id| {
            (
                !docs.contains_key(id),
                origins.get(id).map_or(usize::MAX, |o| o.order),
                *id,
            )
        });
        let deadline = self.budget.limits.deadline;
        for id in order {
            let blob = match self.store.read(&id, &mut self.budget) {
                Ok(b) => b,
                Err(Error::Budget) => return,
                Err(e) => {
                    self.note(e);
                    continue;
                }
            };
            let origin = origins.get(&id);
            let (rel, executable) = match origin {
                Some(o) => (o.path.clone(), o.executable),
                None => (format!("unnamed-{}", &gitobj::hex(&id)[..12]), false),
            };
            let scan = rules::scan_blob(Path::new(&rel), &blob.data, executable, deadline);
            if scan.expired {
                // Out of time mid-blob: what it found so far still counts.
                let _ = self.budget.check();
            } else if !in_checkout.contains(&id) {
                self.out.stats.blobs_scanned += 1;
            }
            let path = match origin {
                Some(o) => shown(&o.commit, &rel),
                None => PathBuf::from(format!("git:{rel}")),
            };
            if !in_checkout.contains(&id) {
                self.keep(&scan.report, &rel, &path);
            }
            if let Some(commit) = docs.get(&id) {
                if rules::grade(&scan.report) >= Grade::High {
                    let signal = scan
                        .report
                        .combos
                        .first()
                        .map(|c| c.rule)
                        .or_else(|| {
                            scan.report
                                .findings
                                .iter()
                                .find(|f| f.effective_sev() == Severity::High)
                                .map(|f| f.rule)
                        })
                        .unwrap_or("capped");
                    self.out.report.combos.push(ComboHit {
                        rule: "docs_commit_sink",
                        path: shown(commit, &rel),
                        line: None,
                        parts: vec!["docs_commit_code", signal],
                    });
                }
            }
            if scan.expired {
                return;
            }
        }
    }

    /// Keep a blob's WARN-or-above findings, capped rules and combos not yet reported for the
    /// same path from another version.
    fn keep(&mut self, report: &PackReport, rel: &str, path: &Path) {
        for f in &report.findings {
            let sev = f.effective_sev();
            if sev < Severity::Warn || !self.seen.insert((f.rule, rel.to_string(), sev)) {
                continue;
            }
            let mut f = f.clone();
            f.path = path.to_path_buf();
            self.out.report.findings.push(f);
        }
        for c in &report.capped {
            if self.seen.insert((c.rule, rel.to_string(), Severity::High)) {
                let mut c = c.clone();
                c.path = path.to_path_buf();
                self.out.report.capped.push(c);
            }
        }
        for c in &report.combos {
            // Combos dedupe under their own key space (a rule id is never both).
            if self
                .seen
                .insert((c.rule, format!("combo:{rel}"), Severity::High))
            {
                let mut c = c.clone();
                c.path = path.to_path_buf();
                self.out.report.combos.push(c);
            }
        }
    }

    fn report_gaps(&mut self, blobs: usize) {
        let gaps = &mut self.out.unscanned;
        if let Some(what) = self.budget.spent {
            gaps.push(format!(
                "{what} budget spent ({} of {} history blobs scanned)",
                self.out.stats.blobs_scanned,
                blobs.saturating_sub(self.out.stats.in_checkout)
            ));
        }
        if self.oversize > 0 {
            gaps.push(format!(
                "{} objects over the per-object size cap ({} bytes)",
                self.oversize, self.budget.limits.max_object
            ));
        }
        if self.corrupt > 0 {
            gaps.push(format!("{} unreadable or corrupt objects", self.corrupt));
        }
        if self.missing_trees > 0 {
            gaps.push(format!(
                "{} trees missing (partial clone?)",
                self.missing_trees
            ));
        }
        if self.deep {
            gaps.push(format!("trees nested past {MAX_TREE_DEPTH} levels"));
        }
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// How a history path is reported: `git:<short commit>:<path>`.
fn shown(commit: &ObjectId, rel: &str) -> PathBuf {
    PathBuf::from(format!("git:{}:{rel}", &gitobj::hex(commit)[..12]))
}

/// A file a docs-only commit should not be touching: executable source by name or mode, or a
/// `package.json` (install lifecycle scripts).
fn executable_path(path: &str, entry: &TreeEntry) -> bool {
    let p = Path::new(path);
    rules::is_code_path(p, entry.is_executable())
        || p.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("package.json"))
}

/// Documentation file names a docs commit subject may name.
fn is_doc_file(word: &str) -> bool {
    let w = word.trim_matches(|c: char| matches!(c, '`' | '"' | '\'' | ',' | '.' | ':'));
    let lower = w.to_ascii_lowercase();
    let stem = lower.rsplit('/').next().unwrap_or(&lower);
    [".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc"]
        .iter()
        .any(|ext| stem.ends_with(ext))
        || ["readme", "changelog", "license", "contributing", "docs"]
            .iter()
            .any(|n| stem == *n || stem.starts_with(&format!("{n}.")))
}

/// True when a commit subject claims documentation only: a conventional `docs:` type, a
/// web-editor default naming a doc file ("Update README.md", "Create docs/guide.md"), or a typo
/// or docs touch-up.
pub fn is_docs_subject(subject: &str) -> bool {
    let s = subject.trim().to_ascii_lowercase();
    if let Some(head) = s.split(':').next() {
        let ty = head.trim_end_matches('!');
        let ty = ty.split('(').next().unwrap_or(ty);
        if s.contains(':') && matches!(ty, "docs" | "doc") {
            return true;
        }
    }
    let words: Vec<&str> = s.split_whitespace().collect();
    let verbs = [
        "update", "updated", "create", "created", "add", "added", "edit", "edited", "improve",
        "tweak", "fix", "fixed", "rename", "delete",
    ];
    match words.as_slice() {
        [verb, rest @ ..] if verbs.contains(verb) && !rest.is_empty() => {
            let rest: Vec<&str> = rest
                .iter()
                .copied()
                .filter(|w| !matches!(*w, "the" | "a" | "in" | "to" | "of" | "and"))
                .collect();
            rest.iter()
                .all(|w| is_doc_file(w) || matches!(*w, "typo" | "typos" | "documentation" | "doc"))
        }
        [single] => matches!(
            *single,
            "docs" | "documentation" | "readme" | "typo" | "typos"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_subjects() {
        for s in [
            "Update README.md",
            "docs: clarify setup",
            "docs(api)!: rename",
            "Create docs/guide.md",
            "fix typo in README",
            "Update the documentation",
            "Updated CHANGELOG.md and README.md",
            "typo",
        ] {
            assert!(is_docs_subject(s), "{s}");
        }
        for s in [
            "Update watch.ts",
            "feat: add stream decoder",
            "Initial commit",
            "Update README.md and src/index.ts",
            "fix: docs link checker",
            "Add files via upload",
            "",
        ] {
            assert!(!is_docs_subject(s), "{s}");
        }
    }
}
