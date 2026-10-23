//! Git history scan of a pack (#10), at `verify add|check` and `install` only (spec D2 §9: the
//! SessionStart sweep keeps its budget).
//!
//! A pack checked out from git carries every earlier version of its files in `.git`: content
//! that was added and then removed, a quietly amended commit, a branch the user can check out.
//! This module reads the pack's own object store through [`gitobj`] (git is never run) and:
//!
//! * scans every blob in the store with the content rules ([`rules::scan_blob`]) under each
//!   distinct file name (and exec bit) it appears at in any commit's tree, up to
//!   [`MAX_VARIANTS`], so a rename cannot move a payload out of a rule's context. A blob is
//!   skipped under a name only when the working-tree file at the same `HEAD` path holds the same
//!   bytes (the checkout scan covers it there). Unreachable objects are scanned too;
//! * reports a commit whose subject says documentation (`docs:`, "Update README.md", "fix typo")
//!   but whose diff against its parent adds or changes executable files: `docs_commit_code`
//!   (WARN, report-only), and `docs_commit_sink` (BLOCK) when the lines that commit *added* to
//!   such a file carry a HIGH signal (the #10 stealer: "Update README.md" slipping a padded
//!   `eval` into a test). A signal already present in the parent version does not count.
//!
//! Every tree walk keeps a visited set and charges each tree visit to the shared [`Budget`], so
//! a crafted object graph (a deep DAG of shared subtrees) costs work linear in distinct trees.
//! Only findings at WARN or above and combos are kept, deduplicated per rule and path across
//! versions; their path reads `git:<commit>:<path>`. Every cap that stops the scan (time, bytes,
//! objects, the per-object size cap) and every object that is missing or cannot be read is
//! reported as `history_unscanned` (WARN) with its reason, never as a clean history.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use super::gitobj::{
    self, parse_commit, parse_tree, Budget, Commit, Error, Kind, Limits, ObjectId, Repo, Store,
    TreeEntry,
};
use super::rules::{self, ComboHit, Ctx, Finding, PackReport, Severity};

/// Time one history scan may take.
pub const HISTORY_TIME: Duration = Duration::from_secs(10);
/// Inflated bytes (and parsed index/tree memory) one history scan may use.
pub const HISTORY_BYTES: u64 = 512 * 1024 * 1024;
/// Objects one history scan may enumerate and read, tree visits included.
pub const HISTORY_OBJECTS: u64 = 500_000;
/// Deepest tree nesting walked.
const MAX_TREE_DEPTH: usize = 64;
/// Changed files collected per commit diff.
const MAX_DIFF_FILES: usize = 10_000;
/// Distinct file names one blob is scanned under.
pub const MAX_VARIANTS: usize = 8;

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
    /// Blob scans run (one per blob and name).
    pub blobs_scanned: usize,
    /// Blob names skipped as identical to the checked-out file.
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
                gaps: Gaps::default(),
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

/// One name a blob appears under.
#[derive(Clone)]
struct Variant {
    commit: ObjectId,
    path: String,
    executable: bool,
    /// Position of the commit in time order.
    order: usize,
}

/// The key a blob is scanned once per: its lowercased file name and exec bit (the rules read
/// context from both).
type NameKey = (String, bool);

fn name_key(path: &str, executable: bool) -> NameKey {
    let name = path.rsplit('/').next().unwrap_or(path);
    (name.to_ascii_lowercase(), executable)
}

/// A code file a docs-described commit added or changed.
struct DocsHit {
    commit: ObjectId,
    path: String,
    executable: bool,
    /// The same path's blob in the parent, when it existed.
    prev: Option<ObjectId>,
}

/// A file a diff found added or changed.
struct Changed {
    path: String,
    entry: TreeEntry,
    prev: Option<ObjectId>,
}

/// Reasons part of the history went unread.
#[derive(Default)]
struct Gaps {
    corrupt: usize,
    oversize: usize,
    missing: usize,
    missing_trees: usize,
    missing_blobs: usize,
    extra_names: usize,
    deep: bool,
}

struct Walk<'a> {
    root: &'a Path,
    store: Store,
    budget: Budget,
    trees: HashMap<ObjectId, Rc<Vec<TreeEntry>>>,
    gaps: Gaps,
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
        let names = self.name_blobs(&commits);
        self.gaps.missing_blobs = names.keys().filter(|id| !self.store.contains(id)).count();
        let in_checkout = self.in_checkout(repo);
        let docs = self.docs_commits(&commits);
        self.docs_sinks(&docs);
        self.scan_blobs(&blobs, &names, &in_checkout);
        self.report_gaps();
    }

    fn note(&mut self, err: Error) {
        match err {
            Error::TooLarge => self.gaps.oversize += 1,
            Error::Corrupt(_) => self.gaps.corrupt += 1,
            Error::Missing => self.gaps.missing += 1,
            Error::Budget => {}
        }
    }

    /// Charge one tree visit (cached trees included): false once the budget is spent.
    fn visit(&mut self) -> bool {
        self.budget.object().is_ok()
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
        let entries = parse_tree(&obj.data)?;
        // Parsed entries outweigh their raw bytes: charge what is kept.
        let held = entries.iter().fold(0usize, |n, e| {
            n.saturating_add(std::mem::size_of::<TreeEntry>())
                .saturating_add(e.name.len())
        });
        self.budget.bytes(held)?;
        let entries = Rc::new(entries);
        self.trees.insert(*id, entries.clone());
        Ok(entries)
    }

    /// A tree, with failures counted (`None` when it cannot be used).
    fn tree_or_note(&mut self, id: &ObjectId) -> Option<Rc<Vec<TreeEntry>>> {
        match self.tree(id) {
            Ok(t) => Some(t),
            Err(Error::Missing) => {
                self.gaps.missing_trees += 1;
                None
            }
            Err(e) => {
                self.note(e);
                None
            }
        }
    }

    /// The names each blob appears under, walking every commit's tree (each tree once).
    fn name_blobs(&mut self, commits: &[(ObjectId, Commit)]) -> HashMap<ObjectId, Vec<Variant>> {
        let mut names: HashMap<ObjectId, Vec<Variant>> = HashMap::new();
        let mut visited: HashSet<ObjectId> = HashSet::new();
        for (order, (cid, commit)) in commits.iter().enumerate() {
            let mut stack = vec![(commit.tree, String::new(), 0usize)];
            while let Some((tree, prefix, depth)) = stack.pop() {
                if !visited.insert(tree) {
                    continue;
                }
                if !self.visit() {
                    return names;
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
                            self.gaps.deep = true;
                        }
                    } else if e.is_file() {
                        let list = names.entry(e.id).or_default();
                        let key = name_key(&path, e.is_executable());
                        if list.iter().any(|v| name_key(&v.path, v.executable) == key) {
                            continue;
                        }
                        if list.len() >= MAX_VARIANTS {
                            self.gaps.extra_names += 1;
                            continue;
                        }
                        list.push(Variant {
                            commit: *cid,
                            path,
                            executable: e.is_executable(),
                            order,
                        });
                    }
                }
            }
        }
        names
    }

    /// `(blob, name)` pairs of `HEAD`'s tree whose bytes equal the working-tree file at the same
    /// path.
    fn in_checkout(&mut self, repo: &Repo) -> HashSet<(ObjectId, NameKey)> {
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
        let mut visited: HashSet<ObjectId> = HashSet::new();
        let mut stack = vec![(commit.tree, String::new(), 0usize)];
        while let Some((tree, prefix, depth)) = stack.pop() {
            if !visited.insert(tree) {
                continue;
            }
            if !self.visit() {
                return same;
            }
            let Ok(entries) = self.tree(&tree) else {
                continue;
            };
            for e in entries.iter() {
                let path = join(&prefix, &e.name);
                if e.is_tree() && depth < MAX_TREE_DEPTH {
                    stack.push((e.id, path, depth + 1));
                    continue;
                }
                let key = (e.id, name_key(&path, e.is_executable()));
                if !e.is_file() || same.contains(&key) {
                    continue;
                }
                let cap = self.budget.limits.max_object as u64;
                let Some(disk) = gitobj::read_regular(&self.root.join(&path), cap) else {
                    continue;
                };
                match self.store.read(&e.id, &mut self.budget) {
                    Ok(blob) if *blob.data == *disk => {
                        same.insert(key);
                    }
                    Err(Error::Budget) => return same,
                    _ => {}
                }
            }
        }
        same
    }

    /// Docs-described commits that touch executable files: each reported `docs_commit_code`,
    /// and every code file they added or changed returned for the sink check.
    fn docs_commits(&mut self, commits: &[(ObjectId, Commit)]) -> Vec<DocsHit> {
        let trees: HashMap<ObjectId, ObjectId> =
            commits.iter().map(|(id, c)| (*id, c.tree)).collect();
        let mut hits = Vec::new();
        for (cid, commit) in commits {
            if self.budget.check().is_err() {
                break;
            }
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
            let mut visited = HashSet::new();
            self.diff(parent_tree, commit.tree, "", 0, &mut visited, &mut changed);
            let code: Vec<Changed> = changed
                .into_iter()
                .filter(|c| executable_path(&c.path, &c.entry))
                .collect();
            let Some(first) = code.first() else {
                continue;
            };
            self.out.report.findings.push(Finding {
                rule: "docs_commit_code",
                sev: Severity::Warn,
                path: shown(cid, &first.path),
                line: None,
                ctx: Ctx::Meta,
            });
            hits.extend(code.into_iter().map(|c| DocsHit {
                commit: *cid,
                executable: c.entry.is_executable(),
                path: c.path,
                prev: c.prev,
            }));
        }
        hits
    }

    /// Files added or changed (content or mode) from `old` to `new`. Each `(old, new)` tree pair
    /// is walked once and every visit is charged to the budget.
    fn diff(
        &mut self,
        old: Option<ObjectId>,
        new: ObjectId,
        prefix: &str,
        depth: usize,
        visited: &mut HashSet<(Option<ObjectId>, ObjectId)>,
        out: &mut Vec<Changed>,
    ) {
        if old == Some(new) || out.len() >= MAX_DIFF_FILES || !visited.insert((old, new)) {
            return;
        }
        if depth > MAX_TREE_DEPTH {
            self.gaps.deep = true;
            return;
        }
        if !self.visit() {
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
                self.diff(prev_tree, e.id, &path, depth + 1, visited, out);
            } else if e.is_file() && !prev.is_some_and(|p| p.id == e.id && p.mode == e.mode) {
                out.push(Changed {
                    path,
                    entry: e.clone(),
                    prev: prev.filter(|p| p.is_file()).map(|p| p.id),
                });
            }
        }
    }

    /// `docs_commit_sink` for each docs-commit code file whose added lines carry a HIGH signal.
    fn docs_sinks(&mut self, hits: &[DocsHit]) {
        let deadline = self.budget.limits.deadline;
        let mut done: HashSet<(ObjectId, String)> = HashSet::new();
        for hit in hits {
            if !done.insert((hit.commit, hit.path.clone())) {
                continue;
            }
            let Some(new_id) = self.blob_at(hit) else {
                continue;
            };
            let new = match self.store.read(&new_id, &mut self.budget) {
                Ok(b) => b,
                Err(Error::Budget) => return,
                Err(e) => {
                    self.note(e);
                    continue;
                }
            };
            let old = match hit.prev {
                None => None,
                Some(p) => match self.store.read(&p, &mut self.budget) {
                    Ok(b) => Some(b),
                    Err(Error::Budget) => return,
                    Err(e) => {
                        // Without the parent version the added lines are unknown: skip.
                        self.note(e);
                        continue;
                    }
                },
            };
            let rel = Path::new(&hit.path);
            let now = rules::scan_blob(rel, &new.data, hit.executable, deadline);
            let before = old
                .as_ref()
                .map(|o| rules::scan_blob(rel, &o.data, hit.executable, deadline).report);
            if now.expired {
                let _ = self.budget.check();
                return;
            }
            let added = match &old {
                Some(o) => added_lines(&o.data, &new.data),
                None => None,
            };
            if let Some(signal) = new_signal(&now.report, before.as_ref(), added.as_ref()) {
                self.out.report.combos.push(ComboHit {
                    rule: "docs_commit_sink",
                    path: shown(&hit.commit, &hit.path),
                    line: None,
                    parts: vec!["docs_commit_code", signal],
                });
            }
        }
    }

    /// The blob a docs hit names (looked up again from the commit's tree).
    fn blob_at(&mut self, hit: &DocsHit) -> Option<ObjectId> {
        let obj = self.store.read(&hit.commit, &mut self.budget).ok()?;
        let mut tree = parse_commit(&obj.data).ok()?.tree;
        let mut parts = hit.path.split('/').peekable();
        while let Some(part) = parts.next() {
            if !self.visit() {
                return None;
            }
            let entries = self.tree_or_note(&tree)?;
            let e = entries.iter().find(|e| e.name == part)?;
            if parts.peek().is_none() {
                return e.is_file().then_some(e.id);
            }
            tree = e.id;
        }
        None
    }

    fn scan_blobs(
        &mut self,
        blobs: &[ObjectId],
        names: &HashMap<ObjectId, Vec<Variant>>,
        in_checkout: &HashSet<(ObjectId, NameKey)>,
    ) {
        let mut order: Vec<ObjectId> = blobs.to_vec();
        order.sort_by_key(|id| {
            (
                names
                    .get(id)
                    .and_then(|v| v.iter().map(|v| v.order).min())
                    .unwrap_or(usize::MAX),
                *id,
            )
        });
        let deadline = self.budget.limits.deadline;
        for id in order {
            let unnamed;
            let variants: &[Variant] = match names.get(&id) {
                Some(v) if !v.is_empty() => v,
                _ => {
                    unnamed = [Variant {
                        commit: id,
                        path: format!("unnamed-{}", &gitobj::hex(&id)[..12]),
                        executable: false,
                        order: usize::MAX,
                    }];
                    &unnamed
                }
            };
            let todo: Vec<&Variant> = variants
                .iter()
                .filter(|v| !in_checkout.contains(&(id, name_key(&v.path, v.executable))))
                .collect();
            self.out.stats.in_checkout += variants.len() - todo.len();
            if todo.is_empty() {
                continue;
            }
            let blob = match self.store.read(&id, &mut self.budget) {
                Ok(b) => b,
                Err(Error::Budget) => return,
                Err(e) => {
                    self.note(e);
                    continue;
                }
            };
            for v in todo {
                let scan = rules::scan_blob(Path::new(&v.path), &blob.data, v.executable, deadline);
                let path = if v.order == usize::MAX {
                    PathBuf::from(format!("git:{}", v.path))
                } else {
                    shown(&v.commit, &v.path)
                };
                self.keep(&scan.report, &v.path, &path);
                if scan.expired {
                    // Out of time mid-blob: what it found so far still counts.
                    let _ = self.budget.check();
                    return;
                }
                self.out.stats.blobs_scanned += 1;
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

    fn report_gaps(&mut self) {
        let g = &self.gaps;
        let gaps = &mut self.out.unscanned;
        if let Some(what) = self.budget.spent {
            gaps.push(format!(
                "{what} budget spent ({} blob scans done, {} blobs in the store)",
                self.out.stats.blobs_scanned, self.out.stats.blobs
            ));
        }
        if g.oversize > 0 {
            gaps.push(format!(
                "{} objects over the per-object size cap ({} bytes)",
                g.oversize, self.budget.limits.max_object
            ));
        }
        if g.corrupt > 0 {
            gaps.push(format!("{} unreadable or corrupt objects", g.corrupt));
        }
        if g.missing > 0 {
            gaps.push(format!(
                "{} objects missing (delta base or object not in the store)",
                g.missing
            ));
        }
        if g.missing_trees > 0 {
            gaps.push(format!(
                "{} trees missing (partial clone?)",
                g.missing_trees
            ));
        }
        if g.missing_blobs > 0 {
            gaps.push(format!(
                "{} history blobs not present (partial clone?)",
                g.missing_blobs
            ));
        }
        if g.extra_names > 0 {
            gaps.push(format!(
                "{} blob names past {MAX_VARIANTS} per blob not scanned",
                g.extra_names
            ));
        }
        if g.deep {
            gaps.push(format!("trees nested past {MAX_TREE_DEPTH} levels"));
        }
    }
}

/// 1-based line numbers of `new` that are not in `old` (a multiset line diff). `None` when the
/// content is not line-comparable as UTF-8 (the whole file then counts as added).
fn added_lines(old: &[u8], new: &[u8]) -> Option<HashSet<u32>> {
    let (old, new) = (
        std::str::from_utf8(old).ok()?,
        std::str::from_utf8(new).ok()?,
    );
    let mut have: HashMap<&str, usize> = HashMap::new();
    for line in old.lines() {
        *have.entry(line).or_default() += 1;
    }
    let mut added = HashSet::new();
    for (i, line) in new.lines().enumerate() {
        match have.get_mut(line) {
            Some(n) if *n > 0 => *n -= 1,
            _ => {
                added.insert(rules::line_no(i));
            }
        }
    }
    Some(added)
}

/// The first HIGH signal of `now` that the docs commit introduced: on an added line, or (for a
/// file-level signal, or when lines cannot be compared) absent from the parent's report.
fn new_signal(
    now: &PackReport,
    before: Option<&PackReport>,
    added: Option<&HashSet<u32>>,
) -> Option<&'static str> {
    let had = |rule: &str| {
        before.is_some_and(|b| {
            b.combos.iter().any(|c| c.rule == rule)
                || b.findings
                    .iter()
                    .any(|f| f.rule == rule && f.effective_sev() == Severity::High)
                || b.capped.iter().any(|c| c.rule == rule)
        })
    };
    let fresh = |rule: &str, line: Option<u32>| match (before, added, line) {
        (None, _, _) => true,
        (Some(_), Some(added), Some(l)) => added.contains(&l),
        _ => !had(rule),
    };
    now.combos
        .iter()
        .find(|c| fresh(c.rule, c.line))
        .map(|c| c.rule)
        .or_else(|| {
            now.findings
                .iter()
                .filter(|f| f.effective_sev() == Severity::High)
                .find(|f| fresh(f.rule, f.line))
                .map(|f| f.rule)
        })
        .or_else(|| {
            now.capped
                .iter()
                .find(|c| {
                    rules::code_severity(c.rule).is_some_and(|s| s >= Severity::Warn)
                        && !had(c.rule)
                })
                .map(|c| c.rule)
        })
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
