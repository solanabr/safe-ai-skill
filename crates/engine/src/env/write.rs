//! `env set` / `env unset`: value intake, encoding, byte-minimal edits verified by re-parsing,
//! and the atomic file write.
//!
//! An edit replaces only the target assignment's value bytes (or appends one line, or drops the
//! assignment's lines); the result is re-parsed and must yield exactly the expected
//! assignments, so an edit can never change how another line reads (an unterminated quote
//! elsewhere would otherwise swallow the new line). Writes go to a temp file in the target's
//! directory (`O_EXCL`), take the target's mode, are fsynced, then renamed over the target.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::env::parse::{EnvFile, Eol, ItemKind, Quote};

/// Largest value `env set` accepts on stdin.
pub const MAX_VALUE_BYTES: usize = 1 << 20;

/// Bytes a value may contain and still be written unquoted.
const BARE_SAFE: &[u8] = b"_./:@%+,=?&~-";

/// Why a value read from stdin was rejected. Messages never include the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueError {
    TooLarge,
    Nul,
    Newline,
    CarriageReturn,
}

impl ValueError {
    pub fn message(self) -> &'static str {
        match self {
            ValueError::TooLarge => "the value on stdin is larger than 1 MiB",
            ValueError::Nul => "the value on stdin contains a NUL byte",
            ValueError::Newline => {
                "the value on stdin contains a line break; pass --multiline to store a multi-line value"
            }
            ValueError::CarriageReturn => "the value on stdin contains a carriage return",
        }
    }
}

/// Validate a value read from stdin: strip exactly one trailing `\n`/`\r\n` (so `echo` works),
/// reject NUL, and reject line breaks unless `multiline` (where `\r\n` reads as `\n`).
pub fn normalize_value(raw: &[u8], multiline: bool) -> Result<Vec<u8>, ValueError> {
    if raw.len() > MAX_VALUE_BYTES {
        return Err(ValueError::TooLarge);
    }
    if raw.contains(&0) {
        return Err(ValueError::Nul);
    }
    let raw = raw
        .strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw);
    let mut value = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if multiline && raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        value.push(raw[i]);
        i += 1;
    }
    if !multiline && value.contains(&b'\n') {
        return Err(ValueError::Newline);
    }
    if value.contains(&b'\r') {
        return Err(ValueError::CarriageReturn);
    }
    Ok(value)
}

/// Whether `value` can be written without quotes (`[A-Za-z0-9_./:@%+,=?&~-]*`).
pub fn is_bare_safe(value: &[u8]) -> bool {
    value
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || BARE_SAFE.contains(b))
}

/// The quote style for `value`: the `existing` one when it can hold the value, otherwise bare
/// if safe, single quotes for `$`/backtick values (no expansion in any loader or in `source`),
/// double quotes with `\ " $ `` escaped for everything else.
pub fn choose_quote(value: &[u8], existing: Option<Quote>) -> Quote {
    match existing {
        Some(Quote::Double) => return Quote::Double,
        Some(Quote::Single) if !value.contains(&b'\'') => return Quote::Single,
        Some(Quote::Bare) if is_bare_safe(value) => return Quote::Bare,
        _ => {}
    }
    if is_bare_safe(value) {
        Quote::Bare
    } else if value.iter().any(|b| matches!(b, b'$' | b'`')) && !value.contains(&b'\'') {
        Quote::Single
    } else {
        Quote::Double
    }
}

/// Encode `value` in `quote` style; line breaks inside quotes are written as `eol`. The caller
/// picks a style that can hold the value ([`choose_quote`]).
pub fn encode(value: &[u8], quote: Quote, eol: Eol) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 2);
    match quote {
        Quote::Bare => out.extend_from_slice(value),
        Quote::Single => {
            out.push(b'\'');
            for &b in value {
                match b {
                    b'\n' => out.extend_from_slice(eol.bytes()),
                    _ => out.push(b),
                }
            }
            out.push(b'\'');
        }
        Quote::Double => {
            out.push(b'"');
            for &b in value {
                match b {
                    b'\\' | b'"' | b'$' | b'`' => out.extend_from_slice(&[b'\\', b]),
                    b'\n' => out.extend_from_slice(eol.bytes()),
                    _ => out.push(b),
                }
            }
            out.push(b'"');
        }
    }
    out
}

/// What `env set` did to one assignment (lines refer to the new file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Added { line: usize },
    Updated { line: usize, old: Vec<u8> },
    Unchanged { line: usize },
}

/// The new file bytes for `env set`, and what changed.
#[derive(Debug)]
pub struct SetPlan {
    pub bytes: Vec<u8>,
    pub changes: Vec<Change>,
    /// Lines of every assignment of the key, when it is assigned more than once.
    pub duplicates: Vec<usize>,
}

/// The new file bytes for `env unset`, and the lines removed (empty: key not assigned).
#[derive(Debug)]
pub struct UnsetPlan {
    pub bytes: Vec<u8>,
    pub removed: Vec<usize>,
}

/// The edit would change how other lines of the file parse (for example an unterminated quote
/// earlier in the file would swallow the new line), so it is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reparse;

/// Whether a new key gets an `export ` prefix: always in `.envrc` (direnv only exports exported
/// variables), otherwise like the file's last assignment.
pub fn export_for_new(file: &EnvFile, envrc: bool) -> bool {
    envrc || file.entries().last().is_some_and(|(_, e)| e.export)
}

/// Plan `env set`: update the last assignment of `key` (every one with `all`), keeping its
/// `export`, quote style when it can hold the value, and a quoted value's inline comment; or
/// append `[export ]KEY=value` with a final newline.
pub fn plan_set(
    file: &EnvFile,
    key: &str,
    value: &[u8],
    all: bool,
    export_new: bool,
) -> Result<SetPlan, Reparse> {
    let eol = file.eol();
    let found: Vec<_> = file.entries().filter(|(_, e)| e.key == key).collect();
    let first_target = if all {
        0
    } else {
        found.len().saturating_sub(1)
    };
    let mut body = file.body.clone();
    let mut expected = signature(file);
    let mut unchanged = Vec::new();

    if found.is_empty() {
        if !body.is_empty() && !body.ends_with(b"\n") {
            body.extend_from_slice(eol.bytes());
        }
        if export_new {
            body.extend_from_slice(b"export ");
        }
        body.extend_from_slice(key.as_bytes());
        body.push(b'=');
        body.extend_from_slice(&encode(value, choose_quote(value, None), eol));
        body.extend_from_slice(eol.bytes());
        expected.push(Sig::Entry {
            key: key.to_string(),
            value: value.to_vec(),
            export: export_new,
        });
    } else {
        // Splice from the end so earlier spans stay valid.
        for (_, entry) in found[first_target..].iter().rev() {
            let encoded = encode(value, choose_quote(value, Some(entry.quote)), eol);
            unchanged.push(file.body[entry.value_span.clone()] == encoded[..]);
            body.splice(entry.value_span.clone(), encoded);
        }
        unchanged.reverse();
        let mut occurrence = 0;
        for sig in &mut expected {
            if let Sig::Entry {
                key: k, value: v, ..
            } = sig
            {
                if k == key {
                    if occurrence >= first_target {
                        *v = value.to_vec();
                    }
                    occurrence += 1;
                }
            }
        }
    }

    let bytes = with_bom(file.bom, &body);
    let after = EnvFile::parse_as(&bytes, file.format);
    if after.bom != file.bom || signature(&after) != expected {
        return Err(Reparse);
    }

    let lines: Vec<usize> = after
        .entries()
        .filter(|(_, e)| e.key == key)
        .map(|(line, _)| line)
        .collect();
    let changes = if found.is_empty() {
        lines
            .last()
            .map(|&line| vec![Change::Added { line }])
            .unwrap_or_default()
    } else {
        found[first_target..]
            .iter()
            .zip(lines.get(first_target..).unwrap_or(&[]))
            .zip(&unchanged)
            .map(|(((_, entry), &line), &same)| {
                if same {
                    Change::Unchanged { line }
                } else {
                    Change::Updated {
                        line,
                        old: entry.value.clone(),
                    }
                }
            })
            .collect()
    };
    let duplicates = if found.len() > 1 {
        found.iter().map(|(line, _)| *line).collect()
    } else {
        Vec::new()
    };
    Ok(SetPlan {
        bytes,
        changes,
        duplicates,
    })
}

/// Plan `env unset`: drop every assignment of `key` (commented keys stay). When the file has
/// no final newline and its last line goes, the line break before it goes too.
pub fn plan_unset(file: &EnvFile, key: &str) -> Result<UnsetPlan, Reparse> {
    let removed: Vec<usize> = file
        .entries()
        .filter(|(_, e)| e.key == key)
        .map(|(line, _)| line)
        .collect();
    if removed.is_empty() {
        return Ok(UnsetPlan {
            bytes: file.to_bytes(),
            removed,
        });
    }
    let mut body = Vec::with_capacity(file.body.len());
    for item in &file.items {
        if !matches!(&item.kind, ItemKind::Entry(e) if e.key == key) {
            body.extend_from_slice(&file.body[item.span.clone()]);
        }
    }
    if !file.body.ends_with(b"\n") {
        if body.ends_with(b"\r\n") {
            body.truncate(body.len() - 2);
        } else if body.ends_with(b"\n") {
            body.truncate(body.len() - 1);
        }
    }

    let bytes = with_bom(file.bom, &body);
    let after = EnvFile::parse_as(&bytes, file.format);
    let mut expected = signature(file);
    expected.retain(|sig| !matches!(sig, Sig::Entry { key: k, .. } if k == key));
    if after.bom != file.bom || signature(&after) != expected {
        return Err(Reparse);
    }
    Ok(UnsetPlan { bytes, removed })
}

/// What an edit must preserve: every assignment and commented key, in order.
#[derive(Debug, PartialEq, Eq)]
enum Sig {
    Entry {
        key: String,
        value: Vec<u8>,
        export: bool,
    },
    Commented(String),
}

fn signature(file: &EnvFile) -> Vec<Sig> {
    file.items
        .iter()
        .filter_map(|item| match &item.kind {
            ItemKind::Entry(e) => Some(Sig::Entry {
                key: e.key.clone(),
                value: e.value.clone(),
                export: e.export,
            }),
            ItemKind::Commented(key) => Some(Sig::Commented(key.clone())),
            ItemKind::Verbatim => None,
        })
        .collect()
}

fn with_bom(bom: bool, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 3);
    if bom {
        out.extend_from_slice(b"\xef\xbb\xbf");
    }
    out.extend_from_slice(body);
    out
}

/// Points where a test can make [`replace_with`] fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Created,
    Written,
    Synced,
}

/// Atomically replace `target` with `bytes` and give it `mode` (unix permission bits): temp file
/// in the same directory, fsync, rename over the target, fsync the directory. The temp file is
/// removed on any failure, and the target is left as it was.
pub fn atomic_replace(target: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    replace_with(target, bytes, mode, &mut |_| Ok(()))
}

pub(crate) fn replace_with(
    target: &Path,
    bytes: &[u8],
    mode: u32,
    fault: &mut dyn FnMut(Stage) -> io::Result<()>,
) -> io::Result<()> {
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let (tmp, file) = create_temp(&dir)?;
    let result = (|| {
        fill(file, bytes, mode, fault)?;
        fault(Stage::Synced)?;
        fs::rename(&tmp, target)
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    sync_dir(&dir);
    Ok(())
}

/// Write, chmod and fsync the temp file; it is closed on return (Windows can't rename an open
/// file).
fn fill(
    mut file: File,
    bytes: &[u8],
    mode: u32,
    fault: &mut dyn FnMut(Stage) -> io::Result<()>,
) -> io::Result<()> {
    fault(Stage::Created)?;
    file.write_all(bytes)?;
    fault(Stage::Written)?;
    set_mode(&file, mode)?;
    file.sync_all()
}

/// Create a fresh temp file (`O_EXCL`, 0600) in `dir`. Its `.env.` name keeps it env-class, so
/// the read gate covers it for the instant it exists.
fn create_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for _ in 0..8 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            ".env.safe-ai-skill-{}-{nanos}-{n}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free temp file name",
    ))
}

#[cfg(unix)]
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_file: &File, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Best-effort fsync of the directory so the rename itself is durable.
#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::parse::{CrlfStyle, ItemKind};
    use crate::env::testgen::{self, Lcg};
    use std::fs;
    use std::path::PathBuf;
    use Quote::{Bare, Double, Single};

    fn parse(bytes: &[u8]) -> EnvFile {
        EnvFile::parse(bytes)
    }

    fn effective(file: &EnvFile, key: &str) -> Option<Vec<u8>> {
        file.entries()
            .filter(|(_, e)| e.key == key)
            .last()
            .map(|(_, e)| e.value.clone())
    }

    /// Assignments and commented keys other than `key`, in order.
    fn others(file: &EnvFile, key: &str) -> Vec<(String, Vec<u8>, bool)> {
        file.items
            .iter()
            .filter_map(|item| match &item.kind {
                ItemKind::Entry(e) if e.key != key => {
                    Some((e.key.clone(), e.value.clone(), e.export))
                }
                ItemKind::Commented(k) => Some((format!("#{k}"), Vec::new(), false)),
                _ => None,
            })
            .collect()
    }

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "safe-ai-skill-env-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn normalize_value_rules() {
        use ValueError::*;
        assert_eq!(normalize_value(b"abc\n", false), Ok(b"abc".to_vec()));
        assert_eq!(normalize_value(b"abc\r\n", false), Ok(b"abc".to_vec()));
        assert_eq!(normalize_value(b"abc\n\n", false), Err(Newline));
        assert_eq!(normalize_value(b"a\nb", false), Err(Newline));
        assert_eq!(normalize_value(b"a\nb\n", true), Ok(b"a\nb".to_vec()));
        assert_eq!(normalize_value(b"a\r\nb\r\n", true), Ok(b"a\nb".to_vec()));
        assert_eq!(normalize_value(b"a\rb", true), Err(CarriageReturn));
        assert_eq!(normalize_value(b"a\rb", false), Err(CarriageReturn));
        assert_eq!(normalize_value(b"a\0b", false), Err(Nul));
        assert_eq!(normalize_value(b"a\0b\n", true), Err(Nul));
        let big = vec![b'a'; MAX_VALUE_BYTES + 1];
        assert_eq!(normalize_value(&big, false), Err(TooLarge));
        let max = vec![b'a'; MAX_VALUE_BYTES];
        assert_eq!(
            normalize_value(&max, false).map(|v| v.len()),
            Ok(MAX_VALUE_BYTES)
        );
        assert_eq!(normalize_value(b"", false), Ok(Vec::new()));
        assert_eq!(normalize_value(b"\n", false), Ok(Vec::new()));
        assert_eq!(
            normalize_value(b"  spaced  ", false),
            Ok(b"  spaced  ".to_vec())
        );
    }

    #[test]
    fn quote_choice() {
        assert_eq!(choose_quote(b"abc-1.2/x:y@z%+,=?&~_", None), Bare);
        assert_eq!(choose_quote(b"", None), Bare);
        assert_eq!(choose_quote(b"a b", None), Double);
        assert_eq!(choose_quote(b"#x", None), Double);
        assert_eq!(choose_quote(b"$x", None), Single);
        assert_eq!(choose_quote(b"`x`", None), Single);
        assert_eq!(choose_quote(b"it's $5", None), Double);
        assert_eq!(choose_quote(b"abc", Some(Single)), Single);
        assert_eq!(choose_quote(b"it's", Some(Single)), Double);
        assert_eq!(choose_quote(b"abc", Some(Double)), Double);
        assert_eq!(choose_quote(b"a b", Some(Bare)), Double);
        assert_eq!(choose_quote(b"$a", Some(Bare)), Single);
        assert_eq!(choose_quote(b"abc", Some(Bare)), Bare);
    }

    #[test]
    fn encodings() {
        assert_eq!(
            encode(b"a\\b\"c$d`e", Double, Eol::Lf),
            b"\"a\\\\b\\\"c\\$d\\`e\"".to_vec()
        );
        assert_eq!(
            encode(b"l1\nl2", Double, Eol::CrLf),
            b"\"l1\r\nl2\"".to_vec()
        );
        assert_eq!(encode(b"$x\ny", Single, Eol::Lf), b"'$x\ny'".to_vec());
        assert_eq!(encode(b"plain", Bare, Eol::Lf), b"plain".to_vec());
        assert_eq!(encode(b"", Double, Eol::Lf), b"\"\"".to_vec());
    }

    #[test]
    fn prop_encode_then_parse_round_trips() {
        let mut rng = Lcg::new(1);
        for _ in 0..3000 {
            let value = testgen::value(&mut rng, true);
            for quote in [Bare, Single, Double] {
                if (quote == Bare && !is_bare_safe(&value))
                    || (quote == Single && value.contains(&b'\''))
                {
                    continue;
                }
                for eol in [Eol::Lf, Eol::CrLf] {
                    let line = [
                        b"K=".as_slice(),
                        &encode(&value, quote, eol),
                        eol.bytes(),
                        b"NEXT=1\n",
                    ]
                    .concat();
                    let f = EnvFile::parse(&line);
                    let got: Vec<(String, Vec<u8>)> = f
                        .entries()
                        .map(|(_, e)| (e.key.clone(), e.value.clone()))
                        .collect();
                    assert_eq!(
                        got,
                        [
                            ("K".to_string(), value.clone()),
                            ("NEXT".into(), b"1".to_vec())
                        ],
                        "{quote:?} {:?}",
                        String::from_utf8_lossy(&line)
                    );
                }
            }
        }
    }

    #[test]
    fn set_appends_updates_and_reports() {
        let p = plan_set(&parse(b"A=1"), "B", b"2", false, false).unwrap();
        assert_eq!(p.bytes, b"A=1\nB=2\n".to_vec());
        assert_eq!(p.changes, [Change::Added { line: 2 }]);
        assert!(p.duplicates.is_empty());

        let p = plan_set(&parse(b"A=1\nB='x' # c\n"), "B", b"y z", false, false).unwrap();
        assert_eq!(p.bytes, b"A=1\nB='y z' # c\n".to_vec());
        assert_eq!(
            p.changes,
            [Change::Updated {
                line: 2,
                old: b"x".to_vec()
            }]
        );

        let p = plan_set(&parse(b"A=\"v\"\n"), "A", b"v", false, false).unwrap();
        assert_eq!(p.changes, [Change::Unchanged { line: 1 }]);
        assert_eq!(p.bytes, b"A=\"v\"\n".to_vec());

        let f = parse(b"A=1\nB=2\nA=3\n");
        let p = plan_set(&f, "A", b"x", false, false).unwrap();
        assert_eq!(p.bytes, b"A=1\nB=2\nA=x\n".to_vec());
        assert_eq!(p.duplicates, [1, 3]);
        let p = plan_set(&f, "A", b"l1\nl2", true, false).unwrap();
        assert_eq!(p.bytes, b"A=\"l1\nl2\"\nB=2\nA=\"l1\nl2\"\n".to_vec());
        assert_eq!(
            p.changes,
            [
                Change::Updated {
                    line: 1,
                    old: b"1".to_vec()
                },
                Change::Updated {
                    line: 4,
                    old: b"3".to_vec()
                }
            ]
        );

        let p = plan_set(&parse(b""), "A", b"1", false, true).unwrap();
        assert_eq!(p.bytes, b"export A=1\n".to_vec());
        let p = plan_set(&parse(b"\xef\xbb\xbf"), "A", b"1", false, false).unwrap();
        assert_eq!(p.bytes, b"\xef\xbb\xbfA=1\n".to_vec());
        let p = plan_set(&parse(b"A=1\r\n"), "B", b"2", false, false).unwrap();
        assert_eq!(p.bytes, b"A=1\r\nB=2\r\n".to_vec());
    }

    #[test]
    fn export_for_new_keys_follows_the_file() {
        assert!(export_for_new(&parse(b""), true));
        assert!(!export_for_new(&parse(b""), false));
        assert!(export_for_new(&parse(b"A=1\nexport B=2\n"), false));
        assert!(!export_for_new(&parse(b"export A=1\nB=2\n"), false));
    }

    #[test]
    fn set_refuses_an_edit_that_changes_how_other_lines_parse() {
        let f = parse(b"A=\"unterminated\n");
        assert_eq!(
            plan_set(&f, "K", b"$a\" #x", false, false).unwrap_err(),
            Reparse
        );
        let p = plan_set(&parse(b"A=1\n"), "K", b"$a\" #x", false, false).unwrap();
        assert_eq!(p.bytes, b"A=1\nK='$a\" #x'\n".to_vec());
    }

    #[test]
    fn unset_cases() {
        let p = plan_unset(&parse(b"A=1\nB=2\nA=3\n"), "A").unwrap();
        assert_eq!(p.bytes, b"B=2\n".to_vec());
        assert_eq!(p.removed, [1, 3]);
        let shape = |body: &[u8], key: &str| plan_unset(&parse(body), key).unwrap().bytes;
        assert_eq!(shape(b"A=1\nB=2", "B"), b"A=1".to_vec());
        assert_eq!(shape(b"A=1\nB=2", "A"), b"B=2".to_vec());
        assert_eq!(shape(b"A=1\nA=2", "A"), b"".to_vec());
        assert_eq!(shape(b"A=1\r\nB=2", "B"), b"A=1".to_vec());
        assert_eq!(
            shape(b"\xef\xbb\xbfA=1\nB=2\n", "A"),
            b"\xef\xbb\xbfB=2\n".to_vec()
        );
        assert_eq!(
            shape(b"A=1\nP=\"x\ny\" # c\nZ=2\n", "P"),
            b"A=1\nZ=2\n".to_vec()
        );
        let p = plan_unset(&parse(b"#A=1\nB=2\n"), "A").unwrap();
        assert!(p.removed.is_empty());
        assert_eq!(p.bytes, b"#A=1\nB=2\n".to_vec());
    }

    #[test]
    fn prop_set_round_trips_on_generated_files() {
        let mut rng = Lcg::new(3);
        for case in 0..2000 {
            let gen = testgen::file(&mut rng, false);
            let file = EnvFile::parse(&gen.bytes);
            let key = *rng.pick(testgen::KEYS);
            let value = testgen::value(&mut rng, true);
            let all = rng.one_in(2);
            let plan = plan_set(&file, key, &value, all, rng.one_in(2))
                .unwrap_or_else(|_| panic!("case {case}: clean file refused a set"));
            let after = EnvFile::parse(&plan.bytes);
            assert_eq!(effective(&after, key), Some(value.clone()), "case {case}");
            assert_eq!(others(&after, key), others(&file, key), "case {case}");
            assert_eq!(after.bom, file.bom);
            if file.crlf() != CrlfStyle::Mixed {
                assert_eq!(after.crlf(), file.crlf(), "case {case}");
            }
            if all {
                let count = |f: &EnvFile| f.entries().filter(|(_, e)| e.key == key).count();
                assert_eq!(count(&after), count(&file).max(1), "case {case}");
                assert!(after
                    .entries()
                    .filter(|(_, e)| e.key == key)
                    .all(|(_, e)| e.value == value));
            }
            let again = plan_set(&after, key, &value, all, false).unwrap();
            assert_eq!(
                again.bytes, plan.bytes,
                "case {case}: set is not idempotent"
            );
            assert!(again
                .changes
                .iter()
                .all(|c| matches!(c, Change::Unchanged { .. })));
        }
    }

    #[test]
    fn prop_unset_removes_only_the_key() {
        let mut rng = Lcg::new(4);
        for case in 0..2000 {
            let gen = testgen::file(&mut rng, false);
            let file = EnvFile::parse(&gen.bytes);
            let key = *rng.pick(testgen::KEYS);
            let plan = plan_unset(&file, key)
                .unwrap_or_else(|_| panic!("case {case}: clean file refused an unset"));
            let after = EnvFile::parse(&plan.bytes);
            assert_eq!(effective(&after, key), None, "case {case}");
            assert_eq!(others(&after, key), others(&file, key), "case {case}");
            assert_eq!(after.bom, file.bom);
            assert_eq!(
                plan.removed,
                file.entries()
                    .filter(|(_, e)| e.key == key)
                    .map(|(line, _)| line)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn prop_dirty_files_are_set_correctly_or_refused() {
        let mut rng = Lcg::new(5);
        let (mut applied, mut refused) = (0, 0);
        for case in 0..2000 {
            let gen = testgen::file(&mut rng, true);
            let file = EnvFile::parse(&gen.bytes);
            let key = *rng.pick(testgen::KEYS);
            let value = testgen::value(&mut rng, true);
            match plan_set(&file, key, &value, rng.one_in(2), false) {
                Ok(plan) => {
                    applied += 1;
                    let after = EnvFile::parse(&plan.bytes);
                    assert_eq!(effective(&after, key), Some(value), "case {case}");
                    assert_eq!(others(&after, key), others(&file, key), "case {case}");
                }
                Err(Reparse) => refused += 1,
            }
            if let Ok(plan) = plan_unset(&file, key) {
                let after = EnvFile::parse(&plan.bytes);
                assert_eq!(effective(&after, key), None, "case {case}");
                assert_eq!(others(&after, key), others(&file, key), "case {case}");
            }
        }
        assert!(applied > refused, "applied {applied}, refused {refused}");
    }

    #[test]
    fn atomic_replace_writes_bytes_and_mode() {
        let dir = scratch("aw");
        let target = dir.join(".env.local");
        fs::write(&target, b"old").unwrap();
        atomic_replace(&target, b"new", 0o640).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640);
        }
        atomic_replace(&dir.join("fresh.env"), b"x", 0o600).unwrap();
        assert_eq!(names(&dir), [".env.local", "fresh.env"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_replace_cleans_up_on_failure() {
        let dir = scratch("af");
        let target = dir.join(".env.local");
        for stage in [Stage::Created, Stage::Written, Stage::Synced] {
            fs::write(&target, b"old").unwrap();
            let err = replace_with(&target, b"new", 0o600, &mut |s| {
                if s == stage {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(err.to_string(), "injected");
            assert_eq!(fs::read(&target).unwrap(), b"old", "{stage:?}");
            assert_eq!(names(&dir), [".env.local"], "{stage:?}");
        }
        // A real failure after the temp file exists: renaming it over a directory.
        fs::create_dir(dir.join("sub.env")).unwrap();
        assert!(atomic_replace(&dir.join("sub.env"), b"x", 0o600).is_err());
        assert_eq!(names(&dir), [".env.local", "sub.env"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
