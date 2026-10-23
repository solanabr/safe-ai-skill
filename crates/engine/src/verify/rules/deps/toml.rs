//! A line-oriented TOML reader, just enough for `Cargo.toml`, `Cargo.lock`, `pyproject.toml`,
//! `poetry.lock`, `uv.lock` and `.cargo/config.toml`: table headers and `key = value` entries,
//! with multi-line arrays, inline tables and multi-line strings gathered into one value.
//!
//! It never fails: a line it cannot read is skipped. Values are kept as raw text (callers look
//! for what they need inside them). Bounded by [`MAX_ENTRIES`] entries and [`MAX_VALUE_BYTES`]
//! per gathered value.

/// Entries read from one file before the rest is ignored.
const MAX_ENTRIES: usize = 100_000;
/// Bytes gathered into one multi-line value before the rest of it is skipped.
const MAX_VALUE_BYTES: usize = 64 * 1024;

/// One header or `key = value` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Entry {
    /// 1-based line of the header or key.
    pub(super) line: u32,
    /// The table the entry is in (the header's own name for a header), as written, without
    /// brackets and with whitespace around dots removed.
    pub(super) table: String,
    /// True for a `[table]` / `[[table]]` header line (`key` and `value` empty).
    pub(super) header: bool,
    /// The key, one layer of quotes removed (a dotted key stays dotted).
    pub(super) key: String,
    /// The raw value, comments removed; multi-line values joined with `\n`.
    pub(super) value: String,
}

/// Track the bracket depth of `s` outside strings, and whether it ends inside a `"""`/`'''`
/// string (`in_multi`). Returns the byte length of `s` before a trailing comment (always an
/// ASCII position, so a char boundary). Works on bytes, so any input is safe.
fn scan_value(s: &str, depth: &mut i64, in_multi: &mut Option<&'static [u8]>) -> usize {
    let b = s.as_bytes();
    let mut i = 0;
    let mut quote: u8 = 0;
    while i < b.len() {
        if let Some(close) = *in_multi {
            match b[i..].windows(3).position(|w| w == close) {
                Some(p) => {
                    i += p + 3;
                    *in_multi = None;
                    continue;
                }
                None => return b.len(),
            }
        }
        let c = b[i];
        if quote != 0 {
            if c == b'\\' && quote == b'"' {
                i += 2;
                continue;
            }
            if c == quote {
                quote = 0;
            }
        } else if b[i..].starts_with(b"\"\"\"") {
            *in_multi = Some(b"\"\"\"");
            i += 3;
            continue;
        } else if b[i..].starts_with(b"'''") {
            *in_multi = Some(b"'''");
            i += 3;
            continue;
        } else {
            match c {
                b'"' | b'\'' => quote = c,
                b'[' | b'{' => *depth += 1,
                b']' | b'}' => *depth -= 1,
                b'#' => return i,
                _ => {}
            }
        }
        i += 1;
    }
    b.len()
}

/// `s` without one layer of surrounding quotes, trimmed.
pub(super) fn unquote(s: &str) -> &str {
    let t = s.trim();
    for q in ['"', '\''] {
        if let Some(inner) = t.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner;
        }
    }
    t
}

/// The table name of a header line body (`[a . b]` → `a.b`).
fn table_name(inner: &str) -> String {
    inner
        .split('.')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(".")
}

/// Every header and entry of `text`, in order.
pub(super) fn entries(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut table = String::new();
    let mut lines = text.lines().enumerate();
    while let Some((i, raw)) = lines.next() {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line_no = super::super::line_no(i);
        if line.starts_with('[') {
            let inner = line.trim_start_matches('[').split(']').next().unwrap_or("");
            table = table_name(inner);
            out.push(Entry {
                line: line_no,
                table: table.clone(),
                header: true,
                key: String::new(),
                value: String::new(),
            });
            continue;
        }
        let Some(eq) = key_end(line) else { continue };
        let key = unquote(&line[..eq]).to_string();
        let first = line[eq + 1..].trim_start();
        let mut depth = 0i64;
        let mut multi = None;
        let keep = scan_value(first, &mut depth, &mut multi);
        let mut value = first[..keep].trim_end().to_string();
        while depth > 0 || multi.is_some() {
            let Some((_, next)) = lines.next() else { break };
            let keep = scan_value(next, &mut depth, &mut multi);
            if value.len() < MAX_VALUE_BYTES {
                value.push('\n');
                value.push_str(next[..keep].trim());
            }
        }
        out.push(Entry {
            line: line_no,
            table: table.clone(),
            header: false,
            key,
            value,
        });
    }
    out
}

/// Byte offset of the `=` ending the key of a `key = value` line (outside quoted keys).
fn key_end(line: &str) -> Option<usize> {
    let mut quote = 0u8;
    for (i, c) in line.bytes().enumerate() {
        if quote != 0 {
            if c == quote {
                quote = 0;
            }
            continue;
        }
        match c {
            b'"' | b'\'' => quote = c,
            b'=' => return Some(i),
            _ => {}
        }
    }
    None
}

/// The value of `key` inside an inline table value (`{ git = "x", rev = "y" }`), unquoted.
pub(super) fn inline_get<'a>(value: &'a str, key: &str) -> Option<&'a str> {
    let body = value.trim().strip_prefix('{')?;
    let mut from = 0;
    while let Some(p) = body[from..].find(key).map(|p| p + from) {
        from = p + key.len();
        let before = body[..p].trim_end();
        let boundary = before.is_empty() || before.ends_with(',') || before.ends_with('{');
        let rest = body[from..].trim_start();
        if !boundary || !rest.starts_with('=') {
            continue;
        }
        let rest = rest[1..].trim_start();
        let quoted = ['"', '\''].into_iter().find_map(|q| {
            rest.strip_prefix(q)
                .map(|inner| inner.find(q).map_or(rest.len(), |e| e + 2))
        });
        let end = quoted
            .or_else(|| rest.find([',', '}']))
            .unwrap_or(rest.len());
        return Some(unquote(&rest[..end]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_entries_and_multiline_values() {
        let text = "# c\n[package]\nname = \"x\" # trailing\n[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\n\n[project]\ndependencies = [\n  \"a==1\",\n  \"b\",\n]\n[ target . 'cfg(unix)' . dependencies ]\nlibc = \"0.2\"\n";
        let e = entries(text);
        let kv: Vec<(&str, &str, u32)> = e
            .iter()
            .filter(|e| !e.header)
            .map(|e| (e.table.as_str(), e.key.as_str(), e.line))
            .collect();
        assert_eq!(
            kv,
            vec![
                ("package", "name", 3),
                ("dependencies", "serde", 5),
                ("project", "dependencies", 8),
                ("target.'cfg(unix)'.dependencies", "libc", 13),
            ]
        );
        assert_eq!(e[1].value, "\"x\"");
        assert!(e
            .iter()
            .any(|x| x.key == "dependencies" && x.value.contains("\"b\"")));
    }

    #[test]
    fn inline_table_lookup() {
        let v = "{ git = \"https://g/x\", rev = 'abc', branch=\"main\" }";
        assert_eq!(inline_get(v, "git"), Some("https://g/x"));
        assert_eq!(inline_get(v, "rev"), Some("abc"));
        assert_eq!(inline_get(v, "branch"), Some("main"));
        assert_eq!(inline_get(v, "tag"), None);
        assert_eq!(inline_get("{ registry-git = \"x\" }", "git"), None);
        assert_eq!(inline_get("\"1.0\"", "git"), None);
    }

    #[test]
    fn hostile_input_is_bounded_and_panic_free() {
        let deep = "a = ".to_string() + &"[".repeat(100_000);
        assert_eq!(entries(&deep).len(), 1);
        let unclosed = "a = \"\"\"\n".to_string() + &"x\n".repeat(50_000);
        let e = entries(&unclosed);
        assert!(e[0].value.len() <= MAX_VALUE_BYTES + 4096);
        for s in [
            "[",
            "]]]",
            "= = =",
            "\"a\" =",
            "[a\"b]",
            "x = '",
            "é = \"\u{2028}\"",
        ] {
            let _ = entries(s);
        }
        let many = "k = 1\n".repeat(MAX_ENTRIES + 10);
        assert_eq!(entries(&many).len(), MAX_ENTRIES);
    }
}
