//! Lossless dotenv parser (plus the Solana CLI's top-level YAML config, read-only).
//!
//! Parsing never fails and never drops a byte: the body is partitioned into [`Item`]s whose
//! spans cover it exactly, so [`EnvFile::to_bytes`] reproduces the input, and an edit (see
//! `write.rs`) splices new bytes into one span while every other line stays byte-identical.
//!
//! Dotenv grammar, one item per line unless a quoted value spans lines:
//! - blank lines, `#` comments and anything unparseable are kept verbatim; `#KEY=…` and
//!   `# export KEY=…` are *commented keys*: listed by `env keys`, never edited;
//! - `[export ]KEY=value`, `KEY` matching `[A-Za-z_][A-Za-z0-9_.]*`, optional blanks around `=`;
//! - `'single'` is literal up to the next `'`; `"double"` runs to the next unescaped `"` and
//!   decodes `\\ \" \$ \``, keeping any other backslash pair as written; both may span lines,
//!   and a `\r\n` inside them reads as `\n`;
//! - a closing quote may only be followed by blanks and an optional `# comment` on its line,
//!   otherwise the value is read as bare (what dotenv does with stray quotes);
//! - a bare value runs to the end of the line, cut at the first `#` that follows a blank, with
//!   trailing blanks trimmed;
//! - a leading UTF-8 BOM is set aside and restored.
//!
//! Duplicate keys are all kept; the last one wins, as with dotenv loaders and `source`
//! (dotenvy, the Rust loader, keeps the first; `env keys` says so when a file has duplicates).
//!
//! Known loader divergences (documented, not emulated):
//! - `\n` inside double quotes stays the two characters backslash and `n`; Node's `dotenv`
//!   and `python-dotenv` expand it to a newline. A value read back by those loaders can differ.
//! - A backtick-quoted value (Node `dotenv` and varlock accept `` `…` `` spanning lines) is
//!   read here as a bare value, so a multiline backtick value lists as several lines; `env set`
//!   writes single or double quotes instead.

use std::ops::Range;

const BOM: &[u8] = b"\xef\xbb\xbf";

/// File grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Dotenv,
    /// The Solana CLI config (`~/.config/solana/cli/config.yml`): listed, never edited.
    Yaml,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::Dotenv => "dotenv",
            Format::Yaml => "yaml",
        }
    }
}

/// How a value is written in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    Bare,
    Single,
    Double,
}

impl Quote {
    pub fn label(self) -> &'static str {
        match self {
            Quote::Bare => "bare",
            Quote::Single => "single",
            Quote::Double => "double",
        }
    }
}

/// Line ending used for the lines an edit writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eol {
    Lf,
    CrLf,
}

impl Eol {
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Eol::Lf => b"\n",
            Eol::CrLf => b"\r\n",
        }
    }
}

/// Line endings found in a file (the `crlf=` field of `env keys`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlfStyle {
    No,
    Yes,
    Mixed,
}

impl CrlfStyle {
    pub fn label(self) -> &'static str {
        match self {
            CrlfStyle::No => "no",
            CrlfStyle::Yes => "yes",
            CrlfStyle::Mixed => "mixed",
        }
    }
}

/// One `KEY=value` assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub export: bool,
    pub quote: Quote,
    /// Decoded value. A secret: never print it.
    pub value: Vec<u8>,
    /// Body bytes an edit replaces: the quoted value with its quotes, or for a bare value
    /// everything to the end of the line, so an inline comment goes with it.
    pub value_span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemKind {
    /// Blank line, comment, or anything that is not an assignment.
    Verbatim,
    /// A commented-out assignment (`#KEY=…`).
    Commented(String),
    Entry(Entry),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub kind: ItemKind,
    /// 1-based line on which the item starts.
    pub line: usize,
    /// Body bytes covered by the item, line ending included.
    pub span: Range<usize>,
}

/// A parsed file. `body` excludes the BOM; item spans index into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFile {
    pub format: Format,
    pub bom: bool,
    pub body: Vec<u8>,
    pub items: Vec<Item>,
}

impl EnvFile {
    /// Parse a dotenv file. Never fails; see the module docs for the grammar.
    pub fn parse(bytes: &[u8]) -> Self {
        Self::build(bytes, Format::Dotenv)
    }

    /// Parse the Solana CLI config: top-level `key: scalar` lines become entries; nested
    /// blocks and everything else stay verbatim.
    pub fn parse_yaml(bytes: &[u8]) -> Self {
        Self::build(bytes, Format::Yaml)
    }

    /// Parse `bytes` with the grammar of `format`.
    pub fn parse_as(bytes: &[u8], format: Format) -> Self {
        Self::build(bytes, format)
    }

    fn build(bytes: &[u8], format: Format) -> Self {
        let (bom, body) = match bytes.strip_prefix(BOM) {
            Some(rest) => (true, rest),
            None => (false, bytes),
        };
        let mut items = Vec::new();
        let mut pos = 0;
        let mut line = 1;
        while pos < body.len() {
            let (content_end, next) = line_bounds(body, pos);
            let entry = match format {
                Format::Dotenv => dotenv_entry(body, pos, content_end, next),
                Format::Yaml => yaml_entry(body, pos, content_end, next),
            };
            let (kind, end) = match entry {
                Some((entry, end)) => (ItemKind::Entry(entry), end),
                None if format == Format::Dotenv => match commented_key(&body[pos..content_end]) {
                    Some(key) => (ItemKind::Commented(key), next),
                    None => (ItemKind::Verbatim, next),
                },
                None => (ItemKind::Verbatim, next),
            };
            items.push(Item {
                kind,
                line,
                span: pos..end,
            });
            line += body[pos..end].iter().filter(|&&b| b == b'\n').count();
            pos = end;
        }
        EnvFile {
            format,
            bom,
            body: body.to_vec(),
            items,
        }
    }

    /// The file bytes: BOM (if any) plus body.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + BOM.len());
        if self.bom {
            out.extend_from_slice(BOM);
        }
        out.extend_from_slice(&self.body);
        out
    }

    /// Every assignment with the line it starts on, in file order.
    pub fn entries(&self) -> impl Iterator<Item = (usize, &Entry)> {
        self.items.iter().filter_map(|item| match &item.kind {
            ItemKind::Entry(entry) => Some((item.line, entry)),
            _ => None,
        })
    }

    /// The line ending new lines should use: the file's first one, `\n` by default.
    pub fn eol(&self) -> Eol {
        match self.body.iter().position(|&b| b == b'\n') {
            Some(i) if i > 0 && self.body[i - 1] == b'\r' => Eol::CrLf,
            _ => Eol::Lf,
        }
    }

    pub fn crlf(&self) -> CrlfStyle {
        let (mut lf, mut crlf) = (0usize, 0usize);
        for (i, &b) in self.body.iter().enumerate() {
            if b == b'\n' {
                if i > 0 && self.body[i - 1] == b'\r' {
                    crlf += 1;
                } else {
                    lf += 1;
                }
            }
        }
        match (lf, crlf) {
            (_, 0) => CrlfStyle::No,
            (0, _) => CrlfStyle::Yes,
            _ => CrlfStyle::Mixed,
        }
    }
}

/// End of the line content starting at `pos` (before `\n` or `\r\n`) and the start of the
/// next line.
fn line_bounds(body: &[u8], pos: usize) -> (usize, usize) {
    match body[pos..].iter().position(|&b| b == b'\n') {
        Some(offset) => {
            let nl = pos + offset;
            let end = if nl > pos && body[nl - 1] == b'\r' {
                nl - 1
            } else {
                nl
            };
            (end, nl + 1)
        }
        None => (body.len(), body.len()),
    }
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn skip_blanks(s: &[u8], mut i: usize) -> usize {
    while s.get(i).copied().is_some_and(is_blank) {
        i += 1;
    }
    i
}

/// End of the key starting at `i` (`[A-Za-z_][A-Za-z0-9_.]*`), or `None` if none starts there.
fn scan_key(s: &[u8], i: usize) -> Option<usize> {
    let first = *s.get(i)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut j = i + 1;
    while s
        .get(j)
        .copied()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        j += 1;
    }
    Some(j)
}

/// When an `export` keyword followed by blanks and a key starts at `i`, where that key starts.
fn after_export(s: &[u8], i: usize) -> Option<usize> {
    if !s.get(i..)?.starts_with(b"export") {
        return None;
    }
    let j = i + b"export".len();
    if !s.get(j).copied().is_some_and(is_blank) {
        return None;
    }
    let k = skip_blanks(s, j);
    scan_key(s, k).map(|_| k)
}

/// Parse `[export ]KEY=value` at `pos`; returns the entry and where its item ends.
fn dotenv_entry(
    body: &[u8],
    pos: usize,
    content_end: usize,
    next: usize,
) -> Option<(Entry, usize)> {
    let line = &body[..content_end];
    let mut start = skip_blanks(line, pos);
    let export = match after_export(line, start) {
        Some(key_start) => {
            start = key_start;
            true
        }
        None => false,
    };
    let key_end = scan_key(line, start)?;
    let eq = skip_blanks(line, key_end);
    if line.get(eq) != Some(&b'=') {
        return None;
    }
    let key = String::from_utf8(line[start..key_end].to_vec()).ok()?;
    let value_start = skip_blanks(line, eq + 1);

    if let Some(&quote @ (b'\'' | b'"')) = line.get(value_start) {
        if let Some((close, end)) = scan_quoted(body, value_start, quote) {
            let raw = &body[value_start + 1..close];
            let (quote, value) = if quote == b'"' {
                (Quote::Double, decode_double(raw))
            } else {
                (Quote::Single, decode_single(raw))
            };
            let entry = Entry {
                key,
                export,
                quote,
                value,
                value_span: value_start..close + 1,
            };
            return Some((entry, end));
        }
    }

    let value_end = bare_value_end(line, eq + 1, value_start);
    let entry = Entry {
        key,
        export,
        quote: Quote::Bare,
        value: line[value_start..value_end].to_vec(),
        value_span: value_start..content_end,
    };
    Some((entry, next))
}

/// Where a bare value starting at `value_start` ends: before the first `#` that follows a
/// blank (the blanks after `=` count, `from` being the byte after `=`), trailing blanks trimmed.
fn bare_value_end(line: &[u8], from: usize, value_start: usize) -> usize {
    let mut end = (value_start..line.len())
        .find(|&k| line[k] == b'#' && k > from && is_blank(line[k - 1]))
        .unwrap_or(line.len());
    while end > value_start && is_blank(line[end - 1]) {
        end -= 1;
    }
    end
}

/// Find the quote closing the one at `open`; returns its index and where the item ends, or
/// `None` when the value is unterminated or junk follows the closing quote on its line.
fn scan_quoted(body: &[u8], open: usize, quote: u8) -> Option<(usize, usize)> {
    let mut j = open + 1;
    while j < body.len() {
        let b = body[j];
        if quote == b'"' && b == b'\\' {
            j += 2;
            continue;
        }
        if b == quote {
            let (rest_end, next) = line_bounds(body, j + 1);
            let rest = &body[j + 1..rest_end];
            let k = skip_blanks(rest, 0);
            return (k == rest.len() || rest[k] == b'#').then_some((j, next));
        }
        j += 1;
    }
    None
}

fn decode_double(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match (raw[i], raw.get(i + 1).copied()) {
            (b'\\', Some(c @ (b'\\' | b'"' | b'$' | b'`'))) => {
                out.push(c);
                i += 2;
            }
            (b'\\', Some(c)) => {
                out.extend_from_slice(&[b'\\', c]);
                i += 2;
            }
            (b'\r', Some(b'\n')) => {
                out.push(b'\n');
                i += 2;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn decode_single(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

/// `KEY` when `content` is a commented-out assignment (`#KEY=…`, `# export KEY=…`).
fn commented_key(content: &[u8]) -> Option<String> {
    let hash = skip_blanks(content, 0);
    if content.get(hash) != Some(&b'#') {
        return None;
    }
    let mut start = skip_blanks(content, hash + 1);
    if let Some(key_start) = after_export(content, start) {
        start = key_start;
    }
    let end = scan_key(content, start)?;
    if content.get(skip_blanks(content, end)) != Some(&b'=') {
        return None;
    }
    String::from_utf8(content[start..end].to_vec()).ok()
}

/// A top-level `key: scalar` line. A key whose value is empty and followed by an indented or
/// `-` block is a mapping or sequence and stays verbatim.
fn yaml_entry(body: &[u8], pos: usize, content_end: usize, next: usize) -> Option<(Entry, usize)> {
    let line = &body[..content_end];
    let key_end = scan_key(line, pos)?;
    let colon = skip_blanks(line, key_end);
    if line.get(colon) != Some(&b':') {
        return None;
    }
    if line.get(colon + 1).is_some_and(|&b| !is_blank(b)) {
        return None;
    }
    let key = String::from_utf8(line[pos..key_end].to_vec()).ok()?;
    let value_start = skip_blanks(line, colon + 1);
    let (quote, value) = match line.get(value_start) {
        Some(b'"') => (Quote::Double, yaml_double(&line[value_start + 1..])?),
        Some(b'\'') => (Quote::Single, yaml_single(&line[value_start + 1..])?),
        Some(b'#') | None => {
            if matches!(body.get(next), Some(b' ' | b'\t' | b'-')) {
                return None;
            }
            (Quote::Bare, Vec::new())
        }
        Some(_) => {
            let end = bare_value_end(line, colon + 1, value_start);
            (Quote::Bare, line[value_start..end].to_vec())
        }
    };
    let entry = Entry {
        key,
        export: false,
        quote,
        value,
        value_span: value_start..content_end,
    };
    Some((entry, next))
}

/// The content of a YAML double-quoted scalar on one line (`\\` and `\"` decoded).
fn yaml_double(rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match (rest[i], rest.get(i + 1).copied()) {
            (b'"', _) => return Some(out),
            (b'\\', Some(c @ (b'\\' | b'"'))) => {
                out.push(c);
                i += 2;
            }
            (b'\\', Some(c)) => {
                out.extend_from_slice(&[b'\\', c]);
                i += 2;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    None
}

/// The content of a YAML single-quoted scalar on one line (`''` is a quote).
fn yaml_single(rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == b'\'' {
            if rest.get(i + 1) == Some(&b'\'') {
                out.push(b'\'');
                i += 2;
                continue;
            }
            return Some(out);
        }
        out.push(rest[i]);
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::testgen::{self, Lcg};

    /// `(line, key, value, quote, export)` for every assignment.
    fn assignments(f: &EnvFile) -> Vec<(usize, String, String, Quote, bool)> {
        f.entries()
            .map(|(line, e)| {
                (
                    line,
                    e.key.clone(),
                    String::from_utf8_lossy(&e.value).into_owned(),
                    e.quote,
                    e.export,
                )
            })
            .collect()
    }

    /// The effective (last) value of `key`.
    fn val(f: &EnvFile, key: &str) -> String {
        f.entries()
            .filter(|(_, e)| e.key == key)
            .last()
            .map(|(_, e)| String::from_utf8_lossy(&e.value).into_owned())
            .unwrap_or_else(|| panic!("no {key} in {:?}", assignments(f)))
    }

    fn commented(f: &EnvFile) -> Vec<(usize, String)> {
        f.items
            .iter()
            .filter_map(|i| match &i.kind {
                ItemKind::Commented(k) => Some((i.line, k.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn bare_values_and_inline_comments() {
        let f = EnvFile::parse(
            b"A=1\nB = two words # c\nC=#not-comment\nD= #comment\nE=x#y\nF=  pad  \n\tG=tab\n",
        );
        assert_eq!(val(&f, "A"), "1");
        assert_eq!(val(&f, "B"), "two words");
        assert_eq!(val(&f, "C"), "#not-comment");
        assert_eq!(val(&f, "D"), "");
        assert_eq!(val(&f, "E"), "x#y");
        assert_eq!(val(&f, "F"), "pad");
        assert_eq!(val(&f, "G"), "tab");
        assert!(f.entries().all(|(_, e)| e.quote == Quote::Bare));
    }

    #[test]
    fn single_and_double_quotes() {
        let f = EnvFile::parse(
            b"A='a b $c \"d\" \\n'\nB=\"x \\\"y\\\" \\\\ \\$ \\` \\n\"\nC=\"\" # empty\nD='' \n",
        );
        assert_eq!(val(&f, "A"), "a b $c \"d\" \\n");
        assert_eq!(val(&f, "B"), "x \"y\" \\ $ ` \\n");
        assert_eq!(val(&f, "C"), "");
        assert_eq!(val(&f, "D"), "");
        let quotes: Vec<Quote> = f.entries().map(|(_, e)| e.quote).collect();
        assert_eq!(
            quotes,
            [Quote::Single, Quote::Double, Quote::Double, Quote::Single]
        );
    }

    #[test]
    fn multiline_quoted_values_are_one_entry() {
        let f = EnvFile::parse(
            b"A=1\nPEM=\"-----BEGIN-----\nMIIE\n-----END-----\" # pem\nS='l1\nl2'\nZ=2\n",
        );
        let got = assignments(&f);
        assert_eq!(got.len(), 4);
        assert_eq!(got[1].0, 2);
        assert_eq!(got[1].2, "-----BEGIN-----\nMIIE\n-----END-----");
        assert_eq!(got[2].0, 5);
        assert_eq!(got[2].2, "l1\nl2");
        assert_eq!(got[3].0, 7);
        assert_eq!(got[3].1, "Z");
    }

    #[test]
    fn stray_quotes_fall_back_to_bare() {
        let f = EnvFile::parse(b"A=\"x\"y\nB=\"unterminated\nC='also\nD=4\n");
        assert_eq!(val(&f, "A"), "\"x\"y");
        assert_eq!(val(&f, "B"), "\"unterminated");
        assert_eq!(val(&f, "C"), "'also");
        assert_eq!(val(&f, "D"), "4");
        assert!(f.entries().all(|(_, e)| e.quote == Quote::Bare));
    }

    #[test]
    fn closing_quote_followed_by_comment_ends_a_multiline_value() {
        // Bash/dotenv read A as spanning two lines here; the parser must agree.
        let f = EnvFile::parse(b"A=\"one\nB=x\" # c\nC=3\n");
        let got = assignments(&f);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].2, "one\nB=x");
        assert_eq!(got[1].1, "C");
        assert_eq!(got[1].0, 3);
    }

    #[test]
    fn export_prefix() {
        let f =
            EnvFile::parse(b"export A=1\nexport \t B=2\nexport=3\nexportC=4\nexport\nexport 9=1\n");
        let got = assignments(&f);
        let keys: Vec<(&str, bool)> = got.iter().map(|g| (g.1.as_str(), g.4)).collect();
        assert_eq!(
            keys,
            [
                ("A", true),
                ("B", true),
                ("export", false),
                ("exportC", false)
            ]
        );
        assert_eq!(f.items.len(), 6);
    }

    #[test]
    fn commented_keys_are_recognised() {
        let f = EnvFile::parse(
            b"#A=1\n# export B=2\n  #  C = x\n# just a comment\n#=x\n#D\nE=1 # F=2\n",
        );
        assert_eq!(
            commented(&f),
            [(1, "A".to_string()), (2, "B".into()), (3, "C".into())]
        );
        assert_eq!(f.entries().count(), 1);
    }

    #[test]
    fn invalid_lines_are_verbatim() {
        let f = EnvFile::parse(b"1A=1\nMY-KEY=1\nKEY\njunk line\n=x\n  \n\n");
        assert_eq!(f.entries().count(), 0);
        assert!(f.items.iter().all(|i| i.kind == ItemKind::Verbatim));
        assert_eq!(f.items.len(), 7);
    }

    #[test]
    fn dotted_and_underscore_keys() {
        let f = EnvFile::parse(b"_A=1\nspring.datasource.url=x\na_b.c_9=2\n");
        let keys: Vec<String> = f.entries().map(|(_, e)| e.key.clone()).collect();
        assert_eq!(keys, ["_A", "spring.datasource.url", "a_b.c_9"]);
    }

    #[test]
    fn bom_and_crlf() {
        let f = EnvFile::parse("\u{feff}A=1\r\nB=\"x\r\ny\"\r\nC=3 \r\n".as_bytes());
        assert!(f.bom);
        assert_eq!(val(&f, "A"), "1");
        assert_eq!(val(&f, "B"), "x\ny");
        assert_eq!(val(&f, "C"), "3");
        assert_eq!(f.crlf(), CrlfStyle::Yes);
        assert_eq!(f.eol(), Eol::CrLf);
        assert_eq!(
            f.to_bytes(),
            "\u{feff}A=1\r\nB=\"x\r\ny\"\r\nC=3 \r\n".as_bytes()
        );
    }

    #[test]
    fn crlf_style_and_eol() {
        assert_eq!(EnvFile::parse(b"A=1").crlf(), CrlfStyle::No);
        assert_eq!(EnvFile::parse(b"A=1").eol(), Eol::Lf);
        assert_eq!(EnvFile::parse(b"A=1\nB=2\n").crlf(), CrlfStyle::No);
        assert_eq!(EnvFile::parse(b"A=1\r\nB=2\r\n").crlf(), CrlfStyle::Yes);
        let mixed = EnvFile::parse(b"A=1\r\nB=2\n");
        assert_eq!(mixed.crlf(), CrlfStyle::Mixed);
        assert_eq!(mixed.eol(), Eol::CrLf);
        assert_eq!(EnvFile::parse(b"A=1\nB=2\r\n").eol(), Eol::Lf);
    }

    #[test]
    fn value_spans() {
        let body = b"A=bare # c\nB = \"q\" # c\nC='s'\nD=\n";
        let f = EnvFile::parse(body);
        let spans: Vec<&[u8]> = f
            .entries()
            .map(|(_, e)| &body[e.value_span.clone()])
            .collect();
        assert_eq!(spans, [&b"bare # c"[..], b"\"q\"", b"'s'", b""]);
    }

    #[test]
    fn items_cover_the_body() {
        let body = b"A=1\n\n# c\nB=\"x\ny\"\nC";
        let f = EnvFile::parse(body);
        let mut pos = 0;
        for item in &f.items {
            assert_eq!(item.span.start, pos);
            pos = item.span.end;
        }
        assert_eq!(pos, body.len());
        let lines: Vec<usize> = f.items.iter().map(|i| i.line).collect();
        assert_eq!(lines, [1, 2, 3, 4, 6]);
    }

    #[test]
    fn lossless_on_awkward_inputs() {
        let cases: &[&[u8]] = &[
            b"",
            b"\n",
            b"\r",
            b"\r\n\r\n",
            b"A=\"\\",
            b"A=\"\\\"",
            b"A='",
            b"\"",
            b"A=1\r",
            b"A=\x00\nB=\xff\xfe\n",
            b"\xef\xbb\xbf",
            b"\xef\xbb",
            b"export \nexport A",
            b"A=\"x\" junk\nB=\"\n\"",
            b"#\n# \n#A\n#A=",
        ];
        for case in cases {
            let f = EnvFile::parse(case);
            assert_eq!(f.to_bytes(), case.to_vec(), "case {case:?}");
            let y = EnvFile::parse_yaml(case);
            assert_eq!(y.to_bytes(), case.to_vec(), "yaml case {case:?}");
        }
    }

    #[test]
    fn yaml_top_level_scalars() {
        let body = b"---\njson_rpc_url: \"https://api.devnet.solana.com\"\nwebsocket_url: ''\n\
keypair_path: /home/u/.config/solana/id.json # wallet\naddress_labels:\n  \"1111\": System Program\n\
commitment: confirmed\nquoted: 'it''s'\nlist:\n- a\n";
        let f = EnvFile::parse_yaml(body);
        assert_eq!(f.format, Format::Yaml);
        let got = assignments(&f);
        let keys: Vec<(usize, &str, &str)> = got
            .iter()
            .map(|g| (g.0, g.1.as_str(), g.2.as_str()))
            .collect();
        assert_eq!(
            keys,
            [
                (2, "json_rpc_url", "https://api.devnet.solana.com"),
                (3, "websocket_url", ""),
                (4, "keypair_path", "/home/u/.config/solana/id.json"),
                (7, "commitment", "confirmed"),
                (8, "quoted", "it's"),
            ]
        );
        assert_eq!(f.to_bytes(), body.to_vec());
    }

    #[test]
    fn prop_parse_is_lossless_and_spans_tile_the_body() {
        let mut rng = Lcg::new(11);
        for case in 0..3000 {
            let bytes = if rng.one_in(2) {
                testgen::file(&mut rng, true).bytes
            } else {
                testgen::bytes(&mut rng)
            };
            for f in [EnvFile::parse(&bytes), EnvFile::parse_yaml(&bytes)] {
                assert_eq!(f.to_bytes(), bytes, "case {case}");
                let mut pos = 0;
                for item in &f.items {
                    assert_eq!(item.span.start, pos, "case {case}");
                    assert!(item.span.end > pos, "case {case}");
                    pos = item.span.end;
                }
                assert_eq!(pos, f.body.len(), "case {case}");
            }
        }
    }

    #[test]
    fn prop_parser_agrees_with_generator() {
        let mut rng = Lcg::new(12);
        let mut checked = 0;
        for case in 0..3000 {
            let gen = testgen::file(&mut rng, false);
            assert!(gen.clean);
            let f = EnvFile::parse(&gen.bytes);
            let got: Vec<(String, Vec<u8>, bool)> = f
                .entries()
                .map(|(_, e)| (e.key.clone(), e.value.clone(), e.export))
                .collect();
            assert_eq!(
                got,
                gen.entries,
                "case {case}: {:?}",
                String::from_utf8_lossy(&gen.bytes)
            );
            let keys: Vec<String> = commented(&f).into_iter().map(|(_, k)| k).collect();
            assert_eq!(keys, gen.commented, "case {case}");
            checked += got.len();
        }
        assert!(checked > 5000, "only {checked} assignments generated");
    }

    #[test]
    fn yaml_bom_crlf() {
        let f = EnvFile::parse_yaml("\u{feff}a: 1\r\nb: \"x\"\r\n".as_bytes());
        assert!(f.bom);
        assert_eq!(val(&f, "a"), "1");
        assert_eq!(val(&f, "b"), "x");
        assert_eq!(f.crlf(), CrlfStyle::Yes);
    }
}
