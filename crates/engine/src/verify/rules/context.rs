//! Context classifier (spec D2.5): decides whether text is code, documentation or metadata,
//! splits Markdown into frontmatter, prose, fenced blocks and inline code, and groups lines into
//! statements and commands so a tool and its marker are only matched inside one command.
//!
//! Also holds the regex-free text helpers every rule shares: word-boundary search, trigger-word
//! bits, shell-style tokens and base64 decoding.

use std::borrow::Cow;
use std::path::Path;

use super::lexer::{self, Carry};
use super::{line_no, Ctx};

/// Longest statement (in lines) the builder joins, bounding cross-line co-occurrence.
const MAX_STMT_LINES: usize = 32;
/// Frontmatter longer than this is treated as prose (a stray `---` rule).
const MAX_FRONTMATTER_LINES: usize = 200;

/// Language family of a unit: drives comment syntax and the sink vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lang {
    Shell,
    Js,
    Python,
    Rust,
    Other,
}

/// How a file's text is analysed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileClass {
    /// Executable source.
    Code(Lang),
    /// Markdown: frontmatter (`meta`), prose, fenced blocks and inline code (`doc`).
    Markdown,
    /// Any other text (JSON, YAML, TOML, HTML, plain text …): `doc`.
    Doc,
}

/// What a line is inside its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Code,
    Text,
    Prose,
    Fence,
    FenceMark,
    Frontmatter,
}

/// Lines `start..end` analysed together as one language in one context.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Unit {
    pub(crate) ctx: Ctx,
    pub(crate) lang: Lang,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

const MARKDOWN_EXTS: &[&str] = &["md", "markdown", "mdx", "mdc", "mkd"];

const DOC_EXTS: &[&str] = &[
    "txt",
    "text",
    "rst",
    "adoc",
    "asciidoc",
    "org",
    "json",
    "jsonc",
    "json5",
    "jsonl",
    "ndjson",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "csv",
    "tsv",
    "xml",
    "html",
    "htm",
    "xhtml",
    "css",
    "scss",
    "sass",
    "less",
    "svg",
    "lock",
    "log",
    "properties",
    "sql",
    "graphql",
    "gql",
    "proto",
    "tf",
    "hcl",
    "ipynb",
    "env",
    "example",
    "sample",
    "template",
    "tmpl",
    "tpl",
    "j2",
    "jinja",
    "diff",
    "patch",
    "pem",
    "crt",
    "plist",
];

fn code_lang_for_ext(ext: &str) -> Option<Lang> {
    Some(match ext {
        "sh" | "bash" | "zsh" | "ksh" | "fish" | "command" | "bats" | "mk" => Lang::Shell,
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "mts" | "cts" | "vue" | "svelte"
        | "astro" => Lang::Js,
        "py" | "pyw" | "pyi" => Lang::Python,
        "rs" => Lang::Rust,
        "rb" | "pl" | "pm" | "php" | "go" | "java" | "kt" | "kts" | "scala" | "swift" | "c"
        | "h" | "cc" | "cpp" | "cxx" | "hpp" | "cs" | "lua" | "ps1" | "psm1" | "bat" | "cmd"
        | "vbs" | "r" | "jl" | "dart" | "ex" | "exs" | "zig" | "nim" | "groovy" | "gradle"
        | "awk" => Lang::Other,
        _ => return None,
    })
}

fn code_lang_for_name(name: &str) -> Option<Lang> {
    Some(match name {
        "makefile" | "gnumakefile" | "justfile" | ".bashrc" | ".bash_profile" | ".zshrc"
        | ".zprofile" | ".profile" | ".envrc" => Lang::Shell,
        "rakefile" => Lang::Other,
        _ => return None,
    })
}

fn shebang_lang(first: &str) -> Option<Lang> {
    let line = first.strip_prefix("#!")?.to_ascii_lowercase();
    for tok in line.split(|c: char| c.is_whitespace() || c == '/') {
        if tok.starts_with("python") {
            return Some(Lang::Python);
        }
        if matches!(tok, "node" | "nodejs" | "deno" | "bun" | "ts-node" | "tsx") {
            return Some(Lang::Js);
        }
        if matches!(tok, "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "ash") {
            return Some(Lang::Shell);
        }
    }
    Some(Lang::Other)
}

/// Classify a file by extension, then special name, then shebang, then exec bit.
///
/// Known documentation extensions stay documentation even with the exec bit set.
pub(crate) fn classify(rel: &Path, first_line: &str, executable: bool) -> FileClass {
    let name = rel
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let ext = rel
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if MARKDOWN_EXTS.contains(&ext.as_str()) {
        return FileClass::Markdown;
    }
    if DOC_EXTS.contains(&ext.as_str()) {
        return FileClass::Doc;
    }
    if let Some(lang) = code_lang_for_ext(&ext).or_else(|| code_lang_for_name(&name)) {
        return FileClass::Code(lang);
    }
    if let Some(lang) = shebang_lang(first_line) {
        return FileClass::Code(lang);
    }
    if executable {
        return FileClass::Code(Lang::Other);
    }
    FileClass::Doc
}

/// Language of a Markdown fence from its info string.
pub(crate) fn fence_lang(info: &str) -> Lang {
    let word = info
        .trim_start_matches(['{', '.'])
        .split(|c: char| c.is_whitespace() || c == ',' || c == '}')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match word.as_str() {
        "" | "sh" | "bash" | "zsh" | "shell" | "console" | "shell-session" | "terminal"
        | "shellscript" | "fish" | "ksh" => Lang::Shell,
        "js" | "javascript" | "ts" | "typescript" | "tsx" | "jsx" | "mjs" | "cjs" | "node" => {
            Lang::Js
        }
        "py" | "python" | "python3" | "py3" => Lang::Python,
        "rs" | "rust" => Lang::Rust,
        _ => Lang::Other,
    }
}

/// One decoded file, split into lines with roles and analysis units.
pub(crate) struct Document<'a> {
    pub(crate) text: &'a str,
    /// ASCII-lowercased copy of `text` (same byte offsets).
    pub(crate) lower: String,
    pub(crate) class: FileClass,
    spans: Vec<(usize, usize)>,
    /// Trigger bits per line (see [`line_bits`]).
    bits: Vec<u32>,
    roles: Vec<Role>,
    units: Vec<Unit>,
}

impl<'a> Document<'a> {
    pub(crate) fn new(text: &'a str, class: FileClass) -> Self {
        let lower = text.to_ascii_lowercase();
        let bytes = text.as_bytes();
        let mut spans = Vec::new();
        let mut start = 0;
        let mut i = 0;
        // Line terminators: `\n`, `\r\n`, a lone `\r`, and U+2028 / U+2029 (JS line breaks).
        while i < bytes.len() {
            let width = match bytes[i] {
                b'\n' => 1,
                b'\r' if bytes.get(i + 1) == Some(&b'\n') => 2,
                b'\r' => 1,
                0xE2 if bytes.get(i + 1) == Some(&0x80)
                    && matches!(bytes.get(i + 2), Some(0xA8 | 0xA9)) =>
                {
                    3
                }
                _ => {
                    i += 1;
                    continue;
                }
            };
            spans.push((start, i));
            i += width;
            start = i;
        }
        if start < bytes.len() {
            spans.push((start, bytes.len()));
        }
        let bits = spans
            .iter()
            .map(|&(s, e)| line_bits(&lower[s..e], &text[s..e]))
            .collect();
        let n = spans.len();
        let mut doc = Document {
            text,
            lower,
            class,
            spans,
            bits,
            roles: Vec::new(),
            units: Vec::new(),
        };
        match class {
            FileClass::Code(lang) => {
                doc.roles = vec![Role::Code; n];
                doc.units.push(Unit {
                    ctx: Ctx::Code,
                    lang,
                    start: 0,
                    end: n,
                });
            }
            FileClass::Doc => {
                doc.roles = vec![Role::Text; n];
                doc.units.push(Unit {
                    ctx: Ctx::Doc,
                    lang: Lang::Other,
                    start: 0,
                    end: n,
                });
            }
            FileClass::Markdown => doc.segment_markdown(),
        }
        doc
    }

    /// Number of lines.
    pub(crate) fn len(&self) -> usize {
        self.spans.len()
    }

    /// Original text of line `i`.
    pub(crate) fn line(&self, i: usize) -> &str {
        let (s, e) = self.spans[i];
        &self.text[s..e]
    }

    /// Lowercased text of line `i`.
    pub(crate) fn lower_line(&self, i: usize) -> &str {
        let (s, e) = self.spans[i];
        &self.lower[s..e]
    }

    /// Role of line `i`.
    pub(crate) fn role(&self, i: usize) -> Role {
        self.roles[i]
    }

    /// Trigger bits of line `i`.
    pub(crate) fn bits(&self, i: usize) -> u32 {
        self.bits[i]
    }

    /// Context of line `i`.
    pub(crate) fn ctx(&self, i: usize) -> Ctx {
        match self.roles[i] {
            Role::Code => Ctx::Code,
            Role::Frontmatter => Ctx::Meta,
            _ => Ctx::Doc,
        }
    }

    /// Analysis units (code files: one; Markdown: one per fenced block).
    pub(crate) fn units(&self) -> &[Unit] {
        &self.units
    }

    /// Line indices of the frontmatter body (between the `---` delimiters).
    pub(crate) fn frontmatter(&self) -> std::ops::Range<usize> {
        let end = self
            .roles
            .iter()
            .position(|r| *r != Role::Frontmatter)
            .unwrap_or(self.roles.len());
        if end >= 2 {
            1..end - 1
        } else {
            0..0
        }
    }

    fn segment_markdown(&mut self) {
        let n = self.spans.len();
        self.roles = vec![Role::Prose; n];
        let mut i = 0;
        if n > 0 && self.line(0).trim_end() == "---" {
            let mut j = 1;
            while j < n && j < MAX_FRONTMATTER_LINES {
                let t = self.line(j).trim_end();
                if t == "---" || t == "..." {
                    break;
                }
                j += 1;
            }
            if j < n && j < MAX_FRONTMATTER_LINES {
                for role in &mut self.roles[..=j] {
                    *role = Role::Frontmatter;
                }
                i = j + 1;
            }
        }
        while i < n {
            let open = fence_open(self.line(i).trim_start());
            let Some((ch, count, info)) = open else {
                i += 1;
                continue;
            };
            let lang = fence_lang(info);
            self.roles[i] = Role::FenceMark;
            let start = i + 1;
            let mut j = start;
            while j < n && !fence_close(self.line(j).trim(), ch, count) {
                self.roles[j] = Role::Fence;
                j += 1;
            }
            self.units.push(Unit {
                ctx: Ctx::Doc,
                lang,
                start,
                end: j,
            });
            if j < n {
                self.roles[j] = Role::FenceMark;
            }
            i = j + 1;
        }
    }
}

/// `(fence char, run length, info string)` when `t` opens a fenced block.
fn fence_open(t: &str) -> Option<(u8, usize, &str)> {
    let ch = *t.as_bytes().first()?;
    if ch != b'`' && ch != b'~' {
        return None;
    }
    let count = t.bytes().take_while(|&b| b == ch).count();
    if count < 3 {
        return None;
    }
    let info = &t[count..];
    if ch == b'`' && info.contains('`') {
        return None;
    }
    Some((ch, count, info.trim()))
}

fn fence_close(t: &str, ch: u8, count: usize) -> bool {
    t.len() >= count && t.bytes().all(|b| b == ch)
}

/// Content ranges of the inline code spans in `line`.
pub(crate) fn inline_spans(line: &str) -> Vec<(usize, usize)> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'`' {
            i += 1;
            continue;
        }
        let open = b[i..].iter().take_while(|&&c| c == b'`').count();
        let content = i + open;
        let mut j = content;
        let mut closed = None;
        while j < b.len() {
            if b[j] == b'`' {
                let run = b[j..].iter().take_while(|&&c| c == b'`').count();
                if run == open {
                    closed = Some(j);
                    break;
                }
                j += run;
            } else {
                j += 1;
            }
        }
        match closed {
            Some(close) => {
                if close > content {
                    out.push((content, close));
                }
                i = close + open;
            }
            None => i = content,
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Statements and commands.
// ---------------------------------------------------------------------------------------

/// Lines joined into one statement.
pub(crate) struct Stmt<'d> {
    pub(crate) lower: Cow<'d, str>,
    pub(crate) orig: Cow<'d, str>,
    first_line: u32,
    /// `(byte offset, line)` where each joined line after the first begins.
    breaks: Vec<(usize, u32)>,
    /// Sorted byte ranges of string/regex literals and comments (everything else is code).
    regions: Vec<(usize, usize)>,
    pub(crate) lang: Lang,
    pub(crate) ctx: Ctx,
    /// Trigger bits of the joined lines.
    pub(crate) bits: u32,
}

impl<'d> Stmt<'d> {
    /// A one-line statement over owned text (package.json scripts).
    pub(crate) fn owned(text: &str, line: u32, lang: Lang, ctx: Ctx) -> Stmt<'static> {
        let lower = text.to_ascii_lowercase();
        let bits = line_bits(&lower, text);
        let mut regions = Vec::new();
        lexer::lex(&lower, lang, Carry::Code, 0, &mut regions);
        Stmt {
            lower: Cow::Owned(lower),
            orig: Cow::Owned(text.to_string()),
            first_line: line,
            breaks: Vec::new(),
            regions,
            lang,
            ctx,
            bits,
        }
    }

    /// A one-line statement borrowed from a document line or span.
    fn borrowed(lower: &'d str, orig: &'d str, line: u32, lang: Lang, ctx: Ctx, bits: u32) -> Self {
        let mut regions = Vec::new();
        lexer::lex(lower, lang, Carry::Code, 0, &mut regions);
        Stmt {
            lower: Cow::Borrowed(lower),
            orig: Cow::Borrowed(orig),
            first_line: line,
            breaks: Vec::new(),
            regions,
            lang,
            ctx,
            bits,
        }
    }

    /// 1-based line of byte `off` in the joined text.
    pub(crate) fn line_at(&self, off: usize) -> u32 {
        self.breaks
            .iter()
            .rev()
            .find(|(o, _)| *o <= off)
            .map(|(_, l)| *l)
            .unwrap_or(self.first_line)
    }

    /// True when byte `off` is inside a string/regex literal or a comment.
    pub(crate) fn is_quoted(&self, off: usize) -> bool {
        lexer::in_regions(&self.regions, off)
    }

    /// The statement split into commands on `;`, `&&` and `||` outside literals and comments.
    /// Commands carry the statement's trigger bits (a superset; every rule re-checks its words).
    pub(crate) fn commands(&self) -> impl Iterator<Item = Cmd<'_>> + '_ {
        split_commands(&self.lower, &self.regions).map(move |(start, end)| Cmd {
            stmt: self,
            start,
            end,
            bits: self.bits,
        })
    }
}

/// One command of a statement.
pub(crate) struct Cmd<'s> {
    stmt: &'s Stmt<'s>,
    start: usize,
    end: usize,
    pub(crate) bits: u32,
}

impl<'s> Cmd<'s> {
    /// Lowercased command text.
    pub(crate) fn lower(&self) -> &'s str {
        &self.stmt.lower[self.start..self.end]
    }

    /// Original command text (same offsets as [`Cmd::lower`]).
    pub(crate) fn orig(&self) -> &'s str {
        &self.stmt.orig[self.start..self.end]
    }

    /// 1-based line of byte `off` within this command.
    pub(crate) fn line_at(&self, off: usize) -> u32 {
        self.stmt.line_at(self.start + off)
    }

    /// True when byte `off` of this command is inside a literal or comment.
    pub(crate) fn quoted(&self, off: usize) -> bool {
        self.stmt.is_quoted(self.start + off)
    }

    pub(crate) fn lang(&self) -> Lang {
        self.stmt.lang
    }

    pub(crate) fn ctx(&self) -> Ctx {
        self.stmt.ctx
    }
}

/// Join the lines of `unit` into statements and hand each one with trigger words to `f`.
///
/// Every line is lexed (block comments, triple-quoted strings and template text carry to the
/// next line). Code (and JS/Python/Rust fences) joins lines while brackets are open; every unit
/// honours a trailing `\`, `|` or `&&`. Shell fences drop a leading `$ `/`% ` prompt.
pub(crate) fn for_each_stmt<'d>(doc: &'d Document<'d>, unit: &Unit, mut f: impl FnMut(&Stmt<'d>)) {
    let brackets =
        unit.ctx == Ctx::Code || matches!(unit.lang, Lang::Js | Lang::Python | Lang::Rust);
    let prompt = unit.ctx == Ctx::Doc && unit.lang == Lang::Shell;
    let mut acc: Vec<usize> = Vec::new();
    // Regions of the accumulated lines: (index into `acc`, start, end), line-relative.
    let mut acc_regions: Vec<(usize, usize, usize)> = Vec::new();
    let mut line_regions: Vec<(usize, usize)> = Vec::new();
    let mut depth: i32 = 0;
    let mut carry = Carry::Code;
    for i in unit.start..unit.end {
        let line = piece(doc.lower_line(i), prompt);
        if acc.is_empty() && carry == Carry::Code && line.trim().is_empty() {
            continue;
        }
        line_regions.clear();
        let lexed = lexer::lex(line, unit.lang, carry, 0, &mut line_regions);
        carry = lexed.carry;
        let cont = continues(line, &line_regions);
        let k = acc.len();
        acc.push(i);
        acc_regions.extend(line_regions.iter().map(|&(a, z)| (k, a, z)));
        if brackets {
            depth = depth.saturating_add(lexed.delta).max(0);
        }
        if (depth == 0 && !cont) || acc.len() >= MAX_STMT_LINES {
            emit_stmt(doc, unit, &acc, &acc_regions, &mut f);
            acc.clear();
            acc_regions.clear();
            depth = 0;
        }
    }
    if !acc.is_empty() {
        emit_stmt(doc, unit, &acc, &acc_regions, &mut f);
    }
}

/// The line continues into the next one: a trailing `\`, `|` or `&&` in code.
fn continues(line: &str, regions: &[(usize, usize)]) -> bool {
    let trimmed = line.trim_end();
    let end = match regions.last() {
        Some(&(start, stop)) if stop >= trimmed.len() => start,
        _ => trimmed.len(),
    };
    let tail = line[..end].trim_end();
    tail.ends_with('\\') || tail.ends_with('|') || tail.ends_with("&&")
}

/// Every Markdown prose line and inline code span, as one-line `doc` statements.
pub(crate) fn for_each_prose_stmt<'d>(doc: &'d Document<'d>, mut f: impl FnMut(&Stmt<'d>)) {
    for i in 0..doc.len() {
        if doc.role(i) != Role::Prose {
            continue;
        }
        let bits = doc.bits(i);
        if bits == 0 {
            continue;
        }
        let lower = doc.lower_line(i);
        let orig = doc.line(i);
        f(&Stmt::borrowed(
            lower,
            orig,
            line_no(i),
            Lang::Other,
            Ctx::Doc,
            bits,
        ));
        if !orig.contains('`') {
            continue;
        }
        for (s, e) in inline_spans(orig) {
            let bits = line_bits(&lower[s..e], &orig[s..e]);
            if bits != 0 {
                f(&Stmt::borrowed(
                    &lower[s..e],
                    &orig[s..e],
                    line_no(i),
                    Lang::Shell,
                    Ctx::Doc,
                    bits,
                ));
            }
        }
    }
}

/// `line` without a leading `$ `/`% ` shell prompt when `prompt` is set.
fn piece(line: &str, prompt: bool) -> &str {
    if !prompt {
        return line;
    }
    let t = line.trim_start();
    t.strip_prefix("$ ")
        .or_else(|| t.strip_prefix("% "))
        .unwrap_or(line)
}

fn emit_stmt<'d>(
    doc: &'d Document<'d>,
    unit: &Unit,
    lines: &[usize],
    regions: &[(usize, usize, usize)],
    f: &mut impl FnMut(&Stmt<'d>),
) {
    let prompt = unit.ctx == Ctx::Doc && unit.lang == Lang::Shell;
    let bits = lines.iter().fold(0, |acc, &i| acc | doc.bits(i));
    if bits == 0 {
        return;
    }
    if let [i] = lines {
        f(&Stmt {
            lower: Cow::Borrowed(piece(doc.lower_line(*i), prompt)),
            orig: Cow::Borrowed(piece(doc.line(*i), prompt)),
            first_line: line_no(*i),
            breaks: Vec::new(),
            regions: regions.iter().map(|&(_, a, z)| (a, z)).collect(),
            lang: unit.lang,
            ctx: unit.ctx,
            bits,
        });
        return;
    }
    let mut lower = String::new();
    let mut orig = String::new();
    let mut breaks = Vec::new();
    let mut starts = Vec::with_capacity(lines.len());
    for (k, &i) in lines.iter().enumerate() {
        if k > 0 {
            lower.push('\n');
            orig.push('\n');
            breaks.push((lower.len(), line_no(i)));
        }
        starts.push(lower.len());
        lower.push_str(piece(doc.lower_line(i), prompt));
        orig.push_str(piece(doc.line(i), prompt));
    }
    f(&Stmt {
        lower: Cow::Owned(lower),
        orig: Cow::Owned(orig),
        first_line: line_no(lines[0]),
        breaks,
        regions: regions
            .iter()
            .map(|&(k, a, z)| (starts[k] + a, starts[k] + z))
            .collect(),
        lang: unit.lang,
        ctx: unit.ctx,
        bits,
    });
}

/// Byte ranges of the commands in `s`: split on `;`, `&&` and `||` outside `regions`.
pub(crate) fn split_commands<'a>(s: &'a str, regions: &'a [(usize, usize)]) -> Commands<'a> {
    Commands { s, regions, at: 0 }
}

/// Iterator over the command ranges of a statement (see [`split_commands`]).
pub(crate) struct Commands<'a> {
    s: &'a str,
    regions: &'a [(usize, usize)],
    at: usize,
}

impl Iterator for Commands<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        let b = self.s.as_bytes();
        while self.at < b.len() {
            let start = self.at;
            let mut i = start;
            let mut end = b.len();
            let mut next = b.len();
            let mut r = self.regions.partition_point(|&(_, stop)| stop <= i);
            while i < b.len() {
                if let Some(&(rs, re)) = self.regions.get(r) {
                    if i >= rs {
                        i = re.max(i + 1);
                        r += 1;
                        continue;
                    }
                }
                let c = b[i];
                match c {
                    b';' => {
                        end = i;
                        next = i + 1;
                        break;
                    }
                    b'&' | b'|' if b.get(i + 1) == Some(&c) => {
                        end = i;
                        next = i + 2;
                        break;
                    }
                    _ => {}
                }
                i += 1;
            }
            self.at = next.max(start + 1);
            let piece = &self.s[start..end.min(b.len())];
            let lead = piece.len() - piece.trim_start().len();
            let trimmed = piece.trim();
            if !trimmed.is_empty() {
                return Some((start + lead, start + lead + trimmed.len()));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------------------
// Trigger words.
// ---------------------------------------------------------------------------------------

/// Network tools (curl, fetch, requests, sockets …).
pub(crate) const T_NET: u32 = 1;
/// eval-family sinks: eval/exec, `Function`, computed globals, vm, pickle/marshal, data: imports.
pub(crate) const T_EVAL: u32 = 1 << 1;
/// Decoders.
pub(crate) const T_DECODE: u32 = 1 << 2;
/// Secret paths.
pub(crate) const T_SECRET: u32 = 1 << 3;
/// Environment access.
pub(crate) const T_ENV: u32 = 1 << 4;
/// Package-manager / git configuration.
pub(crate) const T_REG: u32 = 1 << 5;
/// Package runners.
pub(crate) const T_NPX: u32 = 1 << 6;
/// The `env` word: `.env` files (secret paths proper are [`T_SECRET`]).
pub(crate) const T_DOTENV: u32 = 1 << 11;
/// Prompt-injection phrasing.
pub(crate) const T_INJECT: u32 = 1 << 7;
/// A URL (`http`/`https` word).
pub(crate) const T_URL: u32 = 1 << 8;
/// Process spawning.
pub(crate) const T_SPAWN: u32 = 1 << 9;
/// Shells and interpreters (pipe targets, `-c` / `-e`).
pub(crate) const T_SHELL: u32 = 1 << 10;

// Provisional bits: common words that only matter next to a partner (see `line_bits`).
const P_ID: u32 = 1 << 16;
const P_JSON: u32 = 1 << 17;
const P_SOLANA: u32 = 1 << 18;
const P_CONFIG: u32 = 1 << 19;
const P_IMPORT: u32 = 1 << 20;
const P_DATA: u32 = 1 << 21;
const P_LATEST: u32 = 1 << 22;
const P_YOU: u32 = 1 << 23;
const P_ARE: u32 = 1 << 24;
const P_NOW: u32 = 1 << 25;
const P_FUNCTION: u32 = 1 << 26;
const P_COMMAND: u32 = 1 << 27;
const P_EXPRESSION: u32 = 1 << 28;
const P_MEMBER: u32 = 1 << 29;
const P_INDEX: u32 = 1 << 30;
const P_REQUEST: u32 = 1 << 31;
const PROVISIONAL: u32 = 0xFFFF_0000;

/// Trigger words and their classes, sorted by first byte (lookups scan one first-byte group).
const WORDS: &[(&str, u32)] = &[
    ("__builtins__", T_EVAL),
    ("__import__", T_EVAL),
    ("a2b_base64", T_DECODE),
    ("aiohttp", T_NET),
    ("alert", T_INJECT),
    ("are", P_ARE),
    ("atob", T_DECODE),
    ("aws", T_SECRET),
    ("axios", T_NET),
    ("b64decode", T_DECODE),
    ("base64", T_DECODE),
    ("bash", T_SHELL),
    ("buffer", T_DECODE),
    ("builtins", T_EVAL),
    ("bun", T_SHELL),
    ("bunfig", T_REG),
    ("bunx", T_NPX),
    ("bypass", T_INJECT),
    ("cargo", T_REG),
    ("child_process", T_SPAWN),
    ("codecs", T_DECODE),
    ("command", P_COMMAND),
    ("conceal", T_INJECT),
    ("condarc", T_REG),
    ("config", P_CONFIG),
    ("constructor", P_MEMBER),
    ("createrequire", T_EVAL),
    ("credentials", T_SECRET),
    ("curl", T_NET),
    ("dash", T_SHELL),
    ("data", P_DATA),
    ("declare", T_ENV),
    ("decodebytes", T_DECODE),
    ("deno", T_SHELL),
    ("disregard", T_INJECT),
    ("dlx", T_NPX),
    ("docker", T_SECRET),
    ("downloadfile", T_NET),
    ("downloadstring", T_NET),
    ("env", T_DOTENV | T_ENV),
    ("environ", T_ENV),
    ("environment", T_ENV),
    ("envrc", T_SECRET),
    ("eval", T_EVAL | T_SHELL),
    ("exec", T_EVAL | T_SHELL),
    ("execa", T_SPAWN),
    ("execfile", T_SPAWN),
    ("execfilesync", T_SPAWN),
    ("execl", T_SPAWN),
    ("execlp", T_SPAWN),
    ("execsync", T_SPAWN),
    ("execv", T_SPAWN),
    ("execve", T_SPAWN),
    ("execvp", T_SPAWN),
    ("expression", P_EXPRESSION),
    ("extension", T_SECRET),
    ("fetch", T_NET),
    ("fish", T_SHELL),
    ("forget", T_INJECT),
    ("fork", T_SPAWN),
    ("fromcharcode", T_DECODE),
    ("fromhex", T_DECODE),
    ("ftp", T_NET),
    ("function", P_FUNCTION),
    ("gci", T_ENV),
    ("gemrc", T_REG),
    ("get", P_REQUEST),
    ("getenvironmentvariables", T_ENV),
    ("global", P_MEMBER),
    ("globalthis", T_EVAL),
    ("hide", T_INJECT),
    ("hooks", T_REG),
    ("hookspath", T_REG),
    ("http", T_URL),
    ("https", T_URL),
    ("httpx", T_NET),
    ("id", P_ID),
    ("id_ecdsa", T_SECRET),
    ("id_ed25519", T_SECRET),
    ("id_rsa", T_SECRET),
    ("iex", T_SHELL),
    ("ignore", T_INJECT),
    ("import", P_IMPORT),
    ("index", P_INDEX),
    ("inform", T_INJECT),
    ("informing", T_INJECT),
    ("insteadof", T_REG),
    ("irm", T_NET),
    ("iwr", T_NET),
    ("json", P_JSON),
    ("keypair", T_SECRET),
    ("ksh", T_SHELL),
    ("kube", T_SECRET),
    ("latest", P_LATEST),
    ("login", T_SECRET),
    ("marshal", T_EVAL),
    ("mention", T_INJECT),
    ("nc", T_NET),
    ("ncat", T_NET),
    ("netcat", T_NET),
    ("netrc", T_SECRET),
    ("node", T_SHELL),
    ("nodejs", T_SHELL),
    ("notify", T_INJECT),
    ("notifying", T_INJECT),
    ("now", P_NOW),
    ("npmrc", T_REG),
    ("npx", T_NPX),
    ("openssl", T_DECODE),
    ("override", T_INJECT),
    ("perl", T_SHELL),
    ("php", T_SHELL),
    ("pickle", T_EVAL),
    ("pip", T_REG),
    ("popen", T_SPAWN),
    ("powershell", T_SHELL),
    ("printenv", T_ENV),
    ("pty", T_SPAWN),
    ("pwsh", T_SHELL),
    ("pypirc", T_SECRET),
    ("python", T_SHELL),
    ("python2", T_SHELL),
    ("python3", T_SHELL),
    ("registry", T_REG),
    ("request", P_REQUEST),
    ("requests", T_NET),
    ("restmethod", T_NET),
    ("reveal", T_INJECT),
    ("ruby", T_SHELL),
    ("runincontext", T_EVAL),
    ("runinnewcontext", T_EVAL),
    ("runinthiscontext", T_EVAL),
    ("scp", T_NET),
    ("self", P_MEMBER),
    ("setinterval", T_EVAL),
    ("settimeout", T_EVAL),
    ("sftp", T_NET),
    ("sh", T_SHELL),
    ("shelljs", T_SPAWN),
    ("socket", T_NET),
    ("solana", P_SOLANA),
    ("source", T_SHELL),
    ("spawn", T_SPAWN),
    ("spawnsync", T_SPAWN),
    ("ssh", T_SECRET),
    ("standard_b64decode", T_DECODE),
    ("subprocess", T_SPAWN),
    ("superagent", T_NET),
    ("superstack", T_SECRET),
    ("system", T_SPAWN),
    ("tcp", T_NET),
    ("tell", T_INJECT),
    ("telling", T_INJECT),
    ("this", P_MEMBER),
    ("undici", T_NET),
    ("urllib", T_NET),
    ("urlopen", T_NET),
    ("urlsafe_b64decode", T_DECODE),
    ("uvx", T_NPX),
    ("vm", T_EVAL),
    ("webclient", T_NET),
    ("webrequest", T_NET),
    ("websocket", T_NET),
    ("wget", T_NET),
    ("window", P_MEMBER),
    ("without", T_INJECT),
    ("xmlhttprequest", T_NET),
    ("xxd", T_DECODE),
    ("yarnrc", T_REG),
    ("you", P_YOU),
    ("zsh", T_SHELL),
];

/// Per first byte: the lengths present (bit per length) and the `WORDS` index range.
struct WordIndex {
    lens: [u32; 128],
    start: [usize; 128],
    end: [usize; 128],
}

const INDEX: WordIndex = build_index();

/// Bloom filter over (length, first, second, last byte): rejects almost every non-trigger word
/// with one lookup.
const BLOOM: [u64; 64] = build_bloom();

const fn bloom_slot(w: &[u8]) -> usize {
    let len = w.len();
    let h = (len * 7) ^ (w[0] as usize * 31) ^ (w[1] as usize * 131) ^ (w[len - 1] as usize * 17);
    h & 4095
}

const fn build_bloom() -> [u64; 64] {
    let mut bloom = [0u64; 64];
    let mut k = 0;
    while k < WORDS.len() {
        let slot = bloom_slot(WORDS[k].0.as_bytes());
        bloom[slot / 64] |= 1 << (slot % 64);
        k += 1;
    }
    bloom
}

const fn build_index() -> WordIndex {
    let mut index = WordIndex {
        lens: [0; 128],
        start: [0; 128],
        end: [0; 128],
    };
    let mut k = 0;
    while k < WORDS.len() {
        let w = WORDS[k].0.as_bytes();
        let first = w[0] as usize;
        if index.lens[first] == 0 {
            index.start[first] = k;
        }
        index.lens[first] |= 1 << w.len();
        index.end[first] = k + 1;
        k += 1;
    }
    index
}

/// Word bytes: ASCII alphanumerics and `_`.
const WORD_BYTE: [bool; 256] = {
    let mut t = [false; 256];
    let mut b = 0;
    while b < 256 {
        let c = b as u8;
        t[b] = c.is_ascii_alphanumeric() || c == b'_';
        b += 1;
    }
    t
};

/// Trigger class of one lowercased word.
fn word_bits(w: &[u8]) -> u32 {
    let (Some(&first), 2..=26) = (w.first(), w.len()) else {
        return 0;
    };
    let first = usize::from(first);
    if first >= 128 || INDEX.lens[first] & (1 << w.len()) == 0 {
        return 0;
    }
    let slot = bloom_slot(w);
    if BLOOM[slot / 64] & (1 << (slot % 64)) == 0 {
        return 0;
    }
    WORDS[INDEX.start[first]..INDEX.end[first]]
        .iter()
        .find(|(word, _)| word.as_bytes() == w)
        .map_or(0, |(_, bits)| *bits)
}

/// A computed member with a string key: `x['…']` / `x["…"]`.
fn quoted_member(s: &str) -> bool {
    let b = s.as_bytes();
    s.match_indices('[')
        .any(|(p, _)| matches!(b.get(p + 1), Some(b'\'' | b'"')))
}

/// Words of `s`: maximal runs of ASCII alphanumerics and `_`.
pub(crate) fn words(s: &str) -> impl Iterator<Item = &str> {
    let b = s.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < b.len() && !WORD_BYTE[usize::from(b[i])] {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        let start = i;
        while i < b.len() && WORD_BYTE[usize::from(b[i])] {
            i += 1;
        }
        Some(&s[start..i])
    })
}

/// Trigger classes of one line (`lower` and its original-case text): which rules can match.
pub(crate) fn line_bits(lower: &str, orig: &str) -> u32 {
    let b = lower.as_bytes();
    let mut bits = 0;
    let mut i = 0;
    while i < b.len() {
        if !WORD_BYTE[usize::from(b[i])] {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && WORD_BYTE[usize::from(b[i])] {
            i += 1;
        }
        bits |= word_bits(&b[start..i]);
    }
    if bits & PROVISIONAL == 0 {
        return bits;
    }
    let both = |a: u32, b: u32| bits & a != 0 && bits & b != 0;
    let mut out = bits & !PROVISIONAL;
    if both(P_ID, P_JSON) || both(P_SOLANA, P_CONFIG) {
        out |= T_SECRET;
    }
    if both(P_IMPORT, P_DATA)
        || (bits & P_FUNCTION != 0 && orig.contains("Function"))
        || (bits & P_MEMBER != 0
            && (quoted_member(lower) || lower.contains("constructor.constructor")))
    {
        out |= T_EVAL;
    }
    if bits & P_COMMAND != 0 && (lower.contains("command::new") || lower.contains("exec.command")) {
        out |= T_SPAWN;
    }
    if bits & P_EXPRESSION != 0 && lower.contains("invoke-expression") {
        out |= T_SHELL;
    }
    if bits & P_INDEX != 0
        && (lower.contains("index-url")
            || lower.contains("index_url")
            || lower.contains("indexurl"))
    {
        out |= T_REG;
    }
    if bits & P_LATEST != 0 && lower.contains("@latest") {
        out |= T_NPX;
    }
    if bits & (P_YOU | P_ARE | P_NOW) == (P_YOU | P_ARE | P_NOW) {
        out |= T_INJECT;
    }
    // `http.request(` / `https.get(`: the bare Node clients.
    if bits & P_REQUEST != 0 && bits & T_URL != 0 {
        out |= T_NET;
    }
    out
}

// ---------------------------------------------------------------------------------------
// Matching helpers.
// ---------------------------------------------------------------------------------------

/// Identifier byte for word boundaries (`$` included so `$curl` is a variable, not the tool).
pub(crate) fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// First occurrence of `word` at or after `from`, bounded by non-identifier bytes.
pub(crate) fn find_word_from(hay: &str, word: &str, from: usize) -> Option<usize> {
    let hb = hay.as_bytes();
    let mut i = from;
    while let Some(p) = hay.get(i..).and_then(|rest| rest.find(word)) {
        let s = i + p;
        let e = s + word.len();
        let left = s == 0 || !is_ident(hb[s - 1]);
        let right = e >= hb.len() || !is_ident(hb[e]);
        if left && right {
            return Some(s);
        }
        i = s + 1;
    }
    None
}

/// First occurrence of `word` bounded by non-identifier bytes.
pub(crate) fn find_word(hay: &str, word: &str) -> Option<usize> {
    find_word_from(hay, word, 0)
}

/// First call `name(` (spaces allowed before `(`). With `member == false` a preceding `.`
/// disqualifies the match (so `model.eval()` is not `eval(`).
pub(crate) fn find_call(hay: &str, name: &str, member: bool) -> Option<usize> {
    let hb = hay.as_bytes();
    let mut i = 0;
    while let Some(p) = hay.get(i..).and_then(|rest| rest.find(name)) {
        let s = i + p;
        let e = s + name.len();
        let left = s == 0 || {
            let prev = hb[s - 1];
            !is_ident(prev) && (member || prev != b'.')
        };
        let rest = hay[e..].trim_start();
        if left && rest.starts_with('(') {
            return Some(s);
        }
        i = s + 1;
    }
    None
}

/// Largest char boundary of `s` at or below byte `i`.
pub(crate) fn floor_char_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// First offset of any of `needles` in `hay`.
pub(crate) fn find_any(hay: &str, needles: &[&str]) -> Option<usize> {
    needles.iter().filter_map(|n| hay.find(n)).min()
}

/// Shell-style tokens (unquoted whitespace splits; quotes kept in the token) with offsets.
pub(crate) fn shell_tokens(s: &str) -> Vec<(usize, &str)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut quote = 0u8;
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if quote != 0 {
            if c == b'\\' && quote != b'\'' {
                i += 2;
                continue;
            }
            if c == quote {
                quote = 0;
            }
        } else if c.is_ascii_whitespace() {
            if let Some(st) = start.take() {
                out.push((st, &s[st..i]));
            }
        } else {
            if start.is_none() {
                start = Some(i);
            }
            if c == b'\'' || c == b'"' || c == b'`' {
                quote = c;
            } else if c == b'\\' {
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    if let Some(st) = start {
        out.push((st, &s[st..b.len().max(st)]));
    }
    out
}

/// `tok` without one layer of surrounding quotes.
pub(crate) fn unquote(tok: &str) -> &str {
    let t = tok.trim();
    for q in ['"', '\'', '`'] {
        if let Some(inner) = t.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner;
        }
    }
    t
}

fn b64_val(b: u8) -> Option<u32> {
    Some(u32::from(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    }))
}

/// Base64 alphabet byte (standard and URL-safe, plus padding).
pub(crate) fn is_b64_byte(b: u8) -> bool {
    b64_val(b).is_some() || b == b'='
}

/// Decode standard or URL-safe base64, stopping at padding. `None` on a foreign byte.
pub(crate) fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in s {
        if b == b'=' {
            break;
        }
        acc = (acc << 6) | b64_val(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Fraction of bytes that are printable ASCII or common whitespace.
pub(crate) fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
        .count();
    printable as f64 / bytes.len() as f64
}

/// Quoted literals in `s` whose content is at least `min` base64-alphabet bytes.
pub(crate) fn quoted_b64_literals(s: &str, min: usize) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if q != b'\'' && q != b'"' && q != b'`' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < b.len() && is_b64_byte(b[j]) {
            j += 1;
        }
        if j < b.len() && b[j] == q && j - start >= min {
            out.push(&s[start..j]);
            i = j + 1;
        } else {
            i = start;
        }
    }
    out
}

/// True when `lit` uses only hexadecimal digits.
pub(crate) fn is_hex(lit: &str) -> bool {
    lit.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Host of the first `scheme://host` URL starting at or after `from`, with its offset.
pub(crate) fn next_url_host(s: &str, from: usize) -> Option<(usize, &str)> {
    let p = s.get(from..)?.find("://")? + from;
    let start = p + 3;
    let rest = &s[start..];
    let end = rest
        .find(|c: char| {
            matches!(
                c,
                '/' | '?' | '#' | '\'' | '"' | '`' | ')' | ']' | ',' | '>' | '|' | ';' | '\\'
            ) || c.is_whitespace()
        })
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = if host.starts_with('[') {
        host.split(']')
            .next()
            .map(|h| h.trim_start_matches('['))
            .unwrap_or(host)
    } else if host.starts_with('$') || host.starts_with('{') {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    };
    Some((p, host))
}

/// Loopback / local development hosts.
pub(crate) fn is_local_host(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    h == "localhost"
        || h.ends_with(".localhost")
        || h.starts_with("127.")
        || h == "0.0.0.0"
        || h == "::1"
        || h == "host.docker.internal"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmts(text: &str, class: FileClass) -> Vec<(String, u32)> {
        let doc = Document::new(text, class);
        let mut out = Vec::new();
        for unit in doc.units() {
            for_each_stmt(&doc, unit, |s| {
                out.push((s.lower.to_string(), s.line_at(0)))
            });
        }
        out
    }

    #[test]
    fn classify_by_extension_name_shebang_and_exec_bit() {
        let c = |p: &str, first: &str, x: bool| classify(Path::new(p), first, x);
        assert_eq!(c("SKILL.md", "", false), FileClass::Markdown);
        assert_eq!(c("a/run.sh", "", false), FileClass::Code(Lang::Shell));
        assert_eq!(c("x.ts", "", false), FileClass::Code(Lang::Js));
        assert_eq!(
            c("tool", "#!/usr/bin/env python3", false),
            FileClass::Code(Lang::Python)
        );
        assert_eq!(
            c("tool", "#!/bin/bash", false),
            FileClass::Code(Lang::Shell)
        );
        assert_eq!(c("tool", "plain", true), FileClass::Code(Lang::Other));
        assert_eq!(c("data.json", "", true), FileClass::Doc);
        assert_eq!(c(".envrc", "", false), FileClass::Code(Lang::Shell));
        assert_eq!(c("Makefile", "", false), FileClass::Code(Lang::Shell));
        assert_eq!(c("Dockerfile", "FROM x", false), FileClass::Doc);
        assert_eq!(c("notes", "plain", false), FileClass::Doc);
    }

    #[test]
    fn markdown_roles_frontmatter_fences_and_prose() {
        let text = "---\nname: x\ndescription: y\n---\n# T\n\n```bash\ncurl x\n```\n~~~~py\nprint(1)\n~~~~\ntail\n";
        let doc = Document::new(text, FileClass::Markdown);
        assert_eq!(doc.role(0), Role::Frontmatter);
        assert_eq!(doc.ctx(1), Ctx::Meta);
        assert_eq!(doc.frontmatter(), 1..3);
        assert_eq!(doc.role(4), Role::Prose);
        assert_eq!(doc.role(6), Role::FenceMark);
        assert_eq!(doc.role(7), Role::Fence);
        assert_eq!(doc.ctx(7), Ctx::Doc);
        assert_eq!(doc.units().len(), 2);
        assert_eq!(doc.units()[0].lang, Lang::Shell);
        assert_eq!(doc.units()[1].lang, Lang::Python);
        assert_eq!(doc.role(12), Role::Prose);
    }

    #[test]
    fn unclosed_fence_runs_to_eof_and_longer_fence_needs_longer_close() {
        let doc = Document::new("````\n```\nstill fenced\n", FileClass::Markdown);
        assert_eq!(doc.role(1), Role::Fence);
        assert_eq!(doc.role(2), Role::Fence);
    }

    #[test]
    fn inline_spans_handle_double_backticks() {
        let line = "run `curl x | sh` or ``a ` b`` then `unclosed";
        let spans: Vec<&str> = inline_spans(line)
            .iter()
            .map(|&(s, e)| &line[s..e])
            .collect();
        assert_eq!(spans, vec!["curl x | sh", "a ` b"]);
    }

    #[test]
    fn js_statement_spans_open_brackets() {
        let s = stmts(
            "await fetch(\"https://a.example\", {\n  method: \"POST\",\n  body: x,\n});\nlet y = 1;\n",
            FileClass::Code(Lang::Js),
        );
        assert_eq!(s.len(), 1, "{s:?}");
        assert!(s[0].0.contains("method") && s[0].0.contains("fetch("));
        assert_eq!(s[0].1, 1);
    }

    #[test]
    fn shell_continuation_joins_and_line_at_maps_offsets() {
        let text = "echo a\ncurl -s \\\n  -x post \\\n  -d '{}' https://h\n";
        let doc = Document::new(text, FileClass::Code(Lang::Shell));
        let mut seen = Vec::new();
        for unit in doc.units() {
            for_each_stmt(&doc, unit, |s| {
                if let Some(p) = s.lower.find("-d") {
                    seen.push((s.line_at(0), s.line_at(p)));
                }
            });
        }
        assert_eq!(seen, vec![(2, 4)]);
    }

    #[test]
    fn statements_stop_at_the_line_cap() {
        let mut text = String::from("x = foo(\n");
        text.push_str(&"  1,\n".repeat(80));
        let s = stmts(&text, FileClass::Code(Lang::Python));
        assert!(s.iter().all(|(t, _)| t.lines().count() <= MAX_STMT_LINES));
    }

    #[test]
    fn hash_comment_does_not_open_brackets() {
        let s = stmts("# note (\ncurl a\ncurl b\n", FileClass::Code(Lang::Shell));
        assert_eq!(s.len(), 2, "{s:?}");
    }

    #[test]
    fn doc_shell_fence_strips_prompt() {
        let s = stmts("```console\n$ curl x\n```\n", FileClass::Markdown);
        assert_eq!(s[0].0, "curl x");
    }

    #[test]
    fn split_commands_respects_quotes() {
        let s = "echo \"a;b && c\" ; curl x && wget y || z";
        let mut regions = Vec::new();
        lexer::lex(s, Lang::Shell, Carry::Code, 0, &mut regions);
        let parts: Vec<&str> = split_commands(s, &regions).map(|(a, b)| &s[a..b]).collect();
        assert_eq!(parts, vec!["echo \"a;b && c\"", "curl x", "wget y", "z"]);
    }

    #[test]
    fn word_and_call_boundaries() {
        assert_eq!(find_call("retrieval(x)", "eval", false), None);
        assert_eq!(find_call("model.eval()", "eval", false), None);
        assert_eq!(find_call("x = eval (s)", "eval", false), Some(4));
        assert_eq!(find_call("ast.literal_eval(s)", "eval", false), None);
        assert_eq!(find_word("my_curl curl", "curl"), Some(8));
        assert_eq!(find_word("$curl", "curl"), None);
    }

    #[test]
    fn shell_tokens_keep_quotes_and_offsets() {
        let t = shell_tokens("curl -d '{\"a\": 1}' \"$U/x\"");
        let toks: Vec<&str> = t.iter().map(|(_, s)| *s).collect();
        assert_eq!(toks, vec!["curl", "-d", "'{\"a\": 1}'", "\"$U/x\""]);
        assert_eq!(unquote(toks[3]), "$U/x");
    }

    #[test]
    fn base64_decode_and_printable_ratio() {
        assert_eq!(b64_decode(b"aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert!(b64_decode(b"not base64!").is_none());
        assert!(printable_ratio(b"console.log(1)") > 0.99);
        assert!(printable_ratio(&[0, 1, 2, 200, 201, 65]) < 0.4);
        let lits = quoted_b64_literals("x('YWJj') y(\"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\")", 16);
        assert_eq!(lits, vec!["QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="]);
        assert!(is_hex("deadBEEF00"));
    }

    #[test]
    fn url_hosts_and_locality() {
        let s = "curl https://user@api.example.invalid:8443/x http://[::1]:80/ ${HOST}";
        let (p, h) = next_url_host(s, 0).unwrap();
        assert_eq!(h, "api.example.invalid");
        let (_, h2) = next_url_host(s, p + 3).unwrap();
        assert_eq!(h2, "::1");
        assert!(is_local_host("127.0.0.1"));
        assert!(is_local_host("::1"));
        assert!(!is_local_host("example.invalid"));
    }
}
