//! Statement lexer: which bytes of a line or statement are code, and which are string literals,
//! regex literals or comments.
//!
//! Interpolations are code: JS template `${…}`, Python f-string `{…}` and shell `"$(…)"`. The
//! whole state carries from one line to the next ([`Carry`]): block comments, Python
//! triple-quoted strings (f-string flag included), JS template text, strings continued by a
//! trailing backslash, and the stack of open interpolations with their bracket depth. Comment
//! syntax per language: `//` and `/* */` for JS and Rust, `#` anywhere for Python, `#` at a word
//! start for shell and other text.

use super::context::Lang;

/// What the lexer is inside of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Kind {
    #[default]
    Code,
    Str {
        quote: u8,
        triple: bool,
        fstring: bool,
        raw: bool,
        shell_dq: bool,
    },
    Template,
    Line,
    Block,
    Regex {
        class: bool,
    },
}

/// An open interpolation: the string to resume once `close` brings the depth back to `depth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Frame {
    resume: Kind,
    depth: i32,
    close: u8,
}

/// Interpolations tracked at once; deeper nesting is lexed as code (the safe side).
const MAX_FRAMES: usize = 64;

/// Lexer state carried from one line to the next within a unit: what the line ended inside
/// (a block comment, a multi-line string, template text), the open interpolations and the
/// bracket depth they are measured against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Carry {
    kind: Kind,
    frames: Vec<Frame>,
    depth: i32,
}

impl Carry {
    /// Plain code: nothing open from earlier lines.
    pub(crate) fn is_plain(&self) -> bool {
        self.kind == Kind::Code && self.frames.is_empty()
    }
}

/// Bytes that can change the lexer state in code, per language (everything else is skipped).
const fn special(bytes: &[u8]) -> [bool; 256] {
    let mut table = [false; 256];
    let mut k = 0;
    while k < bytes.len() {
        table[bytes[k] as usize] = true;
        k += 1;
    }
    table
}
const SPECIAL_SLASH: [bool; 256] = special(b"'\"`/(){}[]");
const SPECIAL_PYTHON: [bool; 256] = special(b"'\"`#(){}[]");
const SPECIAL_HASH: [bool; 256] = special(b"'\"`#(){}[]\\");

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// True when the `/` at `i` starts a JS regex literal rather than a division: it follows an
/// operator, an opening bracket, a keyword such as `return`, or nothing — not a name, a number,
/// `)`, `]` or a string.
fn regex_starts(b: &[u8], s: &str, i: usize) -> bool {
    let mut k = i;
    while k > 0 && b[k - 1].is_ascii_whitespace() {
        k -= 1;
    }
    let Some(&p) = k.checked_sub(1).and_then(|j| b.get(j)) else {
        return true;
    };
    if is_word_byte(p) {
        let mut w = k - 1;
        while w > 0 && is_word_byte(b[w - 1]) {
            w -= 1;
        }
        return REGEX_KEYWORDS.contains(&&s[w..k]);
    }
    !matches!(p, b')' | b']' | b'\'' | b'"' | b'`')
}

/// Keywords after which `/` starts a regex literal.
const REGEX_KEYWORDS: &[&str] = &[
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
];

fn push(regions: &mut Vec<(usize, usize)>, base: usize, from: usize, to: usize) {
    if to > from {
        regions.push((base + from, base + to));
    }
}

/// `(f-string, raw)` from the Python prefix letters right before the quote at `q`.
fn python_prefix(b: &[u8], q: usize) -> (bool, bool) {
    let mut k = q;
    while k > 0
        && q - k < 2
        && matches!(
            b[k - 1],
            b'r' | b'f' | b'b' | b'u' | b'R' | b'F' | b'B' | b'U'
        )
    {
        k -= 1;
    }
    if k == q || (k > 0 && (b[k - 1].is_ascii_alphanumeric() || b[k - 1] == b'_')) {
        return (false, false);
    }
    let prefix = &b[k..q];
    (
        prefix.iter().any(|c| matches!(c, b'f' | b'F')),
        prefix.iter().any(|c| matches!(c, b'r' | b'R')),
    )
}

/// End of a Rust char literal starting at `q` (`'x'`, `'\n'`, `'\u{1F600}'`); `None` for a
/// lifetime such as `'a`.
fn rust_char_end(b: &[u8], q: usize) -> Option<usize> {
    let mut j = q + 1;
    if *b.get(j)? == b'\\' {
        j += 2;
        while j < b.len() && j <= q + 12 && b[j] != b'\'' {
            j += 1;
        }
    } else {
        j += 1;
        while j < b.len() && (b[j] & 0xC0) == 0x80 {
            j += 1;
        }
    }
    (b.get(j) == Some(&b'\'')).then_some(j)
}

/// Enter an interpolation from string kind `resume`: code until `close` brings the depth back.
fn open_frame(frames: &mut Vec<Frame>, depth: &mut i32, resume: Kind, close: u8) {
    if frames.len() < MAX_FRAMES {
        frames.push(Frame {
            resume,
            depth: *depth,
            close,
        });
    }
    *depth += 1;
}

/// Lex `s` (one line, or lines joined with `\n`) starting from `carry`, which is updated to the
/// state after the last byte. Appends the byte ranges of literals and comments, offset by `base`,
/// to `regions` in order, and returns the net bracket depth change in code.
pub(crate) fn lex(
    s: &str,
    lang: Lang,
    carry: &mut Carry,
    base: usize,
    regions: &mut Vec<(usize, usize)>,
) -> i32 {
    let b = s.as_bytes();
    let n = b.len();
    let slash_comments = matches!(lang, Lang::Js | Lang::Rust);
    let special = match lang {
        Lang::Js | Lang::Rust => &SPECIAL_SLASH,
        Lang::Python => &SPECIAL_PYTHON,
        Lang::Shell | Lang::Other => &SPECIAL_HASH,
    };
    let start_depth = carry.depth;
    let mut depth = carry.depth;
    let frames = &mut carry.frames;
    let mut kind = carry.kind;
    // Where the current literal or comment began in `s`.
    let mut start = 0;
    // A string whose last byte is an escaping backslash continues on the next line.
    let mut continued = false;
    // Cleared after an unterminated regex: that `/` was a division, and re-lexing from every
    // later `/` could go quadratic on one long line.
    let mut regex_ok = lang == Lang::Js;
    let mut i = 0;
    loop {
        while i < n {
            let c = b[i];
            match kind {
                Kind::Code => {
                    if !special[usize::from(c)] {
                        i += 1;
                        while i < n && !special[usize::from(b[i])] {
                            i += 1;
                        }
                        continue;
                    }
                    if let Some(top) = frames.last() {
                        if c == top.close && depth == top.depth + 1 {
                            depth = top.depth;
                            kind = top.resume;
                            start = i + 1;
                            frames.pop();
                            i += 1;
                            continue;
                        }
                    }
                    match c {
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' | b']' | b'}' => depth -= 1,
                        // Shell and other text: an escaped byte is not syntax (`it\'s`).
                        b'\\' => {
                            i += 2;
                            continue;
                        }
                        b'\'' if lang == Lang::Rust => {
                            if let Some(end) = rust_char_end(b, i) {
                                push(regions, base, i, end + 1);
                                i = end + 1;
                                continue;
                            }
                        }
                        b'"' | b'\'' => {
                            let triple = lang == Lang::Python
                                && b.get(i + 1) == Some(&c)
                                && b.get(i + 2) == Some(&c);
                            let (fstring, raw) = if lang == Lang::Python {
                                python_prefix(b, i)
                            } else {
                                (false, false)
                            };
                            kind = Kind::Str {
                                quote: c,
                                triple,
                                fstring,
                                raw: raw || (lang == Lang::Shell && c == b'\''),
                                shell_dq: lang == Lang::Shell && c == b'"',
                            };
                            start = i;
                            if triple {
                                i += 3;
                                continue;
                            }
                        }
                        b'`' => match lang {
                            Lang::Js => {
                                kind = Kind::Template;
                                start = i;
                            }
                            // Shell backticks are command substitution: code.
                            Lang::Shell => {}
                            _ => {
                                kind = Kind::Str {
                                    quote: c,
                                    triple: false,
                                    fstring: false,
                                    raw: false,
                                    shell_dq: false,
                                };
                                start = i;
                            }
                        },
                        b'/' if slash_comments && b.get(i + 1) == Some(&b'/') => {
                            kind = Kind::Line;
                            start = i;
                        }
                        b'/' if slash_comments && b.get(i + 1) == Some(&b'*') => {
                            kind = Kind::Block;
                            start = i;
                            i += 2;
                            continue;
                        }
                        b'/' if regex_ok && regex_starts(b, s, i) => {
                            kind = Kind::Regex { class: false };
                            start = i;
                        }
                        b'#' if lang == Lang::Python => {
                            kind = Kind::Line;
                            start = i;
                        }
                        b'#' if matches!(lang, Lang::Shell | Lang::Other)
                            && (i == 0 || b[i - 1].is_ascii_whitespace()) =>
                        {
                            kind = Kind::Line;
                            start = i;
                        }
                        _ => {}
                    }
                }
                Kind::Str {
                    quote,
                    triple,
                    fstring,
                    raw,
                    shell_dq,
                } => {
                    let stop = |c: u8| {
                        c == quote
                            || c == b'\n'
                            || (c == b'\\' && !raw)
                            || (fstring && c == b'{')
                            || (shell_dq && c == b'$')
                    };
                    if !stop(c) {
                        i += 1;
                        while i < n && !stop(b[i]) {
                            i += 1;
                        }
                        continue;
                    }
                    if c == b'\\' {
                        continued = i + 1 == n;
                        i += 2;
                        continue;
                    }
                    if fstring && c == b'{' {
                        if b.get(i + 1) == Some(&b'{') {
                            i += 2;
                            continue;
                        }
                        push(regions, base, start, i);
                        open_frame(frames, &mut depth, kind, b'}');
                        kind = Kind::Code;
                        i += 1;
                        continue;
                    }
                    if shell_dq && c == b'$' {
                        if b.get(i + 1) == Some(&b'(') {
                            push(regions, base, start, i);
                            open_frame(frames, &mut depth, kind, b')');
                            kind = Kind::Code;
                            i += 2;
                            continue;
                        }
                    } else if c == quote {
                        if !triple {
                            push(regions, base, start, i + 1);
                            kind = Kind::Code;
                        } else if b.get(i + 1) == Some(&quote) && b.get(i + 2) == Some(&quote) {
                            push(regions, base, start, i + 3);
                            kind = Kind::Code;
                            i += 3;
                            continue;
                        }
                    } else if c == b'\n' && !triple && lang != Lang::Shell {
                        // A single-line string ends at the line end.
                        push(regions, base, start, i);
                        kind = Kind::Code;
                    }
                }
                Kind::Template => {
                    if !matches!(c, b'\\' | b'`' | b'$') {
                        i += 1;
                        while i < n && !matches!(b[i], b'\\' | b'`' | b'$') {
                            i += 1;
                        }
                        continue;
                    }
                    if c == b'\\' {
                        i += 2;
                        continue;
                    }
                    if c == b'`' {
                        push(regions, base, start, i + 1);
                        kind = Kind::Code;
                    } else if b.get(i + 1) == Some(&b'{') {
                        push(regions, base, start, i);
                        open_frame(frames, &mut depth, Kind::Template, b'}');
                        kind = Kind::Code;
                        i += 2;
                        continue;
                    }
                }
                Kind::Line => match b[i..].iter().position(|&c| c == b'\n') {
                    Some(k) => {
                        push(regions, base, start, i + k);
                        kind = Kind::Code;
                        i += k + 1;
                        continue;
                    }
                    None => {
                        i = n;
                        continue;
                    }
                },
                Kind::Block => match b[i..].windows(2).position(|w| w == b"*/") {
                    Some(k) => {
                        push(regions, base, start, i + k + 2);
                        kind = Kind::Code;
                        i += k + 2;
                        continue;
                    }
                    None => {
                        i = n;
                        continue;
                    }
                },
                Kind::Regex { class } => {
                    if c == b'\\' {
                        i += 2;
                        continue;
                    }
                    if c == b'[' {
                        kind = Kind::Regex { class: true };
                    } else if c == b']' {
                        kind = Kind::Regex { class: false };
                    } else if c == b'/' && !class {
                        let mut j = i + 1;
                        while j < n && b[j].is_ascii_alphabetic() {
                            j += 1;
                        }
                        push(regions, base, start, j);
                        kind = Kind::Code;
                        i = j;
                        continue;
                    } else if c == b'\n' {
                        break;
                    }
                }
            }
            i += 1;
        }
        // An unterminated regex was a division: resume as code after its `/`.
        if let Kind::Regex { .. } = kind {
            kind = Kind::Code;
            regex_ok = false;
            i = start + 1;
            continue;
        }
        break;
    }
    if kind != Kind::Code {
        push(regions, base, start, n);
    }
    carry.kind = match kind {
        Kind::Str { triple, .. } if triple || continued => kind,
        Kind::Template | Kind::Block => kind,
        _ => Kind::Code,
    };
    carry.depth = depth;
    depth - start_depth
}

/// True when byte `off` lies in one of the sorted `regions`.
pub(crate) fn in_regions(regions: &[(usize, usize)], off: usize) -> bool {
    let k = regions.partition_point(|&(start, _)| start <= off);
    k > 0 && off < regions[k - 1].1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted(s: &str, lang: Lang, needle: &str) -> bool {
        let mut regions = Vec::new();
        lex(s, lang, &mut Carry::default(), 0, &mut regions);
        in_regions(&regions, s.find(needle).unwrap())
    }

    /// Lex `text` line by line with a carried state; true when `needle` (first occurrence, in
    /// the line holding it) is inside a literal or comment.
    fn quoted_lines(text: &str, lang: Lang, needle: &str) -> bool {
        let mut carry = Carry::default();
        for line in text.split('\n') {
            let mut regions = Vec::new();
            lex(line, lang, &mut carry, 0, &mut regions);
            if let Some(p) = line.find(needle) {
                return in_regions(&regions, p);
            }
        }
        panic!("{needle} not in {text}");
    }

    #[test]
    fn strings_and_comments_are_regions() {
        assert!(quoted("x = 'eval(a)'; y()", Lang::Js, "eval"));
        assert!(!quoted("x = 'a'; eval(y)", Lang::Js, "eval"));
        assert!(quoted("// eval(x)", Lang::Js, "eval"));
        assert!(quoted("x = 1 # eval(x)", Lang::Python, "eval"));
        assert!(quoted("x=1#eval(x)", Lang::Python, "eval"));
        assert!(!quoted("echo a#b; eval x", Lang::Shell, "eval"));
        assert!(quoted("echo 'eval x'", Lang::Shell, "eval"));
    }

    #[test]
    fn interpolations_are_code() {
        assert!(!quoted("const r = `${eval(atob(p))}`;", Lang::Js, "eval"));
        assert!(quoted("const r = `eval(${x})`;", Lang::Js, "eval"));
        assert!(!quoted(
            "r = f\"{exec(b64decode(p))}\"",
            Lang::Python,
            "exec"
        ));
        assert!(quoted("r = f\"exec({x})\"", Lang::Python, "exec"));
        assert!(quoted("r = \"{exec(x)}\"", Lang::Python, "exec"));
        assert!(!quoted("echo \"$(curl x | sh)\"", Lang::Shell, "curl"));
        assert!(quoted("r = f\"{{exec(x)}}\"", Lang::Python, "exec"));
    }

    #[test]
    fn js_regex_literals_do_not_open_strings() {
        assert!(!quoted("/'/; eval(atob(p))", Lang::Js, "eval"));
        assert!(!quoted("const n = a / b; eval(x) / 2", Lang::Js, "eval"));
        assert!(quoted("if (/eval\\(/.test(s)) {}", Lang::Js, "eval"));
    }

    #[test]
    fn block_comments_and_triple_quotes_carry_across_lines() {
        assert!(quoted_lines("/* start\n* eval(x) */", Lang::Js, "eval"));
        assert!(!quoted_lines("/* start\n*/ eval(y)", Lang::Js, "eval"));
        // A `*`-led line outside a block comment is code.
        assert!(!quoted_lines("x = 1\n*eval(atob(p))", Lang::Js, "eval"));
        assert!(quoted_lines(
            "x = '''start\neval(x)\n'''",
            Lang::Python,
            "eval"
        ));
    }

    #[test]
    fn interpolation_frames_carry_across_lines() {
        // A line ending inside `${` keeps the frame: the next line closes it, the template ends.
        assert!(!quoted_lines(
            "const r = `${\n0}`;\neval(atob(s));",
            Lang::Js,
            "eval"
        ));
        assert!(!quoted_lines(
            "const r = `${\n0}`; eval(atob(s));",
            Lang::Js,
            "eval"
        ));
        assert!(quoted_lines(
            "const r = `${\n0} eval(x)`;",
            Lang::Js,
            "eval"
        ));
        // Triple-quoted f-strings keep their f flag across lines.
        assert!(!quoted_lines(
            "r = f\"\"\"\n{exec(x)}\n\"\"\"",
            Lang::Python,
            "exec"
        ));
        assert!(quoted_lines(
            "r = \"\"\"\n{exec(x)}\n\"\"\"",
            Lang::Python,
            "exec"
        ));
        assert!(!quoted_lines(
            "r = f\"\"\"{\n0}\"\"\"\nexec(base64.b64decode(s))",
            Lang::Python,
            "exec"
        ));
        assert!(!quoted_lines(
            "r = f'{\n0}'\nexec(base64.b64decode(s))",
            Lang::Python,
            "exec"
        ));
        assert!(!quoted_lines(
            "x=\"$(\necho hi)\"; curl -s x | sh",
            Lang::Shell,
            "curl"
        ));
        // A backslash-continued string continues; the code after its end is code.
        assert!(!quoted_lines("s = \"abc\\\n\"; eval(x)", Lang::Js, "eval"));
    }

    #[test]
    fn deep_nesting_is_bounded_and_lexed_as_code() {
        let deep = format!("{}eval(x){}", "`${".repeat(200), "}`".repeat(200));
        assert!(!quoted(&deep, Lang::Js, "eval"));
        let mut carry = Carry::default();
        let mut regions = Vec::new();
        lex(
            &"`${".repeat(100_000),
            Lang::Js,
            &mut carry,
            0,
            &mut regions,
        );
        assert!(carry.frames.len() <= MAX_FRAMES);
    }

    #[test]
    fn escapes_and_unterminated_regexes() {
        assert!(!quoted("echo it\\'s; eval x", Lang::Shell, "eval"));
        // `/ 2` opening a line is a division: the quote after it still opens a string.
        assert!(quoted("/ 2; x = 'eval(y)'", Lang::Js, "eval"));
        assert!(!quoted("/[x; eval(y)", Lang::Js, "eval"));
        let line = "(/[".repeat(100_000);
        let mut regions = Vec::new();
        let started = std::time::Instant::now();
        lex(&line, Lang::Js, &mut Carry::default(), 0, &mut regions);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn rust_lifetimes_are_not_strings() {
        assert!(!quoted(
            "fn f<'a>(x: &'a str) { eval(x) }",
            Lang::Rust,
            "eval"
        ));
        assert!(quoted("let c = 'e'; let s = \"eval\";", Lang::Rust, "eval"));
    }

    #[test]
    fn bracket_delta_counts_code_only() {
        let mut regions = Vec::new();
        let mut carry = Carry::default();
        assert_eq!(
            lex("foo(a, '(', {", Lang::Js, &mut carry, 0, &mut regions),
            2
        );
        assert_eq!(lex("}) // (", Lang::Js, &mut carry, 0, &mut regions), -2);
        assert!(carry.is_plain());
    }
}
