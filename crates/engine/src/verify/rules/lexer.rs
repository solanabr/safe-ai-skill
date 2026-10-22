//! Statement lexer: which bytes of a line or statement are code, and which are string literals,
//! regex literals or comments.
//!
//! Interpolations are code: JS template `${…}`, Python f-string `{…}` and shell `"$(…)"`.
//! Block comments, Python triple-quoted strings and JS template text carry from one line to the
//! next. Comment syntax per language: `//` and `/* */` for JS and Rust, `#` anywhere for Python,
//! `#` at a word start for shell and other text.

use super::context::Lang;

/// State carried from one line to the next within a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Carry {
    /// Plain code.
    #[default]
    Code,
    /// Inside `/* … */`.
    BlockComment,
    /// Inside a Python triple-quoted string (its quote byte).
    Triple(u8),
    /// Inside JS template literal text.
    Template,
}

/// One lexed line or statement.
pub(crate) struct Lexed {
    /// State after the last byte.
    pub(crate) carry: Carry,
    /// Net bracket depth change in code.
    pub(crate) delta: i32,
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Code,
    Str {
        quote: u8,
        start: usize,
        triple: bool,
        fstring: bool,
        raw: bool,
        shell_dq: bool,
    },
    Template {
        start: usize,
    },
    Line {
        start: usize,
    },
    Block {
        start: usize,
    },
    Regex {
        start: usize,
        class: bool,
    },
}

/// An open interpolation: the string mode to resume once `close` brings the depth back.
struct Frame {
    resume: Mode,
    depth: i32,
    close: u8,
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

/// The same string mode, restarted at `start` (after an interpolation closes).
fn restart(mode: Mode, start: usize) -> Mode {
    match mode {
        Mode::Str {
            quote,
            triple,
            fstring,
            raw,
            shell_dq,
            ..
        } => Mode::Str {
            quote,
            start,
            triple,
            fstring,
            raw,
            shell_dq,
        },
        Mode::Template { .. } => Mode::Template { start },
        other => other,
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

/// Lex `s` (one line, or lines joined with `\n`) starting in `carry`, appending the byte ranges
/// of literals and comments, offset by `base`, to `regions` in order.
pub(crate) fn lex(
    s: &str,
    lang: Lang,
    carry: Carry,
    base: usize,
    regions: &mut Vec<(usize, usize)>,
) -> Lexed {
    let b = s.as_bytes();
    let n = b.len();
    let slash_comments = matches!(lang, Lang::Js | Lang::Rust);
    let mut mode = match carry {
        Carry::Code => Mode::Code,
        Carry::BlockComment => Mode::Block { start: 0 },
        Carry::Triple(quote) => Mode::Str {
            quote,
            start: 0,
            triple: true,
            fstring: false,
            raw: false,
            shell_dq: false,
        },
        Carry::Template => Mode::Template { start: 0 },
    };
    let mut frames: Vec<Frame> = Vec::new();
    let mut depth = 0i32;
    let special = match lang {
        Lang::Js | Lang::Rust => &SPECIAL_SLASH,
        Lang::Python => &SPECIAL_PYTHON,
        Lang::Shell | Lang::Other => &SPECIAL_HASH,
    };
    // Cleared after an unterminated regex: that `/` was a division, and re-lexing from every
    // later `/` could go quadratic on one long line.
    let mut regex_ok = lang == Lang::Js;
    let mut i = 0;
    loop {
        while i < n {
            let c = b[i];
            match mode {
                Mode::Code => {
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
                            mode = restart(top.resume, i + 1);
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
                            mode = Mode::Str {
                                quote: c,
                                start: i,
                                triple,
                                fstring,
                                raw: raw || (lang == Lang::Shell && c == b'\''),
                                shell_dq: lang == Lang::Shell && c == b'"',
                            };
                            if triple {
                                i += 3;
                                continue;
                            }
                        }
                        b'`' => match lang {
                            Lang::Js => mode = Mode::Template { start: i },
                            // Shell backticks are command substitution: code.
                            Lang::Shell => {}
                            _ => {
                                mode = Mode::Str {
                                    quote: c,
                                    start: i,
                                    triple: false,
                                    fstring: false,
                                    raw: false,
                                    shell_dq: false,
                                }
                            }
                        },
                        b'/' if slash_comments && b.get(i + 1) == Some(&b'/') => {
                            mode = Mode::Line { start: i }
                        }
                        b'/' if slash_comments && b.get(i + 1) == Some(&b'*') => {
                            mode = Mode::Block { start: i };
                            i += 2;
                            continue;
                        }
                        b'/' if regex_ok && regex_starts(b, s, i) => {
                            mode = Mode::Regex {
                                start: i,
                                class: false,
                            }
                        }
                        b'#' if lang == Lang::Python => mode = Mode::Line { start: i },
                        b'#' if matches!(lang, Lang::Shell | Lang::Other)
                            && (i == 0 || b[i - 1].is_ascii_whitespace()) =>
                        {
                            mode = Mode::Line { start: i }
                        }
                        _ => {}
                    }
                }
                Mode::Str {
                    quote,
                    start,
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
                        i += 2;
                        continue;
                    }
                    if fstring && c == b'{' {
                        if b.get(i + 1) == Some(&b'{') {
                            i += 2;
                            continue;
                        }
                        push(regions, base, start, i);
                        frames.push(Frame {
                            resume: mode,
                            depth,
                            close: b'}',
                        });
                        depth += 1;
                        mode = Mode::Code;
                        i += 1;
                        continue;
                    }
                    if shell_dq && c == b'$' {
                        if b.get(i + 1) == Some(&b'(') {
                            push(regions, base, start, i);
                            frames.push(Frame {
                                resume: mode,
                                depth,
                                close: b')',
                            });
                            depth += 1;
                            mode = Mode::Code;
                            i += 2;
                            continue;
                        }
                    } else if c == quote {
                        if !triple {
                            push(regions, base, start, i + 1);
                            mode = Mode::Code;
                        } else if b.get(i + 1) == Some(&quote) && b.get(i + 2) == Some(&quote) {
                            push(regions, base, start, i + 3);
                            mode = Mode::Code;
                            i += 3;
                            continue;
                        }
                    } else if c == b'\n' && !triple && lang != Lang::Shell {
                        // A single-line string ends at the line end.
                        push(regions, base, start, i);
                        mode = Mode::Code;
                    }
                }
                Mode::Template { start } => {
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
                        mode = Mode::Code;
                    } else if b.get(i + 1) == Some(&b'{') {
                        push(regions, base, start, i);
                        frames.push(Frame {
                            resume: mode,
                            depth,
                            close: b'}',
                        });
                        depth += 1;
                        mode = Mode::Code;
                        i += 2;
                        continue;
                    }
                }
                Mode::Line { start } => match b[i..].iter().position(|&c| c == b'\n') {
                    Some(k) => {
                        push(regions, base, start, i + k);
                        mode = Mode::Code;
                        i += k + 1;
                        continue;
                    }
                    None => {
                        i = n;
                        continue;
                    }
                },
                Mode::Block { start } => match b[i..].windows(2).position(|w| w == b"*/") {
                    Some(k) => {
                        push(regions, base, start, i + k + 2);
                        mode = Mode::Code;
                        i += k + 2;
                        continue;
                    }
                    None => {
                        i = n;
                        continue;
                    }
                },
                Mode::Regex { start, class } => {
                    if c == b'\\' {
                        i += 2;
                        continue;
                    }
                    if c == b'[' {
                        mode = Mode::Regex { start, class: true };
                    } else if c == b']' {
                        mode = Mode::Regex {
                            start,
                            class: false,
                        };
                    } else if c == b'/' && !class {
                        let mut j = i + 1;
                        while j < n && b[j].is_ascii_alphabetic() {
                            j += 1;
                        }
                        push(regions, base, start, j);
                        mode = Mode::Code;
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
        if let Mode::Regex { start, .. } = mode {
            mode = Mode::Code;
            regex_ok = false;
            i = start + 1;
            continue;
        }
        break;
    }
    let carry = match mode {
        Mode::Code | Mode::Regex { .. } => Carry::Code,
        Mode::Str {
            quote,
            start,
            triple,
            ..
        } => {
            push(regions, base, start, n);
            if triple {
                Carry::Triple(quote)
            } else {
                Carry::Code
            }
        }
        Mode::Template { start } => {
            push(regions, base, start, n);
            Carry::Template
        }
        Mode::Line { start } => {
            push(regions, base, start, n);
            Carry::Code
        }
        Mode::Block { start } => {
            push(regions, base, start, n);
            Carry::BlockComment
        }
    };
    Lexed {
        carry: if frames.is_empty() {
            carry
        } else {
            Carry::Code
        },
        delta: depth,
    }
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
        lex(s, lang, Carry::Code, 0, &mut regions);
        in_regions(&regions, s.find(needle).unwrap())
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
        let mut regions = Vec::new();
        let first = lex("/* start", Lang::Js, Carry::Code, 0, &mut regions);
        assert_eq!(first.carry, Carry::BlockComment);
        regions.clear();
        let second = lex(
            "* eval(x) */ eval(y)",
            Lang::Js,
            first.carry,
            0,
            &mut regions,
        );
        assert_eq!(second.carry, Carry::Code);
        assert!(in_regions(&regions, 2));
        assert!(!in_regions(&regions, 13));
        regions.clear();
        // A `*`-led line outside a block comment is code.
        lex("*eval(atob(p))", Lang::Js, Carry::Code, 0, &mut regions);
        assert!(regions.is_empty());
        let doc = lex("x = '''start", Lang::Python, Carry::Code, 0, &mut regions);
        assert_eq!(doc.carry, Carry::Triple(b'\''));
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
        lex(&line, Lang::Js, Carry::Code, 0, &mut regions);
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
        assert_eq!(
            lex("foo(a, '(', {", Lang::Js, Carry::Code, 0, &mut regions).delta,
            2
        );
        assert_eq!(
            lex("}) // (", Lang::Js, Carry::Code, 0, &mut regions).delta,
            -2
        );
    }
}
