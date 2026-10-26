//! An order-preserving JSON document for settings files.
//!
//! `serde_json` here is built without `preserve_order`, so a round trip through
//! `serde_json::Value` would sort every user key. The firewall rewrites only its own entries, so
//! it keeps the user's key order and value spellings (numbers stay as written) and re-emits the
//! file with Claude Code's own two-space layout.

use std::fmt::Write;

/// Deepest nesting accepted.
const MAX_DEPTH: usize = 128;

/// A JSON value whose objects keep their key order.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number, as written.
    Num(String),
    /// A string (decoded).
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object, in file order.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// The value under `key` of an object. A duplicated key reads as its last occurrence, as
    /// Claude Code (and serde_json) read it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(entries) => entries.iter().rfind(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value under `key` of an object, mutable (the last occurrence, as [`Json::get`]).
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        match self {
            Json::Obj(entries) => entries.iter_mut().rfind(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value at a dotted path.
    pub fn at(&self, path: &str) -> Option<&Json> {
        path.split('.').try_fold(self, |node, key| node.get(key))
    }

    /// Set `key` of an object: its last occurrence replaced in place, else appended. No-op on a
    /// non-object.
    pub fn set(&mut self, key: &str, value: Json) {
        if let Json::Obj(entries) = self {
            match entries.iter_mut().rfind(|(k, _)| k == key) {
                Some((_, v)) => *v = value,
                None => entries.push((key.to_string(), value)),
            }
        }
    }

    /// Remove `key` of an object (every duplicate).
    pub fn remove(&mut self, key: &str) {
        if let Json::Obj(entries) = self {
            entries.retain(|(k, _)| k != key);
        }
    }

    /// Every prefix of `paths` (dotted) whose last key appears more than once in its object,
    /// in `paths` order without repeats. Each step descends into the last occurrence.
    pub fn duplicate_keys(&self, paths: &[&str]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for path in paths {
            let mut node = Some(self);
            let mut prefix = String::new();
            for key in path.split('.') {
                let Some(Json::Obj(entries)) = node else {
                    break;
                };
                if !prefix.is_empty() {
                    prefix.push('.');
                }
                prefix.push_str(key);
                if entries.iter().filter(|(k, _)| k == key).count() > 1 && !out.contains(&prefix) {
                    out.push(prefix.clone());
                }
                node = node.and_then(|n| n.get(key));
            }
        }
        out
    }

    /// The string elements of an array (others skipped).
    pub fn strings(&self) -> Vec<&str> {
        match self {
            Json::Arr(items) => items
                .iter()
                .filter_map(|v| match v {
                    Json::Str(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Whether this is an empty object.
    pub fn is_empty_obj(&self) -> bool {
        matches!(self, Json::Obj(e) if e.is_empty())
    }
}

/// Parse a settings file. A UTF-8 byte order mark is skipped.
pub fn parse(text: &str) -> Result<Json, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(format!("unexpected data at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.s.get(self.i) {
            self.i += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("{what} at byte {}", self.i))
    }

    fn lit(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            self.err("invalid literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return self.err("nesting too deep");
        }
        match self.s.get(self.i) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'n') => self.lit("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => self.err("expected a value"),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1;
        let mut entries = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Json::Obj(entries));
        }
        loop {
            self.ws();
            if self.s.get(self.i) != Some(&b'"') {
                return self.err("expected a key");
            }
            let key = self.string()?;
            self.ws();
            if self.s.get(self.i) != Some(&b':') {
                return self.err("expected ':'");
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            entries.push((key, v));
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(entries));
                }
                _ => return self.err("expected ',' or '}'"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return self.err("expected ',' or ']'"),
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let from = p.i;
            while let Some(b'0'..=b'9') = p.s.get(p.i) {
                p.i += 1;
            }
            p.i > from
        };
        if self.s.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        if self.s.get(self.i) == Some(&b'0') {
            self.i += 1;
        } else if !digits(self) {
            return self.err("invalid number");
        }
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !digits(self) {
                return self.err("invalid number");
            }
        }
        if let Some(b'e' | b'E') = self.s.get(self.i) {
            self.i += 1;
            if let Some(b'+' | b'-') = self.s.get(self.i) {
                self.i += 1;
            }
            if !digits(self) {
                return self.err("invalid number");
            }
        }
        // The slice is ASCII digits and signs only.
        Ok(Json::Num(
            String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
        ))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let Some(chunk) = self.s.get(self.i..self.i + 4) else {
            return self.err("truncated \\u escape");
        };
        let text = std::str::from_utf8(chunk).map_err(|_| "invalid \\u escape".to_string())?;
        let v = u32::from_str_radix(text, 16).map_err(|_| "invalid \\u escape".to_string())?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&b) = self.s.get(self.i) else {
                return self.err("unterminated string");
            };
            self.i += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let Some(&e) = self.s.get(self.i) else {
                        return self.err("unterminated escape");
                    };
                    self.i += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return self.err("unpaired surrogate");
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err("unpaired surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            match char::from_u32(code) {
                                Some(c) => c,
                                None => return self.err("invalid code point"),
                            }
                        }
                        _ => return self.err("invalid escape"),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1f => return self.err("control character in string"),
                _ => out.push(b),
            }
        }
        String::from_utf8(out).map_err(|_| "invalid UTF-8 in string".to_string())
    }
}

/// Serialize with two-space indentation and a trailing newline (the layout Claude Code writes).
pub fn to_text(v: &Json) -> String {
    to_text_with(v, "  ")
}

/// Serialize with `unit` as one level of indentation, and a trailing newline.
pub fn to_text_with(v: &Json, unit: &str) -> String {
    let mut out = String::new();
    write_value(&mut out, v, 0, unit);
    out.push('\n');
    out
}

/// The indentation unit of a pretty-printed file: the leading whitespace of its first indented
/// line (two spaces when there is none, or it is not spaces or tabs).
pub fn detect_indent(text: &str) -> String {
    text.lines()
        .map(|l| &l[..l.len() - l.trim_start_matches([' ', '\t']).len()])
        .find(|ws| !ws.is_empty())
        .filter(|ws| {
            ws.len() <= 8 && (ws.bytes().all(|b| b == b' ') || ws.bytes().all(|b| b == b'\t'))
        })
        .unwrap_or("  ")
        .to_string()
}

fn indent(out: &mut String, level: usize, unit: &str) {
    for _ in 0..level {
        out.push_str(unit);
    }
}

fn write_str(out: &mut String, s: &str) {
    match serde_json::to_string(s) {
        Ok(q) => out.push_str(&q),
        // Serializing a &str cannot fail; keep the output valid regardless.
        Err(_) => out.push_str("\"\""),
    }
}

fn write_value(out: &mut String, v: &Json, level: usize, unit: &str) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => {
            let _ = write!(out, "{b}");
        }
        Json::Num(n) => out.push_str(n),
        Json::Str(s) => write_str(out, s),
        Json::Arr(items) if items.is_empty() => out.push_str("[]"),
        Json::Arr(items) => {
            out.push_str("[\n");
            for (n, item) in items.iter().enumerate() {
                indent(out, level + 1, unit);
                write_value(out, item, level + 1, unit);
                if n + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, level, unit);
            out.push(']');
        }
        Json::Obj(entries) if entries.is_empty() => out.push_str("{}"),
        Json::Obj(entries) => {
            out.push_str("{\n");
            for (n, (k, item)) in entries.iter().enumerate() {
                indent(out, level + 1, unit);
                write_str(out, k);
                out.push_str(": ");
                write_value(out, item, level + 1, unit);
                if n + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, level, unit);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_order_and_numbers() {
        let text = "{\n  \"z\": 1.50,\n  \"a\": [\n    \"x\",\n    true\n  ],\n  \"m\": {}\n}\n";
        let v = parse(text).unwrap();
        assert_eq!(to_text(&v), text);
    }

    #[test]
    fn escapes_and_surrogates() {
        let v = parse(r#"{"k":"a\"b\\c\u00e9\ud83d\ude00\n"}"#).unwrap();
        assert_eq!(
            v.get("k"),
            Some(&Json::Str("a\"b\\c\u{e9}\u{1F600}\n".into()))
        );
        assert_eq!(parse(&to_text(&v)).unwrap(), v);
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "{",
            "{\"a\":}",
            "[1,]",
            "{\"a\":1} x",
            "01",
            "\"\\ud800\"",
            "nul",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn indent_detection() {
        assert_eq!(detect_indent("{\n    \"a\": 1\n}"), "    ");
        assert_eq!(detect_indent("{\n\t\"a\": 1\n}"), "\t");
        assert_eq!(detect_indent("{}"), "  ");
        let v = parse("{\"a\":[1]}").unwrap();
        assert_eq!(
            to_text_with(&v, "    "),
            "{\n    \"a\": [\n        1\n    ]\n}\n"
        );
    }

    #[test]
    fn duplicate_keys_read_last_and_are_reported() {
        let v = parse(
            r#"{"sandbox":{"enabled":true},"model":"a","sandbox":{"enabled":false,"x":1,"x":2},"model":"b"}"#,
        )
        .unwrap();
        assert_eq!(v.at("sandbox.enabled"), Some(&Json::Bool(false)));
        assert_eq!(
            v.duplicate_keys(&["sandbox.enabled", "sandbox.x", "permissions.deny"]),
            ["sandbox", "sandbox.x"]
        );
        let clean = parse(r#"{"sandbox":{"enabled":true},"a":1,"a":2}"#).unwrap();
        assert!(clean.duplicate_keys(&["sandbox.enabled"]).is_empty());
    }

    #[test]
    fn depth_limit() {
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert!(parse(&deep).is_err());
    }
}
