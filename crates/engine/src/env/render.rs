//! Masked display of env values: everything `env` prints about a value goes through here.
//!
//! Values are never printed. The only verbatim output is a closed allowlist of non-secret words
//! (booleans, cluster monikers, environment names, log levels) and integers of at most five
//! digits. URLs show `scheme://host/…`, placeholders `placeholder`, anything else `set len=N`,
//! plus `fp=<first 6 hex of sha256>` when N ≥ 16 (a hash of a shorter value is guessable).

use std::collections::HashMap;
use std::fmt;

use serde_json::{json, Map, Value};

use crate::audit::sha256_hex;
use crate::env::parse::{Entry, EnvFile, ItemKind};
use crate::env::schema::Schema;

/// Values at least this long get a fingerprint.
const FP_MIN_LEN: usize = 16;

/// Non-secret words shown verbatim (matched case-insensitively).
const VERBATIM: &[&str] = &[
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "devnet",
    "testnet",
    "mainnet-beta",
    "mainnet",
    "localnet",
    "localhost",
    "development",
    "production",
    "test",
    "debug",
    "info",
    "warn",
    "error",
];

/// How a value is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    Empty,
    Placeholder,
    Verbatim(String),
    Url {
        scheme: String,
        host: String,
        fp: Option<String>,
    },
    Set {
        len: usize,
        fp: Option<String>,
    },
}

impl Shown {
    pub fn of(value: &[u8]) -> Self {
        if value.is_empty() {
            return Shown::Empty;
        }
        if let Some(word) = verbatim(value) {
            return Shown::Verbatim(word);
        }
        if is_placeholder(value) {
            return Shown::Placeholder;
        }
        let fp = (value.len() >= FP_MIN_LEN).then(|| fingerprint(value));
        match url_parts(value) {
            Some((scheme, host)) => Shown::Url { scheme, host, fp },
            None => Shown::Set {
                len: value.len(),
                fp,
            },
        }
    }

    /// The `status` field of `env keys --json`.
    pub fn status(&self) -> &'static str {
        match self {
            Shown::Empty => "empty",
            Shown::Placeholder => "placeholder",
            Shown::Verbatim(_) => "verbatim",
            Shown::Url { .. } => "url",
            Shown::Set { .. } => "set",
        }
    }

    /// The host of a URL value.
    pub fn host(&self) -> Option<&str> {
        match self {
            Shown::Url { host, .. } => Some(host),
            _ => None,
        }
    }
}

impl fmt::Display for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp = match self {
            Shown::Empty => return f.write_str("empty"),
            Shown::Placeholder => return f.write_str("placeholder"),
            Shown::Verbatim(word) => return f.write_str(word),
            Shown::Url { scheme, host, fp } => {
                write!(f, "set url={scheme}://{host}/…")?;
                fp
            }
            Shown::Set { len, fp } => {
                write!(f, "set len={len}")?;
                fp
            }
        };
        match fp {
            Some(fp) => write!(f, " fp={fp}"),
            None => Ok(()),
        }
    }
}

/// First 6 hex chars of the value's sha256.
pub fn fingerprint(value: &[u8]) -> String {
    let mut hex = sha256_hex(value);
    hex.truncate(6);
    hex
}

fn verbatim(value: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    let small_int = (1..=5).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit());
    let word = VERBATIM.iter().any(|w| w.eq_ignore_ascii_case(text));
    (small_int || word).then(|| text.to_string())
}

/// Placeholder values: `<…>`, `your-*-here`, `xxx…`, `changeme`, `TODO`. An empty value is
/// reported as `empty` instead (checked first).
fn is_placeholder(value: &[u8]) -> bool {
    let lower = value.to_ascii_lowercase();
    let angle = lower.len() >= 3 && lower.first() == Some(&b'<') && lower.last() == Some(&b'>');
    let your_here = ["your-", "your_", "your "]
        .iter()
        .any(|p| lower.starts_with(p.as_bytes()))
        && ["-here", "_here", " here"]
            .iter()
            .any(|s| lower.ends_with(s.as_bytes()));
    let core: Vec<u8> = lower
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'-' | b'_' | b'.'))
        .collect();
    let xs = core.len() >= 3 && core.iter().all(|&b| b == b'x');
    let word = matches!(
        lower.as_slice(),
        b"changeme" | b"change-me" | b"change_me" | b"todo"
    );
    angle || your_here || xs || word
}

/// Lowercased `(scheme, host)` of a URL value. Userinfo and port are dropped. `None` unless
/// the host is a dotted name, `localhost` or a bracketed IPv6 address, so a token after `://`
/// (or a malformed userinfo) is never mistaken for a host and printed. `None` too when an `@`
/// follows the first `/`, `?` or `#`: the userinfo may contain that delimiter
/// (`https://user:pa?ss@host`), and the text before it would be shown as the host.
fn url_parts(value: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(value).ok()?;
    let (scheme, rest) = text.split_once("://")?;
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes.next()?.is_ascii_alphabetic()
        || !scheme_bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
    {
        return None;
    }
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    if tail.contains('@') {
        return None;
    }
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(inner) = host_port.strip_prefix('[') {
        let (addr, _) = inner.split_once(']')?;
        let valid = !addr.is_empty()
            && addr
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        if !valid {
            return None;
        }
        format!("[{addr}]")
    } else {
        let name = host_port.split(':').next()?;
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && (name.contains('.') || name.eq_ignore_ascii_case("localhost"));
        if !valid {
            return None;
        }
        name.to_string()
    };
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// Why a `--require`d key is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmet {
    Missing,
    Empty,
    Placeholder,
}

impl Unmet {
    pub fn label(self) -> &'static str {
        match self {
            Unmet::Missing => "missing",
            Unmet::Empty => "empty",
            Unmet::Placeholder => "placeholder",
        }
    }
}

/// The `required` keys whose effective (last) assignment is missing, empty or a placeholder.
/// A commented-out key counts as missing.
pub fn unmet(file: &EnvFile, required: &[String]) -> Vec<(String, Unmet)> {
    required
        .iter()
        .filter_map(|key| {
            let reason = match file.entries().filter(|(_, e)| &e.key == key).last() {
                None => Unmet::Missing,
                Some((_, entry)) => match Shown::of(&entry.value) {
                    Shown::Empty => Unmet::Empty,
                    Shown::Placeholder => Unmet::Placeholder,
                    _ => return None,
                },
            };
            Some((key.clone(), reason))
        })
        .collect()
}

/// `KEY (reason), …` for the stderr summary of `--require`.
pub fn unmet_text(unmet: &[(String, Unmet)]) -> String {
    unmet
        .iter()
        .map(|(key, reason)| format!("{key} ({})", reason.label()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// How a value changed, for `env set` reports: `fp 3f9a1c→9b0e77` when both sides carry a
/// fingerprint, `<old>→<new>` displays otherwise.
pub fn change(old: &[u8], new: &[u8]) -> String {
    let (old, new) = (Shown::of(old), Shown::of(new));
    match (&old, &new) {
        (Shown::Set { fp: Some(a), .. }, Shown::Set { fp: Some(b), .. }) => {
            format!("fp {a}→{b}")
        }
        _ => format!("{old}→{new}"),
    }
}

/// Annotation for a key assigned more than once (the last assignment wins).
#[derive(Debug, Clone, Copy)]
enum Dup {
    Wins,
    OverriddenBy(usize),
}

/// One listed line: an assignment, or a commented key (`entry: None`).
struct Row<'a> {
    line: usize,
    key: &'a str,
    entry: Option<&'a Entry>,
    dup: Option<Dup>,
}

/// Listed rows in file order, and the number of distinct assigned keys.
fn rows(file: &EnvFile) -> (Vec<Row<'_>>, usize) {
    let mut last: HashMap<&str, (usize, usize)> = HashMap::new();
    for (line, entry) in file.entries() {
        let slot = last.entry(entry.key.as_str()).or_insert((line, 0));
        slot.0 = line;
        slot.1 += 1;
    }
    let rows = file
        .items
        .iter()
        .filter_map(|item| match &item.kind {
            ItemKind::Entry(entry) => {
                let (winner, count) = last
                    .get(entry.key.as_str())
                    .copied()
                    .unwrap_or((item.line, 1));
                let dup = (count > 1).then_some(if winner == item.line {
                    Dup::Wins
                } else {
                    Dup::OverriddenBy(winner)
                });
                Some(Row {
                    line: item.line,
                    key: &entry.key,
                    entry: Some(entry),
                    dup,
                })
            }
            ItemKind::Commented(key) => Some(Row {
                line: item.line,
                key,
                entry: None,
                dup: None,
            }),
            ItemKind::Verbatim => None,
        })
        .collect();
    (rows, last.len())
}

/// A `.env.schema` found beside the listed file, and how messages name it.
#[derive(Clone, Copy)]
pub struct SchemaView<'a> {
    pub label: &'a str,
    pub schema: &'a Schema,
}

impl SchemaView<'_> {
    /// `[sensitive required type=url]`, `[undeclared]`, or empty when there is nothing to say.
    fn annotation(&self, key: &str) -> String {
        if self.schema.item(key).is_none() {
            return "[undeclared]".into();
        }
        let mut parts = Vec::new();
        if self.schema.is_sensitive(key) {
            parts.push("sensitive".to_string());
        }
        if self.schema.is_required(key) == Some(true) {
            parts.push("required".to_string());
        }
        if let Some(ty) = self.schema.item(key).and_then(|i| i.type_name()) {
            parts.push(format!("type={ty}"));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("[{}]", parts.join(" "))
        }
    }

    /// Declared keys with no assignment in `file`, in schema order.
    fn declared_unset<'s>(&'s self, file: &EnvFile) -> Vec<&'s str> {
        self.schema
            .items
            .iter()
            .map(|i| i.key.as_str())
            .filter(|key| !file.entries().any(|(_, e)| e.key == *key))
            .collect()
    }

    fn json(&self, key: &str) -> Value {
        match self.schema.item(key) {
            None => json!({ "declared": false }),
            Some(item) => json!({
                "declared": true,
                "sensitive": self.schema.is_sensitive(key),
                "required": self.schema.is_required(key),
                "type": item.type_name(),
            }),
        }
    }
}

/// `env keys` text output: a header, then one aligned row per assignment or commented key.
pub fn keys_text(label: &str, file: &EnvFile) -> String {
    keys_text_with(label, file, None)
}

/// [`keys_text`] with schema annotations: each assigned key gets its `sensitive` / `required`
/// / `type` tags or `[undeclared]`, and a footer lists declared keys the file does not set.
pub fn keys_text_with(label: &str, file: &EnvFile, schema: Option<SchemaView<'_>>) -> String {
    let (rows, keys) = rows(file);
    let mut out = format!("# {label} keys={keys} crlf={}", file.crlf().label());
    if file.bom {
        out.push_str(" bom=yes");
    }
    if let Some(view) = schema {
        out.push_str(&format!(" schema={}", view.label));
    }
    out.push('\n');
    let cells: Vec<(String, String, String)> = rows
        .iter()
        .map(|row| {
            let (key, shown) = match row.entry {
                Some(entry) => (row.key.to_string(), Shown::of(&entry.value).to_string()),
                None => (format!("#{}", row.key), "commented".to_string()),
            };
            (format!("L{}", row.line), key, shown)
        })
        .collect();
    let label_width = cells.iter().map(|c| c.0.len()).max().unwrap_or(0);
    let key_width = cells.iter().map(|c| c.1.len()).max().unwrap_or(0);
    for ((line, key, shown), row) in cells.iter().zip(&rows) {
        out.push_str(&format!(
            "{line:<label_width$}   {key:<key_width$}   {shown}"
        ));
        match row.dup {
            Some(Dup::Wins) => out.push_str("   (duplicate; this line wins)"),
            Some(Dup::OverriddenBy(winner)) => {
                out.push_str(&format!("   (duplicate; overridden by L{winner})"))
            }
            None => {}
        }
        if let (Some(view), Some(_)) = (schema, row.entry) {
            let note = view.annotation(row.key);
            if !note.is_empty() {
                out.push_str("   ");
                out.push_str(&note);
            }
        }
        out.push('\n');
    }
    if rows.iter().any(|r| r.dup.is_some()) {
        out.push_str(
            "# duplicates: dotenv loaders and `source` use the last assignment; dotenvy (Rust) keeps the first\n",
        );
    }
    if let Some(view) = schema {
        let unset = view.declared_unset(file);
        if !unset.is_empty() {
            let list: Vec<String> = unset
                .iter()
                .map(|key| match view.schema.is_required(key) {
                    Some(true) => format!("{key} (required)"),
                    _ => (*key).to_string(),
                })
                .collect();
            out.push_str(&format!(
                "# declared in {} but unset: {}\n",
                view.label,
                list.join(", ")
            ));
        }
    }
    out
}

/// `env keys --json` output. `require` adds the `--require` verdict.
pub fn keys_json(label: &str, file: &EnvFile, require: Option<&[(String, Unmet)]>) -> Value {
    keys_json_with(label, file, require, None)
}

/// [`keys_json`] with schema fields: `schema` (file label), a `schema` object per assigned key
/// and `declared_unset`.
pub fn keys_json_with(
    label: &str,
    file: &EnvFile,
    require: Option<&[(String, Unmet)]>,
    schema: Option<SchemaView<'_>>,
) -> Value {
    let (rows, _) = rows(file);
    let keys: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut v = row_json(row);
            if let (Some(view), Some(_)) = (schema, row.entry) {
                v["schema"] = view.json(row.key);
            }
            v
        })
        .collect();
    let mut out = json!({
        "file": label,
        "format": file.format.label(),
        "crlf": file.crlf().label(),
        "bom": file.bom,
        "keys": keys,
    });
    if let Some(unmet) = require {
        let unmet: Vec<Value> = unmet
            .iter()
            .map(|(key, reason)| json!({ "key": key, "reason": reason.label() }))
            .collect();
        out["require"] = json!({ "ok": unmet.is_empty(), "unmet": unmet });
    }
    if let Some(view) = schema {
        out["schema"] = json!(view.label);
        let unset: Vec<Value> = view
            .declared_unset(file)
            .into_iter()
            .map(|key| {
                json!({
                    "key": key,
                    "required": view.schema.is_required(key),
                    "sensitive": view.schema.is_sensitive(key),
                })
            })
            .collect();
        out["declared_unset"] = Value::Array(unset);
    }
    out
}

fn row_json(row: &Row<'_>) -> Value {
    let mut obj = Map::new();
    obj.insert("line".into(), json!(row.line));
    obj.insert("key".into(), json!(row.key));
    let Some(entry) = row.entry else {
        obj.insert("status".into(), json!("commented"));
        obj.insert("display".into(), json!("commented"));
        return Value::Object(obj);
    };
    let shown = Shown::of(&entry.value);
    obj.insert("status".into(), json!(shown.status()));
    obj.insert("display".into(), json!(shown.to_string()));
    match &shown {
        Shown::Set { len, fp } => {
            obj.insert("len".into(), json!(len));
            if let Some(fp) = fp {
                obj.insert("fp".into(), json!(fp));
            }
        }
        Shown::Url { scheme, host, fp } => {
            obj.insert("url".into(), json!(format!("{scheme}://{host}/…")));
            if let Some(fp) = fp {
                obj.insert("fp".into(), json!(fp));
            }
        }
        Shown::Verbatim(word) => {
            obj.insert("value".into(), json!(word));
        }
        Shown::Empty | Shown::Placeholder => {}
    }
    obj.insert("export".into(), json!(entry.export));
    obj.insert("quote".into(), json!(entry.quote.label()));
    match row.dup {
        Some(Dup::Wins) => {
            obj.insert("duplicate".into(), json!("wins"));
        }
        Some(Dup::OverriddenBy(winner)) => {
            obj.insert("duplicate".into(), json!("overridden"));
            obj.insert("overridden_by".into(), json!(winner));
        }
        None => {}
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::testgen::{self, Lcg};

    fn shown(v: &str) -> String {
        Shown::of(v.as_bytes()).to_string()
    }

    fn fp(v: &str) -> String {
        fingerprint(v.as_bytes())
    }

    #[test]
    fn verbatim_only_for_the_allowlist() {
        for word in [
            "true",
            "false",
            "yes",
            "no",
            "on",
            "off",
            "devnet",
            "testnet",
            "mainnet-beta",
            "mainnet",
            "localnet",
            "localhost",
            "development",
            "production",
            "test",
            "debug",
            "info",
            "warn",
            "error",
            "TRUE",
            "Devnet",
            "0",
            "8899",
            "12345",
        ] {
            assert_eq!(shown(word), word);
        }
        assert_eq!(shown("123456"), "set len=6");
        assert_eq!(shown("-1"), "set len=2");
        assert_eq!(shown("1.5"), "set len=3");
        assert_eq!(shown("trueish"), "set len=7");
        assert_eq!(shown("confirmed"), "set len=9");
        assert_eq!(shown(" devnet"), "set len=7");
    }

    #[test]
    fn empty_and_placeholders() {
        assert_eq!(shown(""), "empty");
        for p in [
            "your-api-key-here",
            "YOUR_KEY_HERE",
            "your key here",
            "<token>",
            "<paste key>",
            "xxx",
            "XXXX-XXXX",
            "xxxxxxxx",
            "x.x.x",
            "changeme",
            "Change-Me",
            "change_me",
            "TODO",
            "todo",
        ] {
            assert_eq!(shown(p), "placeholder", "{p}");
        }
        for not in [
            "xx", "your-key", "here", "<abc", "abc>", "todos", "xxxa", "yourhere", "<>",
        ] {
            assert_ne!(shown(not), "placeholder", "{not}");
        }
    }

    #[test]
    fn urls_show_scheme_and_host_only() {
        let helius = "https://mainnet.helius-rpc.com/?api-key=0b1c2d3e";
        assert_eq!(
            shown(helius),
            format!("set url=https://mainnet.helius-rpc.com/… fp={}", fp(helius))
        );
        let pg = "postgres://admin:pw@db.internal:5432/app";
        assert_eq!(
            shown(pg),
            format!("set url=postgres://db.internal/… fp={}", fp(pg))
        );
        let local = "http://localhost:8899";
        assert_eq!(
            shown(local),
            format!("set url=http://localhost/… fp={}", fp(local))
        );
        assert_eq!(shown("ws://[::1]:8900"), "set url=ws://[::1]/…");
        let mixed = "HTTPS://API.Devnet.Solana.COM";
        assert_eq!(
            shown(mixed),
            format!("set url=https://api.devnet.solana.com/… fp={}", fp(mixed))
        );
        let srv = "mongodb+srv://u:p@cluster0.ab1cd.mongodb.net/db";
        assert_eq!(
            shown(srv),
            format!(
                "set url=mongodb+srv://cluster0.ab1cd.mongodb.net/… fp={}",
                fp(srv)
            )
        );
        // Hosts without a dot are not trusted to be hosts (a bare token, a malformed userinfo).
        let token = "redis://SECRETTOKEN";
        assert_eq!(shown(token), format!("set len=19 fp={}", fp(token)));
        let userinfo = "https://user:p/ss@host.io/x";
        assert_eq!(
            shown(userinfo),
            format!("set len={} fp={}", userinfo.len(), fp(userinfo))
        );
        // An `@` after the first `/?#` means the userinfo may hold one of them: no host shown.
        for ambiguous in [
            "https://alice.smith:s3cr?et@db.example.com",
            "https://alice.smith:pa#ss@db.example.com/x",
            "https://host.example.com/users/@alice",
            "https://api.example.com/?email=a@b.example.com",
        ] {
            assert_eq!(
                shown(ambiguous),
                format!("set len={} fp={}", ambiguous.len(), fp(ambiguous)),
                "{ambiguous}"
            );
        }
        let plain_userinfo = "https://user:pass@host.example.com/x";
        assert_eq!(
            shown(plain_userinfo),
            format!(
                "set url=https://host.example.com/… fp={}",
                fp(plain_userinfo)
            )
        );
        assert_eq!(shown("https://"), "set len=8");
        assert_eq!(shown("1http://x.io"), "set len=12");
        assert_eq!(
            shown("https://bad_host.io"),
            format!("set len=19 fp={}", fp("https://bad_host.io"))
        );
    }

    #[test]
    fn fingerprint_only_from_16_bytes() {
        assert_eq!(fp("abc"), "ba7816");
        assert_eq!(shown("abcdefghijklmno"), "set len=15");
        assert_eq!(
            shown("abcdefghijklmnop"),
            format!("set len=16 fp={}", fp("abcdefghijklmnop"))
        );
    }

    #[test]
    fn keys_text_layout() {
        let f = EnvFile::parse(b"CLUSTER=devnet\n#OLD=x\nSHORT=hunter2\nCLUSTER=testnet\n");
        assert_eq!(
            keys_text(".env", &f),
            "# .env keys=2 crlf=no\n\
             L1   CLUSTER   devnet   (duplicate; overridden by L4)\n\
             L2   #OLD      commented\n\
             L3   SHORT     set len=7\n\
             L4   CLUSTER   testnet   (duplicate; this line wins)\n\
             # duplicates: dotenv loaders and `source` use the last assignment; dotenvy (Rust) keeps the first\n"
        );
    }

    #[test]
    fn header_flags() {
        let f = EnvFile::parse("\u{feff}A=1\r\n".as_bytes());
        assert_eq!(
            keys_text("x.env", &f),
            "# x.env keys=1 crlf=yes bom=yes\nL1   A   1\n"
        );
        let empty = EnvFile::parse(b"");
        assert_eq!(keys_text(".env", &empty), "# .env keys=0 crlf=no\n");
    }

    #[test]
    fn keys_json_fields() {
        let api = "3f9a1c0b7e2d4a6f8b1c3e5d7f9a0b2c4d6e";
        let url = "https://mainnet.helius-rpc.com/?api-key=0b1c2d3e";
        let body = format!("export API='{api}'\nC=devnet\nU={url}\nE=\nP=TODO\n#OLD=1\nA=1\nA=2\n");
        let f = EnvFile::parse(body.as_bytes());
        let v = keys_json(".env", &f, None);
        assert_eq!(v["file"], ".env");
        assert_eq!(v["format"], "dotenv");
        assert_eq!(v["crlf"], "no");
        assert_eq!(v["bom"], false);
        assert!(v.get("require").is_none());
        let k = &v["keys"];
        assert_eq!(k[0]["line"], 1);
        assert_eq!(k[0]["key"], "API");
        assert_eq!(k[0]["status"], "set");
        assert_eq!(k[0]["len"], 36);
        assert_eq!(k[0]["fp"], fp(api));
        assert_eq!(k[0]["export"], true);
        assert_eq!(k[0]["quote"], "single");
        assert_eq!(k[0]["display"], format!("set len=36 fp={}", fp(api)));
        assert_eq!(k[1]["status"], "verbatim");
        assert_eq!(k[1]["value"], "devnet");
        assert_eq!(k[2]["status"], "url");
        assert_eq!(k[2]["url"], "https://mainnet.helius-rpc.com/…");
        assert_eq!(k[2]["fp"], fp(url));
        assert_eq!(k[3]["status"], "empty");
        assert_eq!(k[4]["status"], "placeholder");
        assert_eq!(k[5]["status"], "commented");
        assert_eq!(k[5]["key"], "OLD");
        assert_eq!(k[6]["duplicate"], "overridden");
        assert_eq!(k[6]["overridden_by"], 8);
        assert_eq!(k[7]["duplicate"], "wins");
        assert!(k[1].get("duplicate").is_none());

        let unmet = vec![("X".to_string(), Unmet::Missing)];
        let v = keys_json(".env", &f, Some(&unmet));
        assert_eq!(v["require"]["ok"], false);
        assert_eq!(v["require"]["unmet"][0]["key"], "X");
        assert_eq!(v["require"]["unmet"][0]["reason"], "missing");
        let v = keys_json(".env", &f, Some(&[]));
        assert_eq!(v["require"]["ok"], true);
        assert!(!v.to_string().contains(api));
    }

    #[test]
    fn unmet_requirements() {
        let f = EnvFile::parse(b"A=secretvalue\nB=\nC=<x>\n#D=1\nE=1\nE=\nG=0\n");
        let required: Vec<String> = ["A", "B", "C", "D", "E", "F", "G"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let got = unmet(&f, &required);
        let want: Vec<(String, Unmet)> = [
            ("B", Unmet::Empty),
            ("C", Unmet::Placeholder),
            ("D", Unmet::Missing),
            ("E", Unmet::Empty),
            ("F", Unmet::Missing),
        ]
        .iter()
        .map(|(k, u)| (k.to_string(), *u))
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn change_summary() {
        let a = "3f9a1c0b7e2d4a6f8b1c";
        let b = "9b0e77aa11bb22cc33dd";
        assert_eq!(
            change(a.as_bytes(), b.as_bytes()),
            format!("fp {}→{}", fp(a), fp(b))
        );
        assert_eq!(change(b"1", b"devnet"), "1→devnet");
        assert_eq!(
            change(b"short", a.as_bytes()),
            format!("set len=5→set len=20 fp={}", fp(a))
        );
        assert_eq!(change(b"", b"x"), "empty→set len=1");
    }

    #[test]
    fn rendering_never_contains_a_secret() {
        let mut rng = Lcg::new(7);
        for _ in 0..500 {
            let secret = testgen::secret(&mut rng);
            let other = testgen::secret(&mut rng);
            let body = [b"K=".as_slice(), &secret, b"\n# K=", &secret, b"\n"].concat();
            let f = EnvFile::parse(&body);
            let s = String::from_utf8(secret.clone()).unwrap();
            let outputs = [
                keys_text(".env", &f),
                keys_json(".env", &f, None).to_string(),
                change(&secret, &other),
                change(&other, &secret),
                Shown::of(&secret).to_string(),
            ];
            for out in outputs {
                assert!(!out.contains(&s), "{s} leaked in {out}");
            }
        }
    }
}
