//! Native parser for varlock's `.env.schema` (env-spec), spec D3.8.2. safe-ai-skill never runs
//! varlock: loading a schema with varlock executes `$(cmd)`/`exec()` values and `@plugin` code,
//! so this module reads the format itself and evaluates nothing.
//!
//! The schema is dotenv plus decorator comments, parsed with the lossless [`EnvFile`] parser:
//! - **root decorators** (`@defaultSensitive`, `@defaultRequired`, `@currentEnv`, `@import`,
//!   `@plugin`, …) are read from comment lines before the first item;
//! - **item decorators** are read from the comment block directly above a key (no blank line in
//!   between) and from a trailing `# @…` comment on the key's own line;
//! - a decorator comment is a `#` line whose text starts with `@`: `@name`, `@name=value` or
//!   `@name(args)`, several per line.
//!
//! Sensitivity follows varlock: `@defaultSensitive` absent means every item is sensitive;
//! `=false` flips that, `=inferFromPrefix(PREFIX)` makes keys starting with `PREFIX`
//! non-sensitive; an item's `@sensitive`, `@sensitive=false` or `@public` overrides it.
//! Callers use sensitivity only to tighten (a repo's schema never exempts a value).
//!
//! Required-ness is reported only when declared: an item `@required`/`@optional`, or a root
//! `@defaultRequired=true|false|infer`. varlock's own default is not asserted here.

use super::parse::{Entry, EnvFile, ItemKind, Quote};

/// Largest schema read anywhere (the read gate guard uses the same bound).
pub const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// One decorator: `@name`, `@name=value` or `@name(args)` (`value` keeps the parentheses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decorator {
    pub name: String,
    pub value: Option<String>,
}

/// How a value is written: only [`ValueKind::Literal`] has bytes a redactor can match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueKind {
    Empty,
    Literal(Vec<u8>),
    /// An unquoted `name(...)` call (`exec(...)`, `varlock(...)`, `op(...)`).
    Function(String),
    /// `$(cmd)` command substitution.
    Exec,
    /// `$X` / `${X}` expansion.
    Reference,
}

/// The root `@defaultSensitive` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultSensitive {
    True,
    False,
    /// `inferFromPrefix(PREFIX)`: keys starting with `PREFIX` are not sensitive.
    Prefix(String),
}

/// The root `@defaultRequired` rule, when declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultRequired {
    True,
    False,
    /// Required when the schema gives the item a value.
    Infer,
}

/// One declared key (the last declaration wins for duplicates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaItem {
    pub key: String,
    /// 1-based line of the declaration.
    pub line: usize,
    pub decorators: Vec<Decorator>,
    pub value: ValueKind,
}

/// A parsed `.env.schema`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    pub root: Vec<Decorator>,
    pub items: Vec<SchemaItem>,
}

impl Schema {
    /// Parse schema bytes. Never fails: unparseable lines are ignored.
    pub fn parse(bytes: &[u8]) -> Self {
        let file = EnvFile::parse(bytes);
        let mut root = Vec::new();
        let mut items: Vec<SchemaItem> = Vec::new();
        let mut block: Vec<Decorator> = Vec::new();
        let mut seen_entry = false;
        for item in &file.items {
            let raw = &file.body[item.span.clone()];
            let text = String::from_utf8_lossy(raw);
            let trimmed = text.trim();
            match &item.kind {
                ItemKind::Entry(entry) => {
                    seen_entry = true;
                    let mut decorators = std::mem::take(&mut block);
                    decorators.extend(trailing_decorators(&file, entry));
                    let value = value_kind(&file.body, entry);
                    items.retain(|i| i.key != entry.key);
                    items.push(SchemaItem {
                        key: entry.key.clone(),
                        line: item.line,
                        decorators,
                        value,
                    });
                }
                _ if trimmed.is_empty() => block.clear(),
                _ => {
                    let Some(comment) = trimmed.strip_prefix('#') else {
                        block.clear();
                        continue;
                    };
                    for dec in parse_decorators(comment) {
                        if !seen_entry && is_root_decorator(&dec.name) {
                            root.push(dec);
                        } else {
                            block.push(dec);
                        }
                    }
                }
            }
        }
        Schema { root, items }
    }

    /// The root `@defaultSensitive` rule (absent → every item sensitive).
    pub fn default_sensitive(&self) -> DefaultSensitive {
        let Some(dec) = find(&self.root, "defaultSensitive") else {
            return DefaultSensitive::True;
        };
        match dec.value.as_deref().map(unquote) {
            None | Some("true") => DefaultSensitive::True,
            Some("false") => DefaultSensitive::False,
            Some(v) => match v
                .strip_prefix("inferFromPrefix(")
                .and_then(|r| r.strip_suffix(')'))
            {
                Some(prefix) => DefaultSensitive::Prefix(unquote(prefix.trim()).to_string()),
                // Unknown forms read as sensitive: the safe side.
                None => DefaultSensitive::True,
            },
        }
    }

    /// The root `@defaultRequired` rule, if declared.
    pub fn default_required(&self) -> Option<DefaultRequired> {
        let dec = find(&self.root, "defaultRequired")?;
        match dec.value.as_deref().map(unquote) {
            None | Some("true") => Some(DefaultRequired::True),
            Some("false") => Some(DefaultRequired::False),
            Some("infer") => Some(DefaultRequired::Infer),
            Some(_) => None,
        }
    }

    pub fn item(&self, key: &str) -> Option<&SchemaItem> {
        self.items.iter().find(|i| i.key == key)
    }

    /// Effective sensitivity of `key` (an undeclared key follows the root rule).
    pub fn is_sensitive(&self, key: &str) -> bool {
        if let Some(explicit) = self.item(key).and_then(SchemaItem::explicit_sensitive) {
            return explicit;
        }
        match self.default_sensitive() {
            DefaultSensitive::True => true,
            DefaultSensitive::False => false,
            DefaultSensitive::Prefix(prefix) => prefix.is_empty() || !key.starts_with(&prefix),
        }
    }

    /// Declared required-ness of `key`; `None` when the schema does not say.
    pub fn is_required(&self, key: &str) -> Option<bool> {
        let item = self.item(key)?;
        if let Some(explicit) = item.explicit_required() {
            return Some(explicit);
        }
        match self.default_required()? {
            DefaultRequired::True => Some(true),
            DefaultRequired::False => Some(false),
            DefaultRequired::Infer => Some(!matches!(item.value, ValueKind::Empty)),
        }
    }
}

impl SchemaItem {
    /// The item's own sensitivity decorator, if any.
    pub fn explicit_sensitive(&self) -> Option<bool> {
        let mut out = None;
        for dec in &self.decorators {
            match dec.name.as_str() {
                "sensitive" => {
                    out = Some(match dec.value.as_deref().map(unquote) {
                        None | Some("true") => true,
                        Some("false") => false,
                        Some(v) if v.starts_with('{') => {
                            !v.replace(' ', "").contains("enabled=false")
                        }
                        Some(_) => true,
                    })
                }
                "public" if dec.value.as_deref().map(unquote) != Some("false") => out = Some(false),
                _ => {}
            }
        }
        out
    }

    /// The item's own `@required` / `@optional`, if any.
    pub fn explicit_required(&self) -> Option<bool> {
        let mut out = None;
        for dec in &self.decorators {
            match (dec.name.as_str(), dec.value.as_deref().map(unquote)) {
                ("required", None | Some("true")) | ("optional", Some("false")) => out = Some(true),
                ("required", Some("false")) | ("optional", None | Some("true")) => {
                    out = Some(false)
                }
                _ => {}
            }
        }
        out
    }

    /// The `@type` name without arguments (`string(startsWith=sk_)` → `string`).
    pub fn type_name(&self) -> Option<String> {
        let value = find(&self.decorators, "type")?.value.as_deref()?;
        let name: String = unquote(value)
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        (!name.is_empty()).then_some(name)
    }
}

fn find<'a>(decs: &'a [Decorator], name: &str) -> Option<&'a Decorator> {
    decs.iter().rev().find(|d| d.name == name)
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

/// Root-only decorators (read from the header, before the first item).
fn is_root_decorator(name: &str) -> bool {
    name.starts_with("default")
        || name.starts_with("generate")
        || matches!(
            name,
            "currentEnv"
                | "envFlag"
                | "import"
                | "plugin"
                | "redact"
                | "preventLeaks"
                | "disable"
                | "cache"
        )
}

/// Decorators in a trailing `# @…` comment on the entry's own line.
fn trailing_decorators(file: &EnvFile, entry: &Entry) -> Vec<Decorator> {
    let end = entry.value_span.end.min(file.body.len());
    let line_end = file.body[end..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(file.body.len(), |p| end + p);
    let tail = match entry.quote {
        // A bare value's span runs to the end of the line and carries the comment.
        Quote::Bare => &file.body[entry.value_span.start.min(end)..line_end],
        _ => &file.body[end..line_end],
    };
    let tail = String::from_utf8_lossy(tail);
    let hash = match entry.quote {
        Quote::Bare => tail
            .char_indices()
            .find(|&(i, c)| c == '#' && (i == 0 || tail[..i].ends_with([' ', '\t'])))
            .map(|(i, _)| i),
        _ => tail.find('#'),
    };
    hash.map(|i| parse_decorators(&tail[i + 1..]))
        .unwrap_or_default()
}

/// Parse the decorators of one comment's text (after `#`). Text that does not start with `@`
/// is a plain comment and yields nothing.
pub fn parse_decorators(comment: &str) -> Vec<Decorator> {
    let text = comment.trim();
    if !text.starts_with('@') {
        return Vec::new();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        if chars[i] == '#' || chars[i] != '@' {
            break;
        }
        i += 1;
        let start = i;
        while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        if name.is_empty() {
            break;
        }
        let value = match chars.get(i) {
            Some('=') => {
                let (v, next) = scan_value(&chars, i + 1);
                i = next;
                Some(v)
            }
            Some('(') => {
                let (v, next) = scan_value(&chars, i);
                i = next;
                Some(v)
            }
            _ => None,
        };
        out.push(Decorator { name, value });
    }
    out
}

/// A decorator value from `chars[start..]`: up to whitespace outside quotes and brackets.
fn scan_value(chars: &[char], start: usize) -> (String, usize) {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut i = start;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == '\\' {
                    i += 1;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' | '`' => quote = Some(c),
                '(' | '{' | '[' => depth += 1,
                ')' | '}' | ']' => depth = depth.saturating_sub(1),
                c if c.is_whitespace() && depth == 0 => break,
                _ => {}
            },
        }
        i += 1;
    }
    let end = i.min(chars.len());
    (chars[start..end].iter().collect(), end)
}

/// How an entry's value is written (env-spec semantics; nothing is evaluated). Single quotes
/// are literal; unquoted and double-quoted values expand `$(…)` and `$X`; an unquoted
/// `name(…)` is a function call.
pub fn value_kind(body: &[u8], entry: &Entry) -> ValueKind {
    if entry.value.is_empty() {
        return ValueKind::Empty;
    }
    if entry.quote == Quote::Single {
        return ValueKind::Literal(entry.value.clone());
    }
    let raw = &body[entry.value_span.clone()];
    if entry.quote == Quote::Bare && is_call(&entry.value) {
        let name: String = entry
            .value
            .iter()
            .take_while(|&&b| b != b'(')
            .map(|&b| b as char)
            .collect();
        return ValueKind::Function(name);
    }
    match expansion(raw) {
        Some(kind) => kind,
        None => ValueKind::Literal(entry.value.clone()),
    }
}

/// `ident(` … `)`.
fn is_call(value: &[u8]) -> bool {
    let Some(open) = value.iter().position(|&b| b == b'(') else {
        return false;
    };
    open > 0
        && (value[0].is_ascii_alphabetic() || value[0] == b'_')
        && value[..open]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && value.trim_ascii_end().ends_with(b")")
}

/// The first unescaped expansion in raw value text, if any.
fn expansion(raw: &[u8]) -> Option<ValueKind> {
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'\\' => i += 2,
            b'$' => match raw.get(i + 1) {
                Some(b'(') => return Some(ValueKind::Exec),
                Some(b) if *b == b'{' || *b == b'_' || b.is_ascii_alphabetic() => {
                    return Some(ValueKind::Reference)
                }
                _ => i += 1,
            },
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "\
# My app's env schema
# @defaultSensitive=false @defaultRequired=infer
# @currentEnv=$APP_ENV
# ---

# Public RPC endpoint
# @type=url
RPC_URL=https://api.devnet.solana.com

# @sensitive @required
# @type=string(startsWith=sk_)
STRIPE_KEY=

APP_ENV=development # @type=enum(development,production)
ONE_PASSWORD=op(\"op://vault/item/field\")
GIT_SHA=$(git rev-parse HEAD)
DERIVED=${RPC_URL}/v1
LITERAL='$(not a command)'
# @public
PUBLIC_FLAG=true
";

    #[test]
    fn root_and_item_decorators() {
        let s = Schema::parse(EXAMPLE.as_bytes());
        assert_eq!(s.default_sensitive(), DefaultSensitive::False);
        assert_eq!(s.default_required(), Some(DefaultRequired::Infer));
        let stripe = s.item("STRIPE_KEY").unwrap();
        assert_eq!(stripe.line, 12);
        assert_eq!(stripe.explicit_sensitive(), Some(true));
        assert_eq!(stripe.type_name().as_deref(), Some("string"));
        assert!(s.is_sensitive("STRIPE_KEY"));
        assert_eq!(s.is_required("STRIPE_KEY"), Some(true));
        assert!(!s.is_sensitive("RPC_URL"));
        assert_eq!(
            s.item("RPC_URL").unwrap().type_name().as_deref(),
            Some("url")
        );
        assert_eq!(s.is_required("RPC_URL"), Some(true), "infer: has a value");
        assert_eq!(
            s.item("APP_ENV").unwrap().type_name().as_deref(),
            Some("enum"),
            "trailing decorator"
        );
        assert!(!s.is_sensitive("PUBLIC_FLAG"));
        // A comment block separated by a blank line does not attach.
        assert!(s.item("APP_ENV").unwrap().explicit_sensitive().is_none());
    }

    #[test]
    fn value_kinds_are_never_evaluated() {
        let s = Schema::parse(EXAMPLE.as_bytes());
        let kind = |k: &str| s.item(k).unwrap().value.clone();
        assert_eq!(kind("STRIPE_KEY"), ValueKind::Empty);
        assert_eq!(kind("ONE_PASSWORD"), ValueKind::Function("op".into()));
        assert_eq!(kind("GIT_SHA"), ValueKind::Exec);
        assert_eq!(kind("DERIVED"), ValueKind::Reference);
        assert_eq!(
            kind("LITERAL"),
            ValueKind::Literal(b"$(not a command)".to_vec())
        );
        assert_eq!(
            kind("RPC_URL"),
            ValueKind::Literal(b"https://api.devnet.solana.com".to_vec())
        );
    }

    #[test]
    fn default_sensitive_forms() {
        let s = Schema::parse(b"# ---\nA=\n");
        assert_eq!(s.default_sensitive(), DefaultSensitive::True);
        assert!(s.is_sensitive("A"));
        assert!(s.is_sensitive("UNDECLARED"));
        assert_eq!(s.is_required("A"), None, "not declared, not asserted");
        let p =
            Schema::parse(b"# @defaultSensitive=inferFromPrefix(PUBLIC_)\n# ---\nPUBLIC_X=\nY=\n");
        assert_eq!(
            p.default_sensitive(),
            DefaultSensitive::Prefix("PUBLIC_".into())
        );
        assert!(!p.is_sensitive("PUBLIC_X"));
        assert!(p.is_sensitive("Y"));
        let odd = Schema::parse(b"# @defaultSensitive=maybe()\nA=\n");
        assert!(odd.is_sensitive("A"), "unknown forms are sensitive");
    }

    #[test]
    fn item_overrides() {
        let s = Schema::parse(
            b"# @defaultSensitive=true\n# ---\n# @sensitive=false\nA=\n# @public\nB=\n# @sensitive={redact=false, enabled=false}\nC=\n# @sensitive={redact=false}\nD=\n# @optional\nE=\n",
        );
        assert!(!s.is_sensitive("A"));
        assert!(!s.is_sensitive("B"));
        assert!(!s.is_sensitive("C"));
        assert!(s.is_sensitive("D"));
        assert_eq!(s.is_required("E"), Some(false));
    }

    #[test]
    fn decorator_tokenizer() {
        assert_eq!(
            parse_decorators(" @a @b=c @d(\"x y\", z) @e={k=v, j=w} # note"),
            vec![
                Decorator {
                    name: "a".into(),
                    value: None
                },
                Decorator {
                    name: "b".into(),
                    value: Some("c".into())
                },
                Decorator {
                    name: "d".into(),
                    value: Some("(\"x y\", z)".into())
                },
                Decorator {
                    name: "e".into(),
                    value: Some("{k=v, j=w}".into())
                },
            ]
        );
        assert!(parse_decorators(" plain comment @not").is_empty());
        assert!(parse_decorators("").is_empty());
    }

    #[test]
    fn crlf_bom_and_duplicates() {
        let s = Schema::parse(
            b"\xef\xbb\xbf# @defaultSensitive=false\r\n# ---\r\n# @sensitive\r\nK=\r\nK=x\r\n",
        );
        assert_eq!(s.items.len(), 1);
        let k = s.item("K").unwrap();
        assert_eq!(k.line, 5, "last declaration wins");
        assert!(k.decorators.is_empty());
        assert!(!s.is_sensitive("K"));
    }

    #[test]
    fn prop_parse_never_panics_and_keys_match_dotenv() {
        let mut rng = crate::env::testgen::Lcg::new(0x5eed_d3c8);
        for _ in 0..400 {
            let bytes = crate::env::testgen::bytes(&mut rng);
            let schema = Schema::parse(&bytes);
            let file = EnvFile::parse(&bytes);
            for item in &schema.items {
                assert!(file.entries().any(|(_, e)| e.key == item.key));
            }
            for (_, e) in file.entries() {
                assert!(schema.item(&e.key).is_some());
            }
        }
    }
}
