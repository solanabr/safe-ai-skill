//! Secret path classification (spec D3.1, D3.2), shared by the read gate, the Bash secrets
//! gate, MCP path arguments and `safe-ai-skill env`.
//!
//! [`classify`] is pure string work (it reads `$HOME`/`$XDG_CONFIG_HOME`, nothing else) so the
//! Bash gate can call it on every command. [`sniff`] is the bounded content check the read gate
//! adds for files whose name alone does not decide.
//!
//! Matching is case-insensitive (`.ENV` opens `.env` on macOS and Windows), works on `/` and `\`
//! separators, drops an NTFS `:stream` suffix and trailing dots/spaces from each component, and
//! folds `.`/`..` lexically. Callers that can touch the filesystem also classify the resolved
//! (symlink-free) path and keep the stricter verdict.

use std::io::Read;
use std::path::Path;

/// Keypair sniff bound: a keypair file is a few hundred bytes, so anything larger is not one.
pub const SNIFF_BYTES: usize = 4 * 1024;

/// Private-key header scan bound for `*.pem`/`*.key` (a CA bundle can hold a key after many
/// certificates). A larger file of that name cannot be shown clean and is denied.
pub const PEM_SCAN_BYTES: usize = 1024 * 1024;

/// `.env.*` templates: no values, readable when the policy allow-list keeps them.
pub const TEMPLATES: &[&str] = &[".env.example", ".env.sample", ".env.template", ".env.dist"];

/// What a path name says about its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Never readable, by any profile, grant or allow glob. Carries a short description.
    HardDeny(&'static str),
    /// Name alone does not decide: [`sniff`] it (and deny when it cannot be read).
    Suspect(Suspect),
    /// Env class: raw reads denied (or asked, `secrets.env_read: ask`), served by `env`.
    Env,
    /// A varlock `.env.schema`: readable when allow-listed, after the content guard.
    Schema,
    /// `.env.example|.sample|.template|.dist`: readable when allow-listed.
    Template,
    /// Nothing special by name.
    Plain,
}

/// A name that may hold key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suspect {
    /// `id.json`: the Solana CLI keypair name, but also a common data file name.
    IdJson,
    /// `*.pem` / `*.key`: certificates are fine, private keys are not.
    PemKey,
}

impl Class {
    /// Whether this class is never readable.
    pub fn is_hard(self) -> bool {
        matches!(self, Class::HardDeny(_))
    }

    /// The env-class family (env files proper, schemas and templates) that the allow-list
    /// decides on.
    pub fn is_env_family(self) -> bool {
        matches!(self, Class::Env | Class::Schema | Class::Template)
    }
}

/// Classify `path` against `$HOME` (and `$XDG_CONFIG_HOME` for the varlock key store).
pub fn classify(path: &str) -> Class {
    classify_with_homes(path, &homes())
}

/// Classify `path`, treating each of `homes` as the home directory (callers pass the
/// canonical home too, since resolved paths go through symlinked homes).
pub fn classify_with_homes(path: &str, homes: &[String]) -> Class {
    let full = normalize(path, homes.first().map(String::as_str));
    if let Some(class) = tree_class(&full) {
        return class;
    }
    let base = full.rsplit('/').next().unwrap_or_default();
    classify_name(base)
}

/// Classify a bare (already normalised, lowercased) file name.
fn classify_name(base: &str) -> Class {
    if base.ends_with("-keypair.json") {
        return Class::HardDeny("Solana keypair");
    }
    if base == ".env.schema" {
        return Class::Schema;
    }
    if TEMPLATES.contains(&base) {
        return Class::Template;
    }
    let env = matches!(
        base,
        ".env" | ".envrc" | ".dev.vars" | ".varlock-frozen-env"
    ) || base.starts_with(".env.")
        || base.starts_with(".dev.vars.")
        || base.ends_with(".env");
    if env {
        return Class::Env;
    }
    if base == "id.json" {
        return Class::Suspect(Suspect::IdJson);
    }
    if base.ends_with(".pem") || base.ends_with(".key") {
        return Class::Suspect(Suspect::PemKey);
    }
    Class::Plain
}

/// Hard-deny trees, matched as a component sequence anywhere in the path (another user's
/// home is as secret as ours).
const HARD_TREES: &[&str] = &[
    ".config/solana",
    ".ssh",
    ".superstack",
    ".config/varlock",
    ".varlock",
];

/// Rules for the Solana CLI tree, SSH identities, superstack and the varlock key store.
/// `full` is normalised (absolute when the caller expanded `~` or joined a cwd).
fn tree_class(full: &str) -> Option<Class> {
    let rooted = if full.starts_with('/') {
        full.to_string()
    } else {
        format!("/{full}")
    };
    if rooted.ends_with("/.config/solana/cli/config.yml") {
        return Some(Class::Env);
    }
    if let Some(rest) = tree_rest(&rooted, ".config/solana") {
        let _ = rest;
        return Some(Class::HardDeny("Solana config directory"));
    }
    if let Some(name) = tree_rest(&rooted, ".ssh") {
        if name.starts_with("id_") && !name.contains('/') && !name.ends_with(".pub") {
            return Some(Class::HardDeny("SSH private key"));
        }
    }
    if rooted.ends_with("/.superstack/config.json") {
        return Some(Class::HardDeny("superstack config (credential token)"));
    }
    if tree_rest(&rooted, ".config/varlock").is_some() || tree_rest(&rooted, ".varlock").is_some() {
        return Some(Class::HardDeny("varlock key store"));
    }
    if let Some(xdg) = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|x| !x.is_empty())
    {
        let dir = format!("{}/varlock", normalize(&xdg, None).trim_end_matches('/'));
        if full == dir || full.starts_with(&format!("{dir}/")) {
            return Some(Class::HardDeny("varlock key store"));
        }
    }
    None
}

/// The part of `rooted` after the first `/<dir>/` component sequence, if any (`""` when the
/// path ends at `<dir>`).
fn tree_rest<'a>(rooted: &'a str, dir: &str) -> Option<&'a str> {
    let needle = format!("/{dir}/");
    if let Some(i) = rooted.find(&needle) {
        return Some(&rooted[i + needle.len()..]);
    }
    rooted.ends_with(&format!("/{dir}")).then_some("")
}

/// Whether `dir` is, or lies inside, a hard-deny tree (`.config/solana`, `.ssh`,
/// `.superstack`, the varlock key store). A directory search there cannot be made safe by
/// excluding file names.
pub fn is_hard_tree(dir: &str, homes: &[String]) -> bool {
    let full = normalize(dir, homes.first().map(String::as_str));
    let rooted = if full.starts_with('/') {
        full
    } else {
        format!("/{full}")
    };
    HARD_TREES
        .iter()
        .any(|tree| tree_rest(&rooted, tree).is_some())
}

/// `$HOME` (when set) as the classification home list.
pub fn homes() -> Vec<String> {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .into_iter()
        .collect()
}

/// `$HOME` plus its canonical form, for classifying resolved paths.
pub fn homes_resolved() -> Vec<String> {
    let mut out = homes();
    if let Some(real) = out
        .first()
        .and_then(|h| std::fs::canonicalize(h).ok())
        .and_then(|p| p.to_str().map(str::to_string))
    {
        if !out.contains(&real) {
            out.push(real);
        }
    }
    out
}

/// Lowercased, `/`-separated, lexically folded form of `path` with a leading `~` expanded
/// to `home`. Each component loses an NTFS `:stream` suffix (`.env::$DATA`) and trailing dots
/// and spaces (Windows ignores them). A drive letter (`C:`) keeps its colon.
pub fn normalize(path: &str, home: Option<&str>) -> String {
    fold(path, home).to_ascii_lowercase()
}

/// [`normalize`] without the lowercasing (for case-sensitive allow globs).
pub fn fold(path: &str, home: Option<&str>) -> String {
    let text = path.trim().replace('\\', "/");
    let text = match (text.strip_prefix('~'), home) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            format!("{}{rest}", home.replace('\\', "/").trim_end_matches('/'))
        }
        _ => text,
    };
    let absolute = text.starts_with('/');
    let mut parts: Vec<String> = Vec::new();
    for (i, raw) in text.split('/').enumerate() {
        let drive = i == 0
            && raw.len() == 2
            && raw.as_bytes()[1] == b':'
            && raw.as_bytes()[0].is_ascii_alphabetic();
        let comp = if drive {
            raw.to_string()
        } else {
            let no_stream = raw.split(':').next().unwrap_or_default();
            no_stream.trim_end_matches(['.', ' ']).to_string()
        };
        // A component of only dots is `.`/`..` (or Windows-equivalent dots), kept as is.
        let comp = if !raw.is_empty() && raw.bytes().all(|b| b == b'.') {
            raw.to_string()
        } else {
            comp
        };
        match comp.as_str() {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(comp);
                }
            }
            _ => parts.push(comp),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// What a bounded look at a file's bytes found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniffed {
    /// The whole file is a Solana keypair (64-int array or 64-byte base58).
    Keypair,
    /// A `-----BEGIN … PRIVATE KEY-----` block within the scanned prefix.
    PrivateKey,
    /// Scanned and clean (or not a regular file / missing: nothing to read).
    Clean,
    /// Exists but could not be opened or read.
    Unreadable,
    /// Larger than the scan bound without a hit.
    TooLarge,
}

/// Look at up to `limit` bytes of `path`. Missing files and non-regular files (FIFOs,
/// devices, directories) are [`Sniffed::Clean`] and never opened, so a FIFO cannot hang a gate.
pub fn sniff(path: &Path, limit: usize) -> Sniffed {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Sniffed::Clean,
        Err(_) => return Sniffed::Unreadable,
    };
    if !meta.is_file() {
        return Sniffed::Clean;
    }
    let mut buf = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| {
        let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        f.take(cap).read_to_end(&mut buf)
    });
    if read.is_err() {
        return Sniffed::Unreadable;
    }
    let over = buf.len() > limit;
    buf.truncate(limit);
    let text = String::from_utf8_lossy(&buf);
    if has_private_key_block(&text) {
        return Sniffed::PrivateKey;
    }
    if over {
        return Sniffed::TooLarge;
    }
    if is_keypair_content(&text) {
        return Sniffed::Keypair;
    }
    Sniffed::Clean
}

/// Whether `text` holds a PEM / OpenSSH private-key header.
pub fn has_private_key_block(text: &str) -> bool {
    text.match_indices("-----BEGIN").any(|(i, _)| {
        text[i..]
            .lines()
            .next()
            .is_some_and(|l| l.contains("PRIVATE KEY-----"))
    })
}

/// Whether the whole of `text` (trimmed) is a keypair: a JSON array of exactly 64 integers in
/// `0..=255`, or one base58 token that decodes to 64 bytes.
pub fn is_keypair_content(text: &str) -> bool {
    let t = text.trim();
    if let Some(inner) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        let nums: Vec<&str> = inner.split(',').map(str::trim).collect();
        return nums.len() == 64
            && nums.iter().all(|n| {
                !n.is_empty() && n.len() <= 3 && n.parse::<u16>().is_ok_and(|v| v <= 255)
            });
    }
    crate::redact::is_base58_secret_key(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/u";

    fn class(path: &str) -> Class {
        classify_with_homes(path, &[HOME.to_string()])
    }

    #[test]
    fn env_class_names_any_case_and_dir() {
        for p in [
            ".env",
            ".ENV",
            ".Env.Local",
            "/srv/app/.env.production",
            "prod.env",
            "config/Staging.ENV",
            ".envrc",
            ".dev.vars",
            ".dev.vars.staging",
            ".varlock-frozen-env",
            "/home/u/.config/solana/cli/config.yml",
            "~/.config/solana/cli/config.yml",
        ] {
            assert_eq!(class(p), Class::Env, "{p}");
        }
    }

    #[test]
    fn windows_forms_normalise() {
        for p in [
            r"C:\p\.env",
            r"C:\p\.ENV.local",
            ".env::$DATA",
            ".env:stream",
            r"c:\p\.env. ",
            ".env.",
            "/a/b/../.env",
            "/a/.env/.",
        ] {
            assert_eq!(class(p), Class::Env, "{p}");
        }
    }

    #[test]
    fn templates_and_schema() {
        for p in [
            ".env.example",
            "/p/.ENV.SAMPLE",
            ".env.template",
            ".env.dist",
        ] {
            assert_eq!(class(p), Class::Template, "{p}");
        }
        assert_eq!(class(".env.schema"), Class::Schema);
        assert_eq!(class("/p/sub/.ENV.SCHEMA"), Class::Schema);
        for p in [".env.schema.bak", ".env.schema.local", ".env.local"] {
            assert_eq!(class(p), Class::Env, "{p}");
        }
    }

    #[test]
    fn hard_deny_names_and_trees() {
        for p in [
            "wallet-keypair.json",
            "/x/Deploy-Keypair.JSON",
            "/home/u/.config/solana/id.json",
            "~/.config/solana/devnet.json",
            "/home/u/.config/solana/cli/other.yml",
            "/home/u/.ssh/id_ed25519",
            "~/.ssh/id_rsa",
            "/home/u/.superstack/config.json",
            "/home/u/.config/varlock/cache/x",
            "/home/u/.varlock/keys",
            "/home/u/.config/solana/../solana/id.json",
            "/root/.config/solana/id.json",
            ".config/solana/id.json",
            "/Users/x/.ssh/id_ecdsa",
        ] {
            assert!(class(p).is_hard(), "{p}: {:?}", class(p));
        }
        assert_eq!(class("/home/u/.ssh/id_ed25519.pub"), Class::Plain);
        assert_eq!(class("/home/u/.ssh/known_hosts"), Class::Plain);
    }

    #[test]
    fn suspects_and_plain() {
        assert_eq!(class("/p/id.json"), Class::Suspect(Suspect::IdJson));
        assert_eq!(class("server.PEM"), Class::Suspect(Suspect::PemKey));
        assert_eq!(class("tls.key"), Class::Suspect(Suspect::PemKey));
        for p in [
            "/p/src/main.rs",
            "README.md",
            ".env/lib/site.py",
            "environment.ts",
            "dotenv.js",
            "",
        ] {
            assert_eq!(class(p), Class::Plain, "{p}");
        }
    }

    #[test]
    fn normalize_folds_and_lowercases() {
        assert_eq!(normalize("/A/b/../C/./d", None), "/a/c/d");
        assert_eq!(normalize("~/x", Some("/home/u")), "/home/u/x");
        assert_eq!(normalize("~user/x", Some("/home/u")), "~user/x");
        assert_eq!(normalize("../../.env", None), "../../.env");
        assert_eq!(normalize("/../.env", None), "/.env");
        assert_eq!(normalize(r"C:\P\.Env", None), "c:/p/.env");
    }

    #[test]
    fn hard_trees_for_directory_searches() {
        let homes = [HOME.to_string()];
        for d in [
            "/home/u/.config/solana",
            "~/.ssh",
            "/home/u/.config/solana/cli",
        ] {
            assert!(is_hard_tree(d, &homes), "{d}");
        }
        for d in ["/home/u", "/home/u/.config", "/home/u/project"] {
            assert!(!is_hard_tree(d, &homes), "{d}");
        }
    }

    #[test]
    fn keypair_content_shapes() {
        let arr: Vec<String> = (0..64).map(|i| (i * 3 % 256).to_string()).collect();
        let json = format!("[{}]", arr.join(","));
        assert!(is_keypair_content(&json));
        assert!(is_keypair_content(&format!(
            "\n  {}\n",
            json.replace(',', ",\n ")
        )));
        let b58 = bs58::encode([7u8; 64]).into_string();
        assert!(is_keypair_content(&b58));
        let short: Vec<String> = (0..32).map(|i| i.to_string()).collect();
        assert!(!is_keypair_content(&format!("[{}]", short.join(","))));
        assert!(!is_keypair_content(&format!("{{\"k\": {json}}}")));
        assert!(!is_keypair_content(&bs58::encode([7u8; 32]).into_string()));
        let big: Vec<String> = (0..64).map(|_| "300".to_string()).collect();
        assert!(!is_keypair_content(&format!("[{}]", big.join(","))));
    }

    #[test]
    fn private_key_headers() {
        assert!(has_private_key_block(
            "x\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
        ));
        assert!(has_private_key_block("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(has_private_key_block(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        ));
        assert!(!has_private_key_block(
            "-----BEGIN CERTIFICATE-----\nPRIVATE KEY-----"
        ));
    }

    #[test]
    fn sniff_files() {
        let dir = std::env::temp_dir().join(format!("sp-sniff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let arr: Vec<String> = (0..64).map(|i| i.to_string()).collect();
        let kp = dir.join("foo.json");
        std::fs::write(&kp, format!("[{}]", arr.join(","))).unwrap();
        assert_eq!(sniff(&kp, SNIFF_BYTES), Sniffed::Keypair);
        let pem = dir.join("k.pem");
        std::fs::write(&pem, "-----BEGIN PRIVATE KEY-----\nMII\n").unwrap();
        assert_eq!(sniff(&pem, SNIFF_BYTES), Sniffed::PrivateKey);
        let cert = dir.join("c.pem");
        std::fs::write(&cert, "-----BEGIN CERTIFICATE-----\nMII\n").unwrap();
        assert_eq!(sniff(&cert, SNIFF_BYTES), Sniffed::Clean);
        let big = dir.join("big.json");
        std::fs::write(&big, vec![b' '; SNIFF_BYTES + 10]).unwrap();
        assert_eq!(sniff(&big, SNIFF_BYTES), Sniffed::TooLarge);
        assert_eq!(sniff(&dir.join("missing"), SNIFF_BYTES), Sniffed::Clean);
        assert_eq!(sniff(&dir, SNIFF_BYTES), Sniffed::Clean);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
