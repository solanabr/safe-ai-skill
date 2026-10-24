//! Authenticated JSON state files in the plugin data dir (spec D4.2).
//!
//! Each file is an envelope `{"v": 1, "gen": <n>, "mac": "<hex>", "body": <state>}`. The MAC
//! is HMAC-SHA256 under a 32-byte key in `${DATA}/key` (mode 0600, created on the first
//! [`store`]) over `"safe-ai-skill/state/v1\0" + <file name> + "\0" + <gen> + "\0" +
//! canonical(body)`, where the canonical form is compact JSON with object keys sorted. Binding
//! the file name stops a valid `grants.json` body being replayed as another file.
//!
//! ## Generations (restore resistance)
//!
//! Every [`store`] bumps the file's generation and records it in the authenticated index
//! [`GEN_INDEX`]. [`load`] rejects (as [`Loaded::Tampered`]) an envelope whose generation is
//! below the index's, so copying back an older valid `grants.json` (unspent budget) or
//! `spend.json` (a lower total) does not verify. A missing or tampered index makes every
//! file tampered. Residual: restoring a snapshot of the *whole* data dir (index included)
//! is not detected. Writers write the file, then the index, under [`STATE_LOCK`]; readers
//! read the index first, so a concurrent store never makes a reader see an old file with a
//! new index.
//!
//! The first store that creates the key also starts the spend ledger at zero
//! ([`crate::spend::on_key_created`]): a ledger missing once the key exists means deleted.
//!
//! This is tamper-evident, not tamper-proof: anything that can read the key can forge a
//! MAC. It stops the model hand-editing state through a tool that cannot read the key.
//!
//! Floats round-trip exactly (serde_json `float_roundtrip`), which the MAC depends on: it is
//! computed over the value as stored and re-checked over the value as parsed. NaN and
//! infinities have no JSON form, so [`store`] refuses them.
//!
//! [`load`] never decides a fail direction: it reports [`Loaded::Missing`] or
//! [`Loaded::Tampered`] and the caller picks (no relaxation, budget exhausted, ...).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::datadir::DataDir;
use crate::error::{EngineError, Error};

/// Envelope format version.
const VERSION: u64 = 1;

/// Name of the MAC key file inside the data dir.
pub const KEY_FILE: &str = "key";

/// Written next to a state key this engine creates (1.2.0 and later), so a key without it was
/// made by an earlier engine ([`crate::migrate::env_tier_notice`]).
pub const KEY_ERA_MARKER: &str = "env-tier-1.2.0.seen";

/// Key length in bytes.
const KEY_LEN: usize = 32;

/// Largest state file [`load`] reads; anything bigger is `Tampered`.
pub const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;

/// Age after which a lock file counts as stale (the non-unix pending lock).
#[cfg(any(test, not(unix)))]
pub(crate) const STALE_LOCK_AGE: std::time::Duration = std::time::Duration::from_secs(10);

/// Age after which `.<name>.stale.*` debris from an interrupted break is swept.
const DEBRIS_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Domain-separation prefix of the MAC input.
const MAC_DOMAIN: &[u8] = b"safe-ai-skill/state/v1\0";

/// The authenticated generation index: `{file name: generation}`.
pub const GEN_INDEX: &str = "generations.json";

/// Lock file serializing stores (file + index update).
pub(crate) const STATE_LOCK: &str = "state.lock";

/// How long [`FileLock::acquire`] waits.
pub(crate) const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Result of [`load`].
#[derive(Debug, Clone, PartialEq)]
pub enum Loaded<T> {
    /// The file exists, its MAC verifies under the key, and the body parses as `T`.
    Valid(T),
    /// The file does not exist.
    Missing,
    /// The file exists but is not a valid envelope, its MAC fails, the key is missing or
    /// malformed, or the authenticated body does not parse as `T`.
    Tampered,
}

/// Load and authenticate `${dir}/{name}`.
///
/// A state file with no key file is [`Loaded::Tampered`] (the key cannot vanish on its own).
/// Never creates the key.
pub fn load<T: DeserializeOwned + Default>(dir: &DataDir, name: &str) -> Loaded<T> {
    if dir.is_unresolved() {
        return Loaded::Missing;
    }
    if !valid_name(name) {
        return Loaded::Tampered;
    }
    // The index first: a store writes the file, then the index (see the module docs).
    let index = read_envelope(&dir.path, GEN_INDEX);
    let (gen, body) = match read_envelope(&dir.path, name) {
        Envelope::Missing => return Loaded::Missing,
        Envelope::Bad => return Loaded::Tampered,
        Envelope::Good { gen, body } => (gen, body),
    };
    let Envelope::Good { body: index, .. } = index else {
        return Loaded::Tampered;
    };
    match index.get(name).and_then(Value::as_u64) {
        Some(floor) if gen >= floor => {}
        _ => return Loaded::Tampered,
    }
    match T::deserialize(&body) {
        Ok(v) => Loaded::Valid(v),
        Err(_) => Loaded::Tampered,
    }
}

/// Whether `${dir}/{name}` was stored before, as far as the data dir can tell: the
/// authenticated index lists it, or the index exists but does not authenticate, or there is
/// no index although the state key exists (nothing proves the file never existed). A file
/// missing while this holds was deleted.
pub fn was_stored(dir: &DataDir, name: &str) -> bool {
    if dir.is_unresolved() || !valid_name(name) {
        return false;
    }
    match read_envelope(&dir.path, GEN_INDEX) {
        Envelope::Good { body, .. } => body.get(name).and_then(Value::as_u64).unwrap_or(0) > 0,
        Envelope::Bad => true,
        Envelope::Missing => std::fs::symlink_metadata(dir.path.join(KEY_FILE)).is_ok(),
    }
}

/// What [`read_envelope`] found.
enum Envelope {
    Missing,
    Bad,
    Good { gen: u64, body: Value },
}

/// Read and authenticate `${dir}/{name}` (no generation check).
fn read_envelope(dir: &Path, name: &str) -> Envelope {
    let text = match read_regular(&dir.join(name), MAX_STATE_BYTES) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Envelope::Missing,
        Err(_) => return Envelope::Bad,
    };
    let Ok(key) = read_key(dir) else {
        return Envelope::Bad;
    };
    let Ok(Value::Object(mut env)) = serde_json::from_slice::<Value>(&text) else {
        return Envelope::Bad;
    };
    if env.get("v").and_then(Value::as_u64) != Some(VERSION) {
        return Envelope::Bad;
    }
    let (Some(mac), Some(gen)) = (
        env.get("mac").and_then(Value::as_str).and_then(hex_decode),
        env.get("gen").and_then(Value::as_u64),
    ) else {
        return Envelope::Bad;
    };
    let Some(body) = env.remove("body") else {
        return Envelope::Bad;
    };
    if !constant_time_eq(&mac, &state_mac(&key, name, gen, &body)) {
        return Envelope::Bad;
    }
    Envelope::Good { gen, body }
}

/// Write `v` to `${dir}/{name}` as a MAC'd envelope with the next generation, then record
/// that generation in [`GEN_INDEX`]: a 0600 temp file in the same dir, fsync, rename. Creates
/// the data dir and the key when missing (and then starts the spend ledger).
pub fn store<T: Serialize>(dir: &DataDir, name: &str, v: &T) -> Result<(), EngineError> {
    store_inner(dir, name, v, false).map(|_| ())
}

/// [`store`] only when `${dir}/{name}` does not exist yet, checked under [`STATE_LOCK`], so
/// two processes creating the same file never overwrite each other's later write. Returns
/// whether this call wrote it.
pub fn store_new<T: Serialize>(dir: &DataDir, name: &str, v: &T) -> Result<bool, EngineError> {
    store_inner(dir, name, v, true)
}

fn store_inner<T: Serialize>(
    dir: &DataDir,
    name: &str,
    v: &T,
    only_if_missing: bool,
) -> Result<bool, EngineError> {
    if dir.is_unresolved() {
        return Err(Error::Other(
            "the plugin data dir is unresolved; nothing is stored".to_string(),
        ));
    }
    if !valid_name(name) {
        return Err(Error::Other(format!("invalid state file name `{name}`")));
    }
    if has_non_finite_float(v)? {
        return Err(Error::Other(format!(
            "refusing to store `{name}`: it holds a NaN or infinite number"
        )));
    }
    let body = serde_json::to_value(v).map_err(|e| Error::Parse(e.to_string()))?;
    create_dir_private(&dir.path)?;
    sweep_debris(&dir.path, KEY_FILE);
    let (key, created) = load_or_create_key(&dir.path)?;
    if created {
        crate::spend::on_key_created(dir, name);
    }

    let _lock = FileLock::acquire(&dir.path, STATE_LOCK)?;
    if only_if_missing && std::fs::symlink_metadata(dir.path.join(name)).is_ok() {
        return Ok(false);
    }
    let mut index = match read_envelope(&dir.path, GEN_INDEX) {
        Envelope::Good {
            body: Value::Object(map),
            ..
        } => map,
        // A missing or bad index is rebuilt; files it no longer lists stay tampered.
        _ => serde_json::Map::new(),
    };
    // The next generation exceeds both the index's and the file's own (unauthenticated, so
    // it can only push the number up).
    let on_disk = read_regular(&dir.path.join(name), MAX_STATE_BYTES)
        .ok()
        .and_then(|t| serde_json::from_slice::<Value>(&t).ok())
        .and_then(|v| v.get("gen").and_then(Value::as_u64))
        .unwrap_or(0);
    let floor = index.get(name).and_then(Value::as_u64).unwrap_or(0);
    let gen = floor.max(on_disk).saturating_add(1);
    write_envelope(&dir.path, &key, name, gen, &body)?;
    index.insert(name.to_string(), Value::from(gen));
    write_envelope(&dir.path, &key, GEN_INDEX, 0, &Value::Object(index))?;
    Ok(true)
}

/// Serialize and atomically write one envelope.
fn write_envelope(
    dir: &Path,
    key: &[u8],
    name: &str,
    gen: u64,
    body: &Value,
) -> Result<(), EngineError> {
    let mac = hex_encode(&state_mac(key, name, gen, body));
    let envelope = serde_json::json!({ "v": VERSION, "gen": gen, "mac": mac, "body": body });
    let bytes = serde_json::to_vec(&envelope).map_err(|e| Error::Parse(e.to_string()))?;
    write_atomic(dir, name, &bytes)
}

/// A 32-byte value derived from the state key for `label` (HMAC(key, label)); errors when
/// the key cannot be read. Used for salts that must not be computable without the key.
pub(crate) fn derived_key(dir: &DataDir, label: &[u8]) -> Result<[u8; 32], EngineError> {
    let key = read_key(&dir.path)?;
    Ok(hmac_sha256(&key, label))
}

/// Whether `v` serializes any NaN or infinite float. serde_json would write those as `null`,
/// which then fails to load as the number type; serde_yaml keeps them, so walk its value. A
/// value serde_yaml cannot represent is an error: unscanned, it is not stored.
fn has_non_finite_float<T: Serialize>(v: &T) -> Result<bool, EngineError> {
    fn walk(y: &serde_yaml::Value) -> bool {
        use serde_yaml::Value as Y;
        match y {
            Y::Number(n) => n.is_nan() || n.is_infinite(),
            Y::Sequence(items) => items.iter().any(walk),
            Y::Mapping(map) => map.iter().any(|(k, v)| walk(k) || walk(v)),
            Y::Tagged(t) => walk(&t.value),
            Y::Null | Y::Bool(_) | Y::String(_) => false,
        }
    }
    serde_yaml::to_value(v)
        .map(|y| walk(&y))
        .map_err(|e| Error::Other(format!("state value cannot be checked for NaN/inf: {e}")))
}

/// A state file name is one plain path component and never the key itself.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != KEY_FILE
        && name != GEN_INDEX
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
}

/// HMAC over the domain prefix, the file name, the generation and the canonical body.
fn state_mac(key: &[u8], name: &str, gen: u64, body: &Value) -> [u8; 32] {
    let mut msg = Vec::with_capacity(MAC_DOMAIN.len() + name.len() + 64);
    msg.extend_from_slice(MAC_DOMAIN);
    msg.extend_from_slice(name.as_bytes());
    msg.push(0);
    msg.extend_from_slice(gen.to_string().as_bytes());
    msg.push(0);
    canonical_json(body, &mut msg);
    hmac_sha256(key, &msg)
}

/// Compact JSON with object keys sorted (bytewise), independent of map insertion order.
fn canonical_json(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_json(&Value::String(k.clone()), out);
                out.push(b':');
                canonical_json(val, out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_json(item, out);
            }
            out.push(b']');
        }
        // Scalars: serde_json's compact form is already canonical for them.
        scalar => out.extend_from_slice(scalar.to_string().as_bytes()),
    }
}

/// HMAC-SHA256 (RFC 2104) over the `sha2` crate.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// Compare without an early exit on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Seconds after which an empty key file counts as a crashed creation and may be replaced.
const STALE_EMPTY_KEY_SECS: u64 = 60;

/// Read the key. Refused (an error, so [`load`] reports `Tampered`) unless it is a regular
/// file reached without following a symlink, holds exactly [`KEY_LEN`] bytes and, on unix,
/// has no group/other permission bits and is owned by the effective user.
fn read_key(dir: &Path) -> Result<Vec<u8>, EngineError> {
    let bad = |why: &str| Error::Other(format!("state key refused: {why}"));
    let f = open_regular(&dir.join(KEY_FILE))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = f.metadata()?;
        if meta.mode() & 0o077 != 0 {
            return Err(bad("group or other permission bits set"));
        }
        // SAFETY: geteuid has no preconditions and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(bad("not owned by the current user"));
        }
    }
    let key = read_capped(f, KEY_LEN)?;
    if key.len() != KEY_LEN {
        return Err(bad("wrong length"));
    }
    Ok(key)
}

/// Open `path` for reading only if it is a regular file reached without following a symlink.
/// `O_NONBLOCK` keeps a planted FIFO from hanging `open()`; regular files ignore it.
fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = opts.open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// Read at most `max` bytes; more is an error.
fn read_capped(f: std::fs::File, max: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() > max {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(buf)
}

/// [`open_regular`] + [`read_capped`].
fn read_regular(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    read_capped(open_regular(path)?, max)
}

/// Read the key, creating it with `O_EXCL` (mode 0600) when absent. Losing a creation race
/// re-reads the winner's key, retrying briefly while the winner is still writing it.
///
/// Recovery: a creation that crashed leaves an empty `key`; once it is older than
/// [`STALE_EMPTY_KEY_SECS`] it is replaced (no state can have been MAC'd under it). Any other
/// bad key (wrong length, mode, owner, a symlink) is never replaced automatically: delete
/// `${DATA}/key` together with the state files (they would no longer verify) to reset.
/// Returns the key and whether this call created it.
fn load_or_create_key(dir: &Path) -> Result<(Vec<u8>, bool), EngineError> {
    let path = dir.join(KEY_FILE);
    let mut replaced_stale = false;
    loop {
        match open_new_private(&path) {
            Ok(mut f) => {
                let mut key = [0u8; KEY_LEN];
                rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut key)
                    .map_err(|e| Error::Other(format!("OS random source: {e}")))?;
                f.write_all(&key)?;
                f.sync_all()?;
                let _ = std::fs::write(dir.join(KEY_ERA_MARKER), b"1\n");
                return Ok((key.to_vec(), true));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if !replaced_stale && is_stale_empty_key(&path) {
                    replaced_stale = true;
                    break_stale_with(&path, is_stale_empty_meta)?;
                    continue;
                }
                let mut last = Error::Other("state key refused: wrong length".to_string());
                for _ in 0..50 {
                    match read_key(dir) {
                        Ok(key) => return Ok((key, false)),
                        Err(e) => last = e,
                    }
                    // Only an empty or short key may still be being written.
                    let len = std::fs::symlink_metadata(&path).map(|m| m.len());
                    if !matches!(len, Ok(n) if n < KEY_LEN as u64) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                return Err(last);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// An exclusive lock on a lock file in the data dir, released on drop.
pub(crate) struct FileLock {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl FileLock {
    /// `flock(LOCK_EX)` on `dir/name`, retried for [`LOCK_WAIT`]. The kernel drops the lock
    /// when the process exits, so a crash leaves no stale lock. Locks are taken in a fixed
    /// order (a specific lock such as `pending.lock`, then [`STATE_LOCK`]), never reentrantly.
    #[cfg(unix)]
    pub(crate) fn acquire(dir: &Path, name: &str) -> Result<FileLock, EngineError> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            // O_NONBLOCK: a planted FIFO fails open() instead of hanging the hook.
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join(name))?;
        if !file.metadata()?.is_file() {
            return Err(Error::Other(format!("{name} is not a regular file")));
        }
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            // SAFETY: the fd is open for the lifetime of `file`.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(FileLock { _file: file });
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Other(format!("{name} is busy")));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// An `O_EXCL` lock file, removed on drop; one older than [`STALE_LOCK_AGE`] is taken as
    /// stale and broken with [`break_stale`] (rename aside, then remove).
    #[cfg(not(unix))]
    pub(crate) fn acquire(dir: &Path, name: &str) -> Result<FileLock, EngineError> {
        let path = dir.join(name);
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            match open_new_private(&path) {
                Ok(_) => return Ok(FileLock { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::symlink_metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .is_some_and(|age| age > STALE_LOCK_AGE);
                    if stale {
                        break_stale(&path, STALE_LOCK_AGE)?;
                        continue;
                    }
                }
                // Windows refuses to create a file whose previous holder is still deleting it
                // (delete pending while another handle is open): contention, not an error.
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(e) => return Err(e.into()),
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Other(format!("{name} is busy")));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

#[cfg(not(unix))]
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Break a lock-like file older than `min_age` without racing whoever replaced it meanwhile:
/// rename it to a unique name (atomic, so exactly one breaker gets it), re-check the age of
/// what moved, and remove that name, or link it back if it turned out fresh. A path that is
/// already gone is not an error.
#[cfg(any(test, not(unix)))]
pub(crate) fn break_stale(path: &Path, min_age: std::time::Duration) -> std::io::Result<()> {
    break_stale_with(path, |moved| older_than(moved, min_age))
}

/// [`break_stale`], re-checking the file actually moved with `still_stale`: if a fresh file
/// replaced the stale one between the caller's check and the rename, it is linked back
/// (best-effort; never over an existing path) before the aside name is removed.
fn break_stale_with(
    path: &Path,
    still_stale: impl Fn(&std::fs::Metadata) -> bool,
) -> std::io::Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(dir) = path.parent() {
        sweep_debris(dir, &name);
    }
    let aside = path.with_file_name(format!(".{name}.stale.{}.{nanos}", std::process::id()));
    match std::fs::rename(path, &aside) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    if let Ok(moved) = std::fs::symlink_metadata(&aside) {
        if !still_stale(&moved) {
            let _ = std::fs::hard_link(&aside, path);
        }
    }
    match std::fs::remove_file(&aside) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Remove `.<name>.stale.*` debris in `dir` older than [`DEBRIS_AGE`] (left when a break was
/// interrupted between its rename and its remove). Best-effort.
pub(crate) fn sweep_debris(dir: &Path, name: &str) {
    let prefix = format!(".{name}.stale.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let is_debris = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(&prefix));
        let old = std::fs::symlink_metadata(entry.path()).is_ok_and(|m| older_than(&m, DEBRIS_AGE));
        if is_debris && old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Last modified more than `age` ago.
fn older_than(meta: &std::fs::Metadata, age: std::time::Duration) -> bool {
    meta.modified()
        .ok()
        .and_then(|m| m.elapsed().ok())
        .is_some_and(|elapsed| elapsed > age)
}

/// An empty regular file last modified over [`STALE_EMPTY_KEY_SECS`] ago.
fn is_stale_empty_meta(meta: &std::fs::Metadata) -> bool {
    meta.is_file()
        && meta.len() == 0
        && older_than(meta, std::time::Duration::from_secs(STALE_EMPTY_KEY_SECS))
}

/// `key` is an empty regular file (not a symlink) older than [`STALE_EMPTY_KEY_SECS`].
fn is_stale_empty_key(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| is_stale_empty_meta(&m))
}

/// `create_new` with mode 0600 on unix.
pub(crate) fn open_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// `create_dir_all` with mode 0700 on unix for the dirs it creates.
pub(crate) fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Write `bytes` to `dir/name` via a unique 0600 temp file in `dir`, fsync, rename.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), EngineError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp: PathBuf = dir.join(format!(".{name}.{}.{nanos}.tmp", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut f = open_new_private(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, dir.join(name))?;
        // Persist the rename itself; best-effort (not every platform can open a dir).
        #[cfg(unix)]
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(Error::from)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
    struct Demo {
        name: String,
        count: u64,
    }

    fn tmp_data(tag: &str) -> DataDir {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "safe_ai_skill_statefile_{tag}_{}_{nanos}",
            std::process::id()
        ));
        DataDir {
            path,
            trusted: true,
        }
    }

    fn demo() -> Demo {
        Demo {
            name: "g1".into(),
            count: 3,
        }
    }

    fn rewrite(dir: &DataDir, name: &str, edit: impl FnOnce(&mut Value)) {
        let p = dir.path.join(name);
        let mut v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        edit(&mut v);
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    #[test]
    fn store_then_load_round_trips() {
        let dir = tmp_data("roundtrip");
        store(&dir, "grants.json", &demo()).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Valid(demo()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn missing_file_is_missing() {
        let dir = tmp_data("missing");
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Missing);
        // Loading never creates the dir or the key.
        assert!(!dir.path.exists());
    }

    #[test]
    fn edited_body_is_tampered() {
        let dir = tmp_data("body");
        store(&dir, "grants.json", &demo()).unwrap();
        rewrite(&dir, "grants.json", |v| v["body"]["count"] = 999.into());
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn edited_mac_is_tampered() {
        let dir = tmp_data("mac");
        store(&dir, "grants.json", &demo()).unwrap();
        rewrite(&dir, "grants.json", |v| {
            let mac = v["mac"].as_str().unwrap().to_string();
            let flipped = if mac.starts_with('0') { "1" } else { "0" };
            v["mac"] = format!("{flipped}{}", &mac[1..]).into();
        });
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn missing_key_with_existing_state_is_tampered() {
        let dir = tmp_data("nokey");
        store(&dir, "mode.json", &demo()).unwrap();
        std::fs::remove_file(dir.path.join(KEY_FILE)).unwrap();
        assert_eq!(load::<Demo>(&dir, "mode.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn body_replayed_under_another_name_is_tampered() {
        let dir = tmp_data("replay");
        store(&dir, "grants.json", &demo()).unwrap();
        std::fs::copy(dir.path.join("grants.json"), dir.path.join("mode.json")).unwrap();
        assert_eq!(load::<Demo>(&dir, "mode.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn plain_unenveloped_json_is_tampered() {
        let dir = tmp_data("plain");
        store(&dir, "other.json", &demo()).unwrap(); // creates the key
        std::fs::write(dir.path.join("grants.json"), r#"{"name":"g1","count":3}"#).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn wrong_version_or_wrong_shape_is_tampered() {
        let dir = tmp_data("version");
        store(&dir, "grants.json", &demo()).unwrap();
        rewrite(&dir, "grants.json", |v| v["v"] = 2.into());
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        // A genuine envelope whose body is not a `Demo`.
        store(&dir, "grants.json", &vec![1, 2, 3]).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn key_is_reused_not_rotated() {
        let dir = tmp_data("reuse");
        store(&dir, "a.json", &demo()).unwrap();
        let key = std::fs::read(dir.path.join(KEY_FILE)).unwrap();
        assert_eq!(key.len(), KEY_LEN);
        store(&dir, "b.json", &demo()).unwrap();
        assert_eq!(std::fs::read(dir.path.join(KEY_FILE)).unwrap(), key);
        assert_eq!(load::<Demo>(&dir, "a.json"), Loaded::Valid(demo()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn malformed_key_is_never_overwritten() {
        let dir = tmp_data("badkey");
        std::fs::create_dir_all(&dir.path).unwrap();
        std::fs::write(dir.path.join(KEY_FILE), b"short").unwrap();
        assert!(store(&dir, "grants.json", &demo()).is_err());
        assert_eq!(std::fs::read(dir.path.join(KEY_FILE)).unwrap(), b"short");
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[cfg(unix)]
    #[test]
    fn key_and_state_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_data("mode");
        store(&dir, "grants.json", &demo()).unwrap();
        for f in [KEY_FILE, "grants.json"] {
            let mode = std::fs::metadata(dir.path.join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
        // No temp file left behind.
        let names: Vec<_> = std::fs::read_dir(&dir.path)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(!names.iter().any(|n| n.ends_with(".tmp")), "{names:?}");
        let mut names = names;
        names.sort();
        assert_eq!(
            names,
            [
                KEY_ERA_MARKER,
                GEN_INDEX,
                "grants.json",
                KEY_FILE,
                "spend.json",
                STATE_LOCK
            ],
            "the first store also starts the spend ledger"
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn restoring_an_older_valid_file_is_tampered() {
        let dir = tmp_data("restore");
        store(&dir, "grants.json", &demo()).unwrap();
        let old = std::fs::read(dir.path.join("grants.json")).unwrap();
        let newer = Demo {
            name: "g1".into(),
            count: 0,
        };
        store(&dir, "grants.json", &newer).unwrap();
        assert_eq!(
            load::<Demo>(&dir, "grants.json"),
            Loaded::Valid(newer.clone())
        );
        std::fs::write(dir.path.join("grants.json"), &old).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        // Storing again moves past both.
        store(&dir, "grants.json", &newer).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Valid(newer));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_missing_or_edited_index_or_generation_is_tampered() {
        let dir = tmp_data("index");
        store(&dir, "grants.json", &demo()).unwrap();
        // Bumping the generation by hand breaks the MAC.
        rewrite(&dir, "grants.json", |v| v["gen"] = 99.into());
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        store(&dir, "grants.json", &demo()).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Valid(demo()));
        // Deleting the index (to make any generation pass) makes every file tampered.
        std::fs::remove_file(dir.path.join(GEN_INDEX)).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        // The index name is not storable from outside.
        assert!(store(&dir, GEN_INDEX, &demo()).is_err());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn bad_names_are_refused() {
        let dir = tmp_data("names");
        for name in ["", "key", "..", "a/b", "a\\b"] {
            assert!(store(&dir, name, &demo()).is_err(), "{name:?}");
            assert_eq!(load::<Demo>(&dir, name), Loaded::Tampered, "{name:?}");
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        let a: Value =
            serde_json::from_str(r#"{"b":1,"a":{"y":[1,{"q":2,"p":"x"}],"x":null}}"#).unwrap();
        let mut out = Vec::new();
        canonical_json(&a, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"{"a":{"x":null,"y":[1,{"p":"x","q":2}]},"b":1}"#
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_key_is_refused() {
        let dir = tmp_data("keylink");
        store(&dir, "grants.json", &demo()).unwrap();
        let real = dir.path.join("real-key");
        std::fs::rename(dir.path.join(KEY_FILE), &real).unwrap();
        std::os::unix::fs::symlink(&real, dir.path.join(KEY_FILE)).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        assert!(store(&dir, "grants.json", &demo()).is_err());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[cfg(unix)]
    #[test]
    fn key_readable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_data("keymode");
        store(&dir, "grants.json", &demo()).unwrap();
        let key = dir.path.join(KEY_FILE);
        for mode in [0o640, 0o604, 0o660] {
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                load::<Demo>(&dir, "grants.json"),
                Loaded::Tampered,
                "{mode:o}"
            );
            assert!(store(&dir, "grants.json", &demo()).is_err(), "{mode:o}");
        }
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Valid(demo()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn key_that_is_not_a_file_is_refused() {
        let dir = tmp_data("keydir");
        store(&dir, "grants.json", &demo()).unwrap();
        std::fs::remove_file(dir.path.join(KEY_FILE)).unwrap();
        std::fs::create_dir(dir.path.join(KEY_FILE)).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        assert!(store(&dir, "grants.json", &demo()).is_err());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn stale_empty_key_from_a_crashed_creation_is_replaced() {
        let dir = tmp_data("stalekey");
        std::fs::create_dir_all(&dir.path).unwrap();
        let key = dir.path.join(KEY_FILE);
        let f = open_new_private(&key).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
        f.set_modified(old).unwrap();
        drop(f);
        store(&dir, "grants.json", &demo()).unwrap();
        assert_eq!(std::fs::read(&key).unwrap().len(), KEY_LEN);
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Valid(demo()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn fresh_empty_key_is_not_replaced() {
        // Another process may be writing it right now.
        let dir = tmp_data("freshkey");
        std::fs::create_dir_all(&dir.path).unwrap();
        drop(open_new_private(&dir.path.join(KEY_FILE)).unwrap());
        assert!(store(&dir, "grants.json", &demo()).is_err());
        assert!(std::fs::read(dir.path.join(KEY_FILE)).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn unresolved_sentinel_loads_nothing_and_refuses_stores() {
        let dir = crate::datadir::unresolved();
        assert!(store(&dir, "grants.json", &demo()).is_err());
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Missing);
    }

    #[cfg(unix)]
    pub(crate) fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_key_is_refused_without_hanging() {
        let dir = tmp_data("keyfifo");
        store(&dir, "grants.json", &demo()).unwrap();
        std::fs::remove_file(dir.path.join(KEY_FILE)).unwrap();
        mkfifo(&dir.path.join(KEY_FILE));
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        assert!(store(&dir, "grants.json", &demo()).is_err());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn stale_key_break_moves_the_file_aside_and_leaves_no_debris() {
        let dir = tmp_data("stalebreak");
        std::fs::create_dir_all(&dir.path).unwrap();
        let key = dir.path.join(KEY_FILE);
        let f = open_new_private(&key).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(120))
            .unwrap();
        drop(f);
        store(&dir, "grants.json", &demo()).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&dir.path)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let mut want = vec![
            KEY_ERA_MARKER,
            GEN_INDEX,
            "grants.json",
            KEY_FILE,
            "spend.json",
        ];
        // The non-unix lock is an O_EXCL file removed on release; the flock file stays.
        if cfg!(unix) {
            want.push(STATE_LOCK);
        }
        assert_eq!(names, want);
        // Breaking a stale file someone else already removed is not an error.
        assert!(break_stale(&dir.path.join("gone"), STALE_LOCK_AGE).is_ok());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    fn set_age(path: &Path, secs: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(secs))
            .unwrap();
    }

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn break_relinks_a_file_that_turned_fresh() {
        // The caller saw a stale lock; by the rename a fresh one had replaced it.
        let dir = tmp_data("relink");
        std::fs::create_dir_all(&dir.path).unwrap();
        let lock = dir.path.join("pending.lock");
        std::fs::write(&lock, b"fresh").unwrap();
        break_stale(&lock, STALE_LOCK_AGE).unwrap();
        assert_eq!(std::fs::read(&lock).unwrap(), b"fresh");
        assert_eq!(names_in(&dir.path), ["pending.lock"]);
        // A genuinely old one is broken.
        set_age(&lock, STALE_LOCK_AGE.as_secs() + 5);
        break_stale(&lock, STALE_LOCK_AGE).unwrap();
        assert!(names_in(&dir.path).is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn key_break_requires_age_as_well_as_emptiness() {
        let dir = tmp_data("keyage");
        std::fs::create_dir_all(&dir.path).unwrap();
        let key = dir.path.join(KEY_FILE);
        drop(open_new_private(&key).unwrap()); // empty but fresh
        break_stale_with(&key, is_stale_empty_meta).unwrap();
        assert!(key.exists(), "a fresh empty key is linked back");
        set_age(&key, STALE_EMPTY_KEY_SECS + 5);
        break_stale_with(&key, is_stale_empty_meta).unwrap();
        assert!(!key.exists());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn old_break_debris_is_swept() {
        let dir = tmp_data("debris");
        std::fs::create_dir_all(&dir.path).unwrap();
        for name in [
            ".key.stale.1.2",
            ".pending.lock.stale.3.4",
            ".key.stale.5.6",
        ] {
            std::fs::write(dir.path.join(name), b"").unwrap();
        }
        set_age(&dir.path.join(".key.stale.1.2"), DEBRIS_AGE.as_secs() + 5);
        set_age(
            &dir.path.join(".pending.lock.stale.3.4"),
            DEBRIS_AGE.as_secs() + 5,
        );
        store(&dir, "grants.json", &demo()).unwrap();
        assert!(!dir.path.join(".key.stale.1.2").exists());
        assert!(
            dir.path.join(".key.stale.5.6").exists(),
            "fresh debris is kept"
        );
        crate::confirm::create_pending(
            &dir,
            crate::confirm::PendingKind::Mode,
            "m",
            serde_json::Value::Null,
        )
        .unwrap();
        assert!(!dir.path.join(".pending.lock.stale.3.4").exists());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_state_file_is_tampered_without_hanging() {
        let dir = tmp_data("statefifo");
        store(&dir, "other.json", &demo()).unwrap();
        mkfifo(&dir.path.join("grants.json"));
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_state_file_is_tampered() {
        // A genuine grants.json moved aside and reached through a symlink: following it would
        // verify (the MAC binds the name, not the inode), so only O_NOFOLLOW refuses it.
        let dir = tmp_data("statelink");
        store(&dir, "grants.json", &demo()).unwrap();
        std::fs::rename(dir.path.join("grants.json"), dir.path.join("stash")).unwrap();
        std::os::unix::fs::symlink(dir.path.join("stash"), dir.path.join("grants.json")).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn directory_or_oversized_state_file_is_tampered() {
        let dir = tmp_data("statesize");
        store(&dir, "other.json", &demo()).unwrap();
        std::fs::create_dir(dir.path.join("grants.json")).unwrap();
        assert_eq!(load::<Demo>(&dir, "grants.json"), Loaded::Tampered);
        // A genuine envelope padded past the cap with whitespace (still valid JSON).
        store(&dir, "big.json", &demo()).unwrap();
        let mut bytes = std::fs::read(dir.path.join("big.json")).unwrap();
        bytes.resize(MAX_STATE_BYTES + 1, b' ');
        std::fs::write(dir.path.join("big.json"), bytes).unwrap();
        assert_eq!(load::<Demo>(&dir, "big.json"), Loaded::Tampered);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    /// Fails its first serialization and succeeds afterwards. serde_yaml accepts everything
    /// serde_json does in practice, so this is how the NaN scan's own failure is exercised
    /// (the scan serializes first).
    struct FailsOnce(std::cell::Cell<bool>);
    impl Serialize for FailsOnce {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            if self.0.replace(true) {
                s.serialize_u8(1)
            } else {
                Err(serde::ser::Error::custom("first serialization fails"))
            }
        }
    }

    #[test]
    fn value_the_nan_scan_cannot_serialize_is_refused_at_store() {
        let dir = tmp_data("unscannable");
        assert!(store(&dir, "b.json", &FailsOnce(std::cell::Cell::new(false))).is_err());
        assert!(!dir.path.join("b.json").exists());
        // Control: once past the scan it would have stored fine.
        assert!(store(&dir, "b.json", &FailsOnce(std::cell::Cell::new(true))).is_ok());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    /// SplitMix64: a deterministic stream for the property tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        /// Finite f64s from three shapes: any bit pattern, decimal-looking amounts, and small
        /// integers' neighbours.
        fn finite_f64(&mut self) -> f64 {
            loop {
                let r = self.next();
                let v = match r % 3 {
                    0 => f64::from_bits(self.next()),
                    1 => (self.next() % 10_000_000_000) as f64 / 1e9,
                    _ => {
                        let base = (self.next() % 1000) as f64;
                        f64::from_bits(base.to_bits().wrapping_add(self.next() % 5))
                    }
                };
                if v.is_finite() {
                    return v;
                }
            }
        }
    }

    fn same_bits(a: f64, b: f64) -> bool {
        a.to_bits() == b.to_bits()
    }

    #[test]
    fn known_bad_f64_round_trips() {
        let dir = tmp_data("f64known");
        for v in [
            1.500_738_000_000_000_1,
            0.1 + 0.2,
            f64::MIN_POSITIVE,
            f64::MAX,
            f64::MIN,
            f64::EPSILON,
            5e-324,
            -0.0,
            2.225_073_858_507_201e-308,
        ] {
            store(&dir, "f.json", &v).unwrap();
            match load::<f64>(&dir, "f.json") {
                Loaded::Valid(got) => assert!(same_bits(got, v), "{v:e} -> {got:e}"),
                other => panic!("{v:e}: {other:?}"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn ten_thousand_random_f64_round_trip() {
        let dir = tmp_data("f64prop");
        let mut rng = Rng(0x5afe_a15c);
        let values: Vec<f64> = (0..10_000).map(|_| rng.finite_f64()).collect();
        store(&dir, "floats.json", &values).unwrap();
        let Loaded::Valid(got) = load::<Vec<f64>>(&dir, "floats.json") else {
            // Find a culprit for the message.
            let bad = values.iter().find(|v| {
                store(&dir, "one.json", v).unwrap();
                !matches!(load::<f64>(&dir, "one.json"), Loaded::Valid(g) if same_bits(g, **v))
            });
            panic!("10k floats did not round-trip; e.g. {bad:?}");
        };
        assert!(values.iter().zip(&got).all(|(a, b)| same_bits(*a, *b)));
        // A sample stored one by one, each its own envelope.
        for v in values.iter().step_by(100) {
            store(&dir, "one.json", v).unwrap();
            match load::<f64>(&dir, "one.json") {
                Loaded::Valid(g) => assert!(same_bits(g, *v), "{v:e} -> {g:e}"),
                other => panic!("{v:e}: {other:?}"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
    struct Ledger {
        total_sol: f64,
        grants: Vec<GrantLike>,
        caps: std::collections::BTreeMap<String, f64>,
    }

    #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
    struct GrantLike {
        id: String,
        max_tx_sol: f64,
        spent: Option<f64>,
        history: Vec<f64>,
    }

    #[test]
    fn nested_structs_with_f64_round_trip() {
        let dir = tmp_data("f64nested");
        let mut rng = Rng(42);
        for round in 0..20 {
            let ledger = Ledger {
                total_sol: rng.finite_f64(),
                grants: (0..10)
                    .map(|i| GrantLike {
                        id: format!("g{round}-{i}"),
                        max_tx_sol: rng.finite_f64(),
                        spent: (i % 2 == 0).then(|| rng.finite_f64()),
                        history: (0..20).map(|_| rng.finite_f64()).collect(),
                    })
                    .collect(),
                caps: (0..5)
                    .map(|i| (format!("c{i}"), rng.finite_f64()))
                    .collect(),
            };
            store(&dir, "ledger.json", &ledger).unwrap();
            assert_eq!(load::<Ledger>(&dir, "ledger.json"), Loaded::Valid(ledger));
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn non_finite_f64_is_refused_at_store() {
        let dir = tmp_data("nonfinite");
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(store(&dir, "f.json", &v).is_err(), "{v}");
            let nested = GrantLike {
                history: vec![1.0, v],
                ..GrantLike::default()
            };
            assert!(store(&dir, "f.json", &nested).is_err(), "{v} nested");
        }
        assert_eq!(load::<f64>(&dir, "f.json"), Loaded::Missing);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex_decode(s).unwrap()
    }

    /// RFC 4231 test cases 1, 2, 3, 4, 6 and 7 (HMAC-SHA-256).
    #[test]
    fn hmac_sha256_matches_rfc4231() {
        let cases: [(Vec<u8>, Vec<u8>, &str); 6] = [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                unhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than \
block-size data. The key needs to be hashed before being used by the HMAC algorithm."
                    .to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, msg, want) in cases {
            assert_eq!(hex_encode(&hmac_sha256(&key, &msg)), want);
        }
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
