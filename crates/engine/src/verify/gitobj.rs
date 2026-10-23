//! Read-only git object store reader for untrusted pack trees (#10).
//!
//! A pack's repository is hostile input: git is never run on it (its config can name programs
//! git then executes), so objects are read straight from `.git/objects` — loose objects and
//! packfiles (`.idx` v1/v2 plus `.pack` v2/v3, OFS and REF deltas), zlib-inflated with
//! `miniz_oxide`. Every read is bounded:
//!
//! * files are opened without following a final symlink and without blocking (a planted FIFO or
//!   device fails), and only regular files are read, each with a size cap;
//! * an object larger than [`Limits::max_object`] is [`Error::TooLarge`], never inflated;
//! * inflated bytes, objects visited and wall-clock time are charged to one [`Budget`]; once any
//!   is spent every further read is [`Error::Budget`];
//! * delta chains stop at [`MAX_DELTA_DEPTH`] (a REF delta cycle ends there), OFS bases must lie
//!   before their delta, and every copy/insert is bounds-checked against the declared sizes.
//!
//! Malformed input is [`Error::Corrupt`] or [`Error::Missing`]; nothing here panics on it.
//! SHA-256 repositories and object alternates are reported by [`Repo::open`], not read.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;

/// A SHA-1 object id.
pub type ObjectId = [u8; 20];

/// Longest delta chain followed (git's default `pack.depth` is 50).
pub const MAX_DELTA_DEPTH: usize = 128;
/// Largest `.idx` file read.
const MAX_IDX_BYTES: u64 = 256 * 1024 * 1024;
/// Largest small metadata file read (`.git` gitdir file, `HEAD`, a loose ref, `commondir`).
const MAX_SMALL_FILE: u64 = 4096;
/// Largest `packed-refs` or `config` read.
const MAX_META_FILE: u64 = 16 * 1024 * 1024;
/// Resolved pack objects kept for delta bases.
const CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Longest object header (`"commit 18446744073709551615\0"`).
const MAX_HEADER: usize = 32;

/// Object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl Kind {
    fn from_pack(code: u8) -> Option<Kind> {
        match code {
            1 => Some(Kind::Commit),
            2 => Some(Kind::Tree),
            3 => Some(Kind::Blob),
            4 => Some(Kind::Tag),
            _ => None,
        }
    }

    fn from_name(name: &[u8]) -> Option<Kind> {
        match name {
            b"commit" => Some(Kind::Commit),
            b"tree" => Some(Kind::Tree),
            b"blob" => Some(Kind::Blob),
            b"tag" => Some(Kind::Tag),
            _ => None,
        }
    }
}

/// Why an object could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not in this store (a thin pack's REF base, a shallow clone's parent).
    Missing,
    /// Malformed bytes: the reason names what failed.
    Corrupt(&'static str),
    /// Larger than [`Limits::max_object`].
    TooLarge,
    /// The [`Budget`] is spent.
    Budget,
}

/// Caps one history scan works under.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Inflated bytes (objects and delta bases, each time one is produced).
    pub max_bytes: u64,
    /// Objects enumerated or read.
    pub max_objects: u64,
    /// Largest single object.
    pub max_object: usize,
    /// Wall-clock end (`None`: unbounded).
    pub deadline: Option<Instant>,
}

/// What a scan has spent against its [`Limits`].
#[derive(Debug)]
pub struct Budget {
    pub limits: Limits,
    pub bytes: u64,
    pub objects: u64,
    /// Which cap ran out first (`"bytes"`, `"objects"`, `"time"`).
    pub spent: Option<&'static str>,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Budget {
            limits,
            bytes: 0,
            objects: 0,
            spent: None,
        }
    }

    fn fail(&mut self, what: &'static str) -> Error {
        self.spent.get_or_insert(what);
        Error::Budget
    }

    /// Charge `n` inflated bytes.
    pub fn bytes(&mut self, n: usize) -> Result<(), Error> {
        self.check()?;
        self.bytes = self.bytes.saturating_add(n as u64);
        if self.bytes > self.limits.max_bytes {
            return Err(self.fail("bytes"));
        }
        Ok(())
    }

    /// Charge one object.
    pub fn object(&mut self) -> Result<(), Error> {
        self.check()?;
        self.objects = self.objects.saturating_add(1);
        if self.objects > self.limits.max_objects {
            return Err(self.fail("objects"));
        }
        Ok(())
    }

    /// `Err` once any cap is spent (reads the clock).
    pub fn check(&mut self) -> Result<(), Error> {
        if self.spent.is_some() {
            return Err(Error::Budget);
        }
        if self.limits.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(self.fail("time"));
        }
        Ok(())
    }
}

/// One object's content.
#[derive(Debug, Clone)]
pub struct Object {
    pub kind: Kind,
    pub data: Rc<[u8]>,
}

/// Open `path` for reading only if it is a regular file: no final symlink, no blocking on a FIFO
/// or device (the type is taken from the open handle).
fn open_regular(path: &Path) -> std::io::Result<(File, u64)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok((file, meta.len()))
}

/// `path` in full when it is a regular file of at most `cap` bytes.
pub fn read_regular(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let (file, len) = open_regular(path).ok()?;
    if len > cap {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= cap).then_some(bytes)
}

/// True when `path` is a real directory (not a symlink to one).
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Parse 40 lowercase-or-uppercase hex digits.
pub fn parse_hex(hex: &[u8]) -> Option<ObjectId> {
    if hex.len() != 40 {
        return None;
    }
    let mut id = [0u8; 20];
    for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        id[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(id)
}

/// Lowercase hex of `id`.
pub fn hex(id: &ObjectId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inflate a zlib stream from the start of `input` into exactly `size` bytes.
fn inflate_exact(input: &[u8], size: usize) -> Result<Vec<u8>, Error> {
    // One spare byte: a stream that ends exactly at `size` reports done, not "more output".
    let out =
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(input, size.saturating_add(1))
            .map_err(|_| Error::Corrupt("zlib stream"))?;
    if out.len() != size {
        return Err(Error::Corrupt("inflated size differs from the header"));
    }
    Ok(out)
}

/// A repository's object store, located from a pack root.
pub struct Repo {
    /// The `.git` directory (a worktree's or submodule's own, holding `HEAD`).
    pub git_dir: PathBuf,
    /// Where `objects/`, `refs/` and `packed-refs` live (`commondir`, or `git_dir`).
    pub common_dir: PathBuf,
    /// Conditions that leave part of the history unread (alternates), for the report.
    pub notes: Vec<String>,
}

impl Repo {
    /// The repository whose `.git` sits directly in `root`. `Ok(None)` when there is none;
    /// `Err` with a reason when there is one that cannot be read safely.
    pub fn open(root: &Path) -> Result<Option<Repo>, String> {
        let dot = root.join(".git");
        let meta = match std::fs::symlink_metadata(&dot) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };
        let git_dir = if meta.file_type().is_symlink() {
            return Err("`.git` is a symlink (not followed)".into());
        } else if meta.is_dir() {
            dot
        } else {
            let body = read_regular(&dot, MAX_SMALL_FILE).ok_or("`.git` file is unreadable")?;
            let text = String::from_utf8_lossy(&body);
            let target = text
                .lines()
                .next()
                .and_then(|l| l.strip_prefix("gitdir:"))
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .ok_or("`.git` file has no `gitdir:` line")?;
            root.join(target)
        };
        if !is_real_dir(&git_dir) {
            return Err("git directory is missing or a symlink".into());
        }
        let common_dir = match read_regular(&git_dir.join("commondir"), MAX_SMALL_FILE) {
            Some(body) => {
                let text = String::from_utf8_lossy(&body);
                git_dir.join(text.trim())
            }
            None => git_dir.clone(),
        };
        if !is_real_dir(&common_dir.join("objects")) {
            return Err("objects directory is missing or a symlink".into());
        }
        if let Some(config) = read_regular(&common_dir.join("config"), MAX_META_FILE) {
            let lower = String::from_utf8_lossy(&config).to_ascii_lowercase();
            if lower
                .lines()
                .any(|l| l.split_whitespace().collect::<String>() == "objectformat=sha256")
            {
                return Err("SHA-256 object format is not supported".into());
            }
        }
        let mut notes = Vec::new();
        if std::fs::symlink_metadata(common_dir.join("objects/info/alternates")).is_ok() {
            notes.push("objects/info/alternates is not followed".into());
        }
        Ok(Some(Repo {
            git_dir,
            common_dir,
            notes,
        }))
    }

    /// The commit `HEAD` names (through at most a few symbolic refs), if it resolves.
    pub fn head(&self) -> Option<ObjectId> {
        let mut body = read_regular(&self.git_dir.join("HEAD"), MAX_SMALL_FILE)?;
        for _ in 0..5 {
            let text = String::from_utf8_lossy(&body).trim().to_string();
            let Some(name) = text.strip_prefix("ref:").map(str::trim) else {
                return parse_hex(text.as_bytes());
            };
            if !name.starts_with("refs/")
                || name
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return None;
            }
            match read_regular(&self.common_dir.join(name), MAX_SMALL_FILE) {
                Some(next) => body = next,
                None => return self.packed_ref(name),
            }
        }
        None
    }

    fn packed_ref(&self, name: &str) -> Option<ObjectId> {
        let body = read_regular(&self.common_dir.join("packed-refs"), MAX_META_FILE)?;
        body.split(|&b| b == b'\n').find_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let (hex, rest) = (line.get(..40)?, line.get(40..)?);
            (rest.first() == Some(&b' ') && &rest[1..] == name.as_bytes())
                .then(|| parse_hex(hex))
                .flatten()
        })
    }
}

/// Where an object lives.
#[derive(Debug, Clone, Copy)]
enum Loc {
    Loose,
    Packed { pack: u32, offset: u64 },
}

/// One packfile and its index.
struct Pack {
    file: File,
    len: u64,
    /// Entry offsets, sorted: an entry ends where the next begins (or at the trailer).
    offsets: Vec<u64>,
}

/// A pack entry's header.
struct Entry {
    code: u8,
    size: u64,
    /// Where the zlib stream starts.
    data: u64,
    /// Where the entry ends.
    end: u64,
    base: Option<Base>,
}

enum Base {
    Offset(u64),
    Id(ObjectId),
}

/// The object store: every object id found, and how to read it.
pub struct Store {
    objects_dir: PathBuf,
    packs: Vec<Pack>,
    index: HashMap<ObjectId, Loc>,
    cache: HashMap<(u32, u64), Object>,
    cache_bytes: usize,
    /// Pack or index files that could not be used, for the report.
    pub skipped: Vec<String>,
}

impl Store {
    /// Enumerate the loose objects and pack indexes under `repo`'s objects directory. Each id
    /// enumerated is charged to `budget`; when it runs out the store holds what was found.
    pub fn open(repo: &Repo, budget: &mut Budget) -> Store {
        let objects_dir = repo.common_dir.join("objects");
        let mut store = Store {
            objects_dir,
            packs: Vec::new(),
            index: HashMap::new(),
            cache: HashMap::new(),
            cache_bytes: 0,
            skipped: Vec::new(),
        };
        store.load_packs(budget);
        store.load_loose(budget);
        store
    }

    /// Every object id found, sorted.
    pub fn ids(&self) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = self.index.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    pub fn contains(&self, id: &ObjectId) -> bool {
        self.index.contains_key(id)
    }

    fn load_loose(&mut self, budget: &mut Budget) {
        let Ok(dirs) = std::fs::read_dir(&self.objects_dir) else {
            return;
        };
        let mut dirs: Vec<_> = dirs.flatten().collect();
        dirs.sort_by_key(|d| d.file_name());
        for dir in dirs {
            let name = dir.file_name();
            let Some(prefix) = name.to_str().filter(|n| n.len() == 2) else {
                continue;
            };
            if !dir.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(dir.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let file = entry.file_name();
                let Some(rest) = file.to_str().filter(|n| n.len() == 38) else {
                    continue;
                };
                let Some(id) = parse_hex(format!("{prefix}{rest}").as_bytes()) else {
                    continue;
                };
                if self.index.contains_key(&id) {
                    continue;
                }
                if budget.object().is_err() {
                    return;
                }
                self.index.insert(id, Loc::Loose);
            }
        }
    }

    fn load_packs(&mut self, budget: &mut Budget) {
        let pack_dir = self.objects_dir.join("pack");
        let Ok(entries) = std::fs::read_dir(&pack_dir) else {
            return;
        };
        let mut idx_files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "idx"))
            .collect();
        idx_files.sort();
        for idx_path in idx_files {
            let label = idx_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match self.load_pack(&idx_path, budget) {
                Ok(()) => {}
                Err(Error::Budget) => return,
                Err(_) => self.skipped.push(label),
            }
        }
    }

    fn load_pack(&mut self, idx_path: &Path, budget: &mut Budget) -> Result<(), Error> {
        let idx =
            read_regular(idx_path, MAX_IDX_BYTES).ok_or(Error::Corrupt("index unreadable"))?;
        let entries = parse_idx(&idx)?;
        let (mut file, len) = open_regular(&idx_path.with_extension("pack"))
            .map_err(|_| Error::Corrupt("pack unreadable"))?;
        let mut head = [0u8; 12];
        file.read_exact(&mut head)
            .map_err(|_| Error::Corrupt("pack header"))?;
        let version = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
        let count = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
        if &head[..4] != b"PACK" || !(2..=3).contains(&version) || count as usize != entries.len() {
            return Err(Error::Corrupt("pack header"));
        }
        let trailer_at = len
            .checked_sub(20)
            .ok_or(Error::Corrupt("pack too short"))?;
        if entries
            .iter()
            .any(|&(_, off)| off < 12 || off >= trailer_at)
        {
            return Err(Error::Corrupt("index offset outside the pack"));
        }
        let pack = u32::try_from(self.packs.len()).map_err(|_| Error::Corrupt("too many packs"))?;
        let mut offsets: Vec<u64> = entries.iter().map(|&(_, off)| off).collect();
        offsets.sort_unstable();
        offsets.dedup();
        self.packs.push(Pack { file, len, offsets });
        for (id, offset) in entries {
            budget.object()?;
            self.index.entry(id).or_insert(Loc::Packed { pack, offset });
        }
        Ok(())
    }

    /// An object's type and size, without inflating its content where avoidable.
    pub fn info(&mut self, id: &ObjectId, budget: &mut Budget) -> Result<(Kind, u64), Error> {
        budget.check()?;
        match self.index.get(id).copied().ok_or(Error::Missing)? {
            Loc::Loose => self.loose_header(id),
            Loc::Packed { pack, offset } => self.packed_info(pack, offset, budget),
        }
    }

    /// Read one object in full (charged to `budget`).
    pub fn read(&mut self, id: &ObjectId, budget: &mut Budget) -> Result<Object, Error> {
        budget.object()?;
        match self.index.get(id).copied().ok_or(Error::Missing)? {
            Loc::Loose => self.read_loose(id, budget),
            Loc::Packed { pack, offset } => self.read_packed(pack, offset, budget),
        }
    }

    fn loose_path(&self, id: &ObjectId) -> PathBuf {
        let h = hex(id);
        self.objects_dir.join(&h[..2]).join(&h[2..])
    }

    /// Compressed bytes allowed for a loose object (deflate grows stored data slightly).
    fn loose_cap(max_object: usize) -> u64 {
        let raw = max_object as u64 + MAX_HEADER as u64;
        raw + raw / 64 + 4096
    }

    fn loose_header(&mut self, id: &ObjectId) -> Result<(Kind, u64), Error> {
        let (file, _) = open_regular(&self.loose_path(id)).map_err(|_| Error::Missing)?;
        let mut head = Vec::new();
        file.take(1024)
            .read_to_end(&mut head)
            .map_err(|_| Error::Corrupt("loose object unreadable"))?;
        let out = match miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&head, MAX_HEADER) {
            Ok(out) => out,
            Err(e) => e.output,
        };
        let (kind, size, _) = parse_header(&out)?;
        Ok((kind, size))
    }

    fn read_loose(&mut self, id: &ObjectId, budget: &mut Budget) -> Result<Object, Error> {
        let max = budget.limits.max_object;
        let (file, len) = open_regular(&self.loose_path(id)).map_err(|_| Error::Missing)?;
        if len > Self::loose_cap(max) {
            return Err(Error::TooLarge);
        }
        let (kind, size) = self.loose_header(id)?;
        let size = usize::try_from(size).map_err(|_| Error::TooLarge)?;
        if size > max {
            return Err(Error::TooLarge);
        }
        let mut raw = Vec::new();
        file.take(len)
            .read_to_end(&mut raw)
            .map_err(|_| Error::Corrupt("loose object unreadable"))?;
        let header_len = format!("{} {size}", kind_name(kind)).len() + 1;
        let total = header_len.checked_add(size).ok_or(Error::TooLarge)?;
        budget.bytes(total)?;
        let out = inflate_exact(&raw, total)?;
        let (k2, s2, body) = parse_header(&out)?;
        if k2 != kind || s2 as usize != size || body != header_len {
            return Err(Error::Corrupt("loose object header"));
        }
        Ok(Object {
            kind,
            data: Rc::from(&out[body..]),
        })
    }

    fn entry(&mut self, pack: u32, offset: u64) -> Result<Entry, Error> {
        let p = self
            .packs
            .get_mut(pack as usize)
            .ok_or(Error::Corrupt("pack index"))?;
        let trailer_at = p.len.saturating_sub(20);
        let at = p.offsets.partition_point(|&o| o <= offset);
        let end = p.offsets.get(at).copied().unwrap_or(trailer_at);
        if offset >= end || end > trailer_at {
            return Err(Error::Corrupt("pack entry bounds"));
        }
        let mut head = [0u8; 32];
        let want = usize::try_from((end - offset).min(32)).unwrap_or(32);
        p.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| p.file.read_exact(&mut head[..want]))
            .map_err(|_| Error::Corrupt("pack read"))?;
        let head = &head[..want];
        let mut pos = 0usize;
        let mut byte = *head.get(pos).ok_or(Error::Corrupt("pack entry header"))?;
        pos += 1;
        let code = (byte >> 4) & 7;
        let mut size = u64::from(byte & 0x0f);
        let mut shift = 4u32;
        while byte & 0x80 != 0 {
            byte = *head.get(pos).ok_or(Error::Corrupt("pack entry header"))?;
            pos += 1;
            if shift > 57 {
                return Err(Error::Corrupt("pack entry size"));
            }
            size |= u64::from(byte & 0x7f) << shift;
            shift += 7;
        }
        let base = match code {
            6 => {
                let mut byte = *head.get(pos).ok_or(Error::Corrupt("ofs delta"))?;
                pos += 1;
                let mut back = u64::from(byte & 0x7f);
                while byte & 0x80 != 0 {
                    byte = *head.get(pos).ok_or(Error::Corrupt("ofs delta"))?;
                    pos += 1;
                    back = back
                        .checked_add(1)
                        .and_then(|b| b.checked_mul(128))
                        .map(|b| b | u64::from(byte & 0x7f))
                        .ok_or(Error::Corrupt("ofs delta"))?;
                }
                let base = offset
                    .checked_sub(back)
                    .filter(|_| back > 0)
                    .ok_or(Error::Corrupt("ofs delta base"))?;
                Some(Base::Offset(base))
            }
            7 => {
                let raw = head.get(pos..pos + 20).ok_or(Error::Corrupt("ref delta"))?;
                pos += 20;
                let mut id = [0u8; 20];
                id.copy_from_slice(raw);
                Some(Base::Id(id))
            }
            1..=4 => None,
            _ => return Err(Error::Corrupt("pack entry type")),
        };
        Ok(Entry {
            code,
            size,
            data: offset + pos as u64,
            end,
            base,
        })
    }

    /// Inflate an entry's zlib stream (its declared size, at most `max_object`).
    fn inflate_entry(
        &mut self,
        pack: u32,
        entry: &Entry,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, Error> {
        let size = usize::try_from(entry.size).map_err(|_| Error::TooLarge)?;
        if size > budget.limits.max_object {
            return Err(Error::TooLarge);
        }
        let comp = entry.end.saturating_sub(entry.data);
        let cap = Self::loose_cap(budget.limits.max_object);
        if comp > cap {
            return Err(Error::Corrupt("pack entry larger than its content allows"));
        }
        let p = self
            .packs
            .get_mut(pack as usize)
            .ok_or(Error::Corrupt("pack index"))?;
        let mut raw = vec![0u8; usize::try_from(comp).map_err(|_| Error::TooLarge)?];
        p.file
            .seek(SeekFrom::Start(entry.data))
            .and_then(|_| p.file.read_exact(&mut raw))
            .map_err(|_| Error::Corrupt("pack read"))?;
        budget.bytes(size)?;
        inflate_exact(&raw, size)
    }

    fn packed_info(
        &mut self,
        pack: u32,
        offset: u64,
        budget: &mut Budget,
    ) -> Result<(Kind, u64), Error> {
        let first = self.entry(pack, offset)?;
        let mut size = first.size;
        if first.base.is_some() {
            // A delta's result size is the second varint of its data.
            let head = self.delta_head(pack, &first)?;
            size = head;
        }
        let (mut pack, mut entry) = (pack, first);
        for _ in 0..=MAX_DELTA_DEPTH {
            budget.check()?;
            match entry.base.take() {
                None => {
                    let kind =
                        Kind::from_pack(entry.code).ok_or(Error::Corrupt("pack entry type"))?;
                    return Ok((kind, size));
                }
                Some(Base::Offset(base)) => entry = self.entry(pack, base)?,
                Some(Base::Id(id)) => match self.index.get(&id).copied().ok_or(Error::Missing)? {
                    Loc::Loose => return self.loose_header(&id).map(|(k, _)| (k, size)),
                    Loc::Packed { pack: p, offset } => {
                        pack = p;
                        entry = self.entry(p, offset)?;
                    }
                },
            }
        }
        Err(Error::Corrupt("delta chain too deep"))
    }

    /// The result size a delta entry declares, from the first bytes of its inflated data.
    fn delta_head(&mut self, pack: u32, entry: &Entry) -> Result<u64, Error> {
        let p = self
            .packs
            .get_mut(pack as usize)
            .ok_or(Error::Corrupt("pack index"))?;
        let want = usize::try_from(entry.end.saturating_sub(entry.data).min(4096)).unwrap_or(4096);
        let mut raw = vec![0u8; want];
        p.file
            .seek(SeekFrom::Start(entry.data))
            .and_then(|_| p.file.read_exact(&mut raw))
            .map_err(|_| Error::Corrupt("pack read"))?;
        let out = match miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&raw, 32) {
            Ok(out) => out,
            Err(e) => e.output,
        };
        let (_, pos) = varint(&out, 0)?;
        let (result, _) = varint(&out, pos)?;
        Ok(result)
    }

    fn read_packed(
        &mut self,
        pack: u32,
        offset: u64,
        budget: &mut Budget,
    ) -> Result<Object, Error> {
        // Walk down to a base (or a cached object), keeping each delta on the way.
        let mut chain: Vec<((u32, u64), Vec<u8>)> = Vec::new();
        let (mut pack_at, mut off_at) = (pack, offset);
        let base: Object = loop {
            budget.check()?;
            if let Some(hit) = self.cache.get(&(pack_at, off_at)) {
                break hit.clone();
            }
            if chain.len() > MAX_DELTA_DEPTH {
                return Err(Error::Corrupt("delta chain too deep"));
            }
            let entry = self.entry(pack_at, off_at)?;
            let data = self.inflate_entry(pack_at, &entry, budget)?;
            match entry.base {
                None => {
                    let kind =
                        Kind::from_pack(entry.code).ok_or(Error::Corrupt("pack entry type"))?;
                    let obj = Object {
                        kind,
                        data: Rc::from(data),
                    };
                    self.remember((pack_at, off_at), &obj);
                    break obj;
                }
                Some(Base::Offset(b)) => {
                    chain.push(((pack_at, off_at), data));
                    off_at = b;
                }
                Some(Base::Id(id)) => {
                    chain.push(((pack_at, off_at), data));
                    match self.index.get(&id).copied().ok_or(Error::Missing)? {
                        Loc::Loose => break self.read_loose(&id, budget)?,
                        Loc::Packed { pack: p, offset: o } => {
                            pack_at = p;
                            off_at = o;
                        }
                    }
                }
            }
        };
        let mut current = base;
        while let Some((at, delta)) = chain.pop() {
            let data = apply_delta(&current.data, &delta, budget.limits.max_object)?;
            budget.bytes(data.len())?;
            current = Object {
                kind: current.kind,
                data: Rc::from(data),
            };
            self.remember(at, &current);
        }
        Ok(current)
    }

    fn remember(&mut self, at: (u32, u64), obj: &Object) {
        if obj.data.len() > CACHE_BYTES / 4 {
            return;
        }
        if self.cache_bytes + obj.data.len() > CACHE_BYTES {
            self.cache.clear();
            self.cache_bytes = 0;
        }
        self.cache_bytes += obj.data.len();
        self.cache.insert(at, obj.clone());
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Commit => "commit",
        Kind::Tree => "tree",
        Kind::Blob => "blob",
        Kind::Tag => "tag",
    }
}

/// `(kind, size, body offset)` of a loose object's `"<type> <size>\0"` header.
fn parse_header(bytes: &[u8]) -> Result<(Kind, u64, usize), Error> {
    let nul = bytes
        .iter()
        .take(MAX_HEADER)
        .position(|&b| b == 0)
        .ok_or(Error::Corrupt("object header"))?;
    let head = &bytes[..nul];
    let space = head
        .iter()
        .position(|&b| b == b' ')
        .ok_or(Error::Corrupt("object header"))?;
    let kind = Kind::from_name(&head[..space]).ok_or(Error::Corrupt("object type"))?;
    let digits = &head[space + 1..];
    if digits.is_empty()
        || digits.len() > 20
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits[0] == b'0')
    {
        return Err(Error::Corrupt("object size"));
    }
    let size = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(Error::Corrupt("object size"))?;
    Ok((kind, size, nul + 1))
}

/// `(id, offset)` of every entry of a pack index (v1 or v2).
fn parse_idx(idx: &[u8]) -> Result<Vec<(ObjectId, u64)>, Error> {
    let be32 = |at: usize| -> Result<u32, Error> {
        idx.get(at..at + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or(Error::Corrupt("index truncated"))
    };
    let id_at = |at: usize| -> Result<ObjectId, Error> {
        let mut id = [0u8; 20];
        id.copy_from_slice(
            idx.get(at..at + 20)
                .ok_or(Error::Corrupt("index truncated"))?,
        );
        Ok(id)
    };
    let v2 = idx.starts_with(b"\xfftOc");
    let fanout = if v2 {
        if be32(4)? != 2 {
            return Err(Error::Corrupt("index version"));
        }
        8
    } else {
        0
    };
    let mut prev = 0u32;
    for i in 0..256 {
        let v = be32(fanout + i * 4)?;
        if v < prev {
            return Err(Error::Corrupt("index fanout"));
        }
        prev = v;
    }
    let n = prev as usize;
    let table = fanout + 1024;
    let mut out = Vec::with_capacity(n.min(idx.len() / 24));
    if v2 {
        let need = n
            .checked_mul(28)
            .and_then(|b| b.checked_add(table + 40))
            .ok_or(Error::Corrupt("index size"))?;
        if idx.len() < need {
            return Err(Error::Corrupt("index truncated"));
        }
        let off32 = table + n * 24;
        let off64 = table + n * 28;
        for i in 0..n {
            let id = id_at(table + i * 20)?;
            let raw = be32(off32 + i * 4)?;
            let offset = if raw & 0x8000_0000 != 0 {
                let at = off64 + (raw & 0x7fff_ffff) as usize * 8;
                let b = idx
                    .get(at..at + 8)
                    .ok_or(Error::Corrupt("index large offset"))?;
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            } else {
                u64::from(raw)
            };
            out.push((id, offset));
        }
    } else {
        let need = n
            .checked_mul(24)
            .and_then(|b| b.checked_add(table + 40))
            .ok_or(Error::Corrupt("index size"))?;
        if idx.len() < need {
            return Err(Error::Corrupt("index truncated"));
        }
        for i in 0..n {
            let at = table + i * 24;
            out.push((id_at(at + 4)?, u64::from(be32(at)?)));
        }
    }
    Ok(out)
}

/// A delta header varint: `(value, next position)`.
fn varint(bytes: &[u8], mut pos: usize) -> Result<(u64, usize), Error> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(pos).ok_or(Error::Corrupt("delta header"))?;
        pos += 1;
        if shift > 63 {
            return Err(Error::Corrupt("delta header"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, pos));
        }
    }
}

/// Apply a git delta to `base`. The result may not exceed `max` bytes; every copy and insert is
/// checked against the base and the declared result size.
pub fn apply_delta(base: &[u8], delta: &[u8], max: usize) -> Result<Vec<u8>, Error> {
    let (base_len, pos) = varint(delta, 0)?;
    let (result_len, mut pos) = varint(delta, pos)?;
    if base_len != base.len() as u64 {
        return Err(Error::Corrupt("delta base size"));
    }
    let result_len = usize::try_from(result_len).map_err(|_| Error::TooLarge)?;
    if result_len > max {
        return Err(Error::TooLarge);
    }
    let mut out = Vec::with_capacity(result_len);
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    let b = *delta.get(pos).ok_or(Error::Corrupt("delta copy"))?;
                    pos += 1;
                    offset |= usize::from(b) << (8 * bit);
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    let b = *delta.get(pos).ok_or(Error::Corrupt("delta copy"))?;
                    pos += 1;
                    size |= usize::from(b) << (8 * bit);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let chunk = offset
                .checked_add(size)
                .and_then(|end| base.get(offset..end))
                .ok_or(Error::Corrupt("delta copy outside the base"))?;
            if out.len() + chunk.len() > result_len {
                return Err(Error::Corrupt("delta overruns its result"));
            }
            out.extend_from_slice(chunk);
        } else if op != 0 {
            let n = usize::from(op);
            let chunk = delta
                .get(pos..pos + n)
                .ok_or(Error::Corrupt("delta insert"))?;
            pos += n;
            if out.len() + n > result_len {
                return Err(Error::Corrupt("delta overruns its result"));
            }
            out.extend_from_slice(chunk);
        } else {
            return Err(Error::Corrupt("delta opcode 0"));
        }
    }
    if out.len() != result_len {
        return Err(Error::Corrupt("delta result size"));
    }
    Ok(out)
}

/// One tree entry.
#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: String,
    pub id: ObjectId,
}

impl TreeEntry {
    pub fn is_tree(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }

    /// A regular file (not a symlink or submodule).
    pub fn is_file(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }

    pub fn is_executable(&self) -> bool {
        self.is_file() && self.mode & 0o111 != 0
    }
}

/// Parse a tree object. Names that could step out of the tree (`.`, `..`, `/`) or that git
/// itself refuses (`.git`) are rejected as corrupt.
pub fn parse_tree(data: &[u8]) -> Result<Vec<TreeEntry>, Error> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let space = data[pos..]
            .iter()
            .take(8)
            .position(|&b| b == b' ')
            .ok_or(Error::Corrupt("tree mode"))?;
        let mode_digits = &data[pos..pos + space];
        if mode_digits.is_empty() || !mode_digits.iter().all(|b| (b'0'..=b'7').contains(b)) {
            return Err(Error::Corrupt("tree mode"));
        }
        let mode = mode_digits
            .iter()
            .fold(0u32, |m, &d| m * 8 + u32::from(d - b'0'));
        pos += space + 1;
        let nul = data[pos..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::Corrupt("tree name"))?;
        let name = &data[pos..pos + nul];
        if name.is_empty()
            || name == b"."
            || name == b".."
            || name.contains(&b'/')
            || name.eq_ignore_ascii_case(b".git")
        {
            return Err(Error::Corrupt("tree name"));
        }
        pos += nul + 1;
        let raw = data.get(pos..pos + 20).ok_or(Error::Corrupt("tree id"))?;
        pos += 20;
        let mut id = [0u8; 20];
        id.copy_from_slice(raw);
        entries.push(TreeEntry {
            mode,
            name: String::from_utf8_lossy(name).into_owned(),
            id,
        });
    }
    Ok(entries)
}

/// The fields of a commit the history scan uses.
#[derive(Debug, Clone)]
pub struct Commit {
    pub tree: ObjectId,
    pub parents: Vec<ObjectId>,
    /// Committer time (seconds), 0 when absent.
    pub time: i64,
    /// First line of the message.
    pub subject: String,
}

/// Parse a commit object.
pub fn parse_commit(data: &[u8]) -> Result<Commit, Error> {
    let mut tree = None;
    let mut parents = Vec::new();
    let mut time = 0i64;
    let mut pos = 0usize;
    loop {
        let end = data[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|n| pos + n)
            .unwrap_or(data.len());
        let line = &data[pos..end];
        pos = (end + 1).min(data.len());
        if line.is_empty() {
            break;
        }
        if let Some(hex) = line.strip_prefix(b"tree ") {
            tree = Some(parse_hex(hex).ok_or(Error::Corrupt("commit tree"))?);
        } else if let Some(hex) = line.strip_prefix(b"parent ") {
            parents.push(parse_hex(hex).ok_or(Error::Corrupt("commit parent"))?);
        } else if let Some(rest) = line.strip_prefix(b"committer ") {
            let text = String::from_utf8_lossy(rest);
            time = text
                .rsplit(' ')
                .nth(1)
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
        }
        if end >= data.len() {
            break;
        }
    }
    let message = data.get(pos..).unwrap_or(&[]);
    let subject_end = message
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(message.len());
    Ok(Commit {
        tree: tree.ok_or(Error::Corrupt("commit without tree"))?,
        parents,
        time,
        subject: String::from_utf8_lossy(&message[..subject_end.min(1024)])
            .trim()
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(base_len: usize, result_len: usize, ops: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        for mut v in [base_len, result_len] {
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    d.push(b);
                    break;
                }
                d.push(b | 0x80);
            }
        }
        d.extend_from_slice(ops);
        d
    }

    #[test]
    fn delta_copy_and_insert() {
        let base = b"hello world";
        // copy offset 0 size 5, insert "!!"
        let d = delta(base.len(), 7, &[0x90, 5, 2, b'!', b'!']);
        assert_eq!(apply_delta(base, &d, 100).unwrap(), b"hello!!");
    }

    #[test]
    fn hostile_deltas_are_errors_not_panics() {
        let base = b"abc";
        // Wrong base size.
        assert!(apply_delta(base, &delta(4, 1, &[1, b'x']), 100).is_err());
        // Copy past the base.
        assert!(apply_delta(base, &delta(3, 2, &[0x91, 2, 2]), 100).is_err());
        // Insert running off the delta.
        assert!(apply_delta(base, &delta(3, 5, &[5, b'x']), 100).is_err());
        // Result larger than declared.
        assert!(apply_delta(base, &delta(3, 1, &[2, b'x', b'y']), 100).is_err());
        // Result larger than the cap.
        assert_eq!(
            apply_delta(base, &delta(3, 1 << 30, &[]), 1024),
            Err(Error::TooLarge)
        );
        // Opcode 0, truncated header, overlong varint.
        assert!(apply_delta(base, &delta(3, 1, &[0]), 100).is_err());
        assert!(apply_delta(base, &[0x80], 100).is_err());
        assert!(apply_delta(base, &[0xff; 20], 100).is_err());
        // A huge copy offset does not overflow.
        assert!(apply_delta(base, &delta(3, 1, &[0x9f, 0xff, 0xff, 0xff, 0xff, 1]), 100).is_err());
    }

    #[test]
    fn headers_and_trees_reject_garbage() {
        assert!(parse_header(b"blob 3\0abc").is_ok());
        for bad in [
            &b"blob\0"[..],
            b"blob x\0",
            b"blob 01\0",
            b"weird 1\0",
            b"blob 1",
        ] {
            assert!(parse_header(bad).is_err(), "{bad:?}");
        }
        let mut tree = b"100644 a.txt\0".to_vec();
        tree.extend_from_slice(&[7u8; 20]);
        assert_eq!(parse_tree(&tree).unwrap()[0].name, "a.txt");
        for name in [&b".."[..], b".git", b"a/b", b""] {
            let mut t = b"100644 ".to_vec();
            t.extend_from_slice(name);
            t.push(0);
            t.extend_from_slice(&[7u8; 20]);
            assert!(parse_tree(&t).is_err());
        }
        assert!(parse_tree(b"100644 a\0short").is_err());
        assert!(parse_tree(b"10x644 a\0").is_err());
        assert!(parse_commit(b"author x\n\nmsg").is_err());
        assert!(parse_idx(&[0u8; 10]).is_err());
        let mut idx = vec![0xff, b't', b'O', b'c', 0, 0, 0, 2];
        idx.extend_from_slice(&[0xff; 1024]);
        assert!(parse_idx(&idx).is_err());
    }

    #[test]
    fn budget_trips_once_and_stays_spent() {
        let mut b = Budget::new(Limits {
            max_bytes: 10,
            max_objects: 1,
            max_object: 10,
            deadline: None,
        });
        assert!(b.bytes(10).is_ok());
        assert_eq!(b.bytes(1), Err(Error::Budget));
        assert_eq!(b.spent, Some("bytes"));
        assert_eq!(b.object(), Err(Error::Budget));
        assert_eq!(b.spent, Some("bytes"));
    }

    /// A pack entry for [`synthetic_repo`]: id, type code, base, raw payload, declared size.
    struct Raw {
        id: ObjectId,
        code: u8,
        base: Option<SynthBase>,
        payload: Vec<u8>,
        declared: Option<u64>,
    }

    enum SynthBase {
        /// Distance back to the base entry.
        Back(u64),
        Id(ObjectId),
    }

    /// A `.git` with one hand-built pack (no checksums: the reader does not verify them).
    fn synthetic_repo(tag: &str, entries: &[Raw]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "gitobj-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let pack_dir = root.join(".git/objects/pack");
        std::fs::create_dir_all(&pack_dir).unwrap();
        let mut pack = b"PACK".to_vec();
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        let mut offsets = Vec::new();
        for e in entries {
            offsets.push(pack.len() as u64);
            let mut size = e.declared.unwrap_or(e.payload.len() as u64);
            let mut byte = (e.code << 4) | (size & 0x0f) as u8;
            size >>= 4;
            while size > 0 {
                pack.push(byte | 0x80);
                byte = (size & 0x7f) as u8;
                size >>= 7;
            }
            pack.push(byte);
            match &e.base {
                Some(SynthBase::Back(n)) => pack.push(*n as u8 & 0x7f),
                Some(SynthBase::Id(id)) => pack.extend_from_slice(id),
                None => {}
            }
            pack.extend_from_slice(&miniz_oxide::deflate::compress_to_vec_zlib(&e.payload, 6));
        }
        pack.extend_from_slice(&[0u8; 20]);
        let mut sorted: Vec<(ObjectId, u64)> = entries.iter().map(|e| e.id).zip(offsets).collect();
        sorted.sort();
        let mut idx = b"\xfftOc".to_vec();
        idx.extend_from_slice(&2u32.to_be_bytes());
        for b in 0..256usize {
            let n = sorted
                .iter()
                .filter(|(id, _)| usize::from(id[0]) <= b)
                .count();
            idx.extend_from_slice(&(n as u32).to_be_bytes());
        }
        for (id, _) in &sorted {
            idx.extend_from_slice(id);
        }
        idx.extend_from_slice(&vec![0u8; sorted.len() * 4]);
        for (_, off) in &sorted {
            idx.extend_from_slice(&(*off as u32).to_be_bytes());
        }
        idx.extend_from_slice(&[0u8; 40]);
        std::fs::write(pack_dir.join("pack-t.pack"), pack).unwrap();
        std::fs::write(pack_dir.join("pack-t.idx"), idx).unwrap();
        root
    }

    fn limits() -> Limits {
        Limits {
            max_bytes: 1 << 30,
            max_objects: 1 << 20,
            max_object: 1 << 20,
            deadline: Instant::now().checked_add(std::time::Duration::from_secs(30)),
        }
    }

    fn open(root: &Path) -> (Store, Budget) {
        let repo = Repo::open(root).unwrap().unwrap();
        let mut budget = Budget::new(limits());
        let store = Store::open(&repo, &mut budget);
        assert!(store.skipped.is_empty(), "{:?}", store.skipped);
        (store, budget)
    }

    #[test]
    fn synthetic_pack_resolves_ofs_and_ref_deltas() {
        let base = b"hello world".to_vec();
        let d = delta(base.len(), 7, &[0x90, 5, 2, b'!', b'!']);
        let d2 = delta(7, 3, &[0x90, 3]);
        let root = synthetic_repo(
            "ok",
            &[
                Raw {
                    id: [1; 20],
                    code: 3,
                    base: None,
                    payload: base,
                    declared: None,
                },
                Raw {
                    id: [2; 20],
                    code: 6,
                    base: Some(SynthBase::Back(0)),
                    payload: d,
                    declared: None,
                },
                Raw {
                    id: [3; 20],
                    code: 7,
                    base: Some(SynthBase::Id([2; 20])),
                    payload: d2,
                    declared: None,
                },
            ],
        );
        // Fix the OFS distance now that the first entry's length is known.
        let pack_path = root.join(".git/objects/pack/pack-t.pack");
        let (store, _) = open(&root);
        let first_two = store.packs[0].offsets.clone();
        drop(store);
        let mut bytes = std::fs::read(&pack_path).unwrap();
        let at = usize::try_from(first_two[1]).unwrap() + 1;
        bytes[at] = u8::try_from(first_two[1] - first_two[0]).unwrap();
        std::fs::write(&pack_path, bytes).unwrap();

        let (mut store, mut budget) = open(&root);
        assert_eq!(
            &*store.read(&[2; 20], &mut budget).unwrap().data,
            b"hello!!"
        );
        let third = store.read(&[3; 20], &mut budget).unwrap();
        assert_eq!((third.kind, &*third.data), (Kind::Blob, &b"hel"[..]));
        assert_eq!(store.info(&[3; 20], &mut budget).unwrap(), (Kind::Blob, 3));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ref_delta_cycles_and_bad_bases_end_in_errors() {
        let d = delta(3, 3, &[3, b'a', b'b', b'c']);
        let root = synthetic_repo(
            "cycle",
            &[
                // Its own base.
                Raw {
                    id: [1; 20],
                    code: 7,
                    base: Some(SynthBase::Id([1; 20])),
                    payload: d.clone(),
                    declared: None,
                },
                // Two deltas based on each other.
                Raw {
                    id: [2; 20],
                    code: 7,
                    base: Some(SynthBase::Id([3; 20])),
                    payload: d.clone(),
                    declared: None,
                },
                Raw {
                    id: [3; 20],
                    code: 7,
                    base: Some(SynthBase::Id([2; 20])),
                    payload: d.clone(),
                    declared: None,
                },
                // A base that is not in the store (a thin pack).
                Raw {
                    id: [4; 20],
                    code: 7,
                    base: Some(SynthBase::Id([9; 20])),
                    payload: d.clone(),
                    declared: None,
                },
                // An OFS delta pointing at itself (distance 0).
                Raw {
                    id: [5; 20],
                    code: 6,
                    base: Some(SynthBase::Back(0)),
                    payload: d,
                    declared: None,
                },
                // A blob declaring 1 GiB, and a reserved type code.
                Raw {
                    id: [6; 20],
                    code: 3,
                    base: None,
                    payload: b"x".to_vec(),
                    declared: Some(1 << 30),
                },
                Raw {
                    id: [7; 20],
                    code: 5,
                    base: None,
                    payload: b"x".to_vec(),
                    declared: None,
                },
            ],
        );
        let (mut store, mut budget) = open(&root);
        for id in 1..=3u8 {
            assert_eq!(
                store.read(&[id; 20], &mut budget).unwrap_err(),
                Error::Corrupt("delta chain too deep"),
                "{id}"
            );
            assert!(store.info(&[id; 20], &mut budget).is_err());
        }
        assert_eq!(
            store.read(&[4; 20], &mut budget).unwrap_err(),
            Error::Missing
        );
        assert!(matches!(
            store.read(&[5; 20], &mut budget),
            Err(Error::Corrupt(_))
        ));
        assert_eq!(
            store.read(&[6; 20], &mut budget).unwrap_err(),
            Error::TooLarge
        );
        assert!(matches!(
            store.read(&[7; 20], &mut budget),
            Err(Error::Corrupt(_))
        ));
        // The cycles were bounded work: far under the budget.
        assert!(budget.bytes < 4096, "{}", budget.bytes);
        let _ = std::fs::remove_dir_all(&root);
    }
}
