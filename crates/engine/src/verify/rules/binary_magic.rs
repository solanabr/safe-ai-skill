//! Binary content (spec D2.4): magic-byte sniffing for archives and executables behind a text
//! extension, native host-arch executables (BPF/SBF `.so` exempt), shipped Python bytecode, and
//! plain archives. Binary files skip every text rule.

use std::path::Path;

use super::context;
use super::{Ctx, FileOut, PackFacts, Severity, Signal};

/// Extensions that promise text; archive or executable bytes behind one are a masquerade.
const TEXT_EXTS: &[&str] = &[
    "md", "markdown", "mdx", "txt", "text", "json", "yaml", "yml", "toml", "csv", "tsv", "xml",
    "html", "htm", "css", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "sh", "bash", "zsh", "rb",
    "rs", "go", "java", "c", "h", "cpp", "ini", "cfg", "conf", "log", "rst", "adoc", "svg", "sql",
    "env", "lock", "ps1", "bat", "cmd",
];
/// ELF machines that never run on a host CPU: eBPF (247) and Solana SBF (263).
const ELF_EXEMPT: &[u16] = &[247, 263];

/// What the first bytes say a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Magic {
    Archive,
    Elf(u16),
    MachO,
    Pe,
    Pyc,
}

fn sniff(h: &[u8]) -> Option<Magic> {
    const ARCHIVES: &[&[u8]] = &[
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"\x1f\x8b",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!",
        b"\xfd7zXZ\x00",
        b"BZh",
        b"\x28\xb5\x2f\xfd",
    ];
    if ARCHIVES.iter().any(|m| h.starts_with(m)) || h.get(257..262) == Some(b"ustar") {
        return Some(Magic::Archive);
    }
    if h.starts_with(b"\x7fELF") && h.len() >= 20 {
        let machine = if h[5] == 2 {
            u16::from_be_bytes([h[18], h[19]])
        } else {
            u16::from_le_bytes([h[18], h[19]])
        };
        return Some(Magic::Elf(machine));
    }
    if matches!(
        h.get(..4),
        Some(b"\xfe\xed\xfa\xce" | b"\xfe\xed\xfa\xcf" | b"\xce\xfa\xed\xfe" | b"\xcf\xfa\xed\xfe")
    ) {
        return Some(Magic::MachO);
    }
    if h.starts_with(b"\xca\xfe\xba\xbe") && h.len() >= 8 {
        // Fat Mach-O counts its architectures here; a Java class file stores its version (≥ 45).
        let n = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        return (n > 0 && n < 0x30).then_some(Magic::MachO);
    }
    if h.starts_with(b"MZ") && h.len() >= 0x40 {
        let off = u32::from_le_bytes([h[0x3c], h[0x3d], h[0x3e], h[0x3f]]);
        if let Ok(off) = usize::try_from(off) {
            if h.get(off..off.saturating_add(4)) == Some(b"PE\0\0") {
                return Some(Magic::Pe);
            }
        }
    }
    if h.len() >= 4 && h[2] == 0x0d && h[3] == 0x0a && matches!(h[1], 0x0b..=0x0e | 0xf3) {
        return Some(Magic::Pyc);
    }
    None
}

/// How a file's bytes are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Content {
    /// Archive, executable, bytecode or other binary data: no text rules.
    Binary,
    /// UTF-8 text (a leading BOM is dropped).
    Utf8,
    /// UTF-16 text announced by its byte-order mark.
    Utf16 { little_endian: bool },
    /// A text or code file carrying NUL bytes: decoded with the NULs stripped.
    TextWithNul,
}

/// Inspect the head of a file and decide how to read it. A known text/code file (or a BOM)
/// without archive/executable magic is always read as text: NUL bytes do not hide a script.
pub(super) fn scan(rel: &Path, head: &[u8], out: &mut FileOut, facts: &mut PackFacts) -> Content {
    let ext = rel
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "pyc" || ext == "pyo" {
        out.emit("bytecode", Severity::High, None, Ctx::Meta);
        facts.pyc.push(rel.to_path_buf());
        return Content::Binary;
    }
    if head.starts_with(&[0xFF, 0xFE]) {
        return Content::Utf16 {
            little_endian: true,
        };
    }
    if head.starts_with(&[0xFE, 0xFF]) {
        return Content::Utf16 {
            little_endian: false,
        };
    }
    let Some(magic) = sniff(head) else {
        if !head.contains(&0) {
            return Content::Utf8;
        }
        if context::is_text_like(rel) || head.starts_with(b"#!") {
            out.emit("nul_bytes", Severity::Warn, None, Ctx::Meta);
            return Content::TextWithNul;
        }
        return Content::Binary;
    };
    if TEXT_EXTS.contains(&ext.as_str()) {
        out.emit("archive_masquerade", Severity::High, None, Ctx::Meta);
        facts.masquerade.push(rel.to_path_buf());
    }
    match magic {
        Magic::Elf(machine) if ELF_EXEMPT.contains(&machine) => {}
        Magic::Elf(_) | Magic::MachO | Magic::Pe => {
            out.emit("native_binary", Severity::High, None, Ctx::Meta);
            out.signal(Signal::NativeBinary, Ctx::Meta);
        }
        Magic::Pyc => {
            out.emit("bytecode", Severity::High, None, Ctx::Meta);
            facts.pyc.push(rel.to_path_buf());
        }
        Magic::Archive => {
            if !TEXT_EXTS.contains(&ext.as_str()) {
                out.emit("archive", Severity::Info, None, Ctx::Meta);
            }
        }
    }
    Content::Binary
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Ctx, Grade, Severity};

    fn elf(machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        b
    }

    #[test]
    fn archive_behind_text_extension_referenced_by_skill_md_blocks() {
        let pack = TempPack::new("masq");
        pack.file(
            "SKILL.md",
            "---\nname: c\ndescription: syncs context\n---\nRun `pandoc --track-changes=all .*.docx -o out.md`\n",
        );
        pack.bytes(
            ".instructions.docx.txt",
            b"PK\x03\x04\x0a\x00\x00\x00\x00\x00word/sync1.sh\x00echo inert\n",
        );
        let r = pack.scan();
        let f = hits(&r, "archive_masquerade");
        assert_eq!((f[0].sev, f[0].ctx), (Severity::High, Ctx::Meta), "{r:?}");
        assert!(combo(&r, "masquerade_referenced").is_some(), "{r:?}");
        assert_eq!(grade(&r), Grade::Block);
    }

    #[test]
    fn unreferenced_masquerade_is_high_only() {
        let pack = TempPack::new("masq-alone");
        pack.file("SKILL.md", "# nothing here\n");
        pack.bytes("notes.txt", b"\x1f\x8b\x08\x00\x00\x00\x00\x00");
        let r = pack.scan();
        assert!(has(&r, "archive_masquerade"), "{r:?}");
        assert!(r.combos.is_empty());
        assert_eq!(grade(&r), Grade::High);
    }

    #[test]
    fn real_archives_are_info() {
        let pack = TempPack::new("zip");
        pack.bytes(
            "skills/deploy.zip",
            b"PK\x03\x04\x0a\x00\x00\x00\x00\x00\x00\x00",
        );
        let r = pack.scan();
        assert!(
            has(&r, "archive") && !has(&r, "archive_masquerade"),
            "{r:?}"
        );
        assert_eq!(grade(&r), Grade::Clean);
    }

    #[test]
    fn pyc_beside_its_source_blocks_lone_pyc_is_high() {
        let pyc: &[u8] =
            b"\xa7\x0d\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe3\x00";
        let pack = TempPack::new("pyc");
        pack.file("scripts/formatter.py", "def fmt(s):\n    return s\n");
        pack.bytes("scripts/__pycache__/formatter.cpython-311.pyc", pyc);
        let r = pack.scan();
        assert!(has(&r, "bytecode"), "{r:?}");
        let c = combo(&r, "pyc_beside_py").expect("pyc_beside_py");
        assert_eq!(
            c.path,
            std::path::PathBuf::from("scripts/__pycache__/formatter.cpython-311.pyc")
        );

        let pack = TempPack::new("pyc-lone");
        pack.bytes("legacy.pyc", pyc);
        let r = pack.scan();
        assert!(has(&r, "bytecode") && r.combos.is_empty(), "{r:?}");
        assert_eq!(grade(&r), Grade::High);
    }

    #[test]
    fn native_executables_block_but_bpf_and_sbf_do_not() {
        let pack = TempPack::new("elf");
        pack.bytes("bin/tool", &elf(62));
        let r = pack.scan();
        assert!(combo(&r, "native_binary").is_some(), "{r:?}");

        let pack = TempPack::new("macho");
        pack.bytes(
            "bin/tool",
            b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00",
        );
        assert!(combo(&pack.scan(), "native_binary").is_some());

        let mut pe = vec![0u8; 0x100];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let pack = TempPack::new("pe");
        pack.bytes("tool.exe", &pe);
        assert!(combo(&pack.scan(), "native_binary").is_some());

        let pack = TempPack::new("bpf");
        pack.bytes("tests/artifacts/amm.so", &elf(247));
        pack.bytes("tests/artifacts/clmm.so", &elf(263));
        pack.bytes(
            "lib/Main.class",
            b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x10",
        );
        let r = pack.scan();
        assert!(r.combos.is_empty(), "{r:?}");
        assert!(!has(&r, "native_binary"), "{r:?}");
    }

    #[cfg(unix)]
    #[test]
    fn executable_bit_is_inventoried() {
        let pack = TempPack::new("execbit");
        pack.file("scripts/run", "echo hi\n");
        pack.exec("scripts/run");
        let r = pack.scan();
        let f = hits(&r, "executable");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::Info, Ctx::Meta, None),
            "{r:?}"
        );
    }
}
