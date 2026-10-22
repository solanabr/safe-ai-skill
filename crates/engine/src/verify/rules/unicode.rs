//! Invisible and bidirectional Unicode (spec D2.4): bidi controls (Trojan Source), zero-width
//! characters and tag characters (invisible ASCII smuggling). WARN in code and metadata; in
//! documentation bidi and zero-width are INFO (emoji joiners, RTL text) and tag characters WARN.

use super::context::Document;
use super::{line_no, Ctx, FileOut, Severity};

pub(super) fn scan_line(doc: &Document<'_>, i: usize, out: &mut FileOut) {
    let line = doc.line(i);
    if line.is_ascii() {
        return;
    }
    let (mut bidi, mut invisible, mut tag) = (false, false, false);
    let mut prev: Option<char> = None;
    let mut in_flag = false;
    let mut chars = line.chars().peekable();
    let mut first = i == 0;
    while let Some(c) = chars.next() {
        match c {
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => bidi = true,
            '\u{E0000}'..='\u{E007F}' => {
                // A subdivision flag is U+1F3F4 followed by tag characters ending in U+E007F.
                if !in_flag {
                    tag = true;
                }
                if c == '\u{E007F}' {
                    in_flag = false;
                }
            }
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{180E}' | '\u{FEFF}' => {
                let leading_bom = c == '\u{FEFF}' && first;
                let next = chars.peek().copied();
                let emoji_join =
                    c == '\u{200D}' && prev.is_some_and(emojiish) && next.is_some_and(emojiish);
                let script_join = c == '\u{200C}'
                    && prev.is_some_and(|p| !p.is_ascii() && p.is_alphabetic())
                    && next.is_some_and(|n| !n.is_ascii() && n.is_alphabetic());
                if !(leading_bom || emoji_join || script_join) {
                    invisible = true;
                }
            }
            '\u{1F3F4}' => in_flag = true,
            _ => in_flag = false,
        }
        prev = Some(c);
        first = false;
    }

    // Invisible characters hide behaviour rather than being one: they warn in code and meta, and
    // whatever they hide is graded by its own rule. In docs only tag characters (smuggled ASCII
    // aimed at the model) warn; bidi and zero-width there are RTL text and emoji joiners.
    let ctx = doc.ctx(i);
    let code = ctx != Ctx::Doc;
    let line = Some(line_no(i));
    let quiet = if code { Severity::Warn } else { Severity::Info };
    if bidi {
        out.emit("unicode_bidi", quiet, line, ctx);
    }
    if invisible {
        out.emit("unicode_invisible", quiet, line, ctx);
    }
    if tag {
        out.emit("unicode_tag", Severity::Warn, line, ctx);
    }
}

/// Pictographs, variation selector 16 and skin tones: the neighbours of an emoji ZWJ.
fn emojiish(c: char) -> bool {
    matches!(
        u32::from(c),
        0x1F000..=0x1FAFF | 0x2190..=0x21FF | 0x2300..=0x23FF | 0x2600..=0x27BF | 0x2B00..=0x2BFF | 0xFE0F
    )
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{Ctx, Severity};

    #[test]
    fn bidi_in_code_warns_and_in_docs_is_info() {
        let r = scan_one("a.js", "let ok = 1;\nif (x /* \u{202E} } \u{2066} */) {}\n");
        let f = hits(&r, "unicode_bidi");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::Warn, Ctx::Code, Some(2))
        );

        let r = scan_one("README.md", "text \u{202E} reversed\n");
        assert_eq!(hits(&r, "unicode_bidi")[0].sev, Severity::Info);
    }

    #[test]
    fn zero_width_in_code_warns() {
        let r = scan_one("a.py", "pass\u{200B}word = 1\n");
        assert_eq!(
            hits(&r, "unicode_invisible")[0].sev,
            Severity::Warn,
            "{r:?}"
        );
    }

    #[test]
    fn tag_characters_in_a_description_frontmatter_warn_as_meta() {
        let hidden: String = "x"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        let r = scan_one("SKILL.md", &format!("---\nname: s{hidden}\n---\n"));
        let f = hits(&r, "unicode_tag");
        assert_eq!((f[0].sev, f[0].ctx), (Severity::Warn, Ctx::Meta), "{r:?}");
    }

    #[test]
    fn emoji_joiners_and_leading_bom_are_ignored() {
        let r = scan_one(
            "a.md",
            "family \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} ok\n",
        );
        assert!(!has(&r, "unicode_invisible"), "{r:?}");
        let r = scan_one("a.js", "\u{FEFF}const a = 1;\n");
        assert!(!has(&r, "unicode_invisible"), "{r:?}");
    }

    #[test]
    fn tag_characters_warn_in_docs_but_flag_sequences_pass() {
        let smuggled: String = "ignore"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        let r = scan_one("SKILL.md", &format!("# Skill\nHello{smuggled}\n"));
        let f = hits(&r, "unicode_tag");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!((f[0].sev, f[0].line), (Severity::Warn, Some(2)));

        let scotland = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        let r = scan_one("a.md", &format!("flag {scotland}\n"));
        assert!(!has(&r, "unicode_tag"), "{r:?}");
    }
}
