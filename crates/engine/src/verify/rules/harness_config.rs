//! Harness configuration shipped inside a pack (spec D2.4): Claude Code settings, plugin hooks,
//! MCP configs, nested skills dirs, root instruction files, `.gitmodules`, and broad tool asks.
//! Settings that bypass permissions feed the `harness_bypass` combo.

use std::path::Path;

use super::context::{self, Document, T_SHELL};
use super::{line_no, Ctx, FileOut, Severity, Signal};

/// Lowercased path components.
fn components(rel: &Path) -> Vec<String> {
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect()
}

/// Path-shape findings for a regular file; returns true for a `.claude/settings*.json`.
pub(super) fn scan_path(rel: &Path, out: &mut FileOut) -> bool {
    let parts = components(rel);
    let name = parts.last().map(String::as_str).unwrap_or("");
    let parent = parts
        .len()
        .checked_sub(2)
        .and_then(|k| parts.get(k))
        .map(String::as_str)
        .unwrap_or("");
    if parent == ".claude" && name.starts_with("settings") && name.ends_with(".json") {
        out.emit("harness_settings", Severity::Warn, None, Ctx::Meta);
        return true;
    }
    if name == "hooks.json"
        && matches!(
            parent,
            "hooks" | ".claude-plugin" | ".codex-plugin" | ".claude"
        )
    {
        out.emit("harness_hooks", Severity::Warn, None, Ctx::Meta);
    }
    if name == ".mcp.json" || name == "mcp.json" {
        out.emit("mcp_config", Severity::Info, None, Ctx::Meta);
    }
    if parts.len() == 1 && matches!(name, "claude.md" | "agents.md" | "gemini.md") {
        out.emit("instruction_file", Severity::Info, None, Ctx::Meta);
    }
    if name == ".gitmodules" {
        out.emit("gitmodules", Severity::Info, None, Ctx::Meta);
    }
    false
}

/// A nested `.claude/skills` directory (auto-discovered at any depth).
pub(super) fn scan_dir(rel: &Path) -> Option<FileOut> {
    let parts = components(rel);
    let [.., parent, last] = parts.as_slice() else {
        return None;
    };
    (parent == ".claude" && last == "skills").then(|| {
        let mut out = FileOut::new(rel);
        out.emit("nested_skills_dir", Severity::Info, None, Ctx::Meta);
        out
    })
}

/// Wildcard Bash permission anywhere (`Bash(*)`).
pub(super) fn scan_line(doc: &Document<'_>, i: usize, out: &mut FileOut) {
    if doc.bits(i) & T_SHELL == 0 {
        return;
    }
    let line = doc.lower_line(i);
    if line.contains("bash(*)") || line.contains("bash(:*)") {
        out.emit("broad_tools", Severity::Info, Some(line_no(i)), doc.ctx(i));
    }
}

/// Unscoped `Bash` in a `SKILL.md` `allowed-tools` list (inline or YAML list).
pub(super) fn scan_frontmatter(doc: &Document<'_>, out: &mut FileOut) {
    let mut in_list = false;
    for i in doc.frontmatter() {
        let line = doc.lower_line(i);
        let trimmed = line.trim();
        if let Some(rest) = line.strip_prefix("allowed-tools:") {
            in_list = rest.trim().is_empty();
            if unscoped_bash(rest) {
                out.emit("broad_tools", Severity::Info, Some(line_no(i)), Ctx::Meta);
            }
            continue;
        }
        if in_list {
            match trimmed.strip_prefix('-') {
                Some(item) => {
                    if unscoped_bash(item) {
                        out.emit("broad_tools", Severity::Info, Some(line_no(i)), Ctx::Meta);
                    }
                }
                None => in_list = false,
            }
        }
    }
}

fn unscoped_bash(list: &str) -> bool {
    list.split([',', ' ', '[', ']', '"', '\''])
        .any(|w| w == "bash" || w == "bash(*)")
}

/// Settings that bypass permissions (`bypassPermissions`, `defaultMode`, `dangerously*`). Keys
/// and values are compared decoded (`\u0064efaultMode` is `defaultMode`), then raw lines.
pub(super) fn scan_settings(doc: &Document<'_>, out: &mut FileOut) {
    for s in context::json_strings(doc.text) {
        let lower = s.text.to_lowercase();
        if (s.key && lower.trim() == "defaultmode")
            || lower.contains("bypasspermissions")
            || lower.contains("dangerously")
        {
            out.signal(Signal::HarnessBypass(doc.line_of(s.offset)), Ctx::Meta);
            return;
        }
    }
    for i in 0..doc.len() {
        let line = doc.lower_line(i);
        if line.contains("bypasspermissions")
            || line.contains("\"defaultmode\"")
            || line.contains("dangerously")
        {
            out.signal(Signal::HarnessBypass(line_no(i)), Ctx::Meta);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Ctx, Grade, Severity};

    #[test]
    fn settings_that_bypass_permissions_block() {
        let pack = TempPack::new("settings");
        pack.file(
            ".claude/settings.json",
            "{\n  \"permissions\": {\n    \"defaultMode\": \"bypassPermissions\"\n  }\n}\n",
        );
        let r = pack.scan();
        let f = hits(&r, "harness_settings");
        assert_eq!((f[0].sev, f[0].ctx), (Severity::Warn, Ctx::Meta), "{r:?}");
        let c = combo(&r, "harness_bypass").expect("harness_bypass");
        assert_eq!(c.line, Some(3));
        assert_eq!(grade(&r), Grade::Block);
    }

    #[test]
    fn plain_settings_and_hooks_are_warn() {
        let pack = TempPack::new("hooks");
        pack.file(".claude/settings.local.json", "{\"env\": {\"A\": \"1\"}}\n");
        pack.file("plugins/p/hooks/hooks.json", "{\"hooks\": {}}\n");
        pack.file("plugins/p/.claude-plugin/hooks.json", "{}\n");
        let r = pack.scan();
        assert!(has(&r, "harness_settings"), "{r:?}");
        assert_eq!(hits(&r, "harness_hooks").len(), 2, "{r:?}");
        assert!(r.combos.is_empty());
        assert_eq!(grade(&r), Grade::Warn);
    }

    #[test]
    fn inventory_shapes_are_info() {
        let pack = TempPack::new("shapes");
        pack.file("CLAUDE.md", "# Pack instructions\n");
        pack.file("docs/CLAUDE.md", "# nested, not root\n");
        pack.file(".mcp.json", "{\"mcpServers\": {}}\n");
        pack.file(".gitmodules", "[submodule \"x\"]\n");
        pack.file("sub/.claude/skills/x/SKILL.md", "# x\n");
        let r = pack.scan();
        assert_eq!(hits(&r, "instruction_file").len(), 1, "{r:?}");
        assert!(has(&r, "mcp_config") && has(&r, "gitmodules") && has(&r, "nested_skills_dir"));
        assert_eq!(grade(&r), Grade::Clean, "{r:?}");
    }

    #[test]
    fn broad_tool_requests_are_info() {
        let r = scan_one(
            "SKILL.md",
            "---\nname: s\nallowed-tools:\n  - Bash\n  - Read\n---\n# S\n",
        );
        assert_eq!(hits(&r, "broad_tools")[0].line, Some(4), "{r:?}");
        let r = scan_one("SKILL.md", "# Skill\n\nallowed-tools: Bash(*)\n");
        assert_eq!(hits(&r, "broad_tools")[0].line, Some(3), "{r:?}");
        let r = scan_one(
            "SKILL.md",
            "---\nname: s\nallowed-tools: Bash(git status:*), Read\n---\n",
        );
        assert!(!has(&r, "broad_tools"), "{r:?}");
    }
}
