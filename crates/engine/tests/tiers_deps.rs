//! Dependency graph findings (issue #11) per tier, through the built binary.
//!
//! Every finding type of the `deps` rule family on a fixture pack, at each tier: the pack is
//! reported (WARN, with the rule id at `path:line`) and never denied, at High included. A
//! changed dependency set is drift: denied below Off, reported at Off, with the report naming
//! the dependency files that moved. The project `.mcp.json`: floating launches are listed
//! (uvx, docker, git, not only npx), a changed launch is reported once, and nothing is denied.
//! Hostile manifests (huge, malformed, deeply nested) finish the sweep, panic-free and bounded.
//! Hermetic: temp HOME and data dir, no network, no package manager ever runs. Tier Off through
//! the binary needs `--features test-hooks`.

mod common;

use common::{permission_decision, Invocation, Run, TempDir, TEST_HOOKS};
use safe_ai_skill::policy::tier::Tier;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn tiers() -> Vec<Tier> {
    let mut all = Vec::new();
    if TEST_HOOKS {
        all.push(Tier::Off);
    }
    all.extend([Tier::Relaxed, Tier::Medium, Tier::High]);
    all
}

struct World {
    project: TempDir,
    home: TempDir,
    data: TempDir,
    plugin: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        let w = World {
            project: TempDir::new(&format!("{tag}-proj")),
            home: TempDir::new(&format!("{tag}-home")),
            data: TempDir::new(&format!("{tag}-data")),
            plugin: TempDir::new(&format!("{tag}-plugin")),
        };
        std::fs::create_dir_all(w.plugin.join("policy")).unwrap();
        std::fs::write(
            w.plugin.join("policy/default.policy.yaml"),
            "version: 1\nsupply_chain:\n  verify_skills_dirs: [ \".claude/skills\" ]\n  \
             verify_ext_submodules: true\n  ext_dir: \".claude/skills/ext\"\n  on_block: deny\n",
        )
        .unwrap();
        w
    }

    fn cwd(&self) -> &str {
        self.project.path().to_str().unwrap()
    }

    fn pack(&self, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = self.project.join(".claude/skills").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), format!("# {name}\n")).unwrap();
        for (rel, body) in files {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        dir
    }

    fn inv<'a>(&'a self, args: &[&str], tier: Tier) -> Invocation<'a> {
        Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .env("CLAUDE_PLUGIN_ROOT", self.plugin.path().to_str().unwrap())
            .tier(tier)
    }

    fn session(&self, tier: Tier) -> Run {
        let run = self
            .inv(&["verify", "session"], tier)
            .stdin(
                serde_json::json!({"hook_event_name": "SessionStart", "source": "startup", "cwd": self.cwd()})
                    .to_string(),
            )
            .run();
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert!(!run.stderr.contains("panicked"), "{}", run.stderr);
        run
    }

    /// `(systemMessage, additionalContext)`.
    fn report(&self, tier: Tier) -> (String, String) {
        let run = self.session(tier);
        if run.stdout.trim().is_empty() {
            return (String::new(), String::new());
        }
        let v = run.json();
        (
            v["systemMessage"].as_str().unwrap_or_default().to_string(),
            v["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    }

    fn decision(&self, sub: &str, tool: &str, input: serde_json::Value, tier: Tier) -> String {
        let run = self
            .inv(&[sub], tier)
            .stdin(
                serde_json::json!({
                    "hook_event_name": "PreToolUse", "session_id": "s", "cwd": self.cwd(),
                    "tool_name": tool, "tool_input": input,
                })
                .to_string(),
            )
            .run();
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        if run.stdout.trim().is_empty() {
            return String::new();
        }
        permission_decision(&run.json()).unwrap_or_default()
    }

    /// The Skill tool, Read and Bash outcome for the pack `name` (`""` = no opinion).
    fn reach(&self, name: &str, tier: Tier) -> [String; 3] {
        let dir = self.project.join(".claude/skills").join(name);
        [
            self.decision(
                "gate-skill",
                "Skill",
                serde_json::json!({"skill": name}),
                tier,
            ),
            self.decision(
                "gate-read",
                "Read",
                serde_json::json!({"file_path": dir.join("SKILL.md")}),
                tier,
            ),
            self.decision(
                "gate-bash-secrets",
                "Bash",
                serde_json::json!({"command": format!("cat {}/SKILL.md", dir.display())}),
                tier,
            ),
        ]
    }
}

fn open() -> [String; 3] {
    [String::new(), String::new(), String::new()]
}

fn denied() -> [String; 3] {
    ["deny".to_string(), "deny".to_string(), "deny".to_string()]
}

/// One fixture pack per finding type: `(pack, rule, path:line it must be reported at, files)`.
/// `(pack, rule, path:line, files)`.
type Fixture = (
    &'static str,
    &'static str,
    &'static str,
    Vec<(&'static str, String)>,
);

fn fixtures() -> Vec<Fixture> {
    vec![
        (
            "build-rs",
            "dep_build_script",
            "Cargo.toml:1",
            vec![
                ("Cargo.toml", "[package]\nname = \"x\"\n".into()),
                ("build.rs", "fn main() {}\n".into()),
            ],
        ),
        (
            "install-script",
            "dep_install_script",
            "package-lock.json:4",
            vec![(
                "package-lock.json",
                "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/esbuild\": {\n      \"resolved\": \"https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz\",\n      \"hasInstallScript\": true\n    }\n  }\n}\n".into(),
            )],
        ),
        (
            "no-lock",
            "dep_lockfile_missing",
            "package.json:2",
            vec![(
                "package.json",
                "{\n  \"dependencies\": { \"left-pad\": \"^1.3.0\" }\n}\n".into(),
            )],
        ),
        (
            "git-lock",
            "dep_nonregistry_source",
            "Cargo.lock:4",
            vec![(
                "Cargo.lock",
                "version = 3\n[[package]]\nname = \"g\"\nsource = \"git+https://github.com/o/g#abc\"\n".into(),
            )],
        ),
        (
            "git-float",
            "dep_floating_source",
            "requirements.txt:1",
            vec![(
                "requirements.txt",
                "git+https://github.com/o/r.git@main#egg=r\n".into(),
            )],
        ),
        (
            "unpinned-req",
            "dep_unpinned",
            "requirements.txt:2",
            vec![("requirements.txt", "requests==2.31.0\nflask>=2\n".into())],
        ),
        (
            "cargo-config",
            "dep_pm_config",
            ".cargo/config.toml:2",
            vec![(
                ".cargo/config.toml",
                "[build]\nrustc-wrapper = \"./w.sh\"\n".into(),
            )],
        ),
        (
            "mcp-float",
            "mcp_unpinned_launch",
            ".mcp.json:3",
            vec![(
                ".mcp.json",
                "{\n  \"mcpServers\": {\n    \"x\": { \"command\": \"npx\", \"args\": [\"-y\", \"some-mcp\"] }\n  }\n}\n".into(),
            )],
        ),
        (
            "bad-lock",
            "dep_unanalysed",
            "package-lock.json",
            vec![("package-lock.json", "{ \"packages\": ".into())],
        ),
        (
            "pinned-ok",
            "",
            "",
            vec![
                (
                    ".mcp.json",
                    "{\"mcpServers\": {\"h\": {\"command\": \"npx\", \"args\": [\"helius-mcp@2.2.0\"]}}}".into(),
                ),
                ("requirements.txt", "requests==2.31.0\nnumpy===1.26.0\n".into()),
            ],
        ),
    ]
}

#[test]
fn every_dependency_finding_is_reported_and_never_denied_at_any_tier() {
    for tier in tiers() {
        let w = World::new(&format!("deps-{tier:?}"));
        for (name, _, _, files) in fixtures() {
            let files: Vec<(&str, &str)> = files.iter().map(|(p, b)| (*p, b.as_str())).collect();
            w.pack(name, &files);
        }
        let (sys, ctx) = w.report(tier);
        for (name, rule, at, _) in fixtures() {
            if rule.is_empty() {
                assert!(
                    !ctx.contains(&format!("`{name}`")),
                    "{name} at {tier:?}: {ctx}"
                );
                assert!(!sys.contains(name), "{name} at {tier:?}: {sys}");
            } else {
                let line = format!(".claude/skills/{name}/{at} {rule} (warn, meta)");
                assert!(ctx.contains(&line), "{line} at {tier:?}:\n{ctx}");
                assert!(
                    sys.contains(&format!("WARN skill .claude/skills/{name}: warnings only")),
                    "{name} at {tier:?}:\n{sys}"
                );
            }
            assert_eq!(w.reach(name, tier), open(), "{name} at {tier:?}");
        }
        assert!(!sys.contains("BLOCK skill"), "{sys}");
        assert!(!sys.contains("tier high denies"), "{sys}");
    }
}

#[test]
fn a_changed_dependency_set_is_drift_named_in_the_report() {
    for tier in tiers() {
        let w = World::new(&format!("deps-drift-{tier:?}"));
        let lock = "{\"lockfileVersion\": 3, \"packages\": {}}";
        let pack = w.pack(
            "drifty",
            &[
                ("package.json", "{\"dependencies\": {\"a\": \"1.0.0\"}}"),
                ("package-lock.json", lock),
            ],
        );
        w.session(tier);
        assert_eq!(w.reach("drifty", tier), open(), "pinned at {tier:?}");
        std::fs::write(
            pack.join("package-lock.json"),
            "{\"lockfileVersion\": 3, \"packages\": {\"node_modules/a\": {\"resolved\": \"https://evil.invalid/a.tgz\"}}}",
        )
        .unwrap();
        std::fs::write(pack.join("Cargo.lock"), "version = 3\n").unwrap();
        let (sys, ctx) = w.report(tier);
        let note =
            "dependency set differs from the pin: added Cargo.lock, changed package-lock.json";
        assert!(sys.contains("BLOCK skill .claude/skills/drifty"), "{sys}");
        assert!(sys.contains(note), "{sys}");
        assert!(ctx.contains(note), "{ctx}");
        let expect = if tier == Tier::Off { open() } else { denied() };
        assert_eq!(w.reach("drifty", tier), expect, "{tier:?}");
        // Blocked drift is listed every session, the dependency detail with it.
        assert!(w.report(tier).0.contains(note));
        assert!(pack.join("package-lock.json").exists(), "never moved");
    }
}

#[test]
fn a_pack_without_dependency_files_drifts_without_a_dependency_note() {
    let w = World::new("deps-plain-drift");
    let pack = w.pack("plain", &[]);
    w.session(Tier::Relaxed);
    std::fs::write(pack.join("SKILL.md"), "# edited\n").unwrap();
    let (sys, _) = w.report(Tier::Relaxed);
    assert!(sys.contains("BLOCK skill .claude/skills/plain"), "{sys}");
    assert!(!sys.contains("dependency set"), "{sys}");
}

#[test]
fn project_mcp_launches_float_are_listed_changes_reported_once_and_nothing_denied() {
    for tier in tiers() {
        let w = World::new(&format!("deps-mcp-{tier:?}"));
        let first = format!(
            "{{\"mcpServers\": {{\n\"helius\": {{\"command\": \"npx\", \"args\": [\"-y\", \"helius-mcp@2.2.0\"]}},\n\"git\": {{\"command\": \"uvx\", \"args\": [\"mcp-server-git\"]}},\n\"gh\": {{\"command\": \"docker\", \"args\": [\"run\", \"-i\", \"--rm\", \"ghcr.io/github/github-mcp-server\"]}},\n\"pinned\": {{\"command\": \"uvx\", \"args\": [\"--from\", \"git+https://github.com/o/r@{SHA}\", \"r\"]}},\n\"remote\": {{\"type\": \"http\", \"url\": \"https://mcp.example.invalid\"}}\n}}}}"
        );
        std::fs::write(w.project.join(".mcp.json"), &first).unwrap();
        let (sys, ctx) = w.report(tier);
        assert!(
            sys.contains("2 MCP server(s) use an unpinned package spec"),
            "{tier:?}: {sys}"
        );
        assert!(ctx.contains("mcp `git` (.mcp.json:3)"), "{ctx}");
        assert!(ctx.contains("mcp `gh` (.mcp.json:4)"), "{ctx}");
        assert!(
            !ctx.contains("mcp `helius`") && !ctx.contains("mcp `pinned`"),
            "{ctx}"
        );
        assert!(
            !sys.contains("launch changed"),
            "first sight is silent: {sys}"
        );

        let second = first.replace("helius-mcp@2.2.0", "helius-mcp@latest");
        let second = second.replace(
            "\"remote\": {\"type\": \"http\", \"url\": \"https://mcp.example.invalid\"}",
            "\"new\": {\"command\": \"pipx\", \"args\": [\"run\", \"x\"]}",
        );
        std::fs::write(w.project.join(".mcp.json"), second).unwrap();
        let (sys, ctx) = w.report(tier);
        for text in [&sys, &ctx] {
            assert!(
                text.contains("server launch changed since the last session"),
                "{text}"
            );
            assert!(
                text.contains("`helius` `npx -y helius-mcp@2.2.0` -> `npx -y helius-mcp@latest`"),
                "{text}"
            );
            assert!(text.contains("`new` added: `pipx run x`"), "{text}");
            assert!(text.contains("`remote` removed"), "{text}");
        }
        let (sys, _) = w.report(tier);
        assert!(!sys.contains("launch changed"), "reported once: {sys}");
        // No MCP tool is denied for it, at any tier.
        for tool in ["mcp__git__git_status", "mcp__helius__getBalance"] {
            assert_eq!(
                w.decision("gate-mcp", tool, serde_json::json!({}), tier),
                "",
                "{tool} at {tier:?}"
            );
        }
    }
}

#[test]
fn verify_check_prints_the_dependency_inventory() {
    let w = World::new("deps-check");
    let pack = w.pack(
        "inv",
        &[
            ("package.json", "{}"),
            ("crate/Cargo.toml", "[package]\nname = \"c\"\n"),
            ("node_modules/x/package.json", "{}"),
        ],
    );
    let run = w
        .inv(&["verify", "check", pack.to_str().unwrap()], Tier::Relaxed)
        .run();
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let v = run.json();
    let files: Vec<&str> = v["dependencies"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(files, vec!["crate/Cargo.toml", "package.json"]);
    assert_eq!(v["dependencies"]["fingerprint"].as_str().unwrap().len(), 64);
    let kinds: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"dep_manifest"), "{kinds:?}");
}

#[test]
fn hostile_manifests_are_bounded_and_panic_free() {
    let w = World::new("deps-hostile");
    let huge = format!(
        "{{\"packages\": {{\"node_modules/a\": {{\"resolved\": \"{}\"}}}}}}",
        "x".repeat(9 * 1024 * 1024)
    );
    let nested_json = "[".repeat(200_000);
    let nested_toml = format!("[package]\nname = {}\n", "[".repeat(200_000));
    let unclosed = format!("[dependencies]\na = \"\"\"\n{}", "b = 1\n".repeat(100_000));
    let binaryish: String = (0..4096u32)
        .map(|i| char::from_u32(i % 0xD7FF + 1).unwrap_or('x'))
        .collect();
    w.pack(
        "hostile",
        &[
            ("package-lock.json", &huge),
            ("a/package-lock.json", &nested_json),
            ("a/package.json", &nested_json),
            ("b/Cargo.toml", &nested_toml),
            ("c/Cargo.toml", &unclosed),
            ("d/pnpm-lock.yaml", &binaryish),
            ("e/yarn.lock", &"resolved \"".repeat(50_000)),
            ("f/requirements.txt", &"\\\n".repeat(100_000)),
            ("g/go.mod", &"replace (\n".repeat(50_000)),
            (
                "h/.mcp.json",
                &format!(
                    "{{\"mcpServers\": {{\"x\": {{\"command\": \"npx\", \"args\": [{}\"y\"]}}}}}}",
                    "\"-y\",".repeat(50_000)
                ),
            ),
            ("i/poetry.lock", &"[[package]]\n".repeat(50_000)),
        ],
    );
    let started = Instant::now();
    let (_, ctx) = w.report(Tier::High);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
    assert!(!ctx.contains("BLOCK skill"), "{ctx}");
    // Bounded and safe: the pack is either fully scanned (WARN, open at every tier) or the scan
    // deadline cut it on a slow host (unscanned: denied, fail closed). Never anything else.
    let cut = ctx.contains("scan_budget_exceeded");
    assert!(cut || ctx.contains("WARN skill `hostile`"), "{ctx}");
    let expect = if cut { denied() } else { open() };
    assert_eq!(w.reach("hostile", Tier::High), expect, "{ctx}");
    let dir = w.project.join(".claude/skills/hostile");
    let run = w
        .inv(&["verify", "check", dir.to_str().unwrap()], Tier::High)
        .run();
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let v = run.json();
    let unanalysed: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "dep_unanalysed")
        .map(|f| f["path"].as_str().unwrap_or_default().to_string())
        .collect();
    for path in ["package-lock.json", "a/package-lock.json"] {
        assert!(
            unanalysed.iter().any(|p| p == path),
            "{path}: {unanalysed:?}"
        );
    }
}

#[test]
fn upgrade_rehearsal_pinned_packs_without_deps_json_deny_nothing_and_get_recorded() {
    let w = World::new("deps-upgrade");
    let names = ["lockfiles", "crate", "plain"];
    w.pack(
        "lockfiles",
        &[
            ("package.json", "{\"dependencies\": {\"a\": \"1.0.0\"}}"),
            (
                "package-lock.json",
                "{\"lockfileVersion\": 3, \"packages\": {}}",
            ),
        ],
    );
    w.pack(
        "crate",
        &[
            ("Cargo.toml", "[package]\nname = \"c\"\n"),
            ("Cargo.lock", ""),
        ],
    );
    w.pack("plain", &[]);
    // Pin every pack, then remove deps.json: the state a pre-#11 install upgrades from.
    w.session(Tier::High);
    let deps = w.data.join("deps.json");
    assert!(deps.exists());
    std::fs::remove_file(&deps).unwrap();
    for tier in tiers() {
        let (sys, ctx) = w.report(tier);
        assert!(
            !sys.contains("BLOCK skill") && !ctx.contains("scan_budget_exceeded"),
            "{sys}"
        );
        assert!(!sys.contains("dependency set"), "{sys}");
        for name in names {
            assert_eq!(w.reach(name, tier), open(), "{name} at {tier:?}");
        }
        assert!(deps.exists(), "recorded afresh at {tier:?}");
    }
    // A tampered deps.json is the same: recorded afresh, nothing denied for unchanged packs.
    std::fs::write(&deps, "{\"v\":1,\"gen\":1,\"mac\":\"00\",\"body\":{}}").unwrap();
    let (sys, _) = w.report(Tier::High);
    assert!(!sys.contains("BLOCK skill"), "{sys}");
    for name in names {
        assert_eq!(w.reach(name, Tier::High), open(), "{name}");
    }
}
