//! `add skill|mcp|repo <source>` through the built binary: argument parsing, how a source is
//! classified, when the add holds, and the install command (`run`) it prints.
//!
//! No test reaches the internet: a remote source is either `--offline`, one `add` never looks
//! up (a local directory, an unrecognised source), or, in `test-hooks` builds, looked up on a
//! loopback server that stands in for the npm registry, the GitHub API and osv.dev.

mod common;

use common::{Invocation, Run, TempDir};

/// `name` and `version` joined with `@`, built at runtime (avoids fixture mangling).
fn at(name: &str, version: &str) -> String {
    format!("{name}{}{version}", '@')
}

struct World {
    root: TempDir,
    home: TempDir,
    data: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        World {
            root: TempDir::new(&format!("{tag}-root")),
            home: TempDir::new(&format!("{tag}-home")),
            data: TempDir::new(&format!("{tag}-data")),
        }
    }

    fn invoke<'a>(&'a self, args: &[&str]) -> Invocation<'a> {
        let mut all = vec!["add"];
        all.extend_from_slice(args);
        Invocation::new(&all)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.root.path())
    }

    /// Run `add <args>` (exit 0 expected) and parse its JSON.
    fn add(&self, args: &[&str]) -> serde_json::Value {
        let run = self.invoke(args).run();
        assert_eq!(
            run.code,
            Some(0),
            "{args:?}\n{}\n{}",
            run.stdout,
            run.stderr
        );
        run.json()
    }
}

/// `(kind, severity)` of each finding.
fn findings(v: &serde_json::Value) -> Vec<(String, String)> {
    v["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("no findings: {v}"))
        .iter()
        .map(|f| {
            (
                f["kind"].as_str().unwrap_or("").to_string(),
                f["severity"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn pair(kind: &str, severity: &str) -> (String, String) {
    (kind.to_string(), severity.to_string())
}

#[test]
fn an_unrecognised_source_holds_until_yes() {
    let w = World::new("add-other");
    for source in [
        "https://gitlab.com/org/repo",
        "https://example.com/skill.tgz",
    ] {
        let v = w.add(&["skill", source]);
        assert_eq!(
            (&v["status"], &v["verdict"], &v["source_kind"]),
            (
                &serde_json::json!("warn_hold"),
                &serde_json::json!("warn"),
                &serde_json::json!("other")
            ),
            "{v}"
        );
        assert_eq!(
            findings(&v),
            vec![pair("unrecognised_source", "medium")],
            "{v}"
        );
        assert!(v["run"].is_null(), "{v}");
        let v = w.add(&["skill", source, "--yes"]);
        assert_eq!(v["status"], "warn_proceed", "{v}");
        assert_eq!(v["run"], format!("npx skills add {source}"), "{v}");
        assert!(
            v["run_note"]
                .as_str()
                .is_some_and(|n| n.contains("not pinned")),
            "{v}"
        );
    }
}

#[test]
fn a_spoofed_github_host_holds() {
    let w = World::new("add-spoof");
    let sha = "a".repeat(40);
    let spoof = format!("https://evil.example/github.com/a/b/commit/{sha}");
    let v = w.add(&["skill", &spoof]);
    assert_eq!(v["status"], "warn_hold", "{v}");
    assert_eq!(v["source_kind"], "other", "{v}");
    assert_eq!(
        findings(&v),
        vec![pair("unrecognised_source", "medium")],
        "{v}"
    );
}

#[test]
fn owner_repo_is_github() {
    let w = World::new("add-shorthand");
    let v = w.add(&["skill", "owner/repo", "--offline"]);
    assert_eq!(v["source_kind"], "github", "{v}");
    assert_eq!(v["status"], "warn_hold", "{v}");
    assert_eq!(findings(&v), vec![pair("unpinned_ref", "medium")], "{v}");
    let v = w.add(&["skill", "owner/repo", "--offline", "--yes"]);
    assert_eq!(v["run"], "npx skills add owner/repo", "{v}");

    let sha = "b".repeat(40);
    let pinned = at("owner/repo", &sha);
    let v = w.add(&["skill", &pinned, "--offline"]);
    assert_eq!(
        (&v["status"], &v["pin"]),
        (&serde_json::json!("pass"), &serde_json::json!(sha)),
        "{v}"
    );
    assert_eq!(v["run"], format!("npx skills add {pinned}"), "{v}");
}

#[test]
fn a_github_commit_url_prints_the_commit_not_the_url() {
    let w = World::new("add-commit");
    let sha = "c".repeat(40);
    let url = format!("https://github.com/o/r/commit/{sha}");
    let v = w.add(&["skill", &url]);
    assert_eq!(v["status"], "pass", "{v}");
    assert_eq!(
        v["run"],
        format!("npx skills add {}", at("o/r", &sha)),
        "{v}"
    );
    let v = w.add(&["repo", &url]);
    assert_eq!(
        v["run"],
        format!("git clone https://github.com/o/r.git r && git -C r checkout --detach {sha}"),
        "{v}"
    );
}

#[test]
fn a_local_dot_is_a_directory_not_npm() {
    let w = World::new("add-dot");
    std::fs::write(w.root.join("SKILL.md"), "# clean\n").unwrap();
    for source in [".", "./"] {
        let v = w.add(&["skill", source, "--offline"]);
        assert_eq!(v["source_kind"], "local", "{v}");
        assert!(v["state"].is_string(), "not scanned: {v}");
        assert_eq!(v["provenance"], serde_json::json!([]), "{v}");
        assert_eq!(v["status"], "pass", "{v}");
        assert_eq!(v["run"], format!("npx skills add {source}"), "{v}");
    }
}

#[test]
fn a_missing_local_path_is_an_error_for_every_kind() {
    let w = World::new("add-missing");
    std::fs::write(w.root.join("file"), "x").unwrap();
    for kind in ["skill", "mcp", "repo"] {
        for source in ["./nope", "../nope-zz", "./file"] {
            let run = w.invoke(&[kind, source, "--offline"]).run();
            assert_eq!(run.code, Some(1), "{kind} {source}: {}", run.stdout);
            let v = run.json();
            assert_eq!(v["status"], "error", "{v}");
            assert!(v["run"].is_null(), "{v}");
        }
    }
}

#[test]
fn offline_is_a_low_skip_and_prints_the_pinned_command() {
    let w = World::new("add-offline");
    let spec = at("left-pad", "1.3.0");
    let v = w.add(&["mcp", &spec, "--offline"]);
    assert_eq!(v["status"], "pass", "{v}");
    assert_eq!(findings(&v), vec![pair("osv_skipped", "low")], "{v}");
    assert_eq!(v["pin"], "1.3.0", "{v}");
    assert_eq!(
        v["run"],
        format!("claude mcp add left-pad -- npx -y {spec}"),
        "{v}"
    );
}

#[test]
fn flags_may_come_first() {
    let w = World::new("add-flags");
    let spec = at("left-pad", "1.3.0");
    for args in [
        vec!["--offline", "mcp", spec.as_str()],
        vec!["--yes", "--offline", "mcp", spec.as_str()],
        vec!["mcp", "--offline", spec.as_str(), "--yes"],
    ] {
        let v = w.add(&args);
        assert_eq!(
            (&v["kind"], &v["source"]),
            (&serde_json::json!("mcp"), &serde_json::json!(spec)),
            "{args:?}: {v}"
        );
        assert_eq!(v["status"], "pass", "{args:?}: {v}");
    }
    // `--yes` before the source is a flag, not the source.
    let v = w.add(&["skill", "--yes", "owner/repo", "--offline"]);
    assert_eq!(
        (&v["source"], &v["status"]),
        (
            &serde_json::json!("owner/repo"),
            &serde_json::json!("warn_proceed")
        ),
        "{v}"
    );
}

#[test]
fn a_usage_error_exits_3() {
    let w = World::new("add-usage");
    for args in [
        vec![],
        vec!["skill"],
        vec!["--yes", "skill"],
        vec!["skills", "owner/repo"],
        vec!["skill", "owner/repo", "extra"],
        vec!["skill", "owner/repo", "--bogus"],
        vec!["skill", ""],
        vec!["skill", " -x"],
    ] {
        let run: Run = w.invoke(&args).run();
        assert_eq!(
            run.code,
            Some(3),
            "{args:?}: {}\n{}",
            run.stdout,
            run.stderr
        );
        assert!(
            run.stderr.contains("usage: add skill|mcp|repo <source>"),
            "{args:?}: {}",
            run.stderr
        );
        let v = run.json();
        assert_eq!(v["status"], "error", "{v}");
        assert!(
            v["error"]
                .as_str()
                .is_some_and(|e| e.contains("usage: add")),
            "{v}"
        );
    }
}

#[test]
fn a_remote_mcp_url_holds_and_prints_the_http_transport_form() {
    let w = World::new("add-remote");
    let url = "https://mcp.example.com/mcp";
    let v = w.add(&["mcp", url]);
    assert_eq!(v["status"], "warn_hold", "{v}");
    assert_eq!(
        findings(&v),
        vec![pair("unrecognised_source", "medium")],
        "{v}"
    );
    assert!(
        v["findings"][0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("remote MCP server")),
        "{v}"
    );
    let v = w.add(&["mcp", url, "--yes"]);
    assert_eq!(
        v["run"],
        format!("claude mcp add --transport http mcp-example-com {url}"),
        "{v}"
    );
}

#[test]
fn an_mcp_from_github_has_no_install_command() {
    let w = World::new("add-mcp-gh");
    let v = w.add(&["mcp", "owner/repo", "--offline", "--yes"]);
    assert_eq!(v["status"], "warn_proceed", "{v}");
    assert!(v["run"].is_null(), "{v}");
    assert!(
        v["run_note"]
            .as_str()
            .is_some_and(|n| n.contains("claude mcp add")),
        "{v}"
    );
}

/// The online paths: loopback stand-ins for the npm registry, the GitHub API and osv.dev.
#[cfg(feature = "test-hooks")]
mod online {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    use safe_ai_skill::verify::{osv, provenance};

    const NPM: &str = provenance::TEST_NPM_REGISTRY_ENV;
    const GITHUB: &str = provenance::TEST_GITHUB_API_ENV;
    const OSV: &str = osv::TEST_URL_ENV;

    /// Serve `route(method, path, body) -> (status, reply)` on loopback; the base URL.
    fn serve(route: impl Fn(&str, &str, &str) -> (u16, String) + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut length = 0usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
                let (status, reply) = route(&method, &path, &String::from_utf8_lossy(&body));
                let mut stream = reader.into_inner();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        base
    }

    /// A loopback URL nothing listens on.
    fn closed() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        base
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A registry serving `left-pad` 1.3.0 as `latest`, a GitHub API resolving every ref of
    /// `o/r` to [`SHA`], and an osv.dev with no advisories.
    fn healthy() -> String {
        serve(|method, path, _| match (method, path) {
            ("GET", "/npm/left-pad/latest") => {
                (200, r#"{"name":"left-pad","version":"1.3.0"}"#.into())
            }
            ("GET", p) if p.starts_with("/gh/repos/o/r/commits/") => (200, SHA.into()),
            ("POST", "/osv") => (200, "{}".into()),
            _ => (404, r#"{"error":"not found"}"#.into()),
        })
    }

    fn online(w: &World, args: &[&str], npm: &str, gh: &str, osv: &str) -> serde_json::Value {
        let run = w
            .invoke(args)
            .env(NPM, npm)
            .env(GITHUB, gh)
            .env(OSV, osv)
            .run();
        assert_eq!(
            run.code,
            Some(0),
            "{args:?}\n{}\n{}",
            run.stdout,
            run.stderr
        );
        run.json()
    }

    fn healthy_run(w: &World, base: &str, args: &[&str]) -> serde_json::Value {
        online(
            w,
            args,
            &format!("{base}/npm"),
            &format!("{base}/gh"),
            &format!("{base}/osv"),
        )
    }

    #[test]
    fn an_unpinned_npm_source_is_pinned_graded_and_printed_pinned() {
        let w = World::new("add-on-npm");
        let base = healthy();
        let v = healthy_run(&w, &base, &["mcp", "left-pad"]);
        assert_eq!(v["status"], "pass", "{v}");
        assert_eq!(v["pin"], "1.3.0", "{v}");
        assert_eq!(findings(&v), vec![pair("unpinned_version", "low")], "{v}");
        assert!(
            v["findings"][0]["detail"]
                .as_str()
                .is_some_and(|d| d.contains("1.3.0")),
            "{v}"
        );
        assert_eq!(
            v["run"],
            format!(
                "claude mcp add left-pad -- npx -y {}",
                at("left-pad", "1.3.0")
            ),
            "{v}"
        );
    }

    #[test]
    fn a_moving_github_ref_is_pinned_to_its_commit() {
        let w = World::new("add-on-gh");
        let base = healthy();
        let v = healthy_run(&w, &base, &["skill", "o/r"]);
        assert_eq!(
            (&v["status"], &v["pin"]),
            (&serde_json::json!("pass"), &serde_json::json!(SHA)),
            "{v}"
        );
        assert_eq!(findings(&v), vec![pair("unpinned_ref", "low")], "{v}");
        assert_eq!(
            v["run"],
            format!("npx skills add {}", at("o/r", SHA)),
            "{v}"
        );
        let v = healthy_run(
            &w,
            &base,
            &["skill", "https://github.com/o/r/tree/main/skills/x"],
        );
        assert_eq!(
            v["run"],
            format!("npx skills add https://github.com/o/r/tree/{SHA}/skills/x"),
            "{v}"
        );
        let v = healthy_run(&w, &base, &["repo", "https://github.com/o/r"]);
        assert_eq!(
            v["run"],
            format!("git clone https://github.com/o/r.git r && git -C r checkout --detach {SHA}"),
            "{v}"
        );
        // `add mcp` has no command that carries the pin: still held.
        let v = healthy_run(&w, &base, &["mcp", "o/r"]);
        assert_eq!(v["status"], "warn_hold", "{v}");
        assert_eq!(findings(&v), vec![pair("unpinned_ref", "medium")], "{v}");
    }

    #[test]
    fn an_unreachable_osv_holds() {
        let w = World::new("add-on-osv");
        let base = healthy();
        let spec = at("left-pad", "1.3.0");
        let failing = serve(|_, _, _| (503, "{}".into()));
        let garbage = serve(|_, _, _| (200, "<html>".into()));
        for osv in [closed(), failing, garbage] {
            let v = online(
                &w,
                &["mcp", &spec],
                &format!("{base}/npm"),
                &format!("{base}/gh"),
                &osv,
            );
            assert_eq!(v["status"], "warn_hold", "{osv}: {v}");
            assert_eq!(
                findings(&v),
                vec![pair("osv_unavailable", "medium")],
                "{osv}: {v}"
            );
            assert!(v["run"].is_null(), "{v}");
            let yes = ["mcp", spec.as_str(), "--yes"];
            let v = online(
                &w,
                &yes,
                &format!("{base}/npm"),
                &format!("{base}/gh"),
                &osv,
            );
            assert_eq!(v["status"], "warn_proceed", "{v}");
        }
        let v = healthy_run(&w, &base, &["mcp", &spec]);
        assert_eq!(v["status"], "pass", "{v}");
        assert_eq!(v["findings"], serde_json::json!([]), "{v}");
    }

    #[test]
    fn a_known_advisory_blocks() {
        let w = World::new("add-on-cve");
        let base = healthy();
        let osv = serve(|_, _, _| {
            (
                200,
                r#"{"vulns":[{"id":"GHSA-x","summary":"bad","severity":[{"type":"CVSS_V3","score":"9.8"}]}]}"#.into(),
            )
        });
        let v = online(
            &w,
            &["mcp", "left-pad", "--yes"],
            &format!("{base}/npm"),
            &format!("{base}/gh"),
            &osv,
        );
        assert_eq!(v["status"], "blocked", "{v}");
        assert!(findings(&v).contains(&pair("cve", "high")), "{v}");
    }

    #[test]
    fn failed_lookups_keep_the_hold_and_print_the_source() {
        let w = World::new("add-on-down");
        let down = closed();
        let v = online(&w, &["mcp", "left-pad"], &down, &down, &down);
        assert_eq!(v["status"], "warn_hold", "{v}");
        assert_eq!(
            findings(&v),
            vec![pair("unpinned_version", "medium")],
            "{v}"
        );
        assert!(
            v["findings"][0]["detail"]
                .as_str()
                .is_some_and(|d| d.contains("lookup")),
            "{v}"
        );
        let v = online(&w, &["mcp", "left-pad", "--yes"], &down, &down, &down);
        assert_eq!(
            v["run"], "claude mcp add left-pad -- npx -y left-pad",
            "{v}"
        );
        assert!(v["pin"].is_null(), "{v}");
        assert!(
            v["run_note"]
                .as_str()
                .is_some_and(|n| n.contains("not pinned")),
            "{v}"
        );

        let v = online(&w, &["skill", "o/r", "--yes"], &down, &down, &down);
        assert_eq!(v["status"], "warn_proceed", "{v}");
        assert_eq!(findings(&v), vec![pair("unpinned_ref", "medium")], "{v}");
        assert_eq!(v["run"], "npx skills add o/r", "{v}");
    }
}
