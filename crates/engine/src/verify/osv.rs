//! osv.dev CVE lookup for a resolved package version.
//!
//! [`query`] POSTs to the free, Google-maintained osv.dev API and maps each returned
//! advisory to a [`Finding`]. The network call is isolated in [`fetch`]; the pure response
//! parser [`parse_response`] is what the unit tests drive against fixture JSON. When osv.dev
//! cannot answer (network error, timeout, HTTP error, unparseable reply) [`query`] returns a
//! MEDIUM `osv_unavailable` finding, so `add` holds until `--yes` rather than passing a package
//! nobody looked up; it never panics. An explicit `--offline` is the user's choice: a LOW
//! [`skipped`] finding.

use super::{Finding, Report, Severity};

/// osv.dev query endpoint.
const OSV_URL: &str = "https://api.osv.dev/v1/query";

/// Test-only override of [`OSV_URL`], read only in `test-hooks` builds.
pub const TEST_URL_ENV: &str = "SAFE_AI_SKILL_TEST_OSV_URL";

/// Query osv.dev for known vulnerabilities in `pkg`@`version` (npm ecosystem).
///
/// Network is isolated: a request/parse failure yields a MEDIUM `osv_unavailable` finding.
pub fn query(pkg: &str, version: &str) -> Report {
    query_at(&osv_url(), pkg, version)
}

/// [`query`] against the endpoint at `url`.
pub fn query_at(url: &str, pkg: &str, version: &str) -> Report {
    match fetch_at(url, pkg, version) {
        Ok(body) => parse_response(&body),
        Err(why) => unavailable(&format!(
            "osv.dev could not be asked about known vulnerabilities in {pkg}@{version} ({why}), so \
             no CVE check ran; re-run when it is reachable, or pass --yes to take it unchecked"
        )),
    }
}

/// The LOW finding for a lookup the user turned off with `--offline`.
pub fn skipped(pkg: &str) -> Finding {
    Finding::new(
        Severity::Low,
        "osv_skipped",
        format!("the osv.dev CVE lookup for {pkg} was skipped (--offline)"),
    )
}

/// A report holding one MEDIUM `osv_unavailable` finding.
fn unavailable(detail: &str) -> Report {
    let mut report = Report::default();
    report
        .findings
        .push(Finding::new(Severity::Medium, "osv_unavailable", detail));
    report
}

/// [`OSV_URL`], or in a `test-hooks` build the URL in [`TEST_URL_ENV`] when it is set.
fn osv_url() -> String {
    #[cfg(feature = "test-hooks")]
    if let Ok(url) = std::env::var(TEST_URL_ENV) {
        return url;
    }
    OSV_URL.to_string()
}

/// Build the osv.dev request body for `pkg`@`version`. Pure — unit-testable.
pub fn request_body(pkg: &str, version: &str) -> String {
    let v = serde_json::json!({
        "version": version,
        "package": { "ecosystem": "npm", "name": pkg }
    });
    v.to_string()
}

/// POST to osv.dev and return the raw response body.
///
/// Isolated and optional: `Err` with a short reason on any network/HTTP/IO error. Unit tests
/// drive [`fetch_at`] against a loopback server only.
pub fn fetch(pkg: &str, version: &str) -> Result<String, String> {
    fetch_at(&osv_url(), pkg, version)
}

/// [`fetch`] against the endpoint at `url`.
pub fn fetch_at(url: &str, pkg: &str, version: &str) -> Result<String, String> {
    let body = request_body(pkg, version);
    let resp = ureq::agent()
        .post(url)
        .timeout(std::time::Duration::from_secs(4))
        .set("Content-Type", "application/json")
        .set("User-Agent", "safe-ai-skill")
        .send_string(&body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("HTTP {code}"),
            ureq::Error::Transport(_) => "unreachable or timed out".to_string(),
        })?;
    resp.into_string()
        .map_err(|_| "the reply could not be read".to_string())
}

/// Parse an osv.dev response body into a [`Report`]. Pure — unit-testable with fixtures.
///
/// An empty object (`{}`) or an empty/absent `vulns` array → no findings; a body that is not
/// a JSON object → a MEDIUM `osv_unavailable` finding. Each vuln becomes
/// a [`Finding`]; severity is derived from the advisory's `severity`/`database_specific`
/// CVSS when present, otherwise defaults to High.
pub fn parse_response(body: &str) -> Report {
    let mut report = Report::default();
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        _ => {
            return unavailable(
                "osv.dev's reply was not a JSON object, so no CVE check ran; re-run when it \
                 answers, or pass --yes to take it unchecked",
            )
        }
    };

    let vulns = match value.get("vulns").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return report, // `{}` or no vulns → clean
    };

    for vuln in vulns {
        let id = vuln
            .get("id")
            .and_then(|i| i.as_str())
            .unwrap_or("unknown")
            .to_string();
        let summary = vuln
            .get("summary")
            .and_then(|s| s.as_str())
            .or_else(|| vuln.get("details").and_then(|d| d.as_str()))
            .unwrap_or("known vulnerability")
            .to_string();
        let severity = severity_of(vuln);
        report.findings.push(Finding::new(
            severity,
            "cve",
            format!("{id}: {}", truncate(&summary, 200)),
        ));
    }

    report
}

/// Derive a [`Severity`] from a vuln object. Uses a CVSS score when parseable, else High.
fn severity_of(vuln: &serde_json::Value) -> Severity {
    // osv `severity` is an array of {type, score}; score may be a CVSS vector or number.
    if let Some(arr) = vuln.get("severity").and_then(|s| s.as_array()) {
        for item in arr {
            if let Some(score_str) = item.get("score").and_then(|s| s.as_str()) {
                if let Some(num) = cvss_base_score(score_str) {
                    return from_cvss(num);
                }
            }
            if let Some(num) = item.get("score").and_then(|s| s.as_f64()) {
                return from_cvss(num);
            }
        }
    }
    // database_specific.severity is sometimes a plain label.
    if let Some(label) = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
    {
        match label.to_uppercase().as_str() {
            "LOW" => return Severity::Low,
            "MODERATE" | "MEDIUM" => return Severity::Medium,
            "HIGH" | "CRITICAL" => return Severity::High,
            _ => {}
        }
    }
    Severity::High
}

/// Map a numeric CVSS base score to a severity bucket.
fn from_cvss(score: f64) -> Severity {
    if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Extract the numeric base score from a CVSS vector string, when present.
///
/// osv usually carries the *vector* (e.g. `CVSS:3.1/AV:N/...`) not a bare number; without a
/// full CVSS calculator we can't derive the score, so this returns `None` for vectors and
/// only parses bare numeric strings.
fn cvss_base_score(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok()
}

/// Truncate `s` to at most `max` chars (char-boundary safe).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(report: &Report) -> Vec<String> {
        report.findings.iter().map(|f| f.kind.clone()).collect()
    }

    #[test]
    fn empty_response_has_no_findings() {
        let report = parse_response("{}");
        assert!(report.findings.is_empty());
        assert_eq!(report.max_severity(), None);
    }

    #[test]
    fn empty_vulns_array_is_clean() {
        let report = parse_response(r#"{"vulns":[]}"#);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn single_vuln_becomes_finding() {
        let body = r#"{
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "Prototype pollution in foo",
                    "severity": [{"type":"CVSS_V3","score":"9.8"}]
                }
            ]
        }"#;
        let report = parse_response(body);
        assert_eq!(report.findings.len(), 1);
        assert!(kinds(&report).contains(&"cve".to_string()));
        assert_eq!(report.max_severity(), Some(Severity::High));
        assert!(report.findings[0].detail.contains("GHSA-xxxx-yyyy-zzzz"));
    }

    #[test]
    fn medium_cvss_maps_to_medium() {
        let body = r#"{"vulns":[{"id":"X","severity":[{"type":"CVSS_V3","score":"5.3"}]}]}"#;
        let report = parse_response(body);
        assert_eq!(report.max_severity(), Some(Severity::Medium));
    }

    #[test]
    fn no_severity_defaults_high() {
        let body = r#"{"vulns":[{"id":"X","summary":"unknown sev"}]}"#;
        let report = parse_response(body);
        assert_eq!(report.max_severity(), Some(Severity::High));
    }

    #[test]
    fn database_specific_severity_label() {
        let body = r#"{"vulns":[{"id":"X","database_specific":{"severity":"LOW"}}]}"#;
        let report = parse_response(body);
        assert_eq!(report.max_severity(), Some(Severity::Low));
    }

    #[test]
    fn invalid_json_is_unavailable_medium() {
        for body in ["not json", "[]", "\"x\"", ""] {
            let report = parse_response(body);
            assert_eq!(report.max_severity(), Some(Severity::Medium), "{body}");
            assert_eq!(
                kinds(&report),
                vec!["osv_unavailable".to_string()],
                "{body}"
            );
        }
    }

    #[test]
    fn an_unreachable_osv_holds() {
        let base = crate::verify::testnet::serve(|method, _, body| match method {
            "POST" if body.contains("\"bad\"") => (503, "{}".into()),
            "POST" if body.contains("\"html\"") => (200, "<html>".into()),
            "POST" if body.contains("\"vuln\"") => (
                200,
                r#"{"vulns":[{"id":"GHSA-1","severity":[{"type":"CVSS_V3","score":"9.1"}]}]}"#
                    .into(),
            ),
            _ => (200, "{}".into()),
        });
        let closed = crate::verify::testnet::closed();
        for (url, pkg, why) in [
            (base.as_str(), "bad", "HTTP 503"),
            (closed.as_str(), "x", "unreachable or timed out"),
        ] {
            let report = query_at(url, pkg, "1.0.0");
            assert_eq!(kinds(&report), vec!["osv_unavailable".to_string()], "{pkg}");
            assert_eq!(report.max_severity(), Some(Severity::Medium), "{pkg}");
            assert!(report.findings[0].detail.contains(why), "{report:?}");
        }
        let report = query_at(&base, "html", "1.0.0");
        assert_eq!(report.max_severity(), Some(Severity::Medium));
        assert!(query_at(&base, "clean", "1.0.0").findings.is_empty());
        let report = query_at(&base, "vuln", "1.0.0");
        assert_eq!(kinds(&report), vec!["cve".to_string()]);
        assert_eq!(report.max_severity(), Some(Severity::High));
    }

    #[test]
    fn offline_is_a_low_skip() {
        let f = skipped("left-pad");
        assert_eq!(
            (f.severity, f.kind.as_str()),
            (Severity::Low, "osv_skipped")
        );
        assert!(f.detail.contains("--offline"));
    }

    #[test]
    fn request_body_shape() {
        let body = request_body("helius-mcp", "1.2.3");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["package"]["ecosystem"], "npm");
        assert_eq!(v["package"]["name"], "helius-mcp");
        assert_eq!(v["version"], "1.2.3");
    }
}
