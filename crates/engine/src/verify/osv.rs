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

/// Most result pages followed for one package version (osv.dev pages a large or slow answer
/// with `next_page_token`, and may send only the token). An answer still unfinished after them
/// is incomplete, so it holds like an unreachable osv.dev.
const MAX_PAGES: usize = 5;

/// Test-only override of [`OSV_URL`], read only in `test-hooks` builds.
pub const TEST_URL_ENV: &str = "SAFE_AI_SKILL_TEST_OSV_URL";

/// Query osv.dev for known vulnerabilities in `pkg`@`version` (npm ecosystem).
///
/// Network is isolated: a request/parse failure yields a MEDIUM `osv_unavailable` finding.
pub fn query(pkg: &str, version: &str) -> Report {
    query_at(&osv_url(), pkg, version)
}

/// [`query`] against the endpoint at `url`, following `next_page_token` up to [`MAX_PAGES`].
pub fn query_at(url: &str, pkg: &str, version: &str) -> Report {
    let mut report = Report::default();
    let mut token: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let page = fetch_at(url, pkg, version, token.as_deref())
            .and_then(|body| parse_page(&body).ok_or_else(|| "a malformed reply".to_string()));
        match page {
            Ok((found, None)) => {
                report.merge(found);
                return report;
            }
            Ok((found, next)) => {
                report.merge(found);
                token = next;
            }
            Err(why) => {
                report.merge(unavailable(&format!(
                    "osv.dev gave no usable answer about known vulnerabilities in \
                     {pkg}@{version} ({why}), so no CVE check ran; re-run when it is reachable, \
                     or pass --yes to take it unchecked"
                )));
                return report;
            }
        }
    }
    report.merge(unavailable(&format!(
        "osv.dev's answer about {pkg}@{version} was still incomplete after {MAX_PAGES} pages, so \
         the CVE check did not finish; re-run later, or pass --yes to take it unchecked"
    )));
    report
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
    page_request_body(pkg, version, None)
}

/// [`request_body`] for the result page `page_token` names (none: the first page).
pub fn page_request_body(pkg: &str, version: &str, page_token: Option<&str>) -> String {
    let mut v = serde_json::json!({
        "version": version,
        "package": { "ecosystem": "npm", "name": pkg }
    });
    if let (Some(token), Some(map)) = (page_token, v.as_object_mut()) {
        map.insert("page_token".into(), serde_json::json!(token));
    }
    v.to_string()
}

/// POST to osv.dev and return the raw response body.
///
/// Isolated and optional: `Err` with a short reason on any network/HTTP/IO error. Unit tests
/// drive [`fetch_at`] against a loopback server only.
pub fn fetch(pkg: &str, version: &str) -> Result<String, String> {
    fetch_at(&osv_url(), pkg, version, None)
}

/// [`fetch`] of the result page `page_token` names, against the endpoint at `url`.
pub fn fetch_at(
    url: &str,
    pkg: &str,
    version: &str,
    page_token: Option<&str>,
) -> Result<String, String> {
    let body = page_request_body(pkg, version, page_token);
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

/// Parse one osv.dev response body into a [`Report`]. Pure — unit-testable with fixtures.
///
/// `{}` or an empty `vulns` array → no findings. A body that is not a well-formed reply (see
/// [`parse_page`]), or one that says more pages follow (`next_page_token`, which this single
/// page cannot follow), → a MEDIUM `osv_unavailable` finding besides any advisories on it.
pub fn parse_response(body: &str) -> Report {
    match parse_page(body) {
        Some((report, None)) => report,
        Some((mut report, Some(_))) => {
            report.merge(unavailable(
                "osv.dev's reply said more results follow, so the CVE check did not finish; \
                 re-run later, or pass --yes to take it unchecked",
            ));
            report
        }
        None => unavailable(
            "osv.dev's reply was not a well-formed answer, so no CVE check ran; re-run when it \
             answers, or pass --yes to take it unchecked",
        ),
    }
}

/// One result page: its advisories and the `next_page_token`, if more pages follow. `None`
/// unless the body is a JSON object that is `{}`, carries a `vulns` array, or carries only a
/// `next_page_token` (a page osv.dev cut short); a non-array `vulns`, a non-string token or any
/// other object (an error envelope) is not an answer.
///
/// Each vuln becomes a [`Finding`]; severity is derived from the advisory's
/// `severity`/`database_specific` CVSS when present, otherwise defaults to High.
pub fn parse_page(body: &str) -> Option<(Report, Option<String>)> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let map = value.as_object()?;
    let token = match map.get("next_page_token") {
        None => None,
        Some(serde_json::Value::String(t)) if !t.is_empty() => Some(t.clone()),
        Some(_) => return None,
    };
    let vulns = match map.get("vulns") {
        Some(serde_json::Value::Array(arr)) => arr.as_slice(),
        Some(_) => return None,
        None if map.keys().all(|k| k == "next_page_token") => &[],
        None => return None,
    };

    let mut report = Report::default();
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

    Some((report, token))
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
    fn pages_are_followed_and_an_unfinished_answer_holds() {
        // Page 1 holds one advisory and a token; page 2 (asked with that token) the other.
        let base = crate::verify::testnet::serve(|_, _, body| {
            if body.contains("\"page_token\":\"p2\"") {
                (
                    200,
                    r#"{"vulns":[{"id":"B","database_specific":{"severity":"LOW"}}]}"#.into(),
                )
            } else if body.contains("\"two\"") {
                (200, r#"{"vulns":[{"id":"A","database_specific":{"severity":"LOW"}}],"next_page_token":"p2"}"#.into())
            } else {
                // A token and nothing else, forever (osv.dev ran out of time on every page).
                (200, r#"{"next_page_token":"again"}"#.into())
            }
        });
        let report = query_at(&base, "two", "1.0.0");
        let ids: Vec<&str> = report.findings.iter().map(|f| &f.detail[..1]).collect();
        assert_eq!(ids, vec!["A", "B"], "{report:?}");
        assert_eq!(report.max_severity(), Some(Severity::Low));

        let report = query_at(&base, "slow", "1.0.0");
        assert_eq!(kinds(&report), vec!["osv_unavailable".to_string()]);
        assert_eq!(report.max_severity(), Some(Severity::Medium));
        assert!(
            report.findings[0].detail.contains("incomplete"),
            "{report:?}"
        );
    }

    #[test]
    fn only_a_well_formed_reply_counts() {
        for body in [
            r#"{"vulns":"x"}"#,
            r#"{"vulns":{}}"#,
            r#"{"code":3,"message":"bad request"}"#,
            r#"{"next_page_token":5}"#,
            r#"{"next_page_token":""}"#,
        ] {
            let report = parse_response(body);
            assert_eq!(
                kinds(&report),
                vec!["osv_unavailable".to_string()],
                "{body}"
            );
            assert_eq!(report.max_severity(), Some(Severity::Medium), "{body}");
        }
        // One page that says more follow is not clean either.
        let report = parse_response(r#"{"next_page_token":"tok"}"#);
        assert_eq!(report.max_severity(), Some(Severity::Medium));
        assert!(page_request_body("p", "1.0.0", Some("tok")).contains("\"page_token\":\"tok\""));
        assert!(!request_body("p", "1.0.0").contains("page_token"));
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
