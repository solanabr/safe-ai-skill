//! osv.dev CVE lookup for a resolved package version.
//!
//! [`query`] POSTs to the free, Google-maintained osv.dev API and maps each returned
//! advisory to a [`Finding`]. The network call is isolated in [`fetch`]; the pure response
//! parser [`parse_response`] is what the unit tests drive against fixture JSON. On any
//! network failure [`query`] returns a single LOW "unavailable" finding — it never panics
//! and never blocks-by-crash.

use super::{Finding, Report, Severity};

/// osv.dev query endpoint.
const OSV_URL: &str = "https://api.osv.dev/v1/query";

/// Query osv.dev for known vulnerabilities in `pkg`@`version` (npm ecosystem).
///
/// Network is isolated: a request/parse failure yields a LOW informational
/// `osv_unavailable` finding so the orchestrator can degrade to `ask` rather than block.
pub fn query(pkg: &str, version: &str) -> Report {
    match fetch(pkg, version) {
        Some(body) => parse_response(&body),
        None => {
            let mut report = Report::default();
            report.findings.push(Finding::new(
                Severity::Low,
                "osv_unavailable",
                format!("osv.dev lookup for {pkg}@{version} was unavailable (network)"),
            ));
            report
        }
    }
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
/// Isolated and optional: `None` on any network/IO error. NEVER called from unit tests.
pub fn fetch(pkg: &str, version: &str) -> Option<String> {
    let body = request_body(pkg, version);
    let resp = ureq::agent()
        .post(OSV_URL)
        .timeout(std::time::Duration::from_secs(4))
        .set("Content-Type", "application/json")
        .set("User-Agent", "safe-ai-skill")
        .send_string(&body)
        .ok()?;
    resp.into_string().ok()
}

/// Parse an osv.dev response body into a [`Report`]. Pure — unit-testable with fixtures.
///
/// An empty object (`{}`) or an empty/absent `vulns` array → no findings. Each vuln becomes
/// a [`Finding`]; severity is derived from the advisory's `severity`/`database_specific`
/// CVSS when present, otherwise defaults to High.
pub fn parse_response(body: &str) -> Report {
    let mut report = Report::default();
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            report.findings.push(Finding::new(
                Severity::Low,
                "osv_unavailable",
                "osv.dev response was not valid JSON",
            ));
            return report;
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
    fn invalid_json_is_unavailable_low() {
        let report = parse_response("not json");
        assert_eq!(report.max_severity(), Some(Severity::Low));
        assert!(kinds(&report).contains(&"osv_unavailable".to_string()));
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
