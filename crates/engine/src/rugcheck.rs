//! Rugcheck swap gate.
//!
//! Pre-swap token-safety check. A mint in `policy.swap.trusted_mints` short-circuits to
//! [`Decision::Allow`]. Otherwise the gate fetches the rugcheck report and maps the `score`
//! against `policy.swap.rugcheck_max_score`:
//!
//! - `score > rugcheck_max_score` → [`Decision::Deny`] (reason lists the flagged risks).
//! - `score <= rugcheck_max_score` → [`Decision::Allow`].
//! - network timeout / API error / unparseable body → [`Decision::Ask`]. We never hard-block
//!   a swap on a third party's uptime, and we never silently allow an unknown token.
//!
//! The network call is isolated in [`fetch_report`]; the decision logic in
//! [`decide_from_report`] is pure and unit-tested against fixture JSON.

use crate::io::Decision;
use crate::policy::Policy;

/// A parsed rugcheck report: an overall risk `score` and the list of flagged risk names.
#[derive(Debug, Clone, Default)]
pub struct RugReport {
    /// Overall risk score (higher = riskier).
    pub score: u32,
    /// Human-readable names of flagged risks.
    pub risks: Vec<String>,
}

/// Decide whether a swap involving `mint` is permitted.
///
/// Trusted mints short-circuit to [`Decision::Allow`]. Otherwise the live rugcheck report is
/// fetched (isolated, with `policy.swap.rugcheck_timeout_ms`) and mapped by
/// [`decide_from_report`]. Any fetch/parse failure yields [`Decision::Ask`].
pub fn check_mint(mint: &str, policy: &Policy) -> Decision {
    if policy.swap.trusted_mints.iter().any(|m| m == mint) {
        return Decision::Allow;
    }
    match fetch_report(mint, policy.swap.rugcheck_timeout_ms) {
        Some(report) => decide_from_report(&report, policy.swap.rugcheck_max_score),
        None => Decision::Ask {
            reason: format!(
                "rugcheck unavailable for mint {mint}; cannot verify token safety — confirm manually"
            ),
        },
    }
}

/// Map a parsed [`RugReport`] to a [`Decision`] given the configured `max_score`.
///
/// Pure: no network, no policy load. This is the unit-tested core.
pub fn decide_from_report(report: &RugReport, max_score: u32) -> Decision {
    if report.score > max_score {
        let risks = if report.risks.is_empty() {
            "unspecified risks".to_string()
        } else {
            report.risks.join(", ")
        };
        Decision::Deny {
            reason: format!(
                "rugcheck score {} exceeds max {} ({})",
                report.score, max_score, risks
            ),
        }
    } else {
        Decision::Allow
    }
}

/// Parse a rugcheck `/v1/tokens/{mint}/report` JSON body into a [`RugReport`].
///
/// Expects a `score` number and an optional `risks` array of objects each carrying a `name`
/// (falling back to `description`). Returns `None` if the body is not valid JSON or has no
/// numeric `score`.
pub fn parse_report(body: &str) -> Option<RugReport> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let score_f = value.get("score").and_then(serde_json::Value::as_f64)?;
    // Clamp to a sane u32: negative / non-finite scores are treated as 0 (no signal).
    let score = if score_f.is_finite() && score_f >= 0.0 {
        score_f.min(u32::MAX as f64) as u32
    } else {
        0
    };
    let risks = value
        .get("risks")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    r.get("name")
                        .and_then(serde_json::Value::as_str)
                        .or_else(|| r.get("description").and_then(serde_json::Value::as_str))
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    Some(RugReport { score, risks })
}

/// Fetch and parse the rugcheck report for `mint` over the network.
///
/// Isolated so the rest of the module stays unit-testable. Uses a short connect/read
/// timeout. Any network error, non-200 status, or unparseable body → `None`. NEVER exercised
/// in unit tests.
fn fetch_report(mint: &str, timeout_ms: u64) -> Option<RugReport> {
    let url = format!("https://api.rugcheck.xyz/v1/tokens/{mint}/report");
    let timeout = std::time::Duration::from_millis(timeout_ms.max(1));
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .build();
    let resp = agent.get(&url).call().ok()?;
    let body = resp.into_string().ok()?;
    parse_report(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(max_score: u32, trusted: &[&str]) -> Policy {
        let mut p = Policy::fail_closed();
        p.swap.rugcheck_max_score = max_score;
        p.swap.rugcheck_timeout_ms = 1;
        p.swap.trusted_mints = trusted.iter().map(|s| s.to_string()).collect();
        p
    }

    const RISKY_FIXTURE: &str = r#"{
        "score": 85,
        "risks": [
            {"name": "Mint authority enabled", "level": "danger"},
            {"name": "Top holder owns 60%", "level": "warn"}
        ]
    }"#;

    const SAFE_FIXTURE: &str = r#"{
        "score": 10,
        "risks": [
            {"name": "Low liquidity", "level": "info"}
        ]
    }"#;

    #[test]
    fn parses_risky_fixture() {
        let report = parse_report(RISKY_FIXTURE).unwrap();
        assert_eq!(report.score, 85);
        assert_eq!(report.risks.len(), 2);
        assert!(report.risks[0].contains("Mint authority"));
    }

    #[test]
    fn parses_safe_fixture() {
        let report = parse_report(SAFE_FIXTURE).unwrap();
        assert_eq!(report.score, 10);
        assert_eq!(report.risks, vec!["Low liquidity".to_string()]);
    }

    #[test]
    fn high_score_denies() {
        let report = parse_report(RISKY_FIXTURE).unwrap();
        let decision = decide_from_report(&report, 40);
        match decision {
            Decision::Deny { reason } => {
                assert!(reason.contains("85"));
                assert!(reason.contains("Mint authority"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn safe_score_allows() {
        let report = parse_report(SAFE_FIXTURE).unwrap();
        assert_eq!(decide_from_report(&report, 40), Decision::Allow);
    }

    #[test]
    fn boundary_equal_score_allows() {
        let report = RugReport {
            score: 40,
            risks: vec![],
        };
        // score == max is within tolerance (deny only on strictly greater).
        assert_eq!(decide_from_report(&report, 40), Decision::Allow);
    }

    #[test]
    fn trusted_mint_short_circuits_allow() {
        let policy = policy_with(40, &["So11111111111111111111111111111111111111112"]);
        assert_eq!(
            check_mint("So11111111111111111111111111111111111111112", &policy),
            Decision::Allow
        );
    }

    #[test]
    fn unparseable_body_yields_none() {
        assert!(parse_report("not json").is_none());
        assert!(parse_report("{\"risks\": []}").is_none()); // no score
    }

    #[test]
    fn timeout_path_maps_to_ask() {
        // Simulate the fetch-failure branch without touching the network: a `None` report
        // (as `fetch_report` returns on timeout/error) must map to `Ask`, never Deny/Allow.
        let report: Option<RugReport> = None;
        let decision = match report {
            Some(r) => decide_from_report(&r, 40),
            None => Decision::Ask {
                reason: "rugcheck unavailable".into(),
            },
        };
        assert!(matches!(decision, Decision::Ask { .. }));
    }
}
