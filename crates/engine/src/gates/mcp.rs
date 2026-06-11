//! MCP tool gate.

use serde_json::Value;

use crate::context::Context;
use crate::gate::{GateMeta, Scope};
use crate::io::Decision;
use crate::policy::Policy;

/// Gate a sensitive MCP tool call.
///
/// Returns the natural decision (before relaxation) and a [`GateMeta`]. The caller
/// (`main.rs`) applies the relaxation layer.
///
/// Fast path: a tool whose name does not match `policy.mcp.sensitive_name_pattern` AND
/// whose payload carries no value-moving signal returns `(Defer, GateMeta::unknown())`
/// immediately — this is the overwhelming majority of MCP calls (reads).
///
/// Sensitive path: when the name matches OR the payload carries an amount + destination
/// signal, the call is classified (Transfer / Swap / Other), the SOL amount is parsed
/// where derivable (lamports are divided by 1e9), and the program / destination / mint
/// are recorded in [`GateMeta`]. The decision is [`Decision::Ask`]; value-moving MCP
/// calls are never hard-allowed here. Swap routing (rugcheck) is owned by the relaxation
/// path — this gate only classifies `Scope::Swap` and records the mint so `main.rs` can
/// route it.
pub fn decide(
    tool_name: &str,
    payload: Option<&Value>,
    _ctx: &Context,
    policy: &Policy,
) -> (Decision, GateMeta) {
    let name_sensitive = name_matches_sensitive(tool_name, &policy.mcp.sensitive_name_pattern);
    let signal = payload.and_then(payload_signal);

    // Fast path: not a sensitive name and no value-moving payload signal.
    if !name_sensitive && signal.is_none() {
        return (Decision::Defer, GateMeta::unknown());
    }

    // Classify scope from the tool name (preferred) then from the payload signal.
    let scope = classify_scope(tool_name);

    let mut meta = GateMeta::new(scope, false);
    let dest = signal.as_ref().and_then(|s| s.destination.clone());
    let amount = signal.as_ref().and_then(|s| s.amount_sol);
    let mint = signal.as_ref().and_then(|s| s.mint.clone());

    meta.amount_sol = amount;
    meta.destination = dest.clone();

    let short_tool = short_name(tool_name);

    let reason = match scope {
        Scope::Swap => {
            // Record the mint so main can route to the rugcheck/relaxation swap path.
            if let Some(m) = mint.clone() {
                meta.program = Some(m.clone());
                meta.destination = meta.destination.or(Some(m));
            }
            format!(
                "MCP swap: {short_tool}{}",
                match &mint {
                    Some(m) => format!(" (mint {})", truncate(m)),
                    None => String::new(),
                }
            )
        }
        _ => {
            let dest_str = dest
                .as_deref()
                .map(truncate)
                .unwrap_or_else(|| "unknown destination".to_string());
            let amt_str = amount
                .map(|a| format!("{a} SOL"))
                .unwrap_or_else(|| "unspecified amount".to_string());
            format!("MCP value transfer: {short_tool} → {dest_str} ({amt_str})")
        }
    };

    (Decision::Ask { reason }, meta)
}

/// A value-moving payload signal extracted from an MCP tool payload.
struct PayloadSignal {
    amount_sol: Option<f64>,
    destination: Option<String>,
    mint: Option<String>,
}

/// Inspect a payload for value-moving keys. Returns `Some` only when BOTH an amount-like
/// key (`amount`/`lamports`/`sol`/`tokenAmount`/`amountSol`) AND a destination-like key
/// (`destination`/`to`/`recipient`/`mint`) are present — the signature of a transfer-style
/// call. A mint alone (a token reference without a destination) does not trip the signal
/// on its own; name-based classification handles swaps.
fn payload_signal(payload: &Value) -> Option<PayloadSignal> {
    let obj = payload.as_object()?;

    let mut amount_sol: Option<f64> = None;
    let mut has_amount = false;
    // Prefer an explicit SOL field, else lamports (÷1e9), else a raw amount.
    if let Some(v) = obj.get("sol").or_else(|| obj.get("amountSol")) {
        amount_sol = number(v);
        has_amount = true;
    }
    if let Some(v) = obj.get("lamports") {
        has_amount = true;
        if amount_sol.is_none() {
            amount_sol = number(v).map(|n| n / 1_000_000_000.0);
        }
    }
    if let Some(v) = obj.get("amount").or_else(|| obj.get("tokenAmount")) {
        has_amount = true;
        if amount_sol.is_none() {
            // A bare `amount` could be SOL or token base units; record only if it parses,
            // but do not assume lamports here.
            amount_sol = number(v);
        }
    }

    let destination = ["destination", "to", "recipient"]
        .iter()
        .find_map(|k| obj.get(*k).and_then(Value::as_str))
        .map(str::to_string);
    let mint = obj.get("mint").and_then(Value::as_str).map(str::to_string);

    let has_dest = destination.is_some() || mint.is_some();

    if has_amount && has_dest {
        Some(PayloadSignal {
            amount_sol,
            destination,
            mint,
        })
    } else {
        None
    }
}

/// Parse a JSON value as an `f64`, accepting numbers and numeric strings.
fn number(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// Case-insensitive substring match of any `|`-separated alternative in `pattern`
/// against the tool name. (The frozen pattern is a regex-ish alternation; a substring
/// scan is sufficient and avoids a regex dependency.)
fn name_matches_sensitive(tool_name: &str, pattern: &str) -> bool {
    let name = tool_name.to_ascii_lowercase();
    pattern
        .split('|')
        .map(str::trim)
        .filter(|alt| !alt.is_empty())
        .any(|alt| name.contains(&alt.to_ascii_lowercase()))
}

/// Classify the action scope from the tool name.
fn classify_scope(tool_name: &str) -> Scope {
    let n = tool_name.to_ascii_lowercase();
    if n.contains("swap") {
        Scope::Swap
    } else if n.contains("transfer")
        || n.contains("send")
        || n.contains("withdraw")
        || n.contains("pay")
    {
        Scope::Transfer
    } else {
        Scope::Other
    }
}

/// The final `__`-delimited segment of an MCP tool name (`mcp__helius__transferSol` →
/// `transferSol`); falls back to the whole name.
fn short_name(tool_name: &str) -> &str {
    tool_name.rsplit("__").next().unwrap_or(tool_name)
}

/// Shorten an address for display (`AAAA…ZZZZ`) without echoing the whole value.
fn truncate(addr: &str) -> String {
    if addr.len() <= 12 {
        return addr.to_string();
    }
    format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn ctx() -> Context {
        Context::build("", Path::new("."))
    }

    #[test]
    fn fast_allow_get_balance() {
        let (d, m) = decide("mcp__helius__getBalance", None, &ctx(), &Policy::default());
        assert_eq!(d, Decision::Defer);
        assert_eq!(m.scope, Scope::Other);
        assert!(!m.hard_guard);
    }

    #[test]
    fn fast_allow_get_asset() {
        let payload = json!({ "id": "So11111111111111111111111111111111111111112" });
        let (d, _) = decide(
            "mcp__helius__getAsset",
            Some(&payload),
            &ctx(),
            &Policy::default(),
        );
        assert_eq!(d, Decision::Defer);
    }

    #[test]
    fn ask_transfer_sol_with_lamports_and_destination() {
        let payload = json!({
            "destination": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            "lamports": 2_000_000_000u64
        });
        let (d, m) = decide(
            "mcp__helius__transferSol",
            Some(&payload),
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }));
        assert_eq!(m.scope, Scope::Transfer);
        assert_eq!(m.amount_sol, Some(2.0));
        assert!(m.destination.is_some());
    }

    #[test]
    fn ask_transfer_by_name_without_payload() {
        let (d, m) = decide(
            "mcp__helius__transferToken",
            None,
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }));
        assert_eq!(m.scope, Scope::Transfer);
    }

    #[test]
    fn swap_classification() {
        let payload = json!({
            "amount": 5,
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        });
        let (d, m) = decide(
            "mcp__jupiter__swap",
            Some(&payload),
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }));
        assert_eq!(m.scope, Scope::Swap);
        // Mint recorded so main can route to the rugcheck path.
        assert_eq!(
            m.program.as_deref(),
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        );
    }

    #[test]
    fn payload_signal_triggers_unknown_named_tool() {
        // A non-sensitive name but a value-moving payload still gates.
        let payload =
            json!({ "amount": 1.5, "to": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin" });
        let (d, _) = decide(
            "mcp__custom__doThing",
            Some(&payload),
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }));
    }
}
