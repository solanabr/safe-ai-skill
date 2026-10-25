//! W6 gap-closure fixture: MCP routed-action gating (token-boundary names, nested params)
//! and the encoded-payload expander feeding the Bash/secrets gates.
//!
//! The Bash cases emulate the integrator's wiring exactly: `encoded::expand` is run, each
//! decoded command is passed back through `bash::decide` and `secrets::decide`, and the
//! strictest of those, the original command's gates, and `encoded::decide` wins. The MCP
//! cases emulate `cmd_gate_mcp`'s tier-High conversion plus `headless::apply`.

use std::path::Path;

use safe_ai_skill::context::Context;
use safe_ai_skill::gate::GateMeta;
use safe_ai_skill::gates::{bash, encoded, mcp, secrets};
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

/// Strictness order: Deny > Ask > Allow > Defer.
fn rank(d: &Decision) -> u8 {
    match d {
        Decision::Defer => 0,
        Decision::Allow => 1,
        Decision::Ask { .. } => 2,
        Decision::Deny { .. } => 3,
    }
}

fn strictest(a: Decision, b: Decision) -> Decision {
    if rank(&b) > rank(&a) {
        b
    } else {
        a
    }
}

fn label(d: &Decision) -> &'static str {
    match d {
        Decision::Deny { .. } => "D",
        Decision::Ask { .. } => "A",
        Decision::Allow => "L",
        Decision::Defer => "-",
    }
}

fn tier_of(name: &str) -> Tier {
    match name {
        "off" => Tier::Off,
        "medium" => Tier::Medium,
        "high" => Tier::High,
        _ => Tier::Relaxed,
    }
}

fn policy_at(tier: Tier, headless_flag: bool) -> Policy {
    let mut p = Policy::default();
    p.runtime.tier = tier;
    p.runtime.headless = headless_flag;
    p
}

/// The MCP pipeline as `cmd_gate_mcp` applies it (minus the other writers' gates, which are
/// `Defer` for these inputs): `mcp::decide` → tier-High ask-to-deny → `headless::apply`.
fn mcp_decision(tool: &str, payload: &Value, policy: &Policy) -> Decision {
    let ctx = Context::build("", Path::new("."));
    let (decision, _meta) = mcp::decide(tool, Some(payload), &ctx, policy);
    let decision = match decision {
        Decision::Ask { reason } if policy.tier() == Tier::High => Decision::Deny { reason },
        other => other,
    };
    headless::apply(decision, policy.runtime.headless)
}

/// The Bash pipeline as the integrator wires it: original Bash + secrets gates, the encoded
/// expander's decoded commands fed back through both, and `encoded::decide`, strictest wins,
/// then `headless::apply`.
fn bash_decision(command: &str, policy: &Policy) -> Decision {
    let cwd = Path::new(".");
    let ctx = Context::build(command, cwd);
    let (mut decision, _meta): (Decision, GateMeta) = bash::decide(command, &ctx, policy);
    decision = strictest(decision, secrets::decide(command, cwd, policy));

    for decoded in encoded::expand(command) {
        let dctx = Context::build(&decoded, cwd);
        let (bd, _m) = bash::decide(&decoded, &dctx, policy);
        decision = strictest(decision, bd);
        decision = strictest(decision, secrets::decide(&decoded, cwd, policy));
    }
    if let Some(v) = encoded::decide(command) {
        decision = strictest(decision, v.into());
    }
    headless::apply(decision, policy.runtime.headless)
}

#[test]
fn fixture_cases() {
    let raw = include_str!("fixtures/gap/w6-mcp-encoded.jsonl");
    let mut failures = Vec::new();

    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let case: Value = serde_json::from_str(line).expect("valid fixture json");
        let id = case["id"].as_str().unwrap();
        let tool = case["tool"].as_str().unwrap();
        let want = case["want"].as_str().unwrap();
        let policy = policy_at(
            tier_of(case["tier"].as_str().unwrap_or("relaxed")),
            case["headless"].as_bool().unwrap_or(false),
        );

        let got = if tool.starts_with("mcp__") {
            mcp_decision(tool, &case["tool_input"], &policy)
        } else {
            let command = case["tool_input"]["command"].as_str().unwrap();
            bash_decision(command, &policy)
        };

        if label(&got) != want {
            failures.push(format!("{id}: want {want}, got {} ({got:?})", label(&got)));
        }
    }

    assert!(
        failures.is_empty(),
        "fixture mismatches:\n{}",
        failures.join("\n")
    );
}
