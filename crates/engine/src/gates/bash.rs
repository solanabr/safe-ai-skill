//! Bash command gate.
//!
//! Classifies `solana` / `spl-token` / `anchor` commands and decides whether to allow,
//! ask, deny, or defer. A command is split on `&&`, `||`, `;`, and `|`; each segment is
//! classified and decided independently, and the whole command takes the *most
//! restrictive* segment's decision (`Deny` > `Ask` > `Allow` > `Defer`). The returned
//! [`GateMeta`] describes the most significant gated segment so the relaxation layer and
//! grants can reason about it.
//!
//! This gate is pure: it consults the resolved [`Context`] (network already determined by
//! `main.rs`) and the effective [`Policy`], but performs no process or network I/O. The
//! only filesystem touch is the spend ledger, which is read (not committed) here to
//! predict a transfer decision; `main.rs` commits the debit on an actual allow.

use crate::context::{Context, Network};
use crate::gate::{GateMeta, Scope};
use crate::io::Decision;
use crate::policy::Policy;
use crate::spend::{self, SpendLedger};

/// Classify a bash command and decide.
///
/// Returns the natural decision (before relaxation) and a [`GateMeta`] describing the
/// action. The caller (`main.rs`) applies the relaxation layer to the result.
pub fn decide(command: &str, ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let mut best: Option<(Decision, GateMeta)> = None;

    for segment in split_segments(command) {
        let (decision, meta) = decide_segment(segment, ctx, policy);
        // Skip plain readonly/allow-other segments unless nothing more significant wins;
        // we still want a sensible default meta, so seed `best` with the first result.
        match &best {
            None => best = Some((decision, meta)),
            Some((cur_decision, _)) => {
                if severity(&decision) > severity(cur_decision) {
                    best = Some((decision, meta));
                }
            }
        }
    }

    best.unwrap_or_else(|| (Decision::Defer, GateMeta::unknown()))
}

/// Decide a single command segment.
fn decide_segment(segment: &str, ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let tokens = tokenize(segment);
    if tokens.is_empty() {
        return (Decision::Defer, GateMeta::unknown());
    }

    let program = base_program(&tokens[0]);
    match program.as_str() {
        "solana" => classify_solana(&tokens, ctx, policy),
        "spl-token" => classify_spl_token(&tokens, ctx, policy),
        "anchor" => classify_anchor(&tokens, ctx, policy),
        // Not a solana-family command: this gate has no opinion.
        _ => (Decision::Defer, GateMeta::unknown()),
    }
}

/// Classify a `solana ...` command.
fn classify_solana(tokens: &[String], ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let sub = subcommand(tokens, 1);
    match sub.as_deref() {
        Some("transfer") => transfer_decision(tokens, "solana", ctx, policy),
        Some("program") => {
            let action = subcommand(tokens, 2);
            match action.as_deref() {
                Some("deploy") | Some("write-buffer") | Some("upgrade") => {
                    deploy_decision("solana", ctx)
                }
                Some("set-upgrade-authority") => authority_decision("solana", ctx, tokens),
                Some("close") => destructive_decision("solana", ctx, true),
                // Read-only program subcommands (`show`, `dump`, ...).
                Some("show") | Some("dump") => allow_readonly("solana"),
                _ => ask_unknown("solana"),
            }
        }
        Some("close") => destructive_decision("solana", ctx, true),
        Some(s) if is_solana_readonly(s) => allow_readonly("solana"),
        Some(_) => ask_unknown("solana"),
        None => ask_unknown("solana"),
    }
}

/// Classify an `spl-token ...` command.
fn classify_spl_token(tokens: &[String], ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let sub = subcommand(tokens, 1);
    match sub.as_deref() {
        Some("transfer") => transfer_decision(tokens, "spl-token", ctx, policy),
        Some("authorize") => authority_decision("spl-token", ctx, tokens),
        Some("burn") => destructive_decision("spl-token", ctx, false),
        Some("close") => destructive_decision("spl-token", ctx, true),
        Some(s) if is_spl_readonly(s) => allow_readonly("spl-token"),
        Some(_) => ask_unknown("spl-token"),
        None => ask_unknown("spl-token"),
    }
}

/// Classify an `anchor ...` command.
fn classify_anchor(tokens: &[String], ctx: &Context, _policy: &Policy) -> (Decision, GateMeta) {
    let sub = subcommand(tokens, 1);
    match sub.as_deref() {
        Some("deploy") | Some("upgrade") | Some("migrate") => deploy_decision("anchor", ctx),
        // `anchor build|test|idl|keys|...` are local/dev operations.
        Some("build") | Some("test") | Some("idl") | Some("keys") | Some("verify")
        | Some("localnet") | Some("expand") | Some("run") | Some("new") | Some("init") => {
            allow_readonly("anchor")
        }
        Some(_) => ask_unknown("anchor"),
        None => ask_unknown("anchor"),
    }
}

/// Build a transfer decision via the spend ledger (predict-only; no debit here).
fn transfer_decision(
    tokens: &[String],
    program: &str,
    ctx: &Context,
    policy: &Policy,
) -> (Decision, GateMeta) {
    let amount_sol = parse_transfer_amount(tokens);
    let destination = parse_transfer_destination(tokens);

    let mut meta = GateMeta::new(Scope::Transfer, false);
    meta.program = Some(program.to_string());
    meta.amount_sol = amount_sol;
    meta.destination = destination;

    // A mainnet transfer is always at least an ask, regardless of amount.
    let mainnet_ask = matches!(ctx.network, Network::Mainnet);

    let decision = match amount_sol {
        Some(amount) => {
            // Predict the decision against the ledger WITHOUT committing — `main.rs`
            // debits via `spend::record_and_check` only when the action is allowed.
            let ledger = SpendLedger::load(&ctx.plugin_data);
            let spend_decision = spend::check(amount, &ledger, policy);
            if mainnet_ask {
                escalate_to_ask(spend_decision, "Mainnet transfer — approve to proceed")
            } else {
                spend_decision
            }
        }
        None => {
            // No parseable amount: fail safe to ask rather than allow blindly.
            Decision::Ask {
                reason: format!("{program} transfer with no parseable amount — approve to proceed"),
            }
        }
    };

    (decision, meta)
}

/// Build a deploy decision. Mainnet → ask (+ hard guard); otherwise allow.
fn deploy_decision(program: &str, ctx: &Context) -> (Decision, GateMeta) {
    let mainnet = matches!(ctx.network, Network::Mainnet);
    let mut meta = GateMeta::new(Scope::Deploy, mainnet);
    meta.program = Some(program.to_string());

    if mainnet {
        (
            Decision::Ask {
                reason: "MAINNET DEPLOY — approve to proceed".to_string(),
            },
            meta,
        )
    } else {
        (Decision::Allow, meta)
    }
}

/// Build an authority-change decision. Always a hard guard; mainnet phrasing differs.
fn authority_decision(program: &str, ctx: &Context, tokens: &[String]) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Authority, true);
    meta.program = Some(program.to_string());
    if let Some(target) = first_pubkey_arg(tokens) {
        meta.destination = Some(target);
    }

    let reason = if matches!(ctx.network, Network::Mainnet) {
        "Mainnet authority change — approve to proceed"
    } else {
        "Authority change — approve to proceed"
    };
    (
        Decision::Ask {
            reason: reason.to_string(),
        },
        meta,
    )
}

/// Build a destructive (burn/close) decision. Account closes are hard guards.
fn destructive_decision(program: &str, ctx: &Context, account_close: bool) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Destructive, account_close);
    meta.program = Some(program.to_string());

    let what = if account_close {
        "Account close"
    } else {
        "Token burn"
    };
    let net = if matches!(ctx.network, Network::Mainnet) {
        "mainnet "
    } else {
        ""
    };
    (
        Decision::Ask {
            reason: format!("{what} ({net}destructive) — approve to proceed"),
        },
        meta,
    )
}

/// A fast read-only allow with `Scope::Other` metadata.
fn allow_readonly(program: &str) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Other, false);
    meta.program = Some(program.to_string());
    (Decision::Allow, meta)
}

/// An unclassified solana-family command: fail safe to `Ask`, never allow blindly.
fn ask_unknown(program: &str) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Other, false);
    meta.program = Some(program.to_string());
    (
        Decision::Ask {
            reason: format!("Unrecognized {program} command — approve to proceed"),
        },
        meta,
    )
}

/// Escalate an `Allow`/`Defer` to `Ask`; keep an existing `Ask`/`Deny` as-is (a deny must
/// remain a deny; an existing ask reason is preserved).
fn escalate_to_ask(decision: Decision, reason: &str) -> Decision {
    match decision {
        Decision::Allow | Decision::Defer => Decision::Ask {
            reason: reason.to_string(),
        },
        other => other,
    }
}

/// Numeric severity used to pick the most-restrictive decision across segments.
fn severity(decision: &Decision) -> u8 {
    match decision {
        Decision::Defer => 0,
        Decision::Allow => 1,
        Decision::Ask { .. } => 2,
        Decision::Deny { .. } => 3,
    }
}

/// Read-only `solana` subcommands that are always safe to allow.
fn is_solana_readonly(sub: &str) -> bool {
    matches!(
        sub,
        "balance"
            | "address"
            | "logs"
            | "account"
            | "config"
            | "airdrop"
            | "cluster-version"
            | "epoch-info"
            | "epoch"
            | "slot"
            | "rent"
            | "decode-transaction"
            | "confirm"
            | "transaction-history"
            | "block"
            | "block-height"
            | "block-time"
            | "fees"
            | "gossip"
            | "leader-schedule"
            | "ping"
            | "stakes"
            | "supply"
            | "validators"
            | "feature"
    )
}

/// Read-only `spl-token` subcommands that are always safe to allow.
fn is_spl_readonly(sub: &str) -> bool {
    matches!(
        sub,
        "balance" | "accounts" | "address" | "display" | "supply" | "account-info" | "gc"
    )
}

/// The token at index `idx`, skipping leading flags, lowercased.
fn subcommand(tokens: &[String], idx: usize) -> Option<String> {
    // Collect non-flag positional tokens after the program word.
    let positionals: Vec<&String> = tokens.iter().skip(1).filter(|t| !is_flag(t)).collect();
    // idx is 1-based against the original token stream where index 0 is the program.
    positionals
        .get(idx.saturating_sub(1))
        .map(|t| t.to_ascii_lowercase())
}

/// Parse the SOL amount from a `transfer` command.
///
/// Handles `solana transfer <dest> <amount>` and `spl-token transfer <mint> <amount> <dest>`
/// by scanning positional (non-flag) tokens after the subcommand for the first one that
/// parses as a positive number. `ALL` (transfer-all) yields `None`.
fn parse_transfer_amount(tokens: &[String]) -> Option<f64> {
    for tok in tokens.iter().skip(2) {
        if is_flag(tok) {
            continue;
        }
        let cleaned = tok.trim_matches(|c| c == '"' || c == '\'');
        if cleaned.eq_ignore_ascii_case("ALL") {
            return None;
        }
        if let Ok(v) = cleaned.parse::<f64>() {
            if v.is_finite() && v > 0.0 {
                return Some(v);
            }
        }
    }
    None
}

/// The destination pubkey of a `solana transfer <dest> <amount>` command, if base58-ish.
fn parse_transfer_destination(tokens: &[String]) -> Option<String> {
    for tok in tokens.iter().skip(2) {
        if is_flag(tok) {
            continue;
        }
        let cleaned = tok.trim_matches(|c| c == '"' || c == '\'');
        if looks_like_pubkey(cleaned) {
            return Some(cleaned.to_string());
        }
    }
    None
}

/// First base58-looking positional argument across the whole token stream.
fn first_pubkey_arg(tokens: &[String]) -> Option<String> {
    for tok in tokens.iter().skip(1) {
        if is_flag(tok) {
            continue;
        }
        let cleaned = tok.trim_matches(|c| c == '"' || c == '\'');
        if looks_like_pubkey(cleaned) {
            return Some(cleaned.to_string());
        }
    }
    None
}

/// Heuristic: a Solana pubkey is 32–44 base58 chars (no `0`, `O`, `I`, `l`).
fn looks_like_pubkey(s: &str) -> bool {
    let len = s.len();
    if !(32..=44).contains(&len) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'))
}

/// The base program name of a token (strips any directory prefix).
fn base_program(tok: &str) -> String {
    let cleaned = tok.trim_matches(|c| c == '"' || c == '\'');
    cleaned
        .rsplit('/')
        .next()
        .unwrap_or(cleaned)
        .to_ascii_lowercase()
}

/// Whether a token looks like a flag (starts with `-`).
fn is_flag(tok: &str) -> bool {
    tok.starts_with('-')
}

/// Split a command on top-level `&&`, `||`, `;`, `|` separators into segments.
fn split_segments(command: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let bytes = command.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let two = bytes.get(i..i + 2);
        if matches!(two, Some(b"&&")) || matches!(two, Some(b"||")) {
            segments.push(command[start..i].trim());
            i += 2;
            start = i;
            continue;
        }
        let c = bytes[i];
        if c == b';' || c == b'|' {
            segments.push(command[start..i].trim());
            i += 1;
            start = i;
            continue;
        }
        i += 1;
    }
    segments.push(command[start..].trim());
    segments.into_iter().filter(|s| !s.is_empty()).collect()
}

/// Tokenize a segment on whitespace, respecting single/double quotes.
fn tokenize(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for c in segment.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    current.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(c),
            },
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A context with a fixed network and an isolated, per-test plugin-data dir.
    fn ctx_with(network: Network, tag: &str) -> Context {
        let dir =
            std::env::temp_dir().join(format!("safe_ai_skill_bash_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Context {
            network,
            plugin_data: dir.clone(),
            project_dir: PathBuf::from("/tmp"),
        }
    }

    fn policy() -> Policy {
        // Default: per_tx 1.0, hard 10.0, daily 5.0.
        Policy::default()
    }

    const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

    #[test]
    fn transfer_under_cap_allows() {
        let ctx = ctx_with(Network::Devnet, "under_cap");
        let (d, meta) = decide(&format!("solana transfer {DEST} 0.5"), &ctx, &policy());
        assert_eq!(d, Decision::Allow);
        assert_eq!(meta.scope, Scope::Transfer);
        assert_eq!(meta.amount_sol, Some(0.5));
        assert_eq!(meta.destination.as_deref(), Some(DEST));
        assert_eq!(meta.program.as_deref(), Some("solana"));
    }

    #[test]
    fn transfer_over_per_tx_cap_asks() {
        let ctx = ctx_with(Network::Devnet, "over_cap");
        let (d, _) = decide(&format!("solana transfer {DEST} 5"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
    }

    #[test]
    fn transfer_over_hard_cap_denies() {
        let ctx = ctx_with(Network::Devnet, "hard_cap");
        let (d, _) = decide(&format!("solana transfer {DEST} 50"), &ctx, &policy());
        assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
    }

    #[test]
    fn mainnet_transfer_under_cap_still_asks() {
        let ctx = ctx_with(Network::Mainnet, "mainnet_xfer");
        let (d, _) = decide(&format!("solana transfer {DEST} 0.1"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
    }

    #[test]
    fn spl_token_transfer_parses_amount() {
        let ctx = ctx_with(Network::Devnet, "spl_xfer");
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let (d, meta) = decide(
            &format!("spl-token transfer {mint} 0.25 {DEST}"),
            &ctx,
            &policy(),
        );
        assert_eq!(d, Decision::Allow);
        assert_eq!(meta.amount_sol, Some(0.25));
        assert_eq!(meta.program.as_deref(), Some("spl-token"));
    }

    #[test]
    fn mainnet_deploy_asks_and_is_hard_guard() {
        let ctx = ctx_with(Network::Mainnet, "mainnet_deploy");
        let (d, meta) = decide("solana program deploy ./prog.so", &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard);
        assert_eq!(meta.scope, Scope::Deploy);
    }

    #[test]
    fn devnet_deploy_allows() {
        let ctx = ctx_with(Network::Devnet, "devnet_deploy");
        let (d, meta) = decide("solana program deploy ./prog.so", &ctx, &policy());
        assert_eq!(d, Decision::Allow);
        assert!(!meta.hard_guard);
        assert_eq!(meta.scope, Scope::Deploy);
    }

    #[test]
    fn anchor_deploy_devnet_allows() {
        let ctx = ctx_with(Network::Devnet, "anchor_deploy");
        let (d, meta) = decide("anchor deploy", &ctx, &policy());
        assert_eq!(d, Decision::Allow);
        assert_eq!(meta.scope, Scope::Deploy);
        assert_eq!(meta.program.as_deref(), Some("anchor"));
    }

    #[test]
    fn anchor_deploy_mainnet_asks() {
        let ctx = ctx_with(Network::Mainnet, "anchor_deploy_main");
        let (d, _) = decide("anchor deploy", &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
    }

    #[test]
    fn anchor_build_allows() {
        let ctx = ctx_with(Network::Unknown, "anchor_build");
        let (d, _) = decide("anchor build", &ctx, &policy());
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn set_upgrade_authority_asks_hard_guard() {
        let ctx = ctx_with(Network::Devnet, "set_auth");
        let (d, meta) = decide(
            &format!("solana program set-upgrade-authority PROG --new-upgrade-authority {DEST}"),
            &ctx,
            &policy(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard);
        assert_eq!(meta.scope, Scope::Authority);
    }

    #[test]
    fn spl_authorize_asks_hard_guard() {
        let ctx = ctx_with(Network::Devnet, "authorize");
        let (d, meta) = decide(
            &format!("spl-token authorize {DEST} mint {DEST}"),
            &ctx,
            &policy(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard);
        assert_eq!(meta.scope, Scope::Authority);
    }

    #[test]
    fn solana_close_asks_hard_guard() {
        let ctx = ctx_with(Network::Devnet, "close");
        let (d, meta) = decide(&format!("solana close {DEST}"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard, "account_close is a hard guard");
        assert_eq!(meta.scope, Scope::Destructive);
    }

    #[test]
    fn spl_burn_asks_not_hard_guard() {
        let ctx = ctx_with(Network::Devnet, "burn");
        let (d, meta) = decide(&format!("spl-token burn {DEST} 100"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(!meta.hard_guard, "burn is destructive but not a hard guard");
        assert_eq!(meta.scope, Scope::Destructive);
    }

    #[test]
    fn spl_close_asks_hard_guard() {
        let ctx = ctx_with(Network::Devnet, "spl_close");
        let (d, meta) = decide(&format!("spl-token close {DEST}"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard);
    }

    #[test]
    fn readonly_balance_allows() {
        let ctx = ctx_with(Network::Mainnet, "balance");
        let (d, meta) = decide("solana balance", &ctx, &policy());
        assert_eq!(d, Decision::Allow);
        assert_eq!(meta.scope, Scope::Other);
    }

    #[test]
    fn readonly_config_get_allows() {
        let ctx = ctx_with(Network::Mainnet, "config_get");
        let (d, _) = decide("solana config get", &ctx, &policy());
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn pipeline_with_gated_segment_takes_most_restrictive() {
        let ctx = ctx_with(Network::Devnet, "pipeline");
        // readonly | deploy(mainnet not set, devnet→allow) ... use a transfer over hard cap.
        let cmd = format!("solana balance | solana transfer {DEST} 50");
        let (d, meta) = decide(&cmd, &ctx, &policy());
        assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
        assert_eq!(meta.scope, Scope::Transfer);
    }

    #[test]
    fn pipeline_readonly_then_authority_takes_ask() {
        let ctx = ctx_with(Network::Devnet, "pipe_auth");
        let cmd = format!("solana balance && spl-token authorize {DEST} mint {DEST}");
        let (d, meta) = decide(&cmd, &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard);
        assert_eq!(meta.scope, Scope::Authority);
    }

    #[test]
    fn non_solana_command_defers() {
        let ctx = ctx_with(Network::Devnet, "non_solana");
        let (d, _) = decide("ls -la", &ctx, &policy());
        assert_eq!(d, Decision::Defer);
    }

    #[test]
    fn unknown_solana_subcommand_asks() {
        let ctx = ctx_with(Network::Devnet, "unknown_sub");
        let (d, _) = decide("solana frobnicate something", &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
    }

    #[test]
    fn transfer_with_no_amount_asks() {
        let ctx = ctx_with(Network::Devnet, "no_amount");
        let (d, _) = decide(&format!("solana transfer {DEST} ALL"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
    }

    #[test]
    fn cumulative_over_daily_cap_asks() {
        let ctx = ctx_with(Network::Devnet, "cumulative");
        std::fs::create_dir_all(&ctx.plugin_data).unwrap();
        // Pre-load the ledger near the daily cap (5.0).
        let ledger = SpendLedger {
            day: {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() / 86_400)
                    .unwrap_or(0)
            },
            total_sol: 4.8,
        };
        std::fs::write(
            ctx.plugin_data.join("spend.json"),
            serde_json::to_string(&ledger).unwrap(),
        )
        .unwrap();

        // 0.5 is under per-tx (1.0) but pushes daily to 5.3 > 5.0.
        let (d, _) = decide(&format!("solana transfer {DEST} 0.5"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        let _ = std::fs::remove_dir_all(&ctx.plugin_data);
    }

    #[test]
    fn deploy_with_explicit_mainnet_url_meta_program_set() {
        // Network is resolved by main; here we simulate a mainnet ctx.
        let ctx = ctx_with(Network::Mainnet, "deploy_url");
        let (_, meta) = decide(
            "solana program deploy ./p.so -u https://api.mainnet-beta.solana.com",
            &ctx,
            &policy(),
        );
        assert_eq!(meta.program.as_deref(), Some("solana"));
        assert!(meta.hard_guard);
    }
}
