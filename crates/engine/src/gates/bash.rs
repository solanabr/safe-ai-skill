//! Bash command gate.
//!
//! Classifies `solana` / `spl-token` / `anchor` commands and decides whether to allow, ask,
//! deny, or defer (no opinion). A command is split on `&&`, `||`, `;`, and `|`; each segment is
//! classified and decided independently, and the whole command takes the *most
//! restrictive* segment's decision (`Deny` > `Ask` > `Allow` > `Defer`). The returned
//! [`GateMeta`] describes the most significant gated segment so the relaxation layer and
//! grants can reason about it.
//!
//! `Allow` comes only from a within-cap transfer on a positively identified
//! devnet/testnet/localnet, and only when every segment is a solana-family command: an allow
//! vouches for the whole tool call. Read-only commands and deploys to such a network get no
//! opinion, so the normal permission flow applies. Irreversible actions (`--final`, authority
//! changes, closes) are hard-guard asks on every cluster, and `--final` on mainnet is denied.
//!
//! This gate is pure: it consults the resolved [`Context`] (network already determined by
//! `main.rs`) and the effective [`Policy`], but performs no process or network I/O. A segment
//! that names its own cluster (`-um`, `--url …`) is judged on that cluster. The only
//! filesystem touch is the spend ledger, which is read (not committed) here to predict a
//! transfer decision; `main.rs` commits the debit on an actual allow.

use crate::context::{self, Context, Network};
use crate::gate::{GateMeta, Scope};
use crate::io::Decision;
use crate::policy::Policy;
use crate::spend::{self, SpendLedger};

/// Long flags of the `solana` / `spl-token` / `anchor` CLIs that take a value: without an
/// attached `=value`, the next token is the flag's value, never a positional argument.
const VALUE_FLAGS: &[&str] = &[
    // Global options.
    "--url",
    "--config",
    "--keypair",
    "--commitment",
    "--ws",
    "--output",
    "--rpc-timeout",
    "--confirm-timeout",
    "--fee-payer",
    "--program-id",
    "--with-compute-unit-price",
    "--with-compute-unit-limit",
    "--cluster",
    "--provider.cluster",
    "--provider.wallet",
    // Transaction options.
    "--with-memo",
    "--from",
    "--nonce",
    "--nonce-authority",
    "--blockhash",
    "--signer",
    "--derived-address-seed",
    "--derived-address-program-id",
    // `spl-token transfer`.
    "--owner",
    "--mint-decimals",
    "--expected-fee",
    "--multisig-signer",
    "--transfer-hook-account",
    // `anchor deploy` / `anchor program deploy`.
    "--program-name",
    "--program-keypair",
];

/// Long boolean flags of the same CLIs that may precede the positionals this gate reads.
const BOOL_FLAGS: &[&str] = &[
    // Global flags.
    "--help",
    "--version",
    "--verbose",
    "--no-address-labels",
    "--skip-preflight",
    "--skip-seed-phrase-validation",
    "--use-quic",
    "--use-tpu-client",
    "--use-udp",
    "--program-2022",
    "--use-unchecked-instruction",
    // Transfer flags.
    "--no-wait",
    "--allow-unfunded-recipient",
    "--allow-empty-recipient",
    "--fund-recipient",
    "--allow-non-system-account-recipient",
    "--no-recipient-is-ata-owner",
    "--recipient-is-ata-owner",
    "--confidential",
    "--sign-only",
    "--dump-transaction-message",
    // Irreversible-action flags.
    "--final",
    "--disable",
];

/// Short flags that take a value: `-u <url>`, `-k <keypair>`, `-C <config>`, `-p <program>`.
const VALUE_SHORTS: &[char] = &['u', 'k', 'C', 'p'];

/// Classify a bash command and decide.
///
/// Returns the natural decision (before relaxation) and a [`GateMeta`] describing the
/// action. The caller (`main.rs`) applies the relaxation layer to the result.
pub fn decide(command: &str, ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    // `ctx.network` comes from the command's cluster flags whenever it names one anywhere,
    // even in another segment (`echo -ud; solana transfer …`), so it vouches for a segment
    // naming none only when the whole command names none.
    let names_cluster = context::network_from_flags(command).is_some();
    let mut best: Option<(Decision, GateMeta)> = None;
    // Command or process substitution runs code the gate never sees, quoted or not.
    let mut unvetted = ["$(", "`", "<(", ">("].iter().any(|s| command.contains(s));

    for segment in split_segments(command) {
        let network = context::network_from_flags(segment).unwrap_or(if names_cluster {
            Network::Unknown
        } else {
            ctx.network
        });
        let segment_ctx = Context {
            network,
            ..ctx.clone()
        };
        let Some((decision, meta)) = decide_segment(segment, &segment_ctx, policy) else {
            unvetted = true;
            continue;
        };
        // Keep the most restrictive segment; on a tie the first one wins.
        match &best {
            None => best = Some((decision, meta)),
            Some((cur_decision, _)) => {
                if severity(&decision) > severity(cur_decision) {
                    best = Some((decision, meta));
                }
            }
        }
    }

    let Some((decision, mut meta)) = best else {
        return (Decision::Defer, GateMeta::unknown());
    };
    if !unvetted {
        return (decision, meta);
    }
    // Code this gate does not know runs alongside. An allow — natural or from a grant — would
    // vouch for it too, so there is none: no opinion instead, and an ask stays an ask.
    match decision {
        Decision::Allow => (Decision::Defer, meta),
        Decision::Ask { .. } => {
            meta.hard_guard = true;
            (decision, meta)
        }
        other => (other, meta),
    }
}

/// Decide a single command segment; `None` when it is not a solana-family command (this gate
/// has no opinion on it).
fn decide_segment(segment: &str, ctx: &Context, policy: &Policy) -> Option<(Decision, GateMeta)> {
    let tokens = context::tokenize(segment);
    let program = base_program(tokens.first()?);
    match program.as_str() {
        "solana" => Some(classify_solana(&tokens, ctx, policy)),
        "spl-token" => Some(classify_spl_token(&tokens, ctx, policy)),
        "anchor" => Some(classify_anchor(&tokens, ctx, policy)),
        _ => None,
    }
}

/// Classify a `solana ...` command.
fn classify_solana(tokens: &[String], ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let args = Args::parse(tokens);
    let sub = match word_or_ask(&args, 0, "solana") {
        Ok(sub) => sub,
        Err(verdict) => return verdict,
    };
    match sub.as_str() {
        "transfer" => transfer_decision(&args, "solana", ctx, policy),
        "program" => classify_program(&args, tokens, "solana", ctx),
        "config" => match word_or_ask(&args, 1, "solana") {
            Ok(action) if action == "get" => readonly("solana"),
            Ok(action) => ask_not_readonly("solana", &format!("config {action}")),
            Err(verdict) => verdict,
        },
        "close" => destructive_decision("solana", ctx, true),
        "close-vote-account" => irreversible_decision(
            "solana",
            ctx,
            tokens,
            Scope::Destructive,
            "vote-account close",
        ),
        s if is_solana_readonly(s) => readonly("solana"),
        _ => ask_unknown("solana"),
    }
}

/// Classify `<program> program <action> ...`, shared by `solana program` and `anchor program`.
fn classify_program(
    args: &Args,
    tokens: &[String],
    program: &str,
    ctx: &Context,
) -> (Decision, GateMeta) {
    let action = match word_or_ask(args, 1, program) {
        Ok(action) => action,
        Err(verdict) => return verdict,
    };
    match action.as_str() {
        "deploy" | "write-buffer" | "upgrade" => deploy_decision(program, ctx, tokens),
        "set-upgrade-authority" => irreversible_decision(
            program,
            ctx,
            tokens,
            Scope::Authority,
            "upgrade-authority change",
        ),
        "set-buffer-authority" => authority_decision(program, ctx, tokens),
        "close" => irreversible_decision(program, ctx, tokens, Scope::Destructive, "program close"),
        // Read-only program subcommands.
        "show" | "dump" => readonly(program),
        _ => ask_unknown(program),
    }
}

/// Classify an `spl-token ...` command.
fn classify_spl_token(tokens: &[String], ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let args = Args::parse(tokens);
    let sub = match word_or_ask(&args, 0, "spl-token") {
        Ok(sub) => sub,
        Err(verdict) => return verdict,
    };
    match sub.as_str() {
        "transfer" => transfer_decision(&args, "spl-token", ctx, policy),
        "authorize" if has_flag(tokens, "--disable") => irreversible_decision(
            "spl-token",
            ctx,
            tokens,
            Scope::Authority,
            "authority removal (--disable)",
        ),
        "authorize" => authority_decision("spl-token", ctx, tokens),
        "burn" => destructive_decision("spl-token", ctx, false),
        "close" => irreversible_decision(
            "spl-token",
            ctx,
            tokens,
            Scope::Destructive,
            "token-account close",
        ),
        "close-mint" => {
            irreversible_decision("spl-token", ctx, tokens, Scope::Destructive, "mint close")
        }
        // `gc` closes empty token accounts.
        "gc" => destructive_decision("spl-token", ctx, true),
        s if is_spl_readonly(s) => readonly("spl-token"),
        _ => ask_unknown("spl-token"),
    }
}

/// Classify an `anchor ...` command.
fn classify_anchor(tokens: &[String], ctx: &Context, _policy: &Policy) -> (Decision, GateMeta) {
    let args = Args::parse(tokens);
    let sub = match word_or_ask(&args, 0, "anchor") {
        Ok(sub) => sub,
        Err(verdict) => return verdict,
    };
    match sub.as_str() {
        "deploy" | "upgrade" | "migrate" => deploy_decision("anchor", ctx, tokens),
        "program" => classify_program(&args, tokens, "anchor", ctx),
        "idl" | "legacy-idl" => classify_anchor_idl(&args, tokens, &sub, ctx),
        // Local/dev operations.
        "build" | "keys" | "verify" | "localnet" | "expand" | "new" | "init" => readonly("anchor"),
        // `test` deploys to the configured cluster; `run` executes repo-defined scripts.
        "test" | "run" => ask_not_readonly("anchor", &sub),
        _ => ask_unknown("anchor"),
    }
}

/// Classify `anchor idl|legacy-idl <action> ...`: authority changes and closes are
/// irreversible, and no IDL command is on the read-only fast path.
fn classify_anchor_idl(
    args: &Args,
    tokens: &[String],
    sub: &str,
    ctx: &Context,
) -> (Decision, GateMeta) {
    let action = match word_or_ask(args, 1, "anchor") {
        Ok(action) => action,
        Err(verdict) => return verdict,
    };
    match action.as_str() {
        "erase-authority" | "set-authority" => irreversible_decision(
            "anchor",
            ctx,
            tokens,
            Scope::Authority,
            "IDL authority change",
        ),
        "set-buffer-authority" => authority_decision("anchor", ctx, tokens),
        "close" => irreversible_decision(
            "anchor",
            ctx,
            tokens,
            Scope::Destructive,
            "IDL account close",
        ),
        _ => ask_not_readonly("anchor", &format!("{sub} {action}")),
    }
}

/// Build a transfer decision via the spend ledger (predict-only; no debit here).
///
/// Only a definite amount on a positively identified devnet/testnet/localnet can be allowed;
/// mainnet or an unidentified network escalates to ask (a deny stays a deny). `ALL`, or an
/// amount that cannot be identified unambiguously, asks as a hard guard: no grant can budget it.
fn transfer_decision(
    args: &Args,
    program: &str,
    ctx: &Context,
    policy: &Policy,
) -> (Decision, GateMeta) {
    let (amount, destination) = parse_transfer(args, program);

    let mut meta = GateMeta::new(Scope::Transfer, !matches!(amount, Amount::Value(_)));
    meta.program = Some(program.to_string());
    meta.destination = destination;

    let decision = match amount {
        Amount::Value(sol) => {
            meta.amount_sol = Some(sol);
            // Predict the decision against the ledger WITHOUT committing — `main.rs`
            // debits via `spend::commit` only when the action is allowed.
            let ledger = SpendLedger::load(&ctx.plugin_data);
            let spend_decision = spend::check(sol, &ledger, policy);
            match ctx.network {
                Network::Mainnet => {
                    escalate_to_ask(spend_decision, "Mainnet transfer — approve to proceed")
                }
                Network::Unknown => escalate_to_ask(
                    spend_decision,
                    "Transfer on an unidentified network — approve to proceed",
                ),
                Network::Devnet | Network::Testnet | Network::Localnet => spend_decision,
            }
        }
        Amount::All => Decision::Ask {
            reason: format!("{program} transfer of ALL (the entire balance) — approve to proceed"),
        },
        Amount::Unclear => Decision::Ask {
            reason: format!(
                "{program} transfer amount could not be identified unambiguously — approve to proceed"
            ),
        },
    };

    (decision, meta)
}

/// Build a deploy decision (`program deploy|write-buffer|upgrade`, `anchor deploy|upgrade|migrate`).
///
/// `--final` makes the program immutable: irreversible. Otherwise mainnet → ask (+ hard guard),
/// an unidentified network → ask, a positively identified devnet/testnet/localnet → no opinion.
fn deploy_decision(program: &str, ctx: &Context, tokens: &[String]) -> (Decision, GateMeta) {
    if has_flag(tokens, "--final") {
        return irreversible_decision(
            program,
            ctx,
            tokens,
            Scope::Deploy,
            "deploy with --final (program becomes immutable)",
        );
    }

    let mainnet = matches!(ctx.network, Network::Mainnet);
    let mut meta = GateMeta::new(Scope::Deploy, mainnet);
    meta.program = Some(program.to_string());

    let decision = match ctx.network {
        Network::Mainnet => Decision::Ask {
            reason: "MAINNET DEPLOY — approve to proceed".to_string(),
        },
        Network::Unknown => Decision::Ask {
            reason: "Deploy to an unidentified network — approve to proceed".to_string(),
        },
        Network::Devnet | Network::Testnet | Network::Localnet => Decision::Defer,
    };
    (decision, meta)
}

/// Build an irreversible-action decision: a hard-guard ask on every cluster, and a deny for
/// `--final` on mainnet — that one the user runs themselves.
fn irreversible_decision(
    program: &str,
    ctx: &Context,
    tokens: &[String],
    scope: Scope,
    what: &str,
) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(scope, true);
    meta.program = Some(program.to_string());

    let mainnet = matches!(ctx.network, Network::Mainnet);
    let decision = if mainnet && has_flag(tokens, "--final") {
        Decision::Deny {
            reason: format!("Irreversible {what} on MAINNET — run it yourself outside the agent"),
        }
    } else {
        let net = if mainnet { "mainnet " } else { "" };
        Decision::Ask {
            reason: format!("Irreversible {net}{what} — approve to proceed"),
        }
    };
    (decision, meta)
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

/// A read-only fast-path command: no opinion, so the normal permission flow applies.
fn readonly(program: &str) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Other, false);
    meta.program = Some(program.to_string());
    (Decision::Defer, meta)
}

/// A known command that is not read-only (kept off the fast path): ask.
fn ask_not_readonly(program: &str, what: &str) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Other, false);
    meta.program = Some(program.to_string());
    (
        Decision::Ask {
            reason: format!("`{program} {what}` is not read-only — approve to proceed"),
        },
        meta,
    )
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

/// A solana-family command whose words cannot be identified unambiguously (a flag of unknown
/// arity precedes them). It could be anything, so it asks as a hard guard.
fn ask_ambiguous(program: &str) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Other, true);
    meta.program = Some(program.to_string());
    (
        Decision::Ask {
            reason: format!(
                "Could not parse this {program} command unambiguously — approve to proceed"
            ),
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

/// Read-only `solana` subcommands (no opinion). `config` is handled separately: only
/// `config get` is read-only.
fn is_solana_readonly(sub: &str) -> bool {
    matches!(
        sub,
        "balance"
            | "address"
            | "logs"
            | "account"
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

/// Read-only `spl-token` subcommands (no opinion).
fn is_spl_readonly(sub: &str) -> bool {
    matches!(
        sub,
        "balance" | "accounts" | "address" | "display" | "supply" | "account-info"
    )
}

/// The positional arguments of a segment after the program word, with flags, flag values and
/// shell redirections removed.
struct Args<'a> {
    positionals: Vec<&'a str>,
    /// Index from which positions are uncertain: a flag of unknown arity was followed by a word
    /// that may be its value.
    uncertain_from: Option<usize>,
}

/// One positional word of a segment.
enum Word {
    /// The word, lowercased.
    At(String),
    /// No such word.
    Missing,
    /// Unknowable: a flag of unknown arity precedes it.
    Ambiguous,
}

impl<'a> Args<'a> {
    /// Split a tokenized segment (`tokens[0]` is the program word).
    fn parse(tokens: &'a [String]) -> Args<'a> {
        let mut positionals = Vec::new();
        let mut uncertain_from = None;
        let mut iter = argv(tokens).into_iter().peekable();
        while let Some(tok) = iter.next() {
            if tok == "--" {
                positionals.extend(iter.by_ref());
                break;
            }
            match arity(tok) {
                Arity::Positional => positionals.push(tok),
                Arity::Alone => {}
                Arity::TakesNext => {
                    iter.next();
                }
                Arity::Unknown => {
                    // Ambiguous only when a word follows that could be the flag's value.
                    let word_follows = iter
                        .peek()
                        .is_some_and(|next| matches!(arity(next), Arity::Positional));
                    if word_follows && uncertain_from.is_none() {
                        uncertain_from = Some(positionals.len());
                    }
                }
            }
        }
        Args {
            positionals,
            uncertain_from,
        }
    }

    /// The positional word at `idx` (0 = subcommand).
    fn word(&self, idx: usize) -> Word {
        if self.uncertain_from.is_some_and(|from| idx >= from) {
            return Word::Ambiguous;
        }
        self.positionals
            .get(idx)
            .map_or(Word::Missing, |w| Word::At(w.to_ascii_lowercase()))
    }
}

/// The word at `idx`, or the ask to return when it is missing or ambiguous.
fn word_or_ask(args: &Args, idx: usize, program: &str) -> Result<String, (Decision, GateMeta)> {
    match args.word(idx) {
        Word::At(word) => Ok(word),
        Word::Missing => Err(ask_unknown(program)),
        Word::Ambiguous => Err(ask_ambiguous(program)),
    }
}

/// How a token relates to the positional arguments around it.
enum Arity {
    /// Not a flag: a positional argument.
    Positional,
    /// A flag without a separate value: boolean, `--flag=value`, or `-um`.
    Alone,
    /// A flag whose value is the next token.
    TakesNext,
    /// A flag this gate does not know: it may or may not take the next token.
    Unknown,
}

/// Classify one token against [`VALUE_FLAGS`], [`BOOL_FLAGS`] and the short flags.
fn arity(tok: &str) -> Arity {
    if tok == "-" || !tok.starts_with('-') {
        return Arity::Positional;
    }
    if tok.starts_with("--") {
        return if tok.contains('=') || BOOL_FLAGS.contains(&tok) {
            Arity::Alone
        } else if VALUE_FLAGS.contains(&tok) {
            Arity::TakesNext
        } else {
            Arity::Unknown
        };
    }
    for &short in VALUE_SHORTS {
        if let Some(attached) = context::flag_value(tok, &[], short) {
            return if attached.is_some() {
                Arity::Alone
            } else {
                Arity::TakesNext
            };
        }
    }
    let cluster = tok.trim_start_matches('-');
    if cluster.chars().all(|c| context::BOOL_SHORTS.contains(&c)) {
        Arity::Alone
    } else {
        Arity::Unknown
    }
}

/// The tokens after the program word without file-descriptor duplications (`2>&1`, `>&2`):
/// the shell strips those before the CLI sees its argv, and they touch no file. File
/// redirections (`> out.log`) stay as words, so a transfer carrying one never reads as clean.
fn argv(tokens: &[String]) -> Vec<&str> {
    tokens
        .iter()
        .skip(1)
        .map(String::as_str)
        .filter(|tok| !is_fd_duplication(tok))
        .collect()
}

/// Whether `tok` is a file-descriptor duplication such as `2>&1`, `>&2` or `1>&-`.
fn is_fd_duplication(tok: &str) -> bool {
    let op = tok.trim_start_matches(|c: char| c.is_ascii_digit());
    op.strip_prefix(">&")
        .or_else(|| op.strip_prefix("<&"))
        .is_some_and(|fd| !fd.is_empty() && fd.chars().all(|c| c.is_ascii_digit() || c == '-'))
}

/// The amount argument of a transfer.
enum Amount {
    /// A finite, non-negative number.
    Value(f64),
    /// The `ALL` keyword: the entire balance.
    All,
    /// Missing, non-numeric, or not identifiable unambiguously.
    Unclear,
}

/// Parse the positional amount and recipient of `solana transfer <RECIPIENT> <AMOUNT>` or
/// `spl-token transfer <MINT> <AMOUNT> <RECIPIENT>`.
///
/// Flag values never count (`--with-memo 0.0001 DEST 500` sends 500). Any doubt about which
/// word is the amount — a flag of unknown arity, a missing or extra positional (a second
/// command on a new line, say) — yields [`Amount::Unclear`].
fn parse_transfer(args: &Args, program: &str) -> (Amount, Option<String>) {
    // Positionals are `transfer` followed by the CLI arguments; the amount is the second one.
    let (count, recipient_idx) = if program == "spl-token" {
        (4, 3)
    } else {
        (3, 1)
    };
    if args.uncertain_from.is_some() || args.positionals.len() != count {
        return (Amount::Unclear, None);
    }
    let destination = args
        .positionals
        .get(recipient_idx)
        .filter(|r| looks_like_pubkey(r))
        .map(|r| r.to_string());
    let amount = args
        .positionals
        .get(2)
        .map_or(Amount::Unclear, |raw| parse_amount(raw));
    (amount, destination)
}

/// Parse one amount word: `ALL`, or a finite, non-negative number.
fn parse_amount(raw: &str) -> Amount {
    if raw.eq_ignore_ascii_case("ALL") {
        return Amount::All;
    }
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.0 => Amount::Value(v),
        _ => Amount::Unclear,
    }
}

/// Whether any token is `flag` or `flag=...`. Matched anywhere, so a flag value that reads
/// `--final` errs toward the guard.
fn has_flag(tokens: &[String], flag: &str) -> bool {
    tokens.iter().any(|t| {
        t.strip_prefix(flag)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('='))
    })
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
    fn devnet_deploy_has_no_opinion() {
        let ctx = ctx_with(Network::Devnet, "devnet_deploy");
        let (d, meta) = decide("solana program deploy ./prog.so", &ctx, &policy());
        assert_eq!(d, Decision::Defer);
        assert!(!meta.hard_guard);
        assert_eq!(meta.scope, Scope::Deploy);
    }

    #[test]
    fn anchor_deploy_devnet_has_no_opinion() {
        let ctx = ctx_with(Network::Devnet, "anchor_deploy");
        let (d, meta) = decide("anchor deploy", &ctx, &policy());
        assert_eq!(d, Decision::Defer);
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
    fn anchor_build_has_no_opinion() {
        let ctx = ctx_with(Network::Unknown, "anchor_build");
        let (d, _) = decide("anchor build", &ctx, &policy());
        assert_eq!(d, Decision::Defer);
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
    fn readonly_balance_has_no_opinion() {
        let ctx = ctx_with(Network::Mainnet, "balance");
        let (d, meta) = decide("solana balance", &ctx, &policy());
        assert_eq!(d, Decision::Defer);
        assert_eq!(meta.scope, Scope::Other);
    }

    #[test]
    fn readonly_config_get_has_no_opinion() {
        let ctx = ctx_with(Network::Mainnet, "config_get");
        let (d, _) = decide("solana config get", &ctx, &policy());
        assert_eq!(d, Decision::Defer);
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
