//! Bash command gate.
//!
//! Classifies `solana` / `spl-token` / `anchor` commands and decides whether to allow, ask,
//! deny, or defer (no opinion). The command is parsed like a shell would
//! ([`crate::context::shell`]): split on newline, `;`, `&`, `&&`, `||` and `|`, prefixes and
//! wrappers stripped, substitutions, subshells, `-c` scripts and `eval` followed. Each solana
//! command is classified on its own and the whole command takes the *most restrictive*
//! decision (`Deny` > `Ask` > `Allow` > `Defer`). The returned [`GateMeta`] describes the most
//! significant gated command so the relaxation layer and grants can reason about it.
//!
//! D8 v2 (spec §2, §3) splits on-chain actions by recoverability:
//!
//! - **Class U** (the shared list's `irreversible net` rows, [`lists::irreversible`]): denied
//!   with the command echoed on mainnet, testnet and any cluster not positively identified
//!   (Unknown), a hard-guard ask on identified localnet/devnet; at every tier, never granted.
//! - **Class C** (transfers, deploys, buffer closes, authority changes, withdraws): on mainnet
//!   or Unknown an ask below High (a grantable one unless it is an authority change, an
//!   account close or an unbudgetable amount) and a deny at High. `Allow` comes only from a
//!   within-cap transfer on a positively identified devnet/testnet/localnet, and only when
//!   every command is a direct solana-family command; deploys there get no opinion.
//! - A command naming a solana-family program that cannot be parsed, runs code the command
//!   line does not spell out, or runs an expansion as its program asks as a hard guard, and
//!   is denied at High.
//!
//! A command that names its own cluster (`-um`, `--url …`, `-C file`) is judged on it;
//! otherwise `solana`/`spl-token` use [`Context::network`] and `anchor`
//! [`Context::anchor_network`], unless the command changes directory or the CLI config's
//! environment first. With policy `network.mainnet: deny`, every mainnet ask is a deny.
//!
//! The gate performs no process or network I/O: `main.rs` resolved the defaults. It reads a
//! `-C` config file when one is named, and the spend ledger, which is read (not committed)
//! here to predict a transfer decision; `main.rs` commits the debit on an actual allow.

use std::path::Path;

use crate::context::shell::{self, Parsed, SimpleCommand};
use crate::context::{self, Argv, Context, Network};
use crate::gate::{GateMeta, Scope};
use crate::io::Decision;
use crate::lists::{self, Verb, VerbCluster};
use crate::policy::tier::Tier;
use crate::policy::Policy;
use crate::spend::{self, SpendLedger};

/// Classify a bash command and decide.
///
/// Returns the natural decision (before relaxation) and a [`GateMeta`] describing the
/// action. The caller (`main.rs`) applies the relaxation layer to the result.
pub fn decide(command: &str, ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let parsed = shell::parse(command);
    match decide_parsed(command, &parsed, ctx, policy) {
        // An allow vouches for the whole tool call: only for direct (canonical) commands, never
        // one reached behind a wrapper, a quoted or path-qualified program word.
        (Decision::Allow, meta)
            if parsed
                .commands
                .iter()
                .any(|c| c.is_family() && !c.canonical) =>
        {
            (Decision::Defer, meta)
        }
        other => other,
    }
}

/// Whether `command` could concern this gate or the wallet gate: some reading of it names a
/// solana-family program or `solana-keygen` (any path, quoted, escaped, inside wrappers, `-c`
/// strings or substitutions: the raw text is searched), holds ANSI-C quoting, runs an
/// expansion as a program, or cannot be read. `false` lets `gate-bash`, wired for every Bash
/// call, answer no opinion before loading anything. Pure and allocation-light.
pub fn may_concern(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    if lower.contains("$'") {
        return true;
    }
    let plain: String = lower
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    if ["solana", "spl-token", "anchor", "keygen"]
        .iter()
        .any(|w| plain.contains(w))
    {
        return true;
    }
    let parsed = shell::parse(command);
    parsed.unparseable
        || parsed.opaque
        || parsed.write_then_run
        || parsed
            .commands
            .iter()
            .any(|c| c.words.first().is_some_and(|w| w.dynamic))
}

/// The indirection prefilter of the unconditional Bash hook (spec D6.3, default-route).
///
/// Claude Code runs `gate-bash` only for commands its case-sensitive `if: Bash(solana *)`
/// filters match: a command spelled exactly `solana …`, `spl-token …` or `anchor …` at top
/// level (after `;` or `&&` too). When every solana-family command in `command` has that
/// shape, `gate-bash` decides and this returns `None`. Otherwise — a family command behind a
/// wrapper, in a script, after a pipe, spelled differently, or one the parser cannot read —
/// this returns the gate's own decision, resolved like `gate-bash` resolves it (defaults from
/// `cwd`) and with its own meta, so grants and profiles relax it the same way. It never
/// returns an allow or no opinion: those are left to the normal permission flow.
pub fn indirection_prefilter(
    command: &str,
    cwd: &Path,
    policy: &Policy,
) -> Option<(Decision, GateMeta)> {
    // The parse is pure and fast; a substring pre-check would miss `$(echo sol)ana`.
    let parsed = shell::parse(command);
    if !is_routed(&parsed) {
        return None;
    }
    let ctx = Context::build(command, cwd);
    routed_decision(command, &parsed, &ctx, policy)
}

/// [`indirection_prefilter`] with a prepared [`Context`] (its network defaults and data dir).
pub fn indirection_prefilter_in(
    command: &str,
    ctx: &Context,
    policy: &Policy,
) -> Option<(Decision, GateMeta)> {
    let parsed = shell::parse(command);
    if !is_routed(&parsed) {
        return None;
    }
    routed_decision(command, &parsed, ctx, policy)
}

/// Whether the always-on hook decides `parsed` itself (see [`indirection_prefilter`]).
fn is_routed(parsed: &Parsed) -> bool {
    parsed.unparseable
        || parsed.opaque_mention
        || parsed.write_then_run
        || parsed.commands.iter().any(|c| {
            let dynamic_program = c.words.first().is_some_and(|w| w.dynamic);
            let dynamic_words = c.is_family() && c.words.iter().any(|w| w.dynamic);
            dynamic_program || dynamic_words || (c.is_family() && !c.canonical)
        })
}

/// The gate's decision for a routed command, unless it would allow (never the prefilter's).
fn routed_decision(
    command: &str,
    parsed: &Parsed,
    ctx: &Context,
    policy: &Policy,
) -> Option<(Decision, GateMeta)> {
    match decide_parsed(command, parsed, ctx, policy) {
        (decision @ (Decision::Ask { .. } | Decision::Deny { .. }), meta) => Some((decision, meta)),
        _ => None,
    }
}

/// Fold the [`indirection_prefilter`] verdict for `command` into `decision` (the secret
/// gate's, with `meta`), keeping the more restrictive one and the meta of the winner.
pub fn with_indirection_prefilter(
    decision: Decision,
    meta: GateMeta,
    command: &str,
    cwd: &Path,
    policy: &Policy,
) -> (Decision, GateMeta) {
    match indirection_prefilter(command, cwd, policy) {
        Some((routed, routed_meta)) => {
            if severity(&routed) > severity(&decision) {
                (routed, routed_meta)
            } else {
                (decision, meta)
            }
        }
        None => (decision, meta),
    }
}

fn decide_parsed(
    command: &str,
    parsed: &Parsed,
    ctx: &Context,
    policy: &Policy,
) -> (Decision, GateMeta) {
    let tier = policy.tier();
    // A solana-family program named where the parser cannot follow: unparseable text, or an
    // opaque input (a `-c` script, `eval`, interpreter code, a pipe into a shell) that names
    // one. It could be any command at all: a hard-guard ask, whatever its words.
    let named = shell::mentions_family(command);
    if (parsed.unparseable && named) || parsed.opaque_mention {
        return unreadable_at(ask_unparseable(), tier);
    }

    let mut best: Option<(Decision, GateMeta)> = None;
    // Command or process substitution runs code the gate never sees, quoted or not.
    let mut unvetted = parsed.substitution;

    for cmd in &parsed.commands {
        let candidate = if cmd.is_family() {
            family_decision(command, cmd, parsed, ctx, policy, &mut unvetted)
        } else if let Some(verdict) = dynamic_decision(command, cmd, parsed, ctx, tier) {
            verdict
        } else {
            unvetted = true;
            continue;
        };
        // Keep the most restrictive command; on a tie the first one wins.
        let replace = match &best {
            None => true,
            Some((cur, _)) => severity(&candidate.0) > severity(cur),
        };
        if replace {
            best = Some(candidate);
        }
    }

    // Solana text written to a file, then a file or stdin run as code.
    if parsed.write_then_run {
        let unaccounted = unreadable_at(ask_unaccounted(), tier);
        let keep = best
            .as_ref()
            .is_some_and(|(d, _)| severity(d) >= severity(&unaccounted.0));
        if !keep {
            best = Some(unaccounted);
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

/// Decide one solana-family command: Class U first, then the Class C / read-only
/// classification, then the policy and tier rules.
fn family_decision(
    command: &str,
    cmd: &SimpleCommand,
    parsed: &Parsed,
    ctx: &Context,
    policy: &Policy,
    unvetted: &mut bool,
) -> (Decision, GateMeta) {
    let tier = policy.tier();
    let program = cmd.program();
    let argv = Argv::from_shell(&cmd.words);
    let cluster = command_cluster(cmd, &argv, &program, ctx, parsed);
    let irreversible = match irreversible_match(&program, &argv) {
        Ok(found) => found,
        Err(_) => return unreadable_at(ask_lists_unavailable(&program), tier),
    };
    if let Some(row) = irreversible {
        return class_u(&row, &cluster, command, ctx);
    }
    let segment_ctx = Context {
        network: cluster.network,
        ..ctx.clone()
    };
    let (decision, meta) = classify(&program, &argv, &segment_ctx, policy);
    let decision = if cmd.writes_file && decision == Decision::Allow {
        // A redirection writes a file: never part of an allowed transfer.
        *unvetted = true;
        Decision::Ask {
            reason: format!("{program} command redirects output to a file — approve to proceed"),
        }
    } else {
        decision
    };
    let decision = mainnet_policy(decision, cluster.network, policy);
    if is_unreadable_meta(&meta) {
        return unreadable_at((decision, meta), tier);
    }
    let decision = class_c_at(decision, &meta, &cluster, command, ctx, tier);
    (decision, meta)
}

/// A command whose program is an expansion. `None` when it cannot be a solana-family command.
///
/// It may be one when [`shell::dynamic_family_program`] says so, or when its words have the
/// shape of a Class U command for some family program (`$S program-v4 finalize P`): then the
/// Class U verdict for the riskiest reading joins the expansion's own hard-guard ask.
fn dynamic_decision(
    command: &str,
    cmd: &SimpleCommand,
    parsed: &Parsed,
    ctx: &Context,
    tier: Tier,
) -> Option<(Decision, GateMeta)> {
    if !cmd.words.first().is_some_and(|w| w.dynamic) {
        return None;
    }
    let argv = Argv::from_shell(&cmd.words);
    let irreversible = shell::FAMILY
        .iter()
        .find_map(|program| irreversible_match(program, &argv).ok().flatten());
    let dynamic = shell::dynamic_family_program(cmd, parsed);
    if !dynamic && irreversible.is_none() {
        return None;
    }
    let expansion = unreadable_at(ask_dynamic_program(), tier);
    let Some(row) = irreversible else {
        return Some(expansion);
    };
    let base = (!parsed.cwd_changed).then_some(ctx.project_dir.as_path());
    let cluster = match context::explicit_network(&argv, base) {
        Some(network) => Cluster {
            network,
            source: Source::Flags(flag_words(cmd)),
        },
        None => Cluster {
            network: Network::Unknown,
            source: Source::Expansion,
        },
    };
    let class_u = class_u(&row, &cluster, command, ctx);
    Some(if severity(&expansion.0) > severity(&class_u.0) {
        expansion
    } else {
        class_u
    })
}

/// A cluster and where it came from (named in deny reasons).
struct Cluster {
    network: Network,
    source: Source,
}

/// Where a command's cluster came from.
enum Source {
    /// The command's own `-u/--url/--cluster/--provider.cluster/-C` words.
    Flags(String),
    /// The command line sets a variable the CLIs read their config through.
    EnvChanged,
    /// The command line changes directory before an `anchor` command.
    CwdChanged,
    /// `anchor` without a cluster flag: `Anchor.toml`, else the CLI config.
    AnchorDefault,
    /// `solana`/`spl-token` without a cluster flag: the CLI config.
    CliDefault,
    /// An expansion runs as the program: nothing names a cluster.
    Expansion,
}

impl Source {
    fn describe(&self, ctx: &Context) -> String {
        match self {
            Source::Flags(words) if words.is_empty() => "the command's own flags".to_string(),
            Source::Flags(words) => format!("the command's `{words}`"),
            Source::EnvChanged => {
                "the CLI config, after the command line changes the variables it is read \
                 through"
                    .to_string()
            }
            Source::CwdChanged => "Anchor.toml, after the command line changes directory".into(),
            Source::AnchorDefault => {
                let toml = ctx
                    .project_dir
                    .ancestors()
                    .any(|d| d.join("Anchor.toml").exists());
                let base = if toml {
                    "Anchor.toml"
                } else {
                    "the CLI config (`solana config get`)"
                };
                let env = std::env::var("ANCHOR_PROVIDER_URL").is_ok_and(|v| !v.trim().is_empty());
                if env {
                    format!("{base} and ANCHOR_PROVIDER_URL")
                } else {
                    base.to_string()
                }
            }
            Source::CliDefault => "the CLI config (`solana config get`)".to_string(),
            Source::Expansion => "nothing: an expansion runs as the program".to_string(),
        }
    }
}

/// The words of `cmd` that name its cluster (`-um`, `--url x`, `-C file`), as written.
fn flag_words(cmd: &SimpleCommand) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut words = cmd.words.iter().skip(1).map(|w| w.text.as_str());
    while let Some(word) = words.next() {
        let long = ["--url", "--cluster", "--provider.cluster", "--config"]
            .iter()
            .find(|f| word == **f || word.starts_with(&format!("{f}=")));
        let short = !word.starts_with("--")
            && word.starts_with('-')
            && word
                .trim_start_matches('-')
                .trim_start_matches(['v', 'h', 'V'])
                .starts_with(['u', 'C']);
        if long.is_none() && !short {
            continue;
        }
        out.push(word);
        let bare = long.is_some_and(|f| word == *f)
            || (short
                && word
                    .trim_start_matches('-')
                    .trim_start_matches(['v', 'h', 'V'])
                    .len()
                    == 1);
        if bare {
            if let Some(value) = words.next() {
                out.push(value);
            }
        }
    }
    out.join(" ")
}

/// The cluster one solana-family command runs on, with its source: its own flags, else the
/// default for its program — unknown when the command changes directory (for `anchor`, and
/// for a relative `-C`) or the variables the CLIs read their config through.
fn command_cluster(
    cmd: &SimpleCommand,
    argv: &Argv,
    program: &str,
    ctx: &Context,
    parsed: &Parsed,
) -> Cluster {
    let base = (!parsed.cwd_changed).then_some(ctx.project_dir.as_path());
    if let Some(network) = context::explicit_network(argv, base) {
        return Cluster {
            network,
            source: Source::Flags(flag_words(cmd)),
        };
    }
    let (network, source) = if parsed.env_changed {
        (Network::Unknown, Source::EnvChanged)
    } else if program == "anchor" && parsed.cwd_changed {
        (Network::Unknown, Source::CwdChanged)
    } else if program == "anchor" {
        (ctx.anchor_network, Source::AnchorDefault)
    } else {
        (ctx.network, Source::CliDefault)
    };
    Cluster { network, source }
}

/// Class U rows the shared list does not spell but this gate also treats as Class U (same
/// argv grammar): `anchor program close` of a program, and `--final` on the other deploy
/// commands. `anchor legacy-idl …` is read as `anchor idl …`.
const EXTRA_IRREVERSIBLE: &[&[&str]] = &[
    &["anchor", "program", "close", "[--bypass-warning]"],
    &["anchor", "upgrade", "[--final]"],
    &["anchor", "migrate", "[--final]"],
];

/// The Class U row `program` + `argv` matches, written out (`solana program deploy --final`);
/// `None` when none does. Positional words are matched as parsed, even past an uncertain
/// position: a literal Class U spelling is judged as one.
fn irreversible_match(
    program: &str,
    argv: &Argv,
) -> Result<Option<String>, lists::ListsUnavailable> {
    let mut tokens: Vec<String> = Vec::with_capacity(argv.positionals.len() + 1);
    tokens.push(program.to_ascii_lowercase());
    tokens.extend(argv.positionals.iter().map(|w| w.to_ascii_lowercase()));
    if program == "anchor" && tokens.get(1).is_some_and(|t| t == "legacy-idl") {
        tokens[1] = "idl".to_string();
    }
    let rows = lists::irreversible()?;
    let listed = rows
        .iter()
        .filter(|v| v.cluster == VerbCluster::Net)
        .map(|v: &&Verb| v.argv.iter().map(String::as_str).collect::<Vec<_>>());
    let built_in = EXTRA_IRREVERSIBLE.iter().map(|r| r.to_vec());
    Ok(listed
        .chain(built_in)
        .find(|row| row_matches(row, &tokens, |f| argv.has_flag(f)))
        .map(|row| describe_row(&row, &tokens)))
}

/// Whether `row` (literals, `*`, `[--flag]`) matches `tokens` (program + positionals) and
/// the flags `has_flag` reports.
fn row_matches(row: &[&str], tokens: &[String], has_flag: impl Fn(&str) -> bool) -> bool {
    let mut at = 0usize;
    for part in row {
        if let Some(flag) = part.strip_prefix('[').and_then(|p| p.strip_suffix(']')) {
            if !has_flag(flag) {
                return false;
            }
            continue;
        }
        let Some(token) = tokens.get(at) else {
            return false;
        };
        if *part != "*" && !token.eq_ignore_ascii_case(part) {
            return false;
        }
        at = match at.checked_add(1) {
            Some(next) => next,
            None => return false,
        };
    }
    true
}

/// A matched row as words: `*` replaced by the command's word, brackets dropped.
fn describe_row(row: &[&str], tokens: &[String]) -> String {
    let mut at = 0usize;
    let mut out: Vec<&str> = Vec::with_capacity(row.len());
    for part in row {
        if let Some(flag) = part.strip_prefix('[').and_then(|p| p.strip_suffix(']')) {
            out.push(flag);
            continue;
        }
        out.push(if *part == "*" {
            tokens.get(at).map_or("*", String::as_str)
        } else {
            part
        });
        at = at.saturating_add(1);
    }
    out.join(" ")
}

/// Longest command echoed in a reason.
const MAX_ECHO_CHARS: usize = 400;

/// `command` for a reason: whole, or its first [`MAX_ECHO_CHARS`] characters and `…`.
fn echo(command: &str) -> String {
    let command = command.trim();
    match command.char_indices().nth(MAX_ECHO_CHARS) {
        Some((cut, _)) => format!("{}…", &command[..cut]),
        None => command.to_string(),
    }
}

/// How a reason names a cluster.
fn cluster_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Devnet => "devnet",
        Network::Testnet => "testnet",
        Network::Localnet => "localnet",
        Network::Unknown => "an unidentified cluster",
    }
}

/// The Class U decision for `row` on `cluster` (spec §3.1): a hard-guard ask on positively
/// identified localnet/devnet, a deny everywhere else. Never granted: the meta is a hard
/// guard, and the deny echoes `command` for the user to run themselves.
fn class_u(row: &str, cluster: &Cluster, command: &str, ctx: &Context) -> (Decision, GateMeta) {
    let scope = if ["authority", "authorize"].iter().any(|w| row.contains(w)) {
        Scope::Authority
    } else if ["deploy", "upgrade", "write-buffer", "finalize", "--final"]
        .iter()
        .any(|w| row.contains(w))
    {
        Scope::Deploy
    } else {
        Scope::Destructive
    };
    let mut meta = GateMeta::new(scope, true);
    meta.program = row.split(' ').next().map(str::to_string);
    let net = cluster_label(cluster.network);
    let source = cluster.source.describe(ctx);
    let decision = match cluster.network {
        Network::Localnet | Network::Devnet => Decision::Ask {
            reason: format!(
                "Irreversible on-chain action `{row}` on {net} (cluster from {source}): it \
                 destroys the capability even for its owner — approve to proceed (no grant \
                 covers it)"
            ),
        },
        Network::Mainnet | Network::Testnet | Network::Unknown => Decision::Deny {
            reason: format!(
                "Irreversible on-chain action `{row}` on {net} (cluster from {source}): it \
                 destroys the capability even for its owner and runs through the agent only \
                 on a positively identified localnet or devnet. Run it yourself outside the \
                 agent if you intend it: `{}`",
                echo(command)
            ),
        },
    };
    (decision, meta)
}

/// Class C at High (spec §2): on mainnet or an unidentified cluster, an ask for a transfer,
/// deploy, authority change or close is a deny, whatever grant exists. Other tiers keep it.
fn class_c_at(
    decision: Decision,
    meta: &GateMeta,
    cluster: &Cluster,
    command: &str,
    ctx: &Context,
    tier: Tier,
) -> Decision {
    let counterparty = matches!(
        meta.scope,
        Scope::Transfer | Scope::Deploy | Scope::Authority | Scope::Destructive
    );
    let risky = matches!(cluster.network, Network::Mainnet | Network::Unknown);
    match decision {
        Decision::Ask { reason } if tier == Tier::High && counterparty && risky => Decision::Deny {
            reason: format!(
                "{reason} — denied at tier high: a counterparty action on {} (cluster \
                     from {}). Run it yourself outside the agent if you intend it: `{}`",
                cluster_label(cluster.network),
                cluster.source.describe(ctx),
                echo(command)
            ),
        },
        other => other,
    }
}

/// Whether `meta` marks a command the gate cannot read (unparseable, opaque, an expansion
/// program, ambiguous words, lists unavailable): a hard guard of no particular scope.
fn is_unreadable_meta(meta: &GateMeta) -> bool {
    meta.scope == Scope::Other && meta.hard_guard
}

/// An unreadable solana-family command (spec §2, WS-A row): its hard-guard ask is a deny at
/// High.
fn unreadable_at((decision, meta): (Decision, GateMeta), tier: Tier) -> (Decision, GateMeta) {
    match decision {
        Decision::Ask { reason } if tier == Tier::High => (
            Decision::Deny {
                reason: format!(
                    "{reason} — denied at tier high: the gate cannot tell what this runs"
                ),
            },
            meta,
        ),
        other => (other, meta),
    }
}

/// Policy `network.mainnet: deny` turns every mainnet ask into a deny (it can only tighten).
fn mainnet_policy(decision: Decision, network: Network, policy: &Policy) -> Decision {
    match decision {
        Decision::Ask { reason }
            if network == Network::Mainnet && policy.network.mainnet == "deny" =>
        {
            Decision::Deny {
                reason: format!("{reason} — denied: policy network.mainnet is `deny`"),
            }
        }
        other => other,
    }
}

/// Classify one solana-family command.
fn classify(program: &str, argv: &Argv, ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    match program {
        "solana" => classify_solana(argv, ctx, policy),
        "spl-token" => classify_spl_token(argv, ctx, policy),
        _ => classify_anchor(argv, ctx, policy),
    }
}

/// Classify a `solana ...` command.
fn classify_solana(argv: &Argv, ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let sub = match word_or_ask(argv, 0, "solana") {
        Ok(sub) => sub,
        Err(verdict) => return verdict,
    };
    match sub.as_str() {
        "transfer" => transfer_decision(argv, "solana", ctx, policy),
        "program" => classify_program(argv, "solana", ctx),
        "config" => match word_or_ask(argv, 1, "solana") {
            Ok(action) if action == "get" => readonly("solana"),
            Ok(action) => ask_not_readonly("solana", &format!("config {action}")),
            Err(verdict) => verdict,
        },
        "close" => destructive_decision("solana", ctx, true),
        "program-v4" => match word_or_ask(argv, 1, "solana") {
            Ok(action) if action == "deploy" => deploy_decision("solana", ctx, argv),
            Ok(_) => ask_unknown("solana"),
            Err(verdict) => verdict,
        },
        "withdraw-stake" | "withdraw-from-vote-account" | "withdraw-from-nonce-account" => {
            withdraw_decision(&sub, ctx)
        }
        "close-vote-account" => irreversible_decision(
            "solana",
            ctx,
            argv,
            Scope::Destructive,
            "vote-account close",
        ),
        s if is_solana_readonly(s) => readonly("solana"),
        _ => ask_unknown("solana"),
    }
}

/// Classify `<program> program <action> ...`, shared by `solana program` and `anchor program`.
fn classify_program(argv: &Argv, program: &str, ctx: &Context) -> (Decision, GateMeta) {
    let action = match word_or_ask(argv, 1, program) {
        Ok(action) => action,
        Err(verdict) => return verdict,
    };
    match action.as_str() {
        "deploy" | "write-buffer" | "upgrade" | "extend" => deploy_decision(program, ctx, argv),
        "set-upgrade-authority" => irreversible_decision(
            program,
            ctx,
            argv,
            Scope::Authority,
            "upgrade-authority change",
        ),
        "set-buffer-authority" => authority_decision(program, ctx, argv),
        // `close --bypass-warning` (a program) is Class U, decided before this. Without it the
        // CLI closes buffers only: lamports go to the recipient.
        "close" => buffer_close_decision(program, ctx),
        // Read-only program subcommands.
        "show" | "dump" => readonly(program),
        _ => ask_unknown(program),
    }
}

/// Classify an `spl-token ...` command.
fn classify_spl_token(argv: &Argv, ctx: &Context, policy: &Policy) -> (Decision, GateMeta) {
    let sub = match word_or_ask(argv, 0, "spl-token") {
        Ok(sub) => sub,
        Err(verdict) => return verdict,
    };
    match sub.as_str() {
        "transfer" => transfer_decision(argv, "spl-token", ctx, policy),
        "authorize" if argv.has_flag("--disable") => irreversible_decision(
            "spl-token",
            ctx,
            argv,
            Scope::Authority,
            "authority removal (--disable)",
        ),
        "authorize" => authority_decision("spl-token", ctx, argv),
        "burn" => destructive_decision("spl-token", ctx, false),
        "close" => irreversible_decision(
            "spl-token",
            ctx,
            argv,
            Scope::Destructive,
            "token-account close",
        ),
        "close-mint" => {
            irreversible_decision("spl-token", ctx, argv, Scope::Destructive, "mint close")
        }
        // `gc` closes empty token accounts.
        "gc" => destructive_decision("spl-token", ctx, true),
        s if is_spl_readonly(s) => readonly("spl-token"),
        _ => ask_unknown("spl-token"),
    }
}

/// Classify an `anchor ...` command.
fn classify_anchor(argv: &Argv, ctx: &Context, _policy: &Policy) -> (Decision, GateMeta) {
    let sub = match word_or_ask(argv, 0, "anchor") {
        Ok(sub) => sub,
        Err(verdict) => return verdict,
    };
    match sub.as_str() {
        "deploy" | "upgrade" | "migrate" => deploy_decision("anchor", ctx, argv),
        "program" => classify_program(argv, "anchor", ctx),
        "idl" | "legacy-idl" => classify_anchor_idl(argv, &sub, ctx),
        // Local/dev operations.
        "build" | "keys" | "verify" | "localnet" | "expand" | "new" | "init" => readonly("anchor"),
        // `test` deploys to the configured cluster; `run` executes repo-defined scripts.
        "test" | "run" => ask_not_readonly("anchor", &sub),
        _ => ask_unknown("anchor"),
    }
}

/// Classify `anchor idl|legacy-idl <action> ...`: authority changes and closes are
/// irreversible, and no IDL command is on the read-only fast path.
fn classify_anchor_idl(argv: &Argv, sub: &str, ctx: &Context) -> (Decision, GateMeta) {
    let action = match word_or_ask(argv, 1, "anchor") {
        Ok(action) => action,
        Err(verdict) => return verdict,
    };
    match action.as_str() {
        "erase-authority" | "set-authority" => irreversible_decision(
            "anchor",
            ctx,
            argv,
            Scope::Authority,
            "IDL authority change",
        ),
        "set-buffer-authority" => authority_decision("anchor", ctx, argv),
        "close" => {
            irreversible_decision("anchor", ctx, argv, Scope::Destructive, "IDL account close")
        }
        _ => ask_not_readonly("anchor", &format!("{sub} {action}")),
    }
}

/// Build a transfer decision via the spend ledger (predict-only; no debit here).
///
/// Only a definite amount on a positively identified devnet/testnet/localnet can be allowed;
/// mainnet or an unidentified network escalates to ask (a deny stays a deny). `ALL`, or an
/// amount that cannot be identified unambiguously, asks as a hard guard: no grant can budget it.
fn transfer_decision(
    argv: &Argv,
    program: &str,
    ctx: &Context,
    policy: &Policy,
) -> (Decision, GateMeta) {
    let (amount, destination) = parse_transfer(argv, program);

    let mut meta = GateMeta::new(Scope::Transfer, !matches!(amount, Amount::Value(_)));
    meta.program = Some(program.to_string());
    meta.destination = destination;

    let decision = match amount {
        Amount::Value(sol) => {
            meta.amount_sol = Some(sol);
            // Predict the decision against the ledger WITHOUT committing — `main.rs`
            // debits via `spend::commit` only when the action is allowed.
            let ledger = SpendLedger::load(&ctx.plugin_data);
            spend::verdict(sol, &ledger, policy, ctx.network).into()
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

/// Build a deploy decision (`program deploy|write-buffer|upgrade|extend`, `program-v4 deploy`,
/// `anchor deploy|upgrade|migrate`).
///
/// `--final` makes the program immutable: irreversible (Class U, normally decided before
/// this). Otherwise mainnet or an unidentified network → a grantable ask, a positively
/// identified devnet/testnet/localnet → no opinion.
fn deploy_decision(program: &str, ctx: &Context, argv: &Argv) -> (Decision, GateMeta) {
    if argv.has_flag("--final") {
        return irreversible_decision(
            program,
            ctx,
            argv,
            Scope::Deploy,
            "deploy with --final (program becomes immutable)",
        );
    }

    // Grantable on any cluster (spec §2: a covering confirmed grant allows below High).
    let mut meta = GateMeta::new(Scope::Deploy, false);
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

/// Build an irreversible-action decision for a command the Class U rows did not match (an
/// authority change to a new key, an IDL authority change) or, should a list row go, the
/// 1.1.0 fallback: a hard-guard ask on every cluster, and a deny for `--final` on mainnet.
fn irreversible_decision(
    program: &str,
    ctx: &Context,
    argv: &Argv,
    scope: Scope,
    what: &str,
) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(scope, true);
    meta.program = Some(program.to_string());

    let mainnet = matches!(ctx.network, Network::Mainnet);
    let decision = if mainnet && argv.has_flag("--final") {
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
fn authority_decision(program: &str, ctx: &Context, argv: &Argv) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Authority, true);
    meta.program = Some(program.to_string());
    if let Some(target) = first_pubkey_arg(argv) {
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

/// A program buffer close (`program close` without `--bypass-warning`): Class C, a grantable
/// ask on every cluster (spec §2: recoverable close asks; a covering grant allows below High).
fn buffer_close_decision(program: &str, ctx: &Context) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Destructive, false);
    meta.program = Some(program.to_string());
    let net = if matches!(ctx.network, Network::Mainnet) {
        "mainnet "
    } else {
        ""
    };
    (
        Decision::Ask {
            reason: format!(
                "{program} {net}buffer close (recoverable: lamports go to the recipient) — \
                 approve to proceed"
            ),
        },
        meta,
    )
}

/// A stake, vote or nonce withdraw (Class C): it moves lamports to a recipient by an amount
/// this gate does not budget, so a hard-guard ask on every cluster.
fn withdraw_decision(sub: &str, ctx: &Context) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Transfer, true);
    meta.program = Some("solana".to_string());
    let net = if matches!(ctx.network, Network::Mainnet) {
        "mainnet "
    } else {
        ""
    };
    (
        Decision::Ask {
            reason: format!("solana {net}{sub} moves lamports to a recipient — approve to proceed"),
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

/// The shared on-chain list failed to load: the gate cannot tell Class U from anything else, so
/// every solana-family command is a hard-guard ask (fail closed).
fn ask_lists_unavailable(program: &str) -> (Decision, GateMeta) {
    let mut meta = GateMeta::unreadable();
    meta.program = Some(program.to_string());
    (
        Decision::Ask {
            reason: format!(
                "The shared on-chain action list is unavailable, so this {program} command \
                 cannot be classified — approve to proceed"
            ),
        },
        meta,
    )
}

/// A command naming a solana-family program that cannot be parsed, runs code the command line
/// does not spell out (a shell reading a pipe, `eval "$x"`), or runs an expansion as its
/// program. It could be anything, so it asks as a hard guard.
fn ask_unparseable() -> (Decision, GateMeta) {
    (
        Decision::Ask {
            reason: "Could not parse this command, and it names a solana-family program — approve to proceed"
                .to_string(),
        },
        GateMeta::unreadable(),
    )
}

/// A solana-family command is written to a script that is then run: the gate cannot fully see
/// its words. A hard-guard ask.
fn ask_unaccounted() -> (Decision, GateMeta) {
    (
        Decision::Ask {
            reason: "This command runs a solana-family command the gate cannot fully see — approve to proceed"
                .to_string(),
        },
        GateMeta::unreadable(),
    )
}

/// The program is an expansion that could be a solana-family program (`$(echo sol)ana`,
/// `X=solana; $X …`, `$X transfer …`). A hard-guard ask.
fn ask_dynamic_program() -> (Decision, GateMeta) {
    (
        Decision::Ask {
            reason: "This command runs an expansion as its program, and it may be a solana-family program — approve to proceed"
                .to_string(),
        },
        GateMeta::unreadable(),
    )
}

/// A solana-family command whose words cannot be identified unambiguously (a flag of unknown
/// arity or a shell expansion precedes them). It could be anything, so it asks as a hard guard.
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
pub(crate) fn is_solana_readonly(sub: &str) -> bool {
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
pub(crate) fn is_spl_readonly(sub: &str) -> bool {
    matches!(
        sub,
        "balance" | "accounts" | "address" | "display" | "supply" | "account-info"
    )
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

/// The positional word at `idx` (0 = subcommand).
fn word(argv: &Argv, idx: usize) -> Word {
    if argv.uncertain_from.is_some_and(|from| idx >= from) {
        return Word::Ambiguous;
    }
    argv.positionals
        .get(idx)
        .map_or(Word::Missing, |w| Word::At(w.to_ascii_lowercase()))
}

/// The word at `idx`, or the ask to return when it is missing or ambiguous.
fn word_or_ask(argv: &Argv, idx: usize, program: &str) -> Result<String, (Decision, GateMeta)> {
    match word(argv, idx) {
        Word::At(word) => Ok(word),
        Word::Missing => Err(ask_unknown(program)),
        Word::Ambiguous => Err(ask_ambiguous(program)),
    }
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
fn parse_transfer(argv: &Argv, program: &str) -> (Amount, Option<String>) {
    // Positionals are `transfer` followed by the CLI arguments; the amount is the second one.
    let (count, recipient_idx) = if program == "spl-token" {
        (4, 3)
    } else {
        (3, 1)
    };
    if argv.uncertain_from.is_some() || argv.positionals.len() != count {
        return (Amount::Unclear, None);
    }
    let destination = argv
        .positionals
        .get(recipient_idx)
        .filter(|r| looks_like_pubkey(r))
        .map(|r| r.to_string());
    let amount = argv
        .positionals
        .get(2)
        .map_or(Amount::Unclear, |raw| parse_amount(raw));
    (amount, destination)
}

/// Longest amount word accepted; longer is unclear (and could not be a real balance).
const MAX_AMOUNT_LEN: usize = 32;

/// Parse one amount word: `ALL`, or a plain decimal (`500`, `0.5`, `.5`). Exponents, signs,
/// hex, separators, `inf`/`NaN` and overlong words are [`Amount::Unclear`]: a CLI might read
/// them differently.
fn parse_amount(raw: &str) -> Amount {
    if raw.eq_ignore_ascii_case("ALL") {
        return Amount::All;
    }
    let digits = raw.chars().filter(char::is_ascii_digit).count();
    let dots = raw.chars().filter(|&c| c == '.').count();
    let plain = digits > 0
        && dots <= 1
        && raw.len() <= MAX_AMOUNT_LEN
        && raw.chars().all(|c| c.is_ascii_digit() || c == '.');
    if !plain {
        return Amount::Unclear;
    }
    match raw.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.0 => Amount::Value(v),
        _ => Amount::Unclear,
    }
}

/// The first base58-looking positional argument.
fn first_pubkey_arg(argv: &Argv) -> Option<String> {
    argv.positionals
        .iter()
        .find(|w| looks_like_pubkey(w))
        .map(|w| w.to_string())
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
            anchor_network: network,
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
    fn mainnet_deploy_asks_and_is_grantable() {
        // Class C (spec §2): a covering confirmed grant may allow it below High.
        let ctx = ctx_with(Network::Mainnet, "mainnet_deploy");
        let (d, meta) = decide("solana program deploy ./prog.so", &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(!meta.hard_guard);
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
    fn spl_burn_is_class_u() {
        // Class U (spec §3.1): a hard-guard ask on devnet, a deny on mainnet.
        let ctx = ctx_with(Network::Devnet, "burn");
        let (d, meta) = decide(&format!("spl-token burn {DEST} 100"), &ctx, &policy());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard, "Class U is never granted");
        assert_eq!(meta.scope, Scope::Destructive);
        let ctx = ctx_with(Network::Mainnet, "burn_main");
        let (d, _) = decide(&format!("spl-token burn {DEST} 100"), &ctx, &policy());
        assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
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
        // The ledger is an authenticated state file (a plain one counts as exhausted).
        let dir = crate::datadir::DataDir {
            path: ctx.plugin_data.clone(),
            trusted: false,
        };
        crate::statefile::store(&dir, crate::spend::SPEND_FILE, &ledger).unwrap();

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
        assert!(!meta.hard_guard, "a mainnet deploy is grantable Class C");
    }

    #[test]
    fn rows_match_literals_wildcards_and_flags() {
        let parsed = shell::parse("solana -um program-v4 retract P --final");
        let argv = Argv::from_shell(&parsed.commands[0].words);
        let tokens: Vec<String> = std::iter::once("solana".to_string())
            .chain(argv.positionals.iter().map(|w| w.to_string()))
            .collect();
        let has = |f: &str| argv.has_flag(f);
        assert!(row_matches(
            &["solana", "program-v4", "*", "[--final]"],
            &tokens,
            has
        ));
        assert!(!row_matches(
            &["solana", "program-v4", "finalize"],
            &tokens,
            has
        ));
        assert!(!row_matches(
            &["solana", "program-v4", "*", "[--nope]"],
            &tokens,
            has
        ));
        assert_eq!(
            describe_row(&["solana", "program-v4", "*", "[--final]"], &tokens),
            "solana program-v4 retract --final"
        );
    }

    #[test]
    fn class_u_at_high_is_still_an_ask_on_devnet() {
        let ctx = ctx_with(Network::Devnet, "u_high");
        let mut p = policy();
        p.runtime.tier = Tier::High;
        let (d, meta) = decide("spl-token close-mint M", &ctx, &p);
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert!(meta.hard_guard);
    }
}
