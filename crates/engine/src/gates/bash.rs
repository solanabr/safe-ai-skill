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
//!   with the command echoed on mainnet and any cluster not positively identified (Unknown), a
//!   hard-guard ask on identified localnet/devnet/testnet; at every tier, never granted.
//! - **Class C** (transfers, deploys, authority changes, withdraws): on mainnet
//!   or Unknown an ask below High (a grantable one unless it is an authority change, an
//!   account close or an unbudgetable amount) and a deny at High. `Allow` comes only from a
//!   within-cap SOL transfer on a positively identified devnet/testnet/localnet, and only when
//!   every command is a direct solana-family command; deploys there get no opinion. An
//!   `spl-token transfer` amount is in tokens (D3): never budgeted or granted as SOL, no
//!   opinion on identified devnet/testnet/localnet, a hard-guard ask anywhere else.
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
    if over_work_cap(command) {
        return over_cap(policy);
    }
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

/// Longest command the gate parses; longer is a hard-guard ask (deny at High) without parsing.
pub const MAX_PARSE_BYTES: usize = 256 * 1024;

/// Most expansion openers (`$(`, `${`, `<(`, `>(`, backquote) the gate parses; more is a
/// hard-guard ask (deny at High). Nesting costs the parser more than its length.
pub const MAX_EXPANSIONS: usize = 2048;

/// Whether `command` is too large or too nested to parse within the hook's budget.
pub fn over_work_cap(command: &str) -> bool {
    if command.len() > MAX_PARSE_BYTES {
        return true;
    }
    let bytes = command.as_bytes();
    let mut count = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        let opener = match b {
            b'`' => true,
            b'(' | b'{' => i > 0 && matches!(bytes[i - 1], b'$' | b'<' | b'>'),
            _ => false,
        };
        if opener {
            count = count.saturating_add(1);
            if count > MAX_EXPANSIONS {
                return true;
            }
        }
    }
    false
}

/// The verdict for a command over the work cap ([`over_work_cap`]).
pub fn over_cap(policy: &Policy) -> (Decision, GateMeta) {
    unreadable_at(
        (
            Decision::Ask {
                reason: "This command is too large or too deeply nested to check — approve to \
                         proceed"
                    .to_string(),
            },
            GateMeta::unreadable(),
        ),
        policy.tier(),
    )
}

/// Substrings that send a command to the full gate (after line continuations, quotes and
/// backslashes are removed): the family programs, `solana-keygen`, and `xargs` (whose
/// replacement string can become the program).
const TRIGGERS: &[&str] = &["solana", "spl-token", "anchor", "keygen", "xargs"];

/// Whether `command` could concern this gate or the wallet gate. Conservative: when in doubt,
/// the full gate runs. It does when the command is over the work cap (any size over
/// [`MAX_PARSE_BYTES`], trigger or not); holds ANSI-C quoting or
/// a redirection; contains a [`TRIGGERS`] word once `\`+newline, quotes and backslashes are
/// removed; or its parse is unreadable, opaque, writes or runs script text, or has a command
/// whose program is a family program, `solana-keygen`, a file-clobbering program (the wallet
/// gate's), an expansion or an unquoted glob. `false` lets `gate-bash`, wired for every Bash
/// call, answer no opinion before loading policy, lists or state. It parses the command once.
pub fn may_concern(command: &str) -> bool {
    // Too large to parse: the gate asks, whatever the text names (padding must not switch off
    // the parse-based routing below).
    if command.len() > MAX_PARSE_BYTES {
        return true;
    }
    let lower = command.to_ascii_lowercase();
    let joined = lower.replace("\\\r\n", "").replace("\\\n", "");
    let plain: String = joined
        .chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\\'))
        .collect();
    if lower.contains("$'") || TRIGGERS.iter().any(|w| plain.contains(w)) {
        return true;
    }
    if over_work_cap(command) || lower.contains('>') {
        return true;
    }
    let parsed = shell::parse(command);
    parsed.unparseable
        || parsed.opaque
        || parsed.write_then_run
        || parsed.writes_family_text
        || parsed.commands.iter().any(|c| {
            let program = c.program();
            c.is_family()
                || program == "solana-keygen"
                || crate::gates::wallet::is_file_clobber(&program)
                || c.words.first().is_some_and(unresolved_program_word)
                || find_exec(c).is_some()
        })
}

/// Whether a program word names no fixed program: an expansion, or an unquoted glob.
fn unresolved_program_word(word: &shell::Word) -> bool {
    word.dynamic || (word.splits && word.text.contains(['*', '?', '[']))
}

/// Shell glob match of `text` against `pattern` (`*`, `?`, `[…]` with ranges and `!`/`^`
/// negation; everything else literal). Iterative, O(len(pattern) × len(text)).
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // reach[j]: the pattern so far matches text[..j].
    let mut reach = vec![false; t.len() + 1];
    reach[0] = true;
    let mut i = 0usize;
    while let Some(&pc) = p.get(i) {
        let mut next = vec![false; t.len() + 1];
        match pc {
            '*' => {
                let mut on = false;
                for (j, slot) in next.iter_mut().enumerate() {
                    on |= reach[j];
                    *slot = on;
                }
                i += 1;
            }
            '[' => {
                let (class, len) = char_class(p.get(i..).unwrap_or_default());
                for (j, &tc) in t.iter().enumerate() {
                    if reach[j] && class.as_ref().map_or(tc == '[', |c| c.matches(tc)) {
                        next[j + 1] = true;
                    }
                }
                i += len;
            }
            c => {
                for (j, &tc) in t.iter().enumerate() {
                    if reach[j] && (c == '?' || tc == c) {
                        next[j + 1] = true;
                    }
                }
                i += 1;
            }
        }
        reach = next;
    }
    reach[t.len()]
}

/// A `[…]` bracket expression.
struct CharClass {
    negated: bool,
    items: Vec<(char, char)>,
}

impl CharClass {
    fn matches(&self, c: char) -> bool {
        self.items.iter().any(|&(lo, hi)| lo <= c && c <= hi) != self.negated
    }
}

/// Parse the bracket expression at the start of `p` (`p[0] == '['`): the class and the pattern
/// characters it spans. No closing `]` → `None` and a literal `[` of length 1.
fn char_class(p: &[char]) -> (Option<CharClass>, usize) {
    let mut k = 1;
    let negated = matches!(p.get(k), Some('!' | '^'));
    if negated {
        k += 1;
    }
    let mut items = Vec::new();
    let mut first = true;
    while let Some(&c) = p.get(k) {
        if c == ']' && !first {
            return (Some(CharClass { negated, items }), k + 1);
        }
        first = false;
        match (p.get(k + 1), p.get(k + 2)) {
            (Some('-'), Some(&hi)) if hi != ']' => {
                items.push((c, hi));
                k += 3;
            }
            _ => {
                items.push((c, c));
                k += 1;
            }
        }
    }
    (None, 1)
}

/// The replacement strings of `xargs -I R` / `-J R` / `--replace=R` / `-iR` in `command`: a
/// program word containing one is whatever stdin holds.
fn xargs_placeholders(command: &str) -> Vec<String> {
    if !command.contains("xargs") {
        return Vec::new();
    }
    let tokens = context::tokenize(command);
    let mut out = Vec::new();
    let mut in_xargs = false;
    let mut i = 0usize;
    while let Some(tok) = tokens.get(i) {
        i += 1;
        if shell::base_name(tok) == "xargs" {
            in_xargs = true;
            continue;
        }
        if !in_xargs {
            continue;
        }
        let value = if tok == "-I" || tok == "-J" {
            let v = tokens.get(i).cloned();
            i += 1;
            v
        } else if let Some(v) = tok.strip_prefix("--replace=") {
            Some(v.to_string())
        } else if tok == "--replace" || tok == "-i" {
            Some("{}".to_string())
        } else if let Some(v) = tok
            .strip_prefix("-I")
            .or_else(|| tok.strip_prefix("-J"))
            .or_else(|| tok.strip_prefix("-i"))
        {
            Some(v.to_string())
        } else {
            if !tok.starts_with('-') {
                in_xargs = false;
            }
            None
        };
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            out.push(v);
        }
    }
    out
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
        || parsed.opaque
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
    decide_parsed_at(command, parsed, ctx, policy, 0)
}

/// Deepest dynamic `eval`/`-c` script re-parsed by [`hidden_decision`]; deeper asks.
const MAX_HIDDEN_DEPTH: usize = 4;

fn decide_parsed_at(
    command: &str,
    parsed: &Parsed,
    ctx: &Context,
    policy: &Policy,
    depth: usize,
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
    // Gated (non-defer) commands, and whether any ask among them is a hard guard.
    let mut gated = 0usize;
    let mut allows = 0usize;
    let mut hard_ask = false;
    // A cluster change earlier in the line (`solana config set --url …`, a write onto the CLI
    // config): the default for the commands after it.
    let mut config: Option<(Network, String)> = None;
    let placeholders = xargs_placeholders(command);
    // Directories an earlier `cd`/`pushd` names (lowercased), or `None` once one cannot be
    // placed: a relative write onto `config.yml` there may be the CLI config.
    let mut cd_dirs: Option<Vec<String>> = Some(Vec::new());
    // Ask components for a joined reason: (risk, description).
    let mut asks: Vec<(u8, String)> = Vec::new();

    for cmd in &parsed.commands {
        track_cd(cmd, &mut cd_dirs);
        let candidate = if cmd.is_family() {
            family_decision(
                command,
                cmd,
                parsed,
                ctx,
                policy,
                config.as_ref(),
                &mut unvetted,
            )
        } else if let Some(verdict) =
            dynamic_decision(command, cmd, parsed, ctx, tier, &placeholders)
        {
            verdict
        } else if let Some(verdict) = hidden_decision(command, cmd, parsed, ctx, policy, depth) {
            verdict
        } else {
            unvetted = true;
            if let Some(change) = config_write(command, cmd, cd_dirs.as_deref()) {
                config = Some(change);
            }
            continue;
        };
        if let Decision::Ask { reason } = &candidate.0 {
            let net = segment_network(cmd, parsed, ctx, config.as_ref());
            asks.push(ask_component(reason, &candidate.1, net, cmd));
        }
        if let Some(change) = config_set(cmd) {
            config = Some(change);
        }
        if candidate.0 != Decision::Defer {
            gated = gated.saturating_add(1);
        }
        if candidate.0 == Decision::Allow {
            allows = allows.saturating_add(1);
        }
        if matches!(candidate.0, Decision::Ask { .. }) && candidate.1.hard_guard {
            hard_ask = true;
        }
        // Keep the most restrictive command; on a tie a hard guard beats a grantable one, else
        // the first one wins.
        let replace = match &best {
            None => true,
            Some((cur, cur_meta)) => {
                severity(&candidate.0) > severity(cur)
                    || (severity(&candidate.0) == severity(cur)
                        && candidate.1.hard_guard
                        && !cur_meta.hard_guard)
            }
        };
        if replace {
            best = Some(candidate);
        }
    }

    // A grant covers one counterparty action of its own scope: an ask joined from several
    // gated commands, or with a hard-guard ask among them, is never relaxed. Several allowed
    // transfers in one call are budgeted one by one: ask.
    if let Some((decision, meta)) = best.as_mut() {
        if allows > 1 && *decision == Decision::Allow {
            *decision = Decision::Ask {
                reason: "Several transfers in one call — approve to proceed".to_string(),
            };
        }
        if matches!(decision, Decision::Ask { .. }) && (gated > 1 || hard_ask) {
            meta.hard_guard = true;
        }
        if asks.len() > 1 && matches!(decision, Decision::Ask { .. }) {
            *decision = Decision::Ask {
                reason: joined_reason(asks),
            };
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
    config: Option<&(Network, String)>,
    unvetted: &mut bool,
) -> (Decision, GateMeta) {
    let tier = policy.tier();
    let program = cmd.program();
    let argv = Argv::from_shell(&cmd.words);
    let cluster = command_cluster(cmd, &argv, &program, ctx, parsed, config);
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
    placeholders: &[String],
) -> Option<(Decision, GateMeta)> {
    let first = cmd.words.first()?;
    let placeholder = placeholders.iter().any(|p| first.text.contains(p.as_str()));
    let glob = !first.dynamic && unresolved_program_word(first);
    if !first.dynamic && !glob && !placeholder {
        return None;
    }
    let argv = Argv::from_shell(&cmd.words);
    let irreversible = shell::FAMILY
        .iter()
        .find_map(|program| irreversible_match(program, &argv).ok().flatten());
    let dynamic = if glob {
        // A glob can be a family program when its last segment matches one's name.
        let last = first.text.rsplit('/').next().unwrap_or(&first.text);
        ["solana", "spl-token", "anchor", "solana-keygen"]
            .iter()
            .any(|name| glob_match(&last.to_ascii_lowercase(), name))
    } else {
        placeholder || shell::dynamic_family_program(cmd, parsed)
    };
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
    /// An earlier command in the line changed the CLI config (described).
    ConfigChanged(String),
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
                    .any(|d| crate::localfs::exists(d.join("Anchor.toml")));
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
            Source::ConfigChanged(what) => {
                format!("the CLI config as an earlier `{what}` in this command line leaves it")
            }
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
    config: Option<&(Network, String)>,
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
    } else if let Some((net, what)) = config {
        // Anchor reads Anchor.toml first: the riskier of it and the changed CLI config.
        let net = if program == "anchor" {
            context::riskier(ctx.anchor_network, *net)
        } else {
            *net
        };
        (net, Source::ConfigChanged(what.clone()))
    } else if program == "anchor" && parsed.cwd_changed {
        (Network::Unknown, Source::CwdChanged)
    } else if program == "anchor" {
        (ctx.anchor_network, Source::AnchorDefault)
    } else {
        (ctx.network, Source::CliDefault)
    };
    Cluster { network, source }
}

/// The cluster a `solana config set` leaves for later commands: its `--url`/`-u` value, or
/// unknown when the value cannot be read. `None` when `cmd` sets no URL.
fn config_set(cmd: &SimpleCommand) -> Option<(Network, String)> {
    if cmd.program() != "solana" {
        return None;
    }
    let argv = Argv::from_shell(&cmd.words);
    let positional = |i: usize| argv.positionals.get(i).map(|w| w.to_ascii_lowercase());
    if positional(0).as_deref() != Some("config") || positional(1).as_deref() != Some("set") {
        return None;
    }
    let sets_url = argv.has_flag("--url") || argv.has_flag("--config");
    if !sets_url && argv.uncertain_from.is_none() {
        return None;
    }
    let net = if argv.has_flag("--config") {
        Network::Unknown
    } else {
        argv.network().unwrap_or(Network::Unknown)
    };
    Some((net, "solana config set".to_string()))
}

/// A command that writes, copies, moves or edits a solana CLI config file: later commands'
/// default cluster is unknown.
fn config_write(
    command: &str,
    cmd: &SimpleCommand,
    cd_dirs: Option<&[String]>,
) -> Option<(Network, String)> {
    // After a `cd` into a `solana/cli` directory, or one the gate cannot place, a relative
    // `config.yml` may be the CLI config.
    let in_cli_dir = cd_dirs.is_none_or(|dirs| dirs.iter().any(|d| d.contains("solana/cli")));
    let names_config = |t: &str| {
        let t = t.to_ascii_lowercase();
        t.contains("solana/cli/")
            || t.ends_with("cli/config.yml")
            || (in_cli_dir && !t.starts_with(['/', '~', '$']) && t.ends_with("config.yml"))
    };
    let program = cmd.program();
    let edits = crate::gates::wallet::is_file_clobber(&program)
        || matches!(
            program.as_str(),
            "sed" | "perl" | "ed" | "ex" | "awk" | "python" | "python3"
        );
    let by_words = edits && cmd.words.iter().skip(1).any(|w| names_config(&w.text));
    let by_redirect = cmd.writes_file && {
        let t = command.to_ascii_lowercase();
        t.contains("solana/cli/")
            || t.contains("cli/config.yml")
            || (in_cli_dir && t.contains("config.yml"))
    };
    (by_words || by_redirect).then(|| (Network::Unknown, format!("{program} onto the CLI config")))
}

/// Record a `cd`/`pushd` target (lowercased text) in `dirs`; one the gate cannot read (none,
/// `-`, an expansion) or a `popd` makes the set unknown (`None`).
fn track_cd(cmd: &SimpleCommand, dirs: &mut Option<Vec<String>>) {
    let program = cmd.program();
    if program == "popd" {
        *dirs = None;
        return;
    }
    if program != "cd" && program != "pushd" {
        return;
    }
    let target = cmd.words.iter().skip(1).find(|w| !w.text.starts_with('-'));
    match (target, dirs.as_mut()) {
        (Some(w), Some(list)) if !w.dynamic && !w.splits => {
            list.push(w.text.to_ascii_lowercase());
        }
        _ => *dirs = None,
    }
}

/// The script of an `eval` or `sh|bash|… -c` whose text holds an expansion (the parser leaves
/// it opaque): `eval "$S program close …"`, `bash -c "$(…) program close …"`.
pub(crate) fn dynamic_script(cmd: &SimpleCommand) -> Option<String> {
    let program = cmd.program();
    let args = cmd.words.get(1..).unwrap_or_default();
    if program == "eval" {
        return args.iter().any(|w| w.dynamic).then(|| {
            args.iter()
                .map(|w| w.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        });
    }
    const SHELLS: &[&str] = &[
        "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "busybox",
    ];
    if !SHELLS.contains(&program.as_str()) {
        return None;
    }
    let at = args.iter().position(|w| {
        w.text == "-c"
            || (w.text.starts_with('-') && !w.text.starts_with("--") && w.text.ends_with('c'))
    })?;
    let script = args.get(at + 1)?;
    script.dynamic.then(|| script.text.clone())
}

/// The command `find … -exec|-execdir|-ok|-okdir {} …` runs when its program word is the
/// found file (`{}`): whatever the name test matched.
fn find_exec(cmd: &SimpleCommand) -> Option<SimpleCommand> {
    if cmd.program() != "find" {
        return None;
    }
    let at = cmd
        .words
        .iter()
        .position(|w| matches!(w.text.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))?;
    let rest = cmd.words.get(at + 1..)?;
    if !rest.first().is_some_and(|w| w.text.contains("{}")) {
        return None;
    }
    let words: Vec<shell::Word> = rest
        .iter()
        .take_while(|w| !matches!(w.text.as_str(), ";" | "\\;" | "+"))
        .cloned()
        .collect();
    Some(SimpleCommand {
        words,
        indirect: true,
        writes_file: false,
        canonical: false,
    })
}

/// A command the parser could not open: a dynamic `eval`/`-c` script, re-parsed with its
/// expansions as dynamic words and decided like the unwrapped form; or a `find -exec {}`,
/// decided as an expansion program. `None` for neither, or when the script decides nothing.
fn hidden_decision(
    command: &str,
    cmd: &SimpleCommand,
    parsed: &Parsed,
    ctx: &Context,
    policy: &Policy,
    depth: usize,
) -> Option<(Decision, GateMeta)> {
    let tier = policy.tier();
    if let Some(script) = dynamic_script(cmd) {
        if depth >= MAX_HIDDEN_DEPTH || over_work_cap(&script) {
            return Some(unreadable_at(ask_unparseable(), tier));
        }
        let inner = shell::parse(&script);
        let (decision, meta) = decide_parsed_at(command, &inner, ctx, policy, depth + 1);
        return (decision != Decision::Defer).then_some((decision, meta));
    }
    let exec = find_exec(cmd)?;
    dynamic_decision(command, &exec, parsed, ctx, tier, &["{}".to_string()])
}

/// The cluster a gated command was judged on, for ranking ask reasons (Unknown for a command
/// whose program is not a family one).
fn segment_network(
    cmd: &SimpleCommand,
    parsed: &Parsed,
    ctx: &Context,
    config: Option<&(Network, String)>,
) -> Network {
    if !cmd.is_family() {
        return Network::Unknown;
    }
    let argv = Argv::from_shell(&cmd.words);
    command_cluster(cmd, &argv, &cmd.program(), ctx, parsed, config).network
}

/// One ask of a joined command: its risk (hard guard, cluster) and a description naming the
/// cluster and the command.
fn ask_component(
    reason: &str,
    meta: &GateMeta,
    network: Network,
    cmd: &SimpleCommand,
) -> (u8, String) {
    let cluster_risk: u8 = match network {
        Network::Mainnet => 3,
        Network::Unknown => 2,
        Network::Devnet | Network::Testnet | Network::Localnet => 0,
    };
    let counterparty = matches!(
        meta.scope,
        Scope::Transfer | Scope::Deploy | Scope::Authority | Scope::Destructive
    );
    let risk = cluster_risk
        .saturating_mul(4)
        .saturating_add(u8::from(counterparty).saturating_mul(2))
        .saturating_add(u8::from(meta.hard_guard));
    let words: Vec<&str> = cmd.words.iter().map(|w| w.text.as_str()).collect();
    let shown = echo(&words.join(" "));
    let what = reason.trim_end_matches(" — approve to proceed");
    (
        risk,
        format!("{what} (on {}: `{shown}`)", cluster_label(network)),
    )
}

/// The reason for an ask joined from several commands: the riskiest first.
fn joined_reason(mut asks: Vec<(u8, String)>) -> String {
    asks.sort_by_key(|a| std::cmp::Reverse(a.0));
    let mut parts = asks.into_iter().map(|(_, d)| d);
    let first = parts.next().unwrap_or_default();
    let rest: Vec<String> = parts.collect();
    if rest.is_empty() {
        format!("{first} — approve to proceed")
    } else {
        format!(
            "Several gated actions in one call (no grant covers them together). Riskiest: \
             {first}; also: {} — approve to proceed",
            rest.join("; ")
        )
    }
}

/// Class U rows the shared list does not spell but this gate also treats as Class U (same
/// argv grammar): `--final` on the other deploy commands. `anchor legacy-idl …` is read as
/// `anchor idl …`.
const EXTRA_IRREVERSIBLE: &[&[&str]] = &[
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
        Network::Localnet | Network::Devnet | Network::Testnet => Decision::Ask {
            reason: format!(
                "Irreversible on-chain action `{row}` on {net} (cluster from {source}): it \
                 destroys the capability even for its owner — approve to proceed (no grant \
                 covers it)"
            ),
        },
        Network::Mainnet | Network::Unknown => Decision::Deny {
            reason: format!(
                "Irreversible on-chain action `{row}` on {net} (cluster from {source}): it \
                 destroys the capability even for its owner and runs through the agent only \
                 on a positively identified localnet, devnet or testnet. Run it yourself outside the \
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
                "{} — denied at tier high: a counterparty action on {} (cluster \
                     from {}). Run it yourself outside the agent if you intend it: `{}`",
                reason.trim_end_matches(" — approve to proceed"),
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
                    "{} — denied at tier high: the gate cannot tell what this runs",
                    reason.trim_end_matches(" — approve to proceed")
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
        s if SOLANA_AUTHORITY_VERBS.contains(&s) => authority_decision("solana", s, ctx, argv),
        s if SOLANA_CREATE_VERBS.contains(&s)
            && CREATE_AUTHORITY_FLAGS.iter().any(|f| argv.has_flag(f)) =>
        {
            authority_decision("solana", s, ctx, argv)
        }
        // `feature activate|revoke` send a transaction; only `feature status` reads.
        "feature" => match word_or_ask(argv, 1, "solana") {
            Ok(action) if action == "status" => readonly("solana"),
            Ok(action) => ask_not_readonly("solana", &format!("feature {action}")),
            Err(verdict) => verdict,
        },
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
        "set-buffer-authority" => authority_decision(program, "set-buffer-authority", ctx, argv),
        // `program close` in any form is Class U, decided before this (shared list); a hard
        // guard here too in case the list is bypassed.
        "close" => irreversible_decision(program, ctx, argv, Scope::Destructive, "program close"),
        // Read-only program subcommands.
        "show" | "dump" => readonly(program),
        _ => ask_unknown(program),
    }
}

/// Classify an `spl-token ...` command.
fn classify_spl_token(argv: &Argv, ctx: &Context, _policy: &Policy) -> (Decision, GateMeta) {
    let sub = match word_or_ask(argv, 0, "spl-token") {
        Ok(sub) => sub,
        Err(verdict) => return verdict,
    };
    match sub.as_str() {
        "transfer" => token_transfer_decision(argv, ctx),
        "authorize" if argv.has_flag("--disable") => irreversible_decision(
            "spl-token",
            ctx,
            argv,
            Scope::Authority,
            "authority removal (--disable)",
        ),
        "authorize" | "approve" => authority_decision("spl-token", &sub, ctx, argv),
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
        "set-buffer-authority" => {
            authority_decision("anchor", "idl set-buffer-authority", ctx, argv)
        }
        "close" => {
            irreversible_decision("anchor", ctx, argv, Scope::Destructive, "IDL account close")
        }
        _ => ask_not_readonly("anchor", &format!("{sub} {action}")),
    }
}

/// Build a `solana transfer` (SOL) decision via the spend ledger (predict-only; no debit
/// here). Token transfers go through [`token_transfer_decision`] instead.
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

/// Build an `spl-token transfer` decision (spec D3). Its amount is in TOKEN units: it never
/// reaches the SOL caps or the ledger, and no SOL grant covers it (a hard guard with no
/// `amount_sol`). A positively identified devnet, testnet or localnet gets no opinion; mainnet
/// and an unidentified cluster ask, which is a deny headless and at High.
fn token_transfer_decision(argv: &Argv, ctx: &Context) -> (Decision, GateMeta) {
    let (amount, destination) = parse_transfer(argv, "spl-token");
    let mut meta = GateMeta::new(Scope::Transfer, true);
    meta.program = Some("spl-token".to_string());
    meta.destination = destination;
    if matches!(
        ctx.network,
        Network::Devnet | Network::Testnet | Network::Localnet
    ) {
        return (Decision::Defer, meta);
    }
    let mint = argv
        .positionals
        .get(1)
        .filter(|m| argv.uncertain_from.is_none() && looks_like_pubkey(m))
        .map_or_else(|| "an unidentified mint".to_string(), |m| m.to_string());
    let what = match (&amount, argv.positionals.get(2)) {
        (Amount::Value(_), Some(raw)) => format!("{raw} tokens of {mint}"),
        (Amount::All, _) => format!("ALL tokens of {mint}"),
        _ => format!("an unreadable amount of tokens of {mint}"),
    };
    let reason = format!(
        "spl-token transfer of {what} on {}: SOL caps and grants never cover token amounts — \
         approve to proceed",
        cluster_label(ctx.network)
    );
    (Decision::Ask { reason }, meta)
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

/// `solana` subcommands that hand a stake, vote or nonce account's authority to another key
/// (`solana --help`, solana-cli 3.1). Like `spl-token authorize`, they are authority changes:
/// a hard-guard ask on every cluster, denied at High on mainnet or an unidentified cluster.
const SOLANA_AUTHORITY_VERBS: &[&str] = &[
    "stake-authorize",
    "stake-authorize-checked",
    "vote-authorize-voter",
    "vote-authorize-voter-checked",
    "vote-authorize-withdrawer",
    "vote-authorize-withdrawer-checked",
    "authorize-nonce-account",
    // Lockup custodian and vote identity changes.
    "stake-set-lockup",
    "stake-set-lockup-checked",
    "vote-update-validator",
];

/// `solana` subcommands that create a stake or nonce account; with a
/// [`CREATE_AUTHORITY_FLAGS`] flag they hand its authority to another key.
const SOLANA_CREATE_VERBS: &[&str] = &[
    "create-stake-account",
    "create-stake-account-checked",
    "create-nonce-account",
];

/// Flags naming the authority of the account a [`SOLANA_CREATE_VERBS`] command creates.
const CREATE_AUTHORITY_FLAGS: &[&str] = &[
    "--stake-authority",
    "--withdraw-authority",
    "--custodian",
    "--nonce-authority",
];

/// Build an authority-change decision for `<program> <verb>`. Always a hard guard (no grant
/// covers it); mainnet phrasing differs. `spl-token approve` lands here too: a delegate may
/// then move the account's tokens, so it hands over authority over them.
fn authority_decision(
    program: &str,
    verb: &str,
    ctx: &Context,
    argv: &Argv,
) -> (Decision, GateMeta) {
    let mut meta = GateMeta::new(Scope::Authority, true);
    meta.program = Some(program.to_string());
    if let Some(target) = first_pubkey_arg(argv) {
        meta.destination = Some(target);
    }

    let net = if matches!(ctx.network, Network::Mainnet) {
        "Mainnet authority"
    } else {
        "Authority"
    };
    (
        Decision::Ask {
            reason: format!("{net} change (`{program} {verb}`) — approve to proceed"),
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
            | "stake-account"
            | "vote-account"
            | "nonce-account"
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
    fn spl_token_transfer_amount_is_tokens_not_sol() {
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let cmd = format!("spl-token transfer {mint} 0.25 {DEST}");
        let (d, meta) = decide(&cmd, &ctx_with(Network::Devnet, "spl_xfer"), &policy());
        assert_eq!(d, Decision::Defer);
        assert_eq!(meta.amount_sol, None);
        assert_eq!(meta.program.as_deref(), Some("spl-token"));
        assert_eq!(meta.destination.as_deref(), Some(DEST));
        let (d, meta) = decide(&cmd, &ctx_with(Network::Mainnet, "spl_xfer_m"), &policy());
        assert!(
            d.reason().contains(&format!("0.25 tokens of {mint}")),
            "{d:?}"
        );
        assert!(meta.hard_guard);
        assert_eq!(meta.amount_sol, None);
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
