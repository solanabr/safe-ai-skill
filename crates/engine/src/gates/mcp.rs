//! MCP tool gate.

use serde_json::Value;

use crate::context::Context;
use crate::gate::{GateMeta, Scope, Verdict};
use crate::io::Decision;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// One of ai-kit's MCP tool-name denies (`firewall.sh` `DENY_MCP_*`): the tool on `server`
/// is refused by name from tier `from` up, whatever its arguments.
struct NameRule {
    server: &'static str,
    tool: &'static str,
    from: Tier,
    what: &'static str,
}

/// ai-kit's tool-name denies, tier for tier. Medium and High refuse context-mode's executor,
/// fetcher and directory indexer (P17) and Playwright's code runner and raw HTTP client
/// (P18); High also refuses Playwright's in-page evaluator (P18) and Cloudflare's `execute`
/// (P19). Off and Relaxed keep every tool and rely on the content checks.
const NAME_RULES: &[NameRule] = &[
    NameRule {
        server: "context-mode",
        tool: "ctx_execute",
        from: Tier::Medium,
        what: "runs arbitrary code outside the OS sandbox",
    },
    NameRule {
        server: "context-mode",
        tool: "ctx_execute_file",
        from: Tier::Medium,
        what: "runs arbitrary code outside the OS sandbox",
    },
    NameRule {
        server: "context-mode",
        tool: "ctx_batch_execute",
        from: Tier::Medium,
        what: "runs arbitrary commands outside the OS sandbox",
    },
    NameRule {
        server: "context-mode",
        tool: "ctx_fetch_and_index",
        from: Tier::Medium,
        what: "fetches any URL outside the OS sandbox",
    },
    NameRule {
        server: "context-mode",
        tool: "ctx_index",
        from: Tier::Medium,
        what: "indexes any directory outside the read fence",
    },
    NameRule {
        server: "playwright",
        tool: "browser_run_code_unsafe",
        from: Tier::Medium,
        what: "runs arbitrary code in the Playwright process",
    },
    NameRule {
        server: "playwright",
        tool: "browser_network_request",
        from: Tier::Medium,
        what: "sends arbitrary HTTP requests outside the OS sandbox",
    },
    NameRule {
        server: "playwright",
        tool: "browser_evaluate",
        from: Tier::High,
        what: "runs arbitrary JavaScript in the page",
    },
    NameRule {
        server: "cloudflare",
        tool: "execute",
        from: Tier::High,
        what: "runs arbitrary JavaScript against the Cloudflare API",
    },
];

/// ai-kit's tool-name rule for `tool_name` at `tier`: a deny when the tool is one the kit
/// refuses by name at that tier (see [`NAME_RULES`]), `None` otherwise.
///
/// The server segment matches its name as added (`mcp__context-mode__…`) or as a plugin
/// registers it (`mcp__plugin_<plugin>_context-mode__…`); the tool segment matches exactly.
/// No allocation; below Medium it returns at the first comparison.
pub fn decide_name(tool_name: &str, tier: Tier) -> Option<Verdict> {
    if tier < Tier::Medium {
        return None;
    }
    let rest = tool_name.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    let rule = NAME_RULES
        .iter()
        .find(|r| r.tool == tool && tier >= r.from && server_is(server, r.server))?;
    Some(Verdict::Deny(format!(
        "safe-ai-skill refuses `{tool}` by name at tier {}, because it {}; run the work through \
         Bash, where the sandbox and the Bash gates apply, or lower the tier with \
         `safe-ai-skill tier`.",
        tier.label(),
        rule.what
    )))
}

/// Whether the server segment `seg` is `name`, as added or under a plugin prefix
/// (`plugin_<plugin>_<name>`).
fn server_is(seg: &str, name: &str) -> bool {
    seg == name
        || (seg.starts_with("plugin_")
            && seg.len() > name.len()
            && seg.ends_with(name)
            && seg.as_bytes()[seg.len() - name.len() - 1] == b'_')
}

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
    // ai-kit's tool-name denies come first: from their tier up, the tool is refused whatever
    // its arguments, under a hard guard so no grant lifts it.
    if let Some(verdict) = decide_name(tool_name, policy.tier()) {
        return (verdict.into(), GateMeta::new(Scope::Other, true));
    }
    // High-risk MCP class gating runs next: a known-dangerous server/tool (wallet
    // signing, key custody, …) is gated even when its verb is absent from the
    // sensitive-name pattern (e.g. `signTransaction` — "sign" *is* in the pattern, but
    // `signMessage` and key-custody surfaces may not be). This is the kit's most
    // dangerous MCP surface, so it cannot fall through the fast path.
    if let Some((kind, decision_word)) = high_risk_class(tool_name, policy) {
        let reason = high_risk_reason(kind, short_name(tool_name));
        let decision = match decision_word {
            "deny" => Decision::Deny { reason },
            _ => Decision::Ask { reason },
        };
        return (decision, GateMeta::new(Scope::Other, false));
    }

    // Routed tools (Helius `heliusWrite`, …) carry the verb in `tool_input.action`, not the
    // tool name, possibly nested under `params`/`args` (depth ≤ 3). Classify from the tool
    // name AND the action together, using token-boundary matching so `display`/`design`/
    // `minted` do not match `pay`/`sign`/`mint`.
    let action = payload.and_then(extract_action);
    let action_tokens = action
        .as_deref()
        .map(|a| without_read_prefix(name_tokens(a)))
        .unwrap_or_default();
    let mut class_tokens = name_tokens(tool_name);
    class_tokens.extend(action_tokens);
    let wallet_ctx = is_wallet_context(&class_tokens);

    let name_sensitive = tokens_match_sensitive(
        &class_tokens,
        &policy.mcp.sensitive_name_pattern,
        wallet_ctx,
    );
    let signal = payload.and_then(payload_signal);
    // Staking verbs gate even when a user-trimmed pattern lacks them.
    let staking = is_staking(&class_tokens);

    // Fast path: no sensitive verb, no staking verb, and no value-moving payload signal.
    if !name_sensitive && !staking && signal.is_none() {
        return (Decision::Defer, GateMeta::unknown());
    }

    // A token transfer moves value in TOKEN units, never SOL: no SOL grant or cap covers it
    // (D3), so it is never relaxed and carries no SOL amount.
    let token_units = is_token_transfer(&class_tokens);
    // Staking / delegation has no destination but still moves value out of liquid control; its
    // scope stays `Other`, with a stake-specific reason.
    let scope = if staking {
        Scope::Other
    } else {
        classify_scope(&class_tokens)
    };

    let mut meta = GateMeta::new(scope, false);
    let dest = signal.as_ref().and_then(|s| s.destination.clone());
    let mint = signal.as_ref().and_then(|s| s.mint.clone());
    // A SOL transfer's amount is grantable; a token transfer's is not (token units), so it is
    // dropped so no SOL grant can be matched against it.
    let amount = if token_units {
        None
    } else {
        signal.as_ref().and_then(|s| s.amount_sol)
    };

    meta.amount_sol = amount;
    meta.destination = dest.clone();
    // Never relaxable: staking/delegation and token transfers (D3), and any value-moving call
    // whose SOL amount cannot be read (an unknown field, `transfer_all`, a non-numeric value)
    // or is given twice with different values at different nesting levels.
    if staking
        || token_units
        || signal.as_ref().is_some_and(|s| s.ambiguous)
        || (amount.is_none() && matches!(scope, Scope::Transfer | Scope::Swap))
    {
        meta.hard_guard = true;
    }

    let short_tool = action.as_deref().unwrap_or_else(|| short_name(tool_name));

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
        // Staking / delegation moves value out of liquid control even without a destination
        // address. `Scope` has no `Stake` variant, so it stays `Scope::Other` but carries a
        // stake-specific reason. Its SOL amount (if readable) is shown but never grants it.
        _ if staking => {
            let amt_str = stake_amount(payload)
                .map(|a| format!("{a} SOL"))
                .unwrap_or_else(|| "unspecified amount".to_string());
            format!("MCP staking/delegation: {short_tool} ({amt_str}) — approve to proceed")
        }
        _ if token_units => {
            let dest_str = dest
                .as_deref()
                .map(truncate)
                .unwrap_or_else(|| "unknown destination".to_string());
            format!(
                "MCP token transfer: {short_tool} → {dest_str} (token units, so no SOL grant \
                 covers it) — approve to proceed"
            )
        }
        _ => {
            let dest_str = dest
                .as_deref()
                .map(truncate)
                .unwrap_or_else(|| "unknown destination".to_string());
            let amt_str = amount
                .map(|a| format!("{a} SOL"))
                .unwrap_or_else(|| "amount not readable, so no grant covers it".to_string());
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
    /// The amount appears more than once (e.g. top level and `args`) with different values,
    /// so which one the server uses is unknown: no grant covers it.
    ambiguous: bool,
}

/// Nesting keys routed MCP tools put their real parameters under.
const NEST_KEYS: &[&str] = &[
    "params",
    "args",
    "input",
    "arguments",
    "request",
    "payload",
    "body",
];
/// Maximum nesting depth searched under [`NEST_KEYS`].
const MAX_NEST: usize = 4;
/// Largest string-encoded JSON object (`"args": "{…}"`) parsed while searching.
const MAX_NESTED_JSON: usize = 64 * 1024;

/// Inspect a payload for value-moving keys, looking into nested [`NEST_KEYS`] objects (depth
/// ≤ [`MAX_NEST`]). Returns `Some` only when BOTH an amount-like key AND a destination-like key
/// (or a mint) are present — the signature of a transfer-style call. Only `sol`/`amountSol`/
/// `solAmount`, `lamports` (÷1e9) and a bare `amount` yield a SOL amount; `inputAmount`,
/// `tokenAmount` and `value` count as an amount of unknown units.
fn payload_signal(payload: &Value) -> Option<PayloadSignal> {
    let sol = find_all(payload, &["sol", "amountSol", "solAmount"]);
    let lamports = find_all(payload, &["lamports"]);
    let bare = find_all(payload, &["amount"]);
    let unknown_units = find_all(payload, &["tokenAmount", "inputAmount", "value"]);
    let has_amount =
        !(sol.is_empty() && lamports.is_empty() && bare.is_empty() && unknown_units.is_empty());

    let sol_values: Vec<f64> = sol
        .iter()
        .filter_map(number)
        .chain(
            lamports
                .iter()
                .filter_map(number)
                .map(|n| n / 1_000_000_000.0),
        )
        .collect();
    let bare_values: Vec<f64> = bare.iter().filter_map(number).collect();
    let values = if sol_values.is_empty() {
        bare_values
    } else {
        sol_values
    };
    let amount_sol = values.iter().copied().reduce(f64::max);
    let ambiguous = values.windows(2).any(|w| w[0] != w[1]);

    let destination = find_all(
        payload,
        &[
            "destination",
            "to",
            "toAddress",
            "recipient",
            "recipientAddress",
            "receiver",
        ],
    )
    .iter()
    .find_map(|v| v.as_str().map(str::to_string));
    let mint = find_all(payload, &["mint", "mintAddress", "outputMint"])
        .iter()
        .find_map(|v| v.as_str().map(str::to_string));

    if has_amount && (destination.is_some() || mint.is_some()) {
        Some(PayloadSignal {
            amount_sol,
            destination,
            mint,
            ambiguous,
        })
    } else {
        None
    }
}

/// The SOL amount of a staking call, read where present (for the reason text only).
fn stake_amount(payload: Option<&Value>) -> Option<f64> {
    let p = payload?;
    let first = |keys: &[&str]| find_all(p, keys).iter().find_map(number);
    first(&["sol", "amountSol", "solAmount"])
        .or_else(|| first(&["lamports"]).map(|n| n / 1_000_000_000.0))
        .or_else(|| first(&["amount"]))
}

/// Every value of any of `keys` in `payload` and in nested [`NEST_KEYS`] objects (shallowest
/// first), to depth [`MAX_NEST`]. A nest value that is a string holding a JSON object
/// (`"args": "{\"amount\":…}"`) is parsed and searched too.
fn find_all(payload: &Value, keys: &[&str]) -> Vec<Value> {
    let mut out = Vec::new();
    collect_keys(payload, keys, 0, &mut out);
    out
}

fn collect_keys(payload: &Value, keys: &[&str], depth: usize, out: &mut Vec<Value>) {
    let Some(obj) = payload.as_object() else {
        return;
    };
    for k in keys {
        if let Some(v) = obj.get(*k) {
            out.push(v.clone());
        }
    }
    if depth >= MAX_NEST {
        return;
    }
    for nest in NEST_KEYS {
        match obj.get(*nest) {
            Some(inner @ Value::Object(_)) => collect_keys(inner, keys, depth + 1, out),
            Some(Value::String(s))
                if s.len() <= MAX_NESTED_JSON && s.trim_start().starts_with('{') =>
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    collect_keys(&parsed, keys, depth + 1, out);
                }
            }
            _ => {}
        }
    }
}

/// The routed `action` verb of an MCP payload (`tool_input.action`, or nested under
/// [`NEST_KEYS`]); a one-element array (`["transferSol"]`) counts as its string.
fn extract_action(payload: &Value) -> Option<String> {
    find_all(payload, &["action"]).iter().find_map(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => items.iter().find_map(|i| i.as_str().map(str::to_string)),
        _ => None,
    })
}

/// Parse a JSON value as an `f64`, accepting numbers and numeric strings.
fn number(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// Fold a name for matching: drop zero-width and soft-hyphen characters, map fullwidth ASCII
/// to ASCII, and map the common Cyrillic/Greek look-alikes of Latin letters (`trаnsfer` with
/// a Cyrillic `а`). Not full NFKC; enough that a look-alike verb still matches.
fn fold(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{00AD}' | '\u{200B}'..='\u{200F}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}'
            )
        })
        .map(|c| match c {
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            'а' | 'α' => 'a',
            'в' => 'b',
            'с' | 'ϲ' => 'c',
            'е' | 'ε' => 'e',
            'һ' | 'н' => 'h',
            'і' | 'ι' => 'i',
            'ј' => 'j',
            'к' | 'κ' => 'k',
            'м' => 'm',
            'п' | 'η' => 'n',
            'о' | 'ο' => 'o',
            'р' | 'ρ' => 'p',
            'ѕ' => 's',
            'т' | 'τ' => 't',
            'υ' => 'u',
            'ν' => 'v',
            'х' | 'χ' => 'x',
            'у' => 'y',
            'А' | 'Α' => 'A',
            'В' | 'Β' => 'B',
            'С' => 'C',
            'Е' | 'Ε' => 'E',
            'Н' | 'Η' => 'H',
            'І' | 'Ι' => 'I',
            'К' | 'Κ' => 'K',
            'М' | 'Μ' => 'M',
            'О' | 'Ο' => 'O',
            'Р' | 'Ρ' => 'P',
            'Ѕ' => 'S',
            'Т' | 'Τ' => 'T',
            'Х' | 'Χ' => 'X',
            other => other,
        })
        .collect()
}

/// Split an MCP tool name or action verb into lowercase tokens on the `__`/`.`/`_`/`-`/space
/// delimiters and camelCase boundaries (`heliusWrite` → `["helius", "write"]`,
/// `transferSol` → `["transfer", "sol"]`), after [`fold`]. Token-boundary matching keeps
/// `display`/`design`/`minted` from matching `pay`/`sign`/`mint`.
fn name_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower_or_digit = false;
    for c in fold(s).chars() {
        if matches!(c, '_' | '.' | '-') || c.is_whitespace() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower_or_digit = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower_or_digit && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(c.to_ascii_lowercase());
        prev_lower_or_digit = c.is_ascii_lowercase() || c.is_ascii_digit();
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Verbs that are value-moving only on a wallet / Solana / DeFi server: elsewhere they are
/// everyday tool names (`browser_close`, `ctx_execute`, `executeQuery`, `vercel deploy`,
/// `close_issue`, `browser_submit`), so they count only with [`is_wallet_context`].
const CONTEXT_VERBS: &[&str] = &[
    "deposit",
    "execute",
    "submit",
    "authority",
    "launch",
    "deploy",
    "close",
];

/// Tokens that mark a server, tool or action as wallet / Solana / DeFi / transaction surface.
const WALLET_CONTEXT: &[&str] = &[
    "wallet",
    "solana",
    "sol",
    "sak",
    "lamports",
    "spl",
    "defi",
    "dex",
    "jupiter",
    "jup",
    "raydium",
    "orca",
    "meteora",
    "pump",
    "pumpfun",
    "drift",
    "kamino",
    "marginfi",
    "phantom",
    "solflare",
    "backpack",
    "helius",
    "metaplex",
    "onchain",
    "blockchain",
    "crypto",
    "web3",
];

/// Whether the tokens carry a wallet / Solana / DeFi signal.
fn is_wallet_context(tokens: &[String]) -> bool {
    tokens.iter().any(|t| WALLET_CONTEXT.contains(&t.as_str()))
}

/// Whether an alternative of the sensitive-name `pattern` matches the tokens.
///
/// A whole token always matches. A [`CONTEXT_VERBS`] alternative matches only with
/// `wallet_ctx`. With `wallet_ctx`, a non-context alternative of 4+ letters also matches
/// inside a token, so run-together spellings on a wallet server (`signandsend`,
/// `TRANSFERSOL`) still gate; on other servers matching stays token-exact.
fn tokens_match_sensitive(tokens: &[String], pattern: &str, wallet_ctx: bool) -> bool {
    pattern
        .split('|')
        .map(str::trim)
        .filter(|alt| !alt.is_empty())
        .any(|alt| {
            let a = alt.to_ascii_lowercase();
            let contextual = CONTEXT_VERBS.contains(&a.as_str());
            if contextual && !wallet_ctx {
                return false;
            }
            tokens.contains(&a)
                || (wallet_ctx
                    && !contextual
                    && a.len() >= 4
                    && tokens.iter().any(|t| t.contains(a.as_str())))
        })
}

/// Classify the action scope from the tool-name / action tokens.
fn classify_scope(tokens: &[String]) -> Scope {
    let has = |v: &str| tokens.iter().any(|t| t == v);
    // A swap/trade is a value move with its own (rugcheck) relaxation path.
    if has("swap") || has("trade") || has("buy") || has("sell") {
        Scope::Swap
    } else if has("transfer") || has("send") || has("withdraw") || has("pay") || has("drain") {
        Scope::Transfer
    } else {
        Scope::Other
    }
}

/// Whether the tokens indicate a staking / delegation action (no destination, but still
/// value-moving): `stake`, `unstake`, `delegate`, `deactivate`.
fn is_staking(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|t| matches!(t.as_str(), "stake" | "unstake" | "delegate" | "deactivate"))
}

/// Whether the tokens indicate a TOKEN (SPL) transfer: a `token` token alongside a
/// transfer/send verb (`transferToken`, `sendToken`). Token amounts are not SOL (D3).
fn is_token_transfer(tokens: &[String]) -> bool {
    tokens.iter().any(|t| t == "token")
        && tokens
            .iter()
            .any(|t| matches!(t.as_str(), "transfer" | "send"))
}

/// An action's tokens with a leading read clause removed: `getStakeAccounts` and
/// `listTransfers` are reads, so their `stake`/`transfer` tokens must not classify them as
/// mutations. A conjunction after the read verb starts a second clause, which is kept
/// (`getAndSendTransaction` → `["send", "transaction"]`).
fn without_read_prefix(tokens: Vec<String>) -> Vec<String> {
    if !tokens.first().is_some_and(|t| is_read_verb(t)) {
        return tokens;
    }
    match tokens
        .iter()
        .position(|t| matches!(t.as_str(), "and" | "then"))
    {
        Some(i) => tokens[i + 1..].to_vec(),
        None => Vec::new(),
    }
}

/// Whether a token is a read verb (see [`without_read_prefix`]).
fn is_read_verb(token: &str) -> bool {
    matches!(
        token,
        "get"
            | "list"
            | "fetch"
            | "parse"
            | "read"
            | "query"
            | "show"
            | "find"
            | "resolve"
            | "search"
            | "describe"
            | "lookup"
            | "status"
            | "simulate"
            | "estimate"
    )
}

/// Classify an MCP tool against `policy.catalog.high_risk_classes`.
///
/// Matches the MCP server segment (`mcp__<server>__…`) and the short tool name against
/// each class's `ids` (exact / stem match, e.g. server `phantom` ⇒ id `phantom-mcp`) and
/// `keywords` (case-insensitive substring over the server + tool text). The first class
/// that matches wins; returns its `kind` and forced `decision` (`"ask"` / `"deny"`).
///
/// Pure and allocation-light: this runs on every MCP call, so it scans lowercased copies
/// of the two name segments only — no I/O, no registry load.
fn high_risk_class<'p>(tool_name: &str, policy: &'p Policy) -> Option<(&'p str, &'p str)> {
    let server = server_segment(tool_name).to_ascii_lowercase();
    let short = short_name(tool_name).to_ascii_lowercase();

    for class in &policy.catalog.high_risk_classes {
        // The installer-script class targets bash `curl | bash` text, not MCP tools — it
        // is enforced by the secrets gate. Skip it here to avoid spurious `wget`/`| sh`
        // keyword hits on unrelated tool names.
        if class.kind == "installer_script" {
            continue;
        }

        let id_hit = class
            .ids
            .iter()
            .any(|id| id_matches_segment(id, &server, &short));
        let kw_hit = class.keywords.iter().any(|kw| {
            let k = kw.to_ascii_lowercase();
            !k.is_empty() && (server.contains(&k) || short.contains(&k))
        });

        if id_hit || kw_hit {
            return Some((class.kind.as_str(), class.decision.as_str()));
        }
    }
    None
}

/// Whether a catalog id (e.g. `phantom-mcp`) matches the server or short-name segment.
///
/// Compares against the id's stem (everything before the first `-`, so `phantom-mcp` ⇒
/// `phantom`) as well as the full id, in both directions of containment — the server
/// segment of `mcp__phantom__signTransaction` is `phantom`, which the registry id
/// `phantom-mcp` would otherwise never equal.
fn id_matches_segment(id: &str, server: &str, short: &str) -> bool {
    let id_l = id.to_ascii_lowercase();
    if id_l.is_empty() {
        return false;
    }
    let stem = id_l.split('-').next().unwrap_or(&id_l);
    server == id_l
        || short == id_l
        || (!stem.is_empty() && (server == stem || server.contains(stem) || short.contains(stem)))
}

/// A class-specific, non-echoing reason for a high-risk MCP gate.
fn high_risk_reason(kind: &str, short_tool: &str) -> String {
    match kind {
        "wallet_signing" => format!(
            "High-risk MCP: wallet signing tool `{short_tool}` can sign/submit arbitrary transactions — approve to proceed"
        ),
        "key_custody" => format!(
            "High-risk MCP: key-custody tool `{short_tool}` can access/derive private keys — approve to proceed"
        ),
        other => format!(
            "High-risk MCP ({other}): `{short_tool}` is a known dangerous surface — approve to proceed"
        ),
    }
}

/// The `<server>` segment of an MCP tool name (`mcp__phantom__signTransaction` →
/// `phantom`). Falls back to the whole name when the `mcp__<server>__` shape is absent.
fn server_segment(tool_name: &str) -> &str {
    let rest = tool_name.strip_prefix("mcp__").unwrap_or(tool_name);
    rest.split("__").next().unwrap_or(rest)
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

    #[test]
    fn name_rule_server_segment() {
        assert!(server_is("context-mode", "context-mode"));
        assert!(server_is(
            "plugin_context-mode_context-mode",
            "context-mode"
        ));
        assert!(!server_is("my-context-mode", "context-mode"));
        assert!(!server_is("plugin_xcontext-mode", "context-mode"));
        assert!(!server_is("context-mode2", "context-mode"));
        assert!(decide_name("mcp__context-mode", Tier::High).is_none());
        assert!(decide_name("context-mode__ctx_execute", Tier::High).is_none());
        let Some(Verdict::Deny(reason)) = decide_name("mcp__cloudflare__execute", Tier::High)
        else {
            panic!("cloudflare execute is denied at high");
        };
        assert!(
            reason.contains("`execute`") && reason.contains("tier high"),
            "{reason}"
        );
        assert!(reason.ends_with("`safe-ai-skill tier`."), "{reason}");
    }
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
    fn an_unreadable_transfer_amount_is_a_hard_guard() {
        let to = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
        for (tool, payload) in [
            ("mcp__w__transfer", json!({ "to": to, "value": "999" })),
            ("mcp__w__transfer_all", json!({ "to": to })),
            ("mcp__w__transfer", json!({ "to": to, "amount": "lots" })),
            ("mcp__w__swap", json!({ "inputMint": to })),
        ] {
            let (d, m) = decide(tool, Some(&payload), &ctx(), &Policy::default());
            assert!(matches!(d, Decision::Ask { .. }), "{tool} {payload}: {d:?}");
            assert!(m.hard_guard, "{tool} {payload}: no grant may cover it");
            assert_eq!(m.amount_sol, None);
        }
        let (_, m) = decide(
            "mcp__w__transfer",
            Some(&json!({ "to": to, "amount": "0.25" })),
            &ctx(),
            &Policy::default(),
        );
        assert!(!m.hard_guard, "a readable amount stays grantable");
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

    #[test]
    fn helius_write_send_sol_asks_transfer() {
        let payload = json!({
            "destination": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            "lamports": 1_000_000_000u64
        });
        let (d, m) = decide(
            "mcp__helius__heliusWrite.sendSol",
            Some(&payload),
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert_eq!(m.scope, Scope::Transfer);
        assert_eq!(m.amount_sol, Some(1.0));
    }

    #[test]
    fn helius_write_send_token_asks_transfer() {
        let (d, m) = decide(
            "mcp__helius__heliusWrite.sendToken",
            None,
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert_eq!(m.scope, Scope::Transfer);
    }

    #[test]
    fn helius_write_stake_asks() {
        let (d, m) = decide(
            "mcp__helius__heliusWrite.stake",
            None,
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert_eq!(m.scope, Scope::Other);
        assert!(d.reason().contains("staking"), "reason: {}", d.reason());
    }

    #[test]
    fn helius_write_delegate_asks() {
        let (d, m) = decide(
            "mcp__helius__heliusWrite.delegate",
            None,
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert_eq!(m.scope, Scope::Other);
    }

    #[test]
    fn dot_suffixed_send_token_matches() {
        // The dot-suffixed short name tokenizes to include the `send` verb as a whole token.
        assert!(tokens_match_sensitive(
            &name_tokens("mcp__helius__heliusWrite.sendSol"),
            &Policy::default().mcp.sensitive_name_pattern,
            false,
        ));
    }

    #[test]
    fn token_boundary_rejects_substring_false_positives() {
        // `display`/`design`/`minted` must NOT match `pay`/`sign`/`mint`.
        let pat = &Policy::default().mcp.sensitive_name_pattern;
        for name in [
            "mcp__gallery__displayArt",
            "mcp__studio__designReview",
            "mcp__assets__listMinted",
        ] {
            assert!(
                !tokens_match_sensitive(&name_tokens(name), pat, false),
                "{name} should not match"
            );
        }
    }

    #[test]
    fn helius_write_stake_from_action_asks() {
        // The verb lives in the payload `action`, not the tool name.
        for payload in [
            json!({ "action": "stake", "amount": 10 }),
            json!({ "action": "stake" }),
            json!({ "action": "stake", "params": { "amount": 10, "validator": "x" } }),
            json!({ "params": { "action": "sendSol", "to": "x", "amount": 50 } }),
        ] {
            let (d, _m) = decide(
                "mcp__helius__heliusWrite",
                Some(&payload),
                &ctx(),
                &Policy::default(),
            );
            assert!(matches!(d, Decision::Ask { .. }), "{payload}: {d:?}");
        }
    }

    #[test]
    fn token_transfer_is_hard_guarded_and_sol_amount_dropped() {
        let payload = json!({ "action": "sendToken", "mint": "m", "to": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", "amount": 5 });
        let (d, m) = decide(
            "mcp__helius__heliusWrite",
            Some(&payload),
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert_eq!(m.scope, Scope::Transfer);
        assert!(m.hard_guard, "token transfer is never grant-covered (D3)");
        assert_eq!(m.amount_sol, None, "token units are not SOL");
    }

    #[test]
    fn read_action_not_misclassified() {
        // `getStakeAccounts` contains `stake` but is a read — it must not ask.
        let payload = json!({ "action": "getStakeAccounts", "address": "x" });
        let (d, _m) = decide(
            "mcp__helius__heliusWallet",
            Some(&payload),
            &ctx(),
            &Policy::default(),
        );
        assert_eq!(d, Decision::Defer, "{d:?}");
    }

    #[test]
    fn phantom_sign_transaction_high_risk_asks() {
        // "sign" IS in the pattern, but this must be gated as a high-risk wallet-signing
        // class (server `phantom` ⇒ id `phantom-mcp`), not a plain sensitive-name match.
        let (d, m) = decide(
            "mcp__phantom__signTransaction",
            None,
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert_eq!(m.scope, Scope::Other);
        assert!(
            d.reason().contains("wallet signing"),
            "reason: {}",
            d.reason()
        );
    }

    #[test]
    fn phantom_sign_message_high_risk_asks() {
        // `signMessage` does NOT contain "signing" — only the id (server) match catches it.
        let (d, _) = decide(
            "mcp__phantom__signMessage",
            None,
            &ctx(),
            &Policy::default(),
        );
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
    }

    #[test]
    fn x402_key_custody_high_risk_asks() {
        let (d, m) = decide("mcp__x402__createWallet", None, &ctx(), &Policy::default());
        assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
        assert_eq!(m.scope, Scope::Other);
        assert!(d.reason().contains("key-custody"), "reason: {}", d.reason());
    }

    #[test]
    fn high_risk_deny_when_policy_says_deny() {
        let mut p = Policy::default();
        for c in &mut p.catalog.high_risk_classes {
            if c.kind == "wallet_signing" {
                c.decision = "deny".into();
            }
        }
        let (d, _) = decide("mcp__phantom__signTransaction", None, &ctx(), &p);
        assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
    }

    #[test]
    fn benign_helius_read_not_high_risk() {
        // helius must NOT be misclassified as a high-risk server.
        let (d, _) = decide("mcp__helius__getBalance", None, &ctx(), &Policy::default());
        assert_eq!(d, Decision::Defer);
    }
}
