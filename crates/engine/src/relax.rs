//! Relaxation layer: turn an `Ask` into an `Allow` when a grant permits it, and activate
//! confirmed relaxations.
//!
//! Centralizes all grant-driven relaxation so gates stay pure. `main.rs` calls [`apply`] on
//! every gate result before auditing and emitting. Hard guards
//! ([`crate::gate::GateMeta::hard_guard`]) are NEVER relaxed.
//!
//! ## Profile vs grant split
//!
//! 1. **Profile half** — [`crate::policy::Policy::effective`] applies the active profile's
//!    caps before the gate runs (`autopilot` raises the per-tx cap). `paranoid` sets
//!    `ask_all`, which [`apply_verdict`] enforces here: no allow survives it, not even a
//!    grant's.
//! 2. **Grant half** — a time-boxed, budgeted [`crate::grants::Grant`] can upgrade a residual
//!    `Ask` to `Allow` and debit its budget. Only authenticated grants in a trusted data dir
//!    count ([`grants::live`]).
//!
//! ## Confirmation (spec D4.1)
//!
//! `safe-ai-skill allow` and `mode <looser>` only park a pending entry, with no code
//! ([`crate::confirm::create_pending`]). [`announce`] makes the code and returns it for a
//! hook `systemMessage` (user only). [`confirm_prompt`] runs in the `UserPromptSubmit` hook:
//! when the user's whole prompt is `safe-ai-skill confirm <code>`, it consumes the entry,
//! performs it, audits it, and returns the `systemMessage` that tells the user what they just
//! approved; wrong codes lead to the lockout.

use serde_json::{json, Value};

use crate::audit::{self, AuditEntry};
use crate::confirm::{self, Attempt, PendingKind};
use crate::datadir::DataDir;
use crate::gate::{AllowReason, GateMeta, GrantId, Verdict};
use crate::grants::{self, GrantRequest};
use crate::io::Decision;
use crate::mode;
use crate::policy::Policy;

/// The reason an allow becomes an ask under `paranoid`.
pub const ASK_ALL_REASON: &str =
    "safe-ai-skill paranoid profile: every Solana action asks — approve to proceed";

/// Apply the relaxation layer to a gate's natural decision; see [`apply_verdict`].
pub fn apply(natural: Decision, meta: &GateMeta, policy: &Policy, dir: &DataDir) -> Decision {
    match natural {
        Decision::Ask { reason } => apply_verdict(Verdict::Ask(reason), meta, policy, dir).into(),
        Decision::Allow if policy.active_overlay().ask_all => Decision::Ask {
            reason: ASK_ALL_REASON.to_string(),
        },
        other => other,
    }
}

/// [`apply`] over a [`Verdict`]: a relaxed `Ask` becomes
/// `Allow(`[`AllowReason::Grant`]`)` naming the grant that permitted it. This is the only
/// place that mints a [`GrantId`].
///
/// Contract:
/// - `policy` is the EFFECTIVE policy. Under its `ask_all` (paranoid) every `Allow` becomes
///   an `Ask` and no grant is consulted.
/// - Only an `Ask` is a relaxation candidate; `Deny`/`NoOpinion` pass through.
/// - A hard guard is never relaxed.
/// - Otherwise the first live grant ([`grants::live`]: authenticated, trusted dir) that
///   matches within budget / `max_tx_sol` is debited for `meta.amount_sol` and named.
pub fn apply_verdict(natural: Verdict, meta: &GateMeta, policy: &Policy, dir: &DataDir) -> Verdict {
    if policy.active_overlay().ask_all {
        return match natural {
            Verdict::Allow(_) => Verdict::Ask(ASK_ALL_REASON.to_string()),
            other => other,
        };
    }

    if !matches!(natural, Verdict::Ask(_)) || meta.hard_guard {
        return natural;
    }

    let live = grants::live(dir);
    let grant_id = match grants::find_match(&live, meta) {
        Some(g) => g.id.clone(),
        None => return natural,
    };

    // `find_match` verified the budget covers this amount. A debit that cannot be persisted
    // means the grant cannot be charged: keep the ask rather than over-grant.
    let amount = meta.amount_sol.unwrap_or(0.0);
    if grants::debit(dir, &grant_id, amount).is_err() {
        return natural;
    }

    Verdict::Allow(AllowReason::Grant(GrantId::new(grant_id)))
}

/// What the `UserPromptSubmit` hook prints for a confirmation prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmOutcome {
    /// Shown to the user.
    pub system_message: String,
    /// Given to the model.
    pub additional_context: String,
}

impl ConfirmOutcome {
    /// The hook JSON: `systemMessage` plus `hookSpecificOutput.additionalContext`. The prompt
    /// itself is not blocked.
    pub fn hook_output(&self) -> Value {
        json!({
            "systemMessage": self.system_message,
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": self.additional_context,
            },
        })
    }

    fn note(text: String) -> ConfirmOutcome {
        ConfirmOutcome {
            additional_context: text.clone(),
            system_message: text,
        }
    }
}

/// Handle a user prompt that tries to confirm a pending relaxation.
///
/// `prompt` MUST come from [`confirm::user_prompt`] (the `UserPromptSubmit` payload); nothing
/// else is ever passed. `None` when the prompt is not a confirmation attempt (no output).
///
/// The whole prompt, trimmed, must be the single line `safe-ai-skill confirm <code>`
/// ([`confirm::classify`]): a confirm line inside pasted text is refused without consuming
/// anything. Wrong codes count toward the lockout ([`confirm::MAX_FAILURES`]), which cancels
/// every pending request and is audited as a tamper event. The outcome never contains a code.
pub fn confirm_prompt(dir: &DataDir, prompt: &str, now: u64) -> Option<ConfirmOutcome> {
    match confirm::confirm_attempt(dir, prompt, now) {
        Attempt::NotAnAttempt => None,
        Attempt::Embedded => Some(ConfirmOutcome::note(
            "safe-ai-skill: nothing confirmed. Type `safe-ai-skill confirm <code>` as the whole \
             prompt, on its own."
                .to_string(),
        )),
        Attempt::Wrong { remaining } => Some(ConfirmOutcome::note(format!(
            "safe-ai-skill: nothing confirmed. No pending request matches that code; it may have \
             expired (10 minutes) or been used already. {remaining} more wrong code(s) cancel \
             every pending request."
        ))),
        Attempt::LockedOut => {
            audit_event(
                dir,
                "state_tamper",
                "confirm_lockout",
                "too many wrong confirmation codes; every pending request was cancelled",
            );
            Some(ConfirmOutcome::note(
                "safe-ai-skill: too many wrong confirmation codes, so every pending request was \
                 cancelled. Run the command again to get a new code."
                    .to_string(),
            ))
        }
        Attempt::Confirmed(confirmed) => Some(activate(dir, &confirmed, now)),
    }
}

/// The `systemMessage` announcing new confirmation codes, if any (user only).
pub fn announce(dir: &DataDir, now: u64) -> Option<String> {
    confirm::announcement_message(&confirm::announce_pending(dir, now))
}

/// Perform a confirmed pending entry and describe the result.
fn activate(dir: &DataDir, confirmed: &confirm::Confirmed, now: u64) -> ConfirmOutcome {
    let (kind, payload) = (confirmed.kind, &confirmed.payload);
    let result = match kind {
        PendingKind::Grant => activate_grant(dir, payload, now),
        PendingKind::Mode => activate_mode(dir, payload, now),
        // `verify trust` / `verify approve`: performed (and audited) by the supply-chain state.
        PendingKind::Trust | PendingKind::Approve => {
            crate::verify::apply_confirmed(dir, confirmed).map_err(|e| e.to_string())
        }
    };
    let untrusted = if dir.trusted {
        ""
    } else {
        " Warning: the plugin data dir is not in a trusted location, so it will not take effect."
    };
    match result {
        Ok(done) => {
            audit_event(dir, kind_label(kind), "confirmed", &done);
            ConfirmOutcome {
                system_message: format!("safe-ai-skill: you confirmed: {done}.{untrusted}"),
                additional_context: format!(
                    "The user confirmed a safe-ai-skill relaxation: {done}.{untrusted} No action \
                     is needed."
                ),
            }
        }
        Err(why) => {
            audit_event(dir, kind_label(kind), "confirm_failed", &why);
            ConfirmOutcome::note(format!("safe-ai-skill: confirmation failed: {why}."))
        }
    }
}

fn activate_grant(dir: &DataDir, payload: &Value, now: u64) -> Result<String, String> {
    let request: GrantRequest = serde_json::from_value(payload.clone())
        .map_err(|_| "the pending grant is invalid".to_string())?;
    let grant = request.activate(now, grants::new_id(dir, now))?;
    let described = grant.describe(now);
    let replaced = grants::add(dir, grant, now).map_err(|e| format!("could not store it: {e}"))?;
    Ok(if replaced {
        format!("{described} (grants.json had failed authentication and was replaced)")
    } else {
        described
    })
}

fn activate_mode(dir: &DataDir, payload: &Value, now: u64) -> Result<String, String> {
    let profile = payload
        .get("profile")
        .and_then(Value::as_str)
        .filter(|p| mode::is_known_profile(p))
        .ok_or_else(|| "the pending mode change is invalid".to_string())?;
    mode::set(dir, profile, now).map_err(|e| format!("could not store it: {e}"))?;
    Ok(format!("mode {profile}"))
}

fn kind_label(kind: PendingKind) -> &'static str {
    match kind {
        PendingKind::Grant => "grant_create",
        PendingKind::Mode => "mode_set",
        PendingKind::Trust => "verify_trust",
        PendingKind::Approve => "verify_approve",
    }
}

fn audit_event(dir: &DataDir, classification: &str, decision: &str, reason: &str) {
    let entry = AuditEntry::new(
        "",
        "safe-ai-skill",
        classification,
        decision,
        reason,
        audit::sha256_hex(reason.as_bytes()),
    );
    let _ = audit::append(&entry, &dir.path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Scope;
    use crate::grants::tests::{tmp_data, transfer_grant, ADDR};
    use crate::grants::Grants;

    fn effective_policy() -> Policy {
        Policy::fail_closed().effective()
    }

    fn paranoid_policy() -> Policy {
        crate::policy::Policy::from_sources(
            crate::policy::DEFAULT_POLICY_YAML,
            None,
            Some("paranoid"),
            None,
        )
        .effective()
    }

    fn transfer_meta(amount: f64, hard_guard: bool) -> GateMeta {
        GateMeta {
            scope: Scope::Transfer,
            amount_sol: Some(amount),
            program: None,
            destination: None,
            hard_guard,
        }
    }

    fn write_transfer_grant(dir: &DataDir, budget: f64) {
        let mut grant = transfer_grant("g1", u64::MAX);
        grant.budget_sol = budget;
        grants::save(
            dir,
            &Grants {
                grants: vec![grant],
            },
        )
        .unwrap();
    }

    fn ask() -> Decision {
        Decision::Ask {
            reason: "transfer".into(),
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[test]
    fn ask_with_matching_grant_becomes_allow_and_debits() {
        let dir = tmp_data("relax_match");
        write_transfer_grant(&dir, 5.0);
        let out = apply(ask(), &transfer_meta(0.5, false), &effective_policy(), &dir);
        assert_eq!(out, Decision::Allow);
        assert_eq!(grants::live(&dir).grants[0].spent_sol, 0.5);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn verdict_relaxation_names_the_grant() {
        let dir = tmp_data("relax_verdict");
        write_transfer_grant(&dir, 5.0);
        let out = apply_verdict(
            Verdict::Ask("transfer".into()),
            &transfer_meta(0.5, false),
            &effective_policy(),
            &dir,
        );
        match out {
            Verdict::Allow(AllowReason::Grant(id)) => assert_eq!(id.as_str(), "g1"),
            other => panic!("expected a grant allow, got {other:?}"),
        }
        let secret = Verdict::Ask("secret".into());
        assert_eq!(
            apply_verdict(
                secret.clone(),
                &transfer_meta(0.5, true),
                &effective_policy(),
                &dir
            ),
            secret
        );
        assert_eq!(
            apply_verdict(
                Verdict::NoOpinion,
                &transfer_meta(0.5, false),
                &effective_policy(),
                &dir
            ),
            Verdict::NoOpinion
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn ask_without_grant_stays_ask() {
        let dir = tmp_data("relax_nogrant");
        grants::save(&dir, &Grants::default()).unwrap();
        assert_eq!(
            apply(ask(), &transfer_meta(0.5, false), &effective_policy(), &dir),
            ask()
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_hand_written_grant_does_not_relax() {
        let dir = tmp_data("relax_forged");
        std::fs::create_dir_all(&dir.path).unwrap();
        let body = serde_json::to_string(&Grants {
            grants: vec![transfer_grant("forged", u64::MAX)],
        })
        .unwrap();
        std::fs::write(dir.path.join(grants::GRANTS_FILE), body).unwrap();
        assert_eq!(
            apply(ask(), &transfer_meta(0.5, false), &effective_policy(), &dir),
            ask()
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn an_untrusted_data_dir_does_not_relax() {
        let mut dir = tmp_data("relax_untrusted");
        write_transfer_grant(&dir, 5.0);
        dir.trusted = false;
        assert_eq!(
            apply(ask(), &transfer_meta(0.5, false), &effective_policy(), &dir),
            ask()
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn hard_guard_never_relaxed_even_with_grant() {
        let dir = tmp_data("relax_hardguard");
        write_transfer_grant(&dir, 5.0);
        let secret = Decision::Ask {
            reason: "secret read".into(),
        };
        let out = apply(
            secret.clone(),
            &transfer_meta(0.5, true),
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, secret);
        assert_eq!(grants::live(&dir).grants[0].spent_sol, 0.0);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn deny_allow_and_defer_pass_through() {
        let dir = tmp_data("relax_passthrough");
        write_transfer_grant(&dir, 5.0);
        let deny = Decision::Deny {
            reason: "over hard cap".into(),
        };
        let meta = transfer_meta(0.5, false);
        assert_eq!(apply(deny.clone(), &meta, &effective_policy(), &dir), deny);
        assert_eq!(
            apply(Decision::Allow, &meta, &effective_policy(), &dir),
            Decision::Allow
        );
        assert_eq!(
            apply(Decision::Defer, &meta, &effective_policy(), &dir),
            Decision::Defer
        );
        assert_eq!(grants::live(&dir).grants[0].spent_sol, 0.0);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn amount_over_grant_cap_stays_ask() {
        let dir = tmp_data("relax_overcap");
        write_transfer_grant(&dir, 5.0); // max_tx_sol = 1.0
        assert_eq!(
            apply(ask(), &transfer_meta(2.0, false), &effective_policy(), &dir),
            ask()
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn paranoid_turns_every_allow_into_an_ask_and_ignores_grants() {
        let dir = tmp_data("relax_paranoid");
        write_transfer_grant(&dir, 5.0);
        let policy = paranoid_policy();
        let meta = transfer_meta(0.5, false);
        assert_eq!(
            apply(Decision::Allow, &meta, &policy, &dir),
            Decision::Ask {
                reason: ASK_ALL_REASON.into()
            }
        );
        assert_eq!(apply(ask(), &meta, &policy, &dir), ask());
        assert_eq!(
            apply_verdict(
                Verdict::Allow(AllowReason::WithinCapTestnet),
                &meta,
                &policy,
                &dir
            ),
            Verdict::Ask(ASK_ALL_REASON.into())
        );
        assert_eq!(grants::live(&dir).grants[0].spent_sol, 0.0);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    // -----------------------------------------------------------------------------------
    // Prompt-nonce confirmation
    // -----------------------------------------------------------------------------------

    /// Create and announce an entry; the code is what the user's systemMessage would show.
    fn pending(dir: &DataDir, kind: PendingKind, payload: Value) -> confirm::Nonce {
        confirm::create_pending(dir, kind, "summary", payload).unwrap();
        let shown = confirm::announce_pending(dir, now());
        assert_eq!(shown.len(), 1);
        shown[0].code.clone()
    }

    fn pending_grant(dir: &DataDir) -> confirm::Nonce {
        let req = GrantRequest::from_args("transfer", "30m", 1.0, 5.0, "", ADDR, false).unwrap();
        pending(dir, PendingKind::Grant, serde_json::to_value(&req).unwrap())
    }

    #[test]
    fn wrong_codes_lock_out_and_audit_a_tamper_event() {
        let dir = tmp_data("confirm_lockout");
        let code = pending_grant(&dir);
        let wrong = if code.as_str() == "11111111" {
            "22222222"
        } else {
            "11111111"
        };
        for _ in 0..2 {
            let out =
                confirm_prompt(&dir, &format!("safe-ai-skill confirm {wrong}"), now()).unwrap();
            assert!(out.system_message.contains("nothing confirmed"));
        }
        let out = confirm_prompt(&dir, &format!("safe-ai-skill confirm {wrong}"), now()).unwrap();
        assert!(
            out.system_message.contains("cancelled"),
            "{}",
            out.system_message
        );
        let audit = std::fs::read_to_string(dir.path.join("audit.jsonl")).unwrap();
        assert!(audit.contains("confirm_lockout"), "{audit}");
        let late = confirm_prompt(&dir, &format!("safe-ai-skill confirm {code}"), now()).unwrap();
        assert!(late.system_message.contains("nothing confirmed"));
        assert!(grants::live(&dir).grants.is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn announce_shows_the_code_once_and_never_in_model_context() {
        let dir = tmp_data("confirm_announce");
        let req = GrantRequest::from_args("swap", "1h", 1.0, 2.0, "", "", false).unwrap();
        confirm::create_pending(
            &dir,
            PendingKind::Grant,
            &req.summary(),
            serde_json::to_value(&req).unwrap(),
        )
        .unwrap();
        let msg = announce(&dir, now()).expect("an announcement");
        let code: String = msg
            .split("safe-ai-skill confirm ")
            .nth(1)
            .unwrap()
            .chars()
            .take(8)
            .collect();
        assert!(msg.contains("swap"), "{msg}");
        assert_eq!(announce(&dir, now()), None);
        let out = confirm_prompt(&dir, &format!("safe-ai-skill confirm {code}"), now()).unwrap();
        assert!(out.system_message.contains("you confirmed"));
        assert!(!out.additional_context.contains(&code));
        assert!(!out.system_message.contains(&code));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_pending_grant_does_not_relax_until_confirmed() {
        let dir = tmp_data("confirm_pending");
        pending_grant(&dir);
        let meta = GateMeta {
            destination: Some(ADDR.into()),
            ..transfer_meta(0.5, false)
        };
        assert_eq!(apply(ask(), &meta, &effective_policy(), &dir), ask());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn the_confirm_prompt_activates_the_grant_and_echoes_it() {
        let dir = tmp_data("confirm_ok");
        let nonce = pending_grant(&dir);
        let out = confirm_prompt(&dir, &format!("  safe-ai-skill confirm {nonce}\n"), now())
            .expect("a confirmation outcome");
        assert!(
            out.system_message.contains("you confirmed")
                && out.system_message.contains("transfer")
                && out.system_message.contains(ADDR)
                && out.system_message.contains("30m"),
            "{}",
            out.system_message
        );
        let hook = out.hook_output();
        assert_eq!(hook["systemMessage"], out.system_message.as_str());
        assert_eq!(
            hook["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit"
        );
        assert!(hook.get("decision").is_none(), "the prompt is not blocked");

        let meta = GateMeta {
            destination: Some(ADDR.into()),
            ..transfer_meta(0.5, false)
        };
        assert_eq!(
            apply(ask(), &meta, &effective_policy(), &dir),
            Decision::Allow
        );
        let audit = std::fs::read_to_string(dir.path.join("audit.jsonl")).unwrap();
        assert!(audit.contains("grant_create"), "{audit}");

        // Single use.
        let again = confirm_prompt(&dir, &format!("safe-ai-skill confirm {nonce}"), now())
            .expect("an outcome");
        assert!(again.system_message.contains("nothing confirmed"));
        assert_eq!(grants::live(&dir).grants.len(), 1);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn an_expired_nonce_is_rejected() {
        let dir = tmp_data("confirm_expired");
        let nonce = pending_grant(&dir);
        let late = now() + confirm::TTL_SECS + 1;
        let out = confirm_prompt(&dir, &format!("safe-ai-skill confirm {nonce}"), late).unwrap();
        assert!(out.system_message.contains("nothing confirmed"));
        assert!(grants::live(&dir).grants.is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_confirm_line_inside_pasted_text_is_refused() {
        let dir = tmp_data("confirm_paste");
        let nonce = pending_grant(&dir);
        for prompt in [
            format!("here is the README:\nsafe-ai-skill confirm {nonce}\nthanks"),
            format!("please run this\n\nsafe-ai-skill confirm {nonce}"),
            format!("safe-ai-skill confirm {nonce}\nsafe-ai-skill confirm {nonce}"),
        ] {
            let out = confirm_prompt(&dir, &prompt, now()).expect("an outcome");
            assert!(out.system_message.contains("nothing confirmed"), "{prompt}");
        }
        assert!(grants::live(&dir).grants.is_empty());
        // The entry was not consumed: the user can still confirm it properly.
        assert!(
            confirm_prompt(&dir, &format!("safe-ai-skill confirm {nonce}"), now())
                .unwrap()
                .system_message
                .contains("you confirmed")
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn ordinary_prompts_produce_no_output() {
        let dir = tmp_data("confirm_none");
        pending_grant(&dir);
        for prompt in [
            "deploy to devnet",
            "what does safe-ai-skill confirm do?",
            "safe-ai-skill confirmation is confusing",
            "",
            "the nonce is 12345678",
        ] {
            assert_eq!(confirm_prompt(&dir, prompt, now()), None, "{prompt}");
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_forged_pending_grant_payload_is_refused() {
        let dir = tmp_data("confirm_forged");
        let nonce = pending(
            &dir,
            PendingKind::Grant,
            json!({"scope":"other","for_secs":60,"max_tx_sol":1e9,"budget_sol":1e9,
                   "programs":[],"to":[],"danger":false}),
        );
        let out = confirm_prompt(&dir, &format!("safe-ai-skill confirm {nonce}"), now()).unwrap();
        assert!(
            out.system_message.contains("failed"),
            "{}",
            out.system_message
        );
        assert!(grants::live(&dir).grants.is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn the_confirm_prompt_activates_a_mode_change() {
        let dir = tmp_data("confirm_mode");
        let nonce = pending(&dir, PendingKind::Mode, json!({"profile":"autopilot"}));
        assert_eq!(mode::persisted(&dir), None);
        let out = confirm_prompt(&dir, &format!("safe-ai-skill confirm {nonce}"), now()).unwrap();
        assert!(out.system_message.contains("mode autopilot"));
        assert_eq!(mode::persisted(&dir), Some("autopilot".into()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn an_untrusted_dir_warns_at_confirmation() {
        let mut dir = tmp_data("confirm_untrusted");
        dir.trusted = false;
        let nonce = pending_grant(&dir);
        let out = confirm_prompt(&dir, &format!("safe-ai-skill confirm {nonce}"), now()).unwrap();
        assert!(out.system_message.contains("not in a trusted location"));
        let _ = std::fs::remove_dir_all(&dir.path);
    }
}
