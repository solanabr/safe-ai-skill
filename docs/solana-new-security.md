# Security Audit: sendaifun/solana-new (superstack / solana.new)

**Audit date:** 2026-06-11
**Auditor:** safe-solana-ai security research (defensive, read-only)
**Target:** https://github.com/sendaifun/solana-new — the open-source platform behind
`https://www.solana.new`, installed via `curl -fsSL https://www.solana.new/setup.sh | bash`
**Scope:** install chain, telemetry/exfil, secrets handling, code-execution surfaces,
supply chain, permission posture, locally installed artifacts
**Local evidence base:** `/Users/azrael/.claude/skills/` (27 skill directories),
`/Users/azrael/.superstack/config.json`, `/Users/azrael/.claude/settings.json`,
`public/setup.sh` (fetched raw from GitHub), `cli/*.ts` (fetched from GitHub)

---

## Executive Summary

solana-new / superstack is a well-intentioned Solana developer toolkit that ships a
`curl | bash` installer, telemetry-instrumented skill files, and a global permission
grant to Claude Code. The project is not malicious and the authors have made visible
privacy-first design choices (telemetry opt-out, limited payload schema, no code/path
collection in Convex). However, several implementation gaps create real attack surface.

**Verdict: evidence of slop — not intentionally dirty, but structurally unsound for
production security use.**

The most significant findings are architectural: the installer trusts an unsigned,
unauthenticated CDN tarball rebuilt on every git push; the telemetry endpoint URL is
stored in a world-readable, user-writable plaintext config file that can be redirected to
an attacker-controlled server; skill preambles fire before user consent in at least one
skill; the npm package name `superstack` is squatted by an unrelated library, silently
failing the global install path; and Claude Code's global permission table is widened to
allow unrestricted `Bash`, `Read`, `Glob`, and `Grep` with no per-command scoping.

None of these findings require a nation-state threat model to exploit. A local write to
`~/.superstack/config.json` redirects all skill telemetry to an arbitrary endpoint. A
main-branch push to the GitHub repo is served live to all `--update` users within Vercel's
five-minute cache window, with no integrity check.

**Count by severity:** 3 Critical · 4 High · 4 Medium · 3 Low = **14 findings total**

---

## Findings Table

| ID | Title | Severity | Location | Evidence | Impact | Remediation |
|----|-------|----------|----------|----------|--------|-------------|
| SS-01 | Unsigned unauthenticated tarball download | Critical | `public/setup.sh:~190` | `curl -fsSL "${BASE_URL}/skills.tar.gz" -o "$TMP_DIR/skills.tar.gz"` — no hash, no signature, no checksum | Any `--update` user executes arbitrary code delivered from the Vercel CDN on every main-branch push; MITM or CDN compromise → RCE | Publish tarball hash in a separate signed channel; SRI hash in setup.sh; sign releases with GPG or Sigstore |
| SS-02 | Attacker-mutable telemetry endpoint | Critical | `public/setup.sh:~353`, all `SKILL.md` preambles | `c.convexUrl = 'https://...'` written to `~/.superstack/config.json` (mode 644); preambles read it: `_CONVEX_URL=$(cat ~/.superstack/config.json ... \| cut -d'"' -f4)` then `curl -s -X POST "$_CONVEX_URL/api/mutation"` | Any process with user-write access can redirect ALL skill telemetry to an attacker server; skill metadata (skill name, platform, OS arch, timestamp, CLI version, session ID) is exfiltrated to arbitrary URL | Hardcode the Convex URL in the skill binary / SKILL.md; do not make it config-mutable |
| SS-03 | Global Bash/Read/Glob/Grep permission grant | Critical | `public/setup.sh:~272–291` | `node -e "... c.permissions.allow.push(rule) ..."` adds `["Bash","Read","Glob","Grep"]` to `~/.claude/settings.json`; no per-command scoping | Every Claude Code session (all projects, all agents) runs with unrestricted shell and file read permissions; a skill or prompt injection that reaches Claude can run arbitrary commands or read keypairs without a confirmation prompt | Use per-command patterns (`Bash(npm *)`, `Read(~/.claude/skills/**)`) instead of token-level grants; educate users on the scope impact |
| SS-04 | Telemetry fires before user consent in navigate-skills | High | `~/.claude/skills/navigate-skills/SKILL.md:23` | Curl fires at line 23 with no `_TEL_TIER` guard; the guard only exists at line 181 (closing event); contrast with `colosseum-copilot/SKILL.md:17` which has `if [ "$_TEL_TIER" != "off" ]; then` | A user who set `telemetryTier=off` still has an outbound POST to the Convex endpoint every time `navigate-skills` is invoked, violating the opt-out contract | Move the opening curl inside the same `_TEL_TIER != "off"` guard used by the closing telemetry |
| SS-05 | Plaintext JWT stored world-readable | High | `~/.superstack/config.json` (mode 644) | Decoded JWT: `{scope:"colosseum_copilot:read", username:"kaue", sub:"72807", exp:1787183961}`; token grants read access to Colosseum Copilot API for 90 days | Any local user (shared machine, CI) can read the token and impersonate the authenticated user against the Colosseum API; file is world-readable on macOS default umask | Write config with mode 0600; consider OS keychain integration; rotate on detection |
| SS-06 | Non-interactive install defaults to telemetry ON | High | `public/setup.sh:~335` | `else\n  TELEMETRY_CHOICE="anonymous"\nfi` — when stdin is not a TTY (piped `curl \| bash`), telemetry defaults to "anonymous" with no explicit user consent | Users running the standard documented install command (`curl -fsSL ... \| bash`) have telemetry enabled without being asked; GDPR/CCPA-relevant for EU/US users | Default to "off" in non-interactive mode; require explicit opt-in |
| SS-07 | Two distinct Convex deployment URLs — consistency gap | High | `public/setup.sh:353`, `~/.superstack/config.json` | setup.sh hardcodes `sensible-crocodile-923.convex.cloud`; the machine's `config.json` contains `fastidious-fish-811.convex.cloud` (written by a prior install); skills always use the config.json value | If older config.json value points to a decommissioned or attacker-controlled endpoint, all skill telemetry is silently misdirected; no validation or update of the stored URL | On each run, validate convexUrl matches a known-good value; provide migration for stale configs |
| SS-08 | npm package name "superstack" is squatted | Medium | `package.json:"name":"superstack"`, `install.sh:NPM_PACKAGE="superstack"` | `npm view superstack` returns `0.0.4` by `shtylman@gmail.com` — the defunctzombie "long stack traces" library; `npm install -g superstack` installs the wrong package; install.sh silently falls back to `npx -y superstack init` → executes wrong package | Users running `npm install -g superstack` per install.sh documentation install an unrelated package; the fallback `npx -y superstack init` also executes it; no error shown | Register the "superstack" npm name or rename the package; use a scoped name (`@sendaifun/superstack`) |
| SS-09 | Community skills install via arbitrary GitHub URL | Medium | `cli/interactive-skills.ts`, `solana-skills.json` | `npx skills add ${s.url}` where `s.url` is any GitHub URL from the 65-entry community catalog | Any catalog entry whose GitHub repo is compromised or account-squatted delivers arbitrary code to users who select it; no hash pinning, no org verification | Pin community skill versions to immutable SHA refs in the catalog; add a curation/review notice |
| SS-10 | MCP setup_command and repo clone_command executed via `sh -c` without sanitization | Medium | `cli/workspace-setup.ts:~55` | `spawn("sh", ["-c", cmd], {...})` where `cmd` comes directly from catalog JSON string fields | If catalog JSON is tampered (compromised GitHub repo, supply-chain mutation of npm package) the command string executes with full user shell privileges; no escaping or allowlisting | Validate commands against an allowlist of prefixes (`git clone`, `npm install`, `npx skills add`); reject strings containing shell metacharacters outside known patterns |
| SS-11 | Vercel main-branch deploy = live update (no release gate) | Medium | `vercel.json`, `scripts/package-skills.sh` | Build command: `bash scripts/package-skills.sh`; route: `/skills.tar.gz` with `cache-control: max-age=300`; the tarball is rebuilt from `main` on every push | Any merged PR or direct push to main is live to all `--update` users within five minutes with no version gate, no changelog, no user notification | Require tagged releases; serve production tarball from a release tag rather than the live main build; add `cache-control: no-cache` gating for the `--update` flow |
| SS-12 | Founder Pass reads GitHub GraphQL via `gh auth` token | Low | `public/setup.sh:~410–440` | `gh api graphql -f query='...' -F login="$login"` — uses the authenticated gh CLI token to fetch contribution counts and repo counts | The GitHub token's permissions are not checked before use; if the user's `gh` token has broad scope, the query runs under that scope; however the query only reads public data, so impact is low | Document that `gh auth status` is checked; consider adding a `--no-github` flag to skip the Founder Pass fetch |
| SS-13 | Uninstall does not revert settings.json | Low | `cli/uninstall.ts` | "The function does not address `settings.json`" — confirmed from source; only the `public/setup.sh --uninstall` path (manifest-based) reverts permissions; the npm `superstack uninstall` command leaves permissions widened | After `npx superstack uninstall`, the global `["Bash","Read","Glob","Grep"]` allow entries remain permanently in `~/.claude/settings.json`; no indication to user | Implement permission revert in the CLI uninstall command mirroring the shell script's manifest-based revert |
| SS-14 | convex dependency in production package | Low | `package.json:"dependencies":{"convex":"^1.34.1"}` | The Convex SDK is a runtime production dependency using a semver range (`^1.34.1`); patch-level updates are auto-accepted | Minor Convex SDK supply-chain compromise would affect all CLI users; `^` range means any `1.x.y` update is automatically trusted | Pin to an exact version with lockfile (`convex@1.34.1`); use `npm audit` in CI |

---

## Deep-Dive Analysis by Investigation Area

### 1. The Install Chain

The canonical install is `curl -fsSL https://www.solana.new/setup.sh | bash`.

**Stage 1 — setup.sh fetch.** The script is served from Vercel (solana-new-landing.vercel.app
via the catch-all rewrite in `vercel.json`). There is no SRI hash, no GPG signature, and no
content-length verification. A MITM or Vercel account compromise delivers arbitrary code directly
into the user's shell.

**Stage 2 — skills.tar.gz download.** Inside `setup.sh` at approximately line 190:
```bash
curl -fsSL "${BASE_URL}/skills.tar.gz" -o "$TMP_DIR/skills.tar.gz"
# ...
tar -xzf "$TMP_DIR/skills.tar.gz" -C "$TMP_DIR"
```
No hash is verified after download. The tarball is the output of `scripts/package-skills.sh`,
which runs on every Vercel deployment from main. Five minutes after a main-branch push, every
user who runs `--update` gets the new content.

**Stage 3 — Claude Code permission grant.** The setup script then modifies
`~/.claude/settings.json`:
```bash
node -e "
  const c = JSON.parse(fs.readFileSync(p, 'utf8'));
  const rules = ['Bash', 'Read', 'Glob', 'Grep'];
  for (const rule of rules) {
    if (!c.permissions.allow.includes(rule)) {
      c.permissions.allow.push(rule);
    }
  }
  fs.writeFileSync(p, JSON.stringify(c, null, 2));
"
```
These are token-level grants (`Bash` = all bash commands, `Read` = all file reads) that apply
globally, not scoped to the skills directories.

**Stage 4 — convexUrl written to config.** The setup script hardcodes the Convex deployment
URL into `~/.superstack/config.json`:
```bash
c.convexUrl = 'https://sensible-crocodile-923.convex.cloud';
```
This file is created with the default umask (0644 on macOS) — world-readable.

**Stage 5 — npm install fallback.** The newer `install.sh` attempts `npm install -g superstack`.
This command resolves to the defunctzombie "long stack traces" library (v0.0.4, published 2015),
not the sendaifun project. The install silently fails with a warning and falls back to
`npx -y superstack init`, which also resolves to the wrong package.

### 2. Telemetry and Exfiltration Analysis

**What is sent.** Every SKILL.md preamble (all 24 installed skills) fires a POST to the
Convex mutation endpoint on skill invocation:
```bash
curl -s -X POST "$_CONVEX_URL/api/mutation" \
  -H "Content-Type: application/json" \
  -d '{"path":"telemetry:track","args":{"skill":"<name>","phase":"<phase>",
       "status":"success","version":"0.2.0",
       "platform":"'$(uname -s)-$(uname -m)'","timestamp":'$(date +%s)000'}}'
```
The Convex schema (`convex/schema.ts`) confirms the stored fields: `skill`, `phase`, `command`,
`status`, `durationMs`, `errorClass`, `version`, `platform`, `agentCli`, `timestamp`,
`installationId`. No code, no file paths, no project names — consistent with the stated privacy
design. The ending preamble also writes a local JSONL:
```
{"skill":"colosseum-copilot","phase":"idea","event":"completed","outcome":"success","duration_s":"0","session":"79793-1779408455","ts":"2026-05-22T00:07:35Z","platform":"Darwin-arm64"}
```

**The attacker-mutable URL problem.** The endpoint is read from `~/.superstack/config.json`
every time a skill runs. This file is 0644 and can be written by any process running as the
same user. If repointed to an attacker server, all skill invocations — for the lifetime of
the installation — silently POST to that server. The attacker receives the same metadata
fields, but because the curl fires in the background with `>/dev/null 2>&1`, the user
receives no feedback.

**Two Convex deployments.** The current `public/setup.sh` writes
`sensible-crocodile-923.convex.cloud`; but this machine's config.json (written by an earlier
install) has `fastidious-fish-811.convex.cloud`. Both are live Convex deployments owned by the
project. The skills use whatever URL is in config.json, creating a permanent drift risk for
users who installed before the URL changed.

**Pre-consent firing in navigate-skills.** The `navigate-skills/SKILL.md` preamble fires the
opening curl at line 23 without checking `_TEL_TIER`. The variable is read at line 17 but is
not consulted before the curl executes. The comparison `if [ "$_TEL_TIER" != "off" ]` only
appears at line 181, guarding the closing telemetry. A user with `telemetryTier=off` still
has an outbound POST on every `/navigate-skills` invocation as long as `_CONVEX_URL` is set.

**The CLI telemetry.ts discrepancy.** The CLI's `syncToConvex()` function reads CONVEX_URL
*only* from `process.env.CONVEX_URL || process.env.PROD_CONVEX_URL`. The skill SKILL.md
preambles read it from `~/.superstack/config.json`. These are two separate code paths.
If neither env var is set (standard user installation), the CLI telemetry never fires, but
the skill preambles always fire because the config.json has convexUrl populated.

### 3. Secrets Handling

**Colosseum Copilot JWT.** The `~/.superstack/config.json` on this machine contains:
```json
{
  "copilotToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "copilotTokenSetAt": "2026-05-21T23:59:52Z"
}
```
Decoded payload: `scope: "colosseum_copilot:read"`, `username: "kaue"`, `sub: "72807"`,
`exp: 1787183961` (expires 2026-08-19). The token grants read-only API access to Colosseum
Copilot project data for 90 days.

**File permissions.** The file is mode 0644 (world-readable). On a shared macOS system or
any multi-user environment, every other logged-in user can read this token with a trivial
`cat ~/.superstack/config.json` command. Best practice for secret-containing config files
is 0600. The `~/.claude/settings.json` file on this machine is correctly 0600; the
superstack config is not.

**Keypair files.** The skill preambles and SKILL.md workflow content do not touch
`~/.config/solana/id.json` or project keypair files. The data guides in
`skills/data/guides/` reference keypair paths in instructional context only. No skill
actively reads, uploads, or forwards keypair material. This is a genuine privacy-first
design choice that should be acknowledged.

**Token not included in telemetry.** Verification confirmed: the copilotToken is never
included in the curl POST body. The telemetry payload contains only the fields declared
in `convex/schema.ts`.

### 4. Code-Execution Surfaces

**A. Skill preamble bash blocks.** Every SKILL.md contains an explicit `## Preamble (run first)`
section with fenced bash code blocks. Claude Code executes these blocks when the skill
activates. The preamble code is delivered from `skills.tar.gz` (unauthenticated tarball).
If the tarball content changes (main-branch push, Vercel deploy), the new preamble executes
on the next skill invocation. The global `Bash` permission grant means these blocks run
without a user confirmation prompt.

**B. workspace-setup.ts `spawn("sh", ["-c", cmd])`.**
```typescript
const child = spawn("sh", ["-c", cmd], {
  stdio: ["ignore", "pipe", "pipe"],
  cwd,
  env: { ...process.env, npm_config_yes: "true" },
});
```
`cmd` is a string taken directly from the catalog JSON fields (`setup_command`,
`clone_command`, `install_command`). If any catalog JSON entry is mutated — through a
compromised community contributor PR, a hijacked npm dependency, or a poisoned GitHub repo
referenced in the catalog — the command string executes without sanitization. No allowlist,
no metacharacter filter, no sandbox.

**C. `npx skills add <arbitrary-url>`.** Community skills install via:
```
npx skills add https://github.com/<org>/<repo>
```
The `skills` package (v1.5.11, by rauchg/Vercel) handles this. The URL is arbitrary GitHub.
There is no hash pinning, no version lock, no org verification in the catalog entries.

**D. MCP setup commands.** The `solana-mcps.json` catalog lists setup commands such as:
- `npx @mcp-dockmaster/mcp-server-jupiter` (unpinned `@latest` equivalent)
- `npx -y @opensvm/dexscreener-mcp-server` (unpinned)
- `npx mcp-remote https://rugcheck.aethercore.dev` (remote HTTP MCP, no TLS pinning)

These are displayed to users and, in `workspace-setup.ts`, potentially executed via `sh -c`.

**E. npm postinstall.**
```json
"postinstall": "node dist/cli/index.js init --agent 2>/dev/null || true"
```
When `superstack` is installed as an npm package (`npm install -g superstack`), the
postinstall hook runs `init --agent`, which copies skill directories globally. This executes
automatically without user interaction. The `|| true` swallows all errors silently, including
cases where the wrong `superstack` package was installed.

### 5. Supply Chain

**Vercel main-branch deploy.** The `vercel.json` build configuration:
```json
"buildCommand": "bash scripts/package-skills.sh"
```
Skills are packaged on every deployment. There is no tag-gate. A direct push to `main`
(the default branch, open to contributions) triggers an immediate live update to
`https://www.solana.new/skills.tar.gz` within Vercel's 5-minute cache window.

**No SRI / no hash pinning.** Neither `setup.sh` nor `install.sh` verifies the tarball
hash after download. There is no `sha256sum --check` step. A CDN-level substitution
attack would succeed undetected.

**Community contributions.** The repository has recent commits from multiple external
contributors (`Uttam-Singhh`, `brucexu-eth`, `bogidotcom`, `4manj`, `Sharathxct`,
`abishekk92`) plus Claude/Copilot AI co-authors. Skill catalog entries added by contributors
pointing to their own GitHub repositories have no independent security review.

**npm name squatting (SS-08).** The intended `npm install -g superstack` resolves to
defunctzombie's unrelated 2015 package. This creates two risks: (1) the install silently
does the wrong thing; (2) if the old package is ever abandoned or taken over by a
malicious actor who then publishes a new version, users running `npm install -g superstack`
would receive malicious code through an apparently official channel.

**Unpinned transitive deps.** The sole production dependency `convex@^1.34.1` accepts
any `1.x.y` patch release without lockfile re-review.

**skills-lock.json.** The repository contains a `skills-lock.json` with SHA-256 hashes for
five Convex skills from `get-convex/agent-skills`. This is the right idea, but it only
covers five community skills and is not enforced at install time in the shell script path.

### 6. Permission and Sandbox Posture

The global Claude Code permission grant (`"Bash"`, `"Read"`, `"Glob"`, `"Grep"`) applies to
`~/.claude/settings.json` — the user-level settings file that governs **all Claude Code
sessions across all projects**. This means:

- Every project, whether or not it uses superstack, runs with these permissions
- Prompt injection in any Claude session can execute arbitrary shell commands without confirmation
- Any skill that runs (via auto-activation from a user's prompt) has unrestricted file read access
- The `Read` permission grant allows reading `~/.config/solana/id.json` (keypair), `.env` files,
  and any other file on the system without a prompt

The `public/setup.sh --uninstall` path (via manifest) correctly reverts these permissions.
However the CLI `superstack uninstall` command (in `cli/uninstall.ts`) does not — it only
removes skill directories. Users who installed via npm and uninstall via the CLI retain the
widened global permissions permanently.

---

## safe-solana-ai Mitigations

This section maps each finding to what safe-solana-ai (ssai) does — and does not — address.

| Finding | ssai Mitigation | Coverage |
|---------|----------------|----------|
| SS-01 Unsigned tarball | `~/.claude/skills/` is write-denied in ssai sandbox; session-start `verify` checks skill hash drift | Partial — catches post-install drift, not the initial install |
| SS-02 Attacker-mutable URL | `deny: Read(**/.superstack/config.json)` in `settings.json:246` blocks Read tool on config; but `Bash(cat *)` is allowed | Partial — blocks `Read` tool, does NOT block `Bash(cat ~/.superstack/config.json)` |
| SS-03 Broad permission grant | ssai `settings.json` uses per-command `allow` patterns (`Bash(anchor *)`, etc.) plus a `deny` list; project-level settings override user-level for ssai sessions | Mitigated within ssai sessions — the global `~/.claude/settings.json` widening remains for non-ssai sessions |
| SS-04 Pre-consent telemetry | `deny: Read(**/.superstack/config.json)` would prevent preamble from reading convexUrl | Mitigated — if Read is denied, the `_CONVEX_URL` extraction fails, curl silently skips |
| SS-05 World-readable JWT | `deny: Read(**/.superstack/config.json)` blocks Read tool; `gate-bash-secrets` hook (per SECURITY.md) blocks Bash reads | Mitigated at tool level; does not fix file permissions on disk |
| SS-06 Default-on telemetry | No mitigation — this is an install-time issue before ssai is in place | Not mitigated — install happens before ssai loads |
| SS-07 Stale Convex URL | If `Read` is denied for config.json, the URL cannot be read and curl silently skips | Mitigated indirectly |
| SS-08 npm squatting | ssai does not install from npm; installs from git submodule | Not applicable to ssai install path |
| SS-09 Community skill arbitrary URL | ssai's `claudeMdExcludes` and skill directory pinning limit which external skill directories load | Partial — ssai users who also run `npx skills add` can still install arbitrary skills |
| SS-10 sh -c catalog commands | ssai hooks gate Bash commands; `deny` patterns block obviously destructive commands | Partial — generic shell injection in catalog commands not fully blocked |
| SS-11 No release gate | Not addressable by ssai — upstream deployment issue | Not mitigated |
| SS-12 Founder Pass GitHub API | No ssai mitigation needed; impact is low (only reads public data) | Not needed |
| SS-13 Uninstall leaves permissions | ssai uses project-level `settings.json` that takes precedence; but `~/.claude/settings.json` remains | Partial — ssai project settings narrow permissions, but the user's global settings remain widened for other projects |
| SS-14 Unpinned convex dep | ssai's `cargo audit` workflow does not cover npm deps of external tools | Not mitigated |

**Honest gaps.** Two findings are NOT blocked by ssai in its current form:

1. **SS-01 at install time.** If the user runs `curl -fsSL https://www.solana.new/setup.sh | bash`
   before setting up ssai, the skills are installed with no integrity check. ssai's verify
   hook catches hash drift on subsequent sessions, but not the initial compromise.

2. **SS-02 via Bash.** `deny: Read(**/.superstack/config.json)` blocks the `Read` tool but does
   not block `Bash(cat ~/.superstack/config.json)`. The `gate-bash-secrets` hook described in
   `SECURITY.md` would close this gap if it patterns-matches the full path, but the current
   `settings.json` deny list does not contain a `Bash(cat *superstack*)` entry. This should
   be added.

---

## Responsible Disclosure Note

This audit was conducted as defensive research to understand the security posture of
tooling used by members of the Solana developer community, specifically to inform the
hardening approach of safe-solana-ai. All code was read-only (no vulnerability
exploitation, no tampering).

The sendaifun team has demonstrated genuine privacy-first intent: the Convex schema
explicitly excludes file paths and code from telemetry, the opt-out mechanism exists and
is documented, and the uninstall path (in the shell script) properly reverts permission
changes. The issues identified are implementation gaps, not evidence of malicious design.

The most impactful findings (SS-01 through SS-03) are suitable for direct responsible
disclosure to the sendaifun team at https://github.com/sendaifun/solana-new/security or
via their public communication channels. Suggested priorities for the team:

1. Add SRI hash verification to setup.sh for the skills.tar.gz download
2. Move convexUrl out of the mutable config file (hardcode in SKILL.md or use a pinned env var)
3. Scope the Claude Code permission grants to skill-specific patterns rather than token-level grants
4. Default telemetry to "off" in non-interactive installs
5. Correct the file permissions on `~/.superstack/config.json` to 0600
6. Fix the npm package name conflict (register or rename)
7. Fix the missing `_TEL_TIER` guard in `navigate-skills/SKILL.md`

---

## Sources

All findings are based on:
- `https://raw.githubusercontent.com/sendaifun/solana-new/main/public/setup.sh` (retrieved 2026-06-11)
- `https://github.com/sendaifun/solana-new/blob/main/cli/telemetry.ts` (retrieved 2026-06-11)
- `https://github.com/sendaifun/solana-new/blob/main/cli/workspace-setup.ts` (retrieved 2026-06-11)
- `https://github.com/sendaifun/solana-new/blob/main/cli/copilot-auth.ts` (retrieved 2026-06-11)
- `https://github.com/sendaifun/solana-new/blob/main/convex/schema.ts` (retrieved 2026-06-11)
- `https://github.com/sendaifun/solana-new/blob/main/package.json` (retrieved 2026-06-11)
- `https://github.com/sendaifun/solana-new/blob/main/vercel.json` (retrieved 2026-06-11)
- Local installed artifacts: `/Users/azrael/.claude/skills/` (27 SKILL.md files, inspected 2026-06-11)
- Local config: `/Users/azrael/.superstack/config.json`, `/Users/azrael/.claude/settings.json`
- npm registry: `npm view superstack` confirming package name conflict
- JWT decode: Python base64/JSON decode of token payload from `config.json`
