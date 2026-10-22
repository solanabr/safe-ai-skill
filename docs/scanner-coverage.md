# Scanner coverage

safe-ai-skill scans skill packs with a native rule engine (`crates/engine/src/verify/rules/`).
It has no network access, runs no processes and has no LLM. This page maps the engine against the
pack-review checklist in solanabr/ai-kit's `docs/skill-packs.md`, and lists what stays a manual
review step. Decision record: design spec D2.4–D2.5, D2.10 and D7.1.

## How a pack is graded

Every finding has a rule id, a severity (`info`, `warn` or `high`), a pack-relative `path:line` and a
context:

| Context | What it covers |
|---|---|
| `code` | Executable source, decided by extension, shebang or exec bit, plus `` !`cmd` `` lines. Lines are joined into statements (open brackets, `\` continuations), and a tool and its marker must appear in the same command. |
| `doc` | Markdown prose, fenced blocks and inline code, and any other text file (JSON, YAML, HTML …). |
| `meta` | Pack structure: manifests, harness config, `SKILL.md` frontmatter, symlinks and binaries. |

The pack grade (`rules::grade`) is decided as follows:

* **clean**: nothing above INFO.
* **warn**: the worst finding is WARN. **Findings in docs are capped at WARN**, because the runtime
  gates catch execution.
* **high**: at least one code or meta finding at HIGH. A pack seen for the first time is recorded as
  *unreviewed* and the user is warned. It is never blocked.
* **block**: only a combination rule fires. Drift against a pin or a committed `packs.lock` is
  decided by the verify state machine, not by the scanner.

A sink written inside a string literal or a comment (code-as-data: a help text, a rule table, a
command built for a remote host) is graded WARN and never feeds a combination rule.

## Combination rules (the only BLOCKs)

| Combo | Fires when |
|---|---|
| `padding_sink` | A run of 100+ whitespace characters (space, tab, Unicode Zs, blank-rendering fillers) has an exec, env-dump or network sink on the same line; or 50+ blank lines are followed by such a sink. Code only. |
| `exec_b64_literal` | An execution sink and a quoted base64 literal of 64+ characters appear in the same command. The literal must not be hex, and either a decoder is present or the literal decodes to text, so signatures, hashes and keys don't count. |
| `eval_decoder` | `eval` / `Function(` anywhere in the pack's code plus a decoder anywhere in it (a split payload). Build output (`dist/`, `build/`, `out/`, `.next/`, `node_modules/`, `*.min.js`, `*.bundle.js`) is left out of this cross-file rule. |
| `symlink_escape` | A symlink target leaves the pack, judged lexically from the link's directory. An absolute target always counts. |
| `pyc_beside_py` | `x.pyc` (or `__pycache__/x.cpython-NNN.pyc`) ships next to `x.py`. |
| `native_binary` | A native ELF, Mach-O or PE file. BPF and SBF `.so` files (e_machine 247 and 263) are exempt. |
| `masquerade_referenced` | Archive or executable bytes sit behind a text extension, and a `SKILL.md` names the file, its stem or its disguised inner extension (`.docx` in `x.docx.txt`). |
| `bang_exfil` | A `` !`cmd` `` outside a fence touches the network, a secret path, the environment or a credential variable. |
| `description_injection` | A `SKILL.md` description carries shell syntax (`$(`, `\| sh`, `&&` …), a URL with a fetch/visit/follow verb in front of it, an instruction aimed at every turn ("before responding …"), or injection phrasing. Tag characters are decoded first. |
| `lifecycle_network` | An npm `preinstall`, `install`, `postinstall` or `prepare` script reaches the network (curl, wget, npx, a URL …) or evaluates inline code (`node -e`, `python -c`, `eval`). |
| `harness_bypass` | A shipped `.claude/settings*.json` contains `bypassPermissions`, `defaultMode` or `dangerously*`. |
| `registry_hijack` | Code writes package-manager registry config (`.npmrc`, `.yarnrc`, `pip.conf`, `npm config set registry`, git `insteadOf` …) and names a registry host other than npmjs, yarnpkg, PyPI, crates.io or rubygems in the same file. A git `insteadOf` that only adds credentials to the same host is not a hijack. |

## ai-kit checklist coverage

The checklist from ai-kit's `docs/skill-packs.md` ("Non-official pack provenance"):

| Checklist item | Rules (code / doc severity) | Stays manual |
|---|---|---|
| Lines over 500 characters (payload hidden behind padding) | `padding_horizontal` HIGH / WARN; `padding_vertical` HIGH / WARN; `long_line` INFO; `encoded_blob` WARN (a long base64 run that decodes to text, i.e. printable ratio ≥ 0.75; data such as account state sits near 0.34); combo `padding_sink` | Reading what a long data line encodes |
| `eval` / `atob` / `new Function` / `createRequire` | `eval` HIGH; `obfuscated_sink` HIGH (computed eval, `constructor.constructor`, `data:` imports, string timers, `vm`, Python `exec`/`pickle`/`marshal`/`__import__`); `exec_decode` HIGH; `decoder` INFO; `create_require` INFO; combos `exec_b64_literal`, `eval_decoder` | Deobfuscating anything beyond these shapes |
| `child_process` | `child_process` INFO (also a sink for `padding_sink`); `shell_eval` INFO | What each spawned command does |
| Env-var and keypair reads | `secret_read` HIGH / WARN (keypair, `.config/solana`, `.ssh`, `.aws/credentials`, `.netrc`, `.env*` except templates; a read call or a read command next to the path); `env_dump` INFO; `embedded_secret_key` INFO | Reading individual env-var names |
| Hardcoded URLs and IPs in source | `telemetry_post` HIGH / WARN (a POST carrying usage words or local data to an external host); `network_post` WARN / INFO; `ip_literal` WARN / INFO (public IPv4 destinations) | Judging whether each endpoint is the vendor's own |
| Pipe-to-shell installers | `download_and_run` HIGH / WARN (`curl … \| sh`, `sh -c "$(curl …)"`, `bash <(curl …)`, `iex (iwr …)`, eval of fetched content) | — |
| Install lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`) | `lifecycle_script` HIGH, at the key's line; every `package.json` script is scanned as shell code; combo `lifecycle_network` | What the script's own files do |
| Invisible and bidirectional Unicode | `unicode_bidi`, `unicode_invisible` WARN / INFO; `unicode_tag` WARN. Emoji joiners, script joiners and a leading BOM are ignored. | Trojan Source review of flagged lines |
| Symlinks (target, and whether it leaves the pack) | `symlink` INFO; combo `symlink_escape`. Links are never followed. | — |
| Executables (`find -perm -u+x`, naming each) | `executable` INFO for each file with an exec bit; shebang and exec-bit files are scanned as code | **What each executable does** |
| Every blob in full history | Not at SessionStart | **Manual**, or the hardened git reader planned for `verify add` (spec D7.3) |
| `hooks.json` | `harness_hooks` WARN (`hooks/`, `.claude-plugin/`, `.codex-plugin/`) | — |
| `.claude/settings.json` | `harness_settings` WARN; combo `harness_bypass` | — |
| `.mcp.json` | `mcp_config` INFO; `unpinned_npx` INFO for `@latest` / unpinned runners | Each connector's scope |
| A nested `.claude/skills/` | `nested_skills_dir` INFO | — |
| A root `CLAUDE.md`, `AGENTS.md` or `GEMINI.md` | `instruction_file` INFO; `prompt_injection` and `hidden_instruction` WARN anywhere | Reading the instructions |
| The pack's own `.gitmodules` | `gitmodules` INFO | Vetting the nested repositories |
| Author, provenance, license | — | **Manual** (the table in ai-kit's `skill-packs.md`) |

Beyond the checklist, the engine also covers:

* **Archives and executables in disguise:** `archive_masquerade` HIGH and `archive` INFO.
* **Shipped bytecode:** `bytecode` HIGH.
* **Package-manager and git tampering:** `registry_write` and `git_hooks_write` HIGH.
* **Load-time commands:** `bang_cmd` HIGH.
* **Model-facing text:**
  * the `SKILL.md` description (`description_url` WARN, combo `description_injection`);
  * prompt-injection phrasing;
  * instruction-carrying HTML comments;
  * unscoped `Bash` grants (`broad_tools` INFO).
* **Unscanned tails:** `oversize_file`, HIGH for code past the 16 MiB scan cap.

Lockfiles (`*.lock`, `package-lock.json`, `pnpm-lock.yaml` …) without an exec bit or shebang are
dependency data. They are inventoried at `verify add|check` (spec D7.2), not text-scanned.
`build.rs`, proc-macro crates, `.cargo/config.toml`, `binding.gyp` and npm `hasInstallScript` are
build-time execution, reported at `verify add|check` (D7.2), not at SessionStart.

## External scanners (spec D7.1)

| | safe-ai-skill | SkillSpector | Sentry skill-scanner | Cisco skill-scanner |
|---|---|---|---|---|
| Runs offline, no LLM | yes | only with `--no-llm` (still calls osv.dev) | yes | partly |
| Padding | yes, plus combo | yes | no | no |
| JS exec surface (`execSync`, `createRequire`, `Function(atob…)`) | yes | partial | partial | partial |
| Lifecycle (`prepare` included) | yes | partial | partial (omits `prepare`) | no |
| Symlinks | reported, never followed | silently skipped | crashes on a loop | yes |
| Harness config | yes | yes | partial | ? |
| Docs vs code grading | yes | no | no | no |

SkillSpector `--no-llm` is suggested as an advisory SARIF job in ai-kit CI when pins are bumped. Its
rule ideas were reimplemented here; no rule lists were copied.

## Acceptance corpus

`crates/engine/tests/rules_corpus.rs`:

* **Shapes** (always run): the four Trail of Bits skills re-synthesised (csv-summarizer vertical padding plus env dump,
  context-loader docx masquerade, simple-formatter `.pyc`, dev-env-setup registry overwrite), the
  issue #10 stealer, the scanner-research demo pack, harness bypass and bang exfil all **BLOCK**.
  Google's `exec(base64.b64decode('{encoded_script}'))` (built as a string) is **WARN**. Fixtures
  are inert: payloads decode to a `console.log`, and hosts are `example.invalid`.
* **ai-kit** (opt-in): the 46 packs at the commit pinned in `aikit.manifest.tsv` give **0 BLOCK and
  13 HIGH** (limit 14), each HIGH a true behaviour, and every pack matches its expected grade. Run it with:

  ```bash
  SAFE_AI_SKILL_CORPUS=1 cargo test --release --test rules_corpus -- --nocapture
  # add SAFE_AI_SKILL_CORPUS_DIR=<ai-kit checkout> to reuse a clone,
  # and SAFE_AI_SKILL_CORPUS_VERBOSE=1 to list every combo, HIGH and WARN finding.
  ```

  Release builds also assert that the scan stays under 5 s. It measures 2.3–3.6 s for 106 MB of
  text across 13.5k files (about 0.5 s of that is file I/O).

## Known limits

* **Obfuscation beyond the listed shapes.** Rule-based recall is low by nature: Cisco's
  benchmark puts rules-only recall at about 8% at HIGH. The runtime gates remain the backstop.
* **Unpaired fragments.** A payload split so that no sink and decoder or padding ever meet in
  hand-written code grades HIGH at most.
* **Multi-line strings.** Python docstrings and template literals spanning lines are not tracked
  as strings across lines.
* **Unknown endpoint variables.** An unresolved variable named like an endpoint (`$RPC_URL`) is
  treated as user-configured.
* **History.** Full-history and docs-only-commit checks (D7.3) are not implemented at
  SessionStart.
